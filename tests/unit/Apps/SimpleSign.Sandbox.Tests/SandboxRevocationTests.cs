using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Shouldly;
using SimpleSign.Core.Extensions;
using SimpleSign.Core.Revocation;
using SimpleSign.Core.Validation;
using SimpleSign.Sandbox.Endpoints;
using SimpleSign.Sandbox.Pki;
using SimpleSign.Sandbox.Services;

namespace SimpleSign.Sandbox.Tests;

/// <summary>
/// The revocation services, read by the library's own checkers as a client would: CRLs over HTTP,
/// HTTPS and LDAP, OCSP (by the CA or a delegated responder) and their failures, the revoked and
/// expired CAs, and the TSA name. These are the cases of INDECOPI requirements 11, 12 and 30.
/// </summary>
[Collection(SandboxCollection.Name)]
[Trait("Category", "Unit")]
public sealed class SandboxRevocationTests(SandboxFixture fixture)
{
    private HttpClient Http => fixture.Http;

    [Theory]
    [InlineData("rsa-2048", ChainRevocationStatus.Good)]
    [InlineData("revoked", ChainRevocationStatus.Revoked)]
    [InlineData("good-ocsp", ChainRevocationStatus.Good)]
    [InlineData("revoked-ocsp", ChainRevocationStatus.Revoked)]
    [InlineData("good-crl-https", ChainRevocationStatus.Good)]
    [InlineData("revoked-crl-https", ChainRevocationStatus.Revoked)]
    [InlineData("good-crl-ldap", ChainRevocationStatus.Good)]
    [InlineData("revoked-crl-ldap", ChainRevocationStatus.Revoked)]
    [InlineData("under-revoked-ca", ChainRevocationStatus.Revoked)]
    [InlineData("tsa-revoked", ChainRevocationStatus.Revoked)]
    public async Task ChainRevocationChecker_Seed_HasItsStatus(string id, ChainRevocationStatus expected) =>
        (await CheckAsync(id)).Status.ShouldBe(expected);

    [Fact]
    public async Task Ldap_RevokedSeed_IsLoggedAsAnLdapSearch()
    {
        await CheckAsync("revoked-crl-ldap");

        var log = await Http.GetFromJsonAsync<SandboxRequest[]>("api/log", SandboxFixture.Json);
        log!.ShouldContain(r => r.Service == "CRL (LDAP)" && r.Path == "ldap cn=intermediate,o=sandbox" && r.Status == 0);
    }

    [Fact]
    public async Task Https_Crl_IsServedOverTls()
    {
        await CheckAsync("good-crl-https");

        var log = await Http.GetFromJsonAsync<SandboxRequest[]>("api/log", SandboxFixture.Json);
        log!.ShouldContain(r => r.Service == "CRL (HTTPS)" && r.Path == "/crl/intermediate.crl");
    }

    [Fact]
    public async Task Ldap_WithoutLoopbackOrigin_IsRefusedByTheLibrary()
    {
        var policy = fixture.Policy with { LoopbackOrigins = [] };

        (await CheckAsync("revoked-crl-ldap", policy)).Status.ShouldBe(ChainRevocationStatus.Unknown);
    }

    [Theory]
    [InlineData(CrlFault.Expired)]
    [InlineData(CrlFault.WrongKey)]
    [InlineData(CrlFault.Down)]
    public async Task CrlFault_OnlyCrlPointer_StatusIsUnknown(CrlFault fault)
    {
        var result = await WithFaultsAsync(new SandboxFaults(Crl: fault), () => CheckAsync("good-crl-https"));

        result.Status.ShouldBe(ChainRevocationStatus.Unknown);
    }

    [Fact]
    public async Task CrlFault_Stale_ServesTheCrlFromBeforeTheRevocation()
    {
        try
        {
            (await Http.PostAsJsonAsync("api/certificates/good-crl-ldap/revoke", new RevokeRequest("KeyCompromise"))).EnsureSuccessStatusCode();
            (await CheckAsync("good-crl-ldap")).Status.ShouldBe(ChainRevocationStatus.Revoked);

            // A client that kept (or is served) the previous CRL does not see the revocation.
            var stale = await WithFaultsAsync(new SandboxFaults(Crl: CrlFault.Stale), () => CheckAsync("good-crl-ldap"));
            stale.Status.ShouldBe(ChainRevocationStatus.Good);
        }
        finally
        {
            (await Http.PostAsync("api/certificates/good-crl-ldap/unrevoke", null)).EnsureSuccessStatusCode();
        }
    }

    [Theory]
    [InlineData(OcspFault.Unauthorized)]
    [InlineData(OcspFault.Expired)]
    [InlineData(OcspFault.TryLater)]
    [InlineData(OcspFault.Down)]
    public async Task OcspFault_RevokedOcspOnly_IsNotTakenAsGood(OcspFault fault)
    {
        var result = await WithFaultsAsync(new SandboxFaults(Ocsp: fault), () => CheckAsync("revoked-ocsp"));

        result.Status.ShouldNotBe(ChainRevocationStatus.Good);
    }

    [Fact]
    public async Task OcspFault_Unknown_IsNeitherGoodNorRevoked()
    {
        var result = await WithFaultsAsync(new SandboxFaults(Ocsp: OcspFault.Unknown), () => CheckAsync("good-ocsp"));

        result.Status.ShouldBe(ChainRevocationStatus.Unknown);
    }

    [Theory]
    [InlineData("good-ocsp", true)]
    [InlineData("revoked-ocsp", false)]
    public async Task OcspDelegatedSigner_IsAccepted(string id, bool good)
    {
        var result = await WithFaultsAsync(new SandboxFaults(OcspSigner: OcspSigner.Delegated), () => FetchOcspAsync(id));

        result.IsValid.ShouldBe(good);
        result.ResponderCertificates.ShouldContain(c => c.Subject.Contains("OCSP Responder"));
    }

    [Fact]
    public async Task OcspClient_GoodAndRevoked_AreTold()
    {
        (await FetchOcspAsync("good-ocsp")).IsValid.ShouldBeTrue();
        (await FetchOcspAsync("revoked-ocsp")).IsValid.ShouldBeFalse();
    }

    [Theory]
    [InlineData(RevocationPublication.CrlOnly, ChainRevocationStatus.Good, true)]
    [InlineData(RevocationPublication.OcspOnly, ChainRevocationStatus.Revoked, false)]
    public async Task Publication_OneSourceOnly_IsSeenOnlyThere(RevocationPublication publication, ChainRevocationStatus ocspOnlyCertificate, bool ocspGood)
    {
        try
        {
            (await Http.PostAsJsonAsync("api/certificates/good-ocsp/revoke", new RevokeRequest("KeyCompromise", publication), SandboxFixture.Json)).EnsureSuccessStatusCode();

            (await CheckAsync("good-ocsp")).Status.ShouldBe(ocspOnlyCertificate);
            (await FetchOcspAsync("good-ocsp")).IsValid.ShouldBe(ocspGood);
        }
        finally
        {
            (await Http.PostAsync("api/certificates/good-ocsp/unrevoke", null)).EnsureSuccessStatusCode();
        }
    }

    [Fact]
    public async Task ExpiredCa_LeafUnderIt_DoesNotBuildAChain()
    {
        using var leaf = await LeafAsync("under-expired-ca");
        using var expiredCa = X509CertificateLoader.LoadCertificate(await Http.GetByteArrayAsync("aia/intermediate-expired.cer"));

        leaf.NotAfter.ShouldBeGreaterThan(DateTime.Now);
        expiredCa.NotAfter.ShouldBeLessThan(DateTime.Now);
        using var chain = new X509Chain();
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.CustomTrustStore.Add(fixture.Root);
        chain.ChainPolicy.ExtraStore.Add(expiredCa);
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        chain.Build(leaf).ShouldBeFalse();
        chain.ChainStatus.ShouldContain(s => s.Status == X509ChainStatusFlags.NotTimeValid);
    }

    [Theory]
    [InlineData("tsa/tsr", true)]
    [InlineData("tsa/wrong-name", false)]
    public async Task Tsa_NameInTheToken_MatchesOnlyForTheRightTsa(string path, bool matches)
    {
        byte[] data = Encoding.UTF8.GetBytes("timestamp me");
        var request = Rfc3161TimestampRequest.CreateFromData(data, HashAlgorithmName.SHA256, requestSignerCertificates: true);
        using var content = new ByteArrayContent(request.Encode());
        var response = await Http.PostAsync(path, content);
        response.EnsureSuccessStatusCode();
        var token = request.ProcessResponse(await response.Content.ReadAsByteArrayAsync(), out _);

        TimestampTsaChecks.TsaNameMatches(token.AsSignedCms().Encode()).ShouldBe(matches);
    }

    [Fact]
    public async Task Tsa_Revoked_SignsWithTheRevokedCertificate()
    {
        byte[] data = Encoding.UTF8.GetBytes("timestamp me");
        var request = Rfc3161TimestampRequest.CreateFromData(data, HashAlgorithmName.SHA256, requestSignerCertificates: true);
        using var content = new ByteArrayContent(request.Encode());
        var response = await Http.PostAsync("tsa/revoked", content);
        var token = request.ProcessResponse(await response.Content.ReadAsByteArrayAsync(), out _);

        token.VerifySignatureForData(data, out var signer).ShouldBeTrue();
        using var revoked = await LeafAsync("tsa-revoked");
        signer!.Thumbprint.ShouldBe(revoked.Thumbprint);
    }

    private async Task<ChainRevocationResult> CheckAsync(string id, Core.Http.OutboundHttpPolicy? policy = null)
    {
        var leaf = await LeafAsync(id);
        var pki = (await Http.GetFromJsonAsync<PkiView>("api/pki", SandboxFixture.Json))!;
        string issuerId = pki.Certificates.Single(c => c.Id == id).IssuerId!;
        var issuer = X509CertificateLoader.LoadCertificate(await Http.GetByteArrayAsync($"aia/{issuerId}.cer"));
        // A fresh checker each time: its CRL cache must not carry a status from another test.
        var checker = new ChainRevocationChecker(fixture.Client, outboundPolicy: policy ?? fixture.Policy);
        return await checker.CheckAsync([leaf, issuer, fixture.Root], DateTimeOffset.UtcNow, [], [], allowOnline: true, CancellationToken.None);
    }

    private async Task<OcspFetchResult> FetchOcspAsync(string id)
    {
        var leaf = await LeafAsync(id);
        var issuer = X509CertificateLoader.LoadCertificate(await Http.GetByteArrayAsync("aia/intermediate.cer"));
        var client = new OcspClient(fixture.Client) { OutboundPolicy = fixture.Policy };
        return await client.FetchOcspResponseAsync(leaf, issuer, OcspClient.GetOcspUri(leaf)!.AbsoluteUri, CancellationToken.None);
    }

    private async Task<X509Certificate2> LeafAsync(string id) => X509CertificateLoader.LoadCertificate(await Http.GetByteArrayAsync($"api/certificates/{id}/cer"));

    private async Task<T> WithFaultsAsync<T>(SandboxFaults faults, Func<Task<T>> action)
    {
        (await Http.PutAsJsonAsync("api/faults", faults, SandboxFixture.Json)).EnsureSuccessStatusCode();
        try
        {
            return await action();
        }
        finally
        {
            (await Http.PutAsJsonAsync("api/faults", new SandboxFaults(), SandboxFixture.Json)).EnsureSuccessStatusCode();
        }
    }
}
