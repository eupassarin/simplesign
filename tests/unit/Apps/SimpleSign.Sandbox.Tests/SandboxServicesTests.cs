using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Shouldly;
using SimpleSign.Core.Revocation;
using SimpleSign.Core.Signing;
using SimpleSign.Sandbox.Endpoints;
using SimpleSign.Sandbox.Services;
using SimpleSign.Signers.Cloud.Csc;

namespace SimpleSign.Sandbox.Tests;

/// <summary>The services a client reaches over the network: AIA, CRL, TSA and CSC, with their failures.</summary>
[Collection(SandboxCollection.Name)]
[Trait("Category", "Unit")]
public sealed class SandboxServicesTests(SandboxFixture fixture)
{
    private HttpClient Http => fixture.Http;

    [Fact]
    public void Info_NewEnvironment_PointsToItsOwnUrl()
    {
        fixture.Info.Name.ShouldBe("tests");
        fixture.Info.BaseUrl.ShouldBe(fixture.BaseUrl.AbsoluteUri);
        fixture.Info.Urls.IntermediateCrl.ShouldBe(fixture.BaseUrl + "crl/intermediate.crl");
        fixture.Info.Tsa.Url.ShouldBe(fixture.BaseUrl + "tsa/tsr");
        fixture.Info.Csc.BaseUrl.ShouldBe(fixture.BaseUrl + "csc/v2/");
    }

    [Fact]
    public async Task Aia_IssuerCertificates_FormTheChain()
    {
        using var root = X509CertificateLoader.LoadCertificate(await Http.GetByteArrayAsync("aia/root.cer"));
        using var intermediate = X509CertificateLoader.LoadCertificate(await Http.GetByteArrayAsync("aia/intermediate.cer"));
        using var fromPem = X509Certificate2.CreateFromPem(await Http.GetStringAsync("root.pem"));

        root.Thumbprint.ShouldBe(fixture.Info.RootThumbprint);
        fromPem.Thumbprint.ShouldBe(root.Thumbprint);
        intermediate.Issuer.ShouldBe(root.Subject);
        using var leaf = await LeafAsync("rsa-2048");
        leaf.Issuer.ShouldBe(intermediate.Subject);
        leaf.Extensions.OfType<X509AuthorityInformationAccessExtension>().Single().EnumerateCAIssuersUris().ShouldContain(fixture.Info.Urls.IntermediateCertificate);
    }

    [Fact]
    public async Task Crl_SignedByTheIssuer_ReportsGoodAndRevoked()
    {
        using var intermediate = X509CertificateLoader.LoadCertificate(await Http.GetByteArrayAsync("aia/intermediate.cer"));
        byte[] crl = await Http.GetByteArrayAsync("crl/intermediate.crl");
        using var good = await LeafAsync("rsa-2048");
        using var revoked = await LeafAsync("revoked");

        CrlEvaluator.Evaluate(good, crl, intermediate, DateTimeOffset.UtcNow).ShouldBe(CrlStatus.Good);
        CrlEvaluator.Evaluate(revoked, crl, intermediate, DateTimeOffset.UtcNow).ShouldBe(CrlStatus.Revoked);
        CrlEvaluator.Evaluate(good, crl, revoked, DateTimeOffset.UtcNow).ShouldBe(CrlStatus.NotApplicable);
    }

    [Fact]
    public async Task Revoke_Certificate_IsInTheNextCrlUntilTakenBack()
    {
        using var intermediate = X509CertificateLoader.LoadCertificate(await Http.GetByteArrayAsync("aia/intermediate.cer"));
        using var leaf = await LeafAsync("ecdsa-p384");
        try
        {
            (await Http.PostAsJsonAsync("api/certificates/ecdsa-p384/revoke", new RevokeRequest("Superseded"))).EnsureSuccessStatusCode();
            CrlEvaluator.Evaluate(leaf, await Http.GetByteArrayAsync("crl/intermediate.crl"), intermediate, DateTimeOffset.UtcNow).ShouldBe(CrlStatus.Revoked);
        }
        finally
        {
            (await Http.PostAsync("api/certificates/ecdsa-p384/unrevoke", null)).EnsureSuccessStatusCode();
        }

        CrlEvaluator.Evaluate(leaf, await Http.GetByteArrayAsync("crl/intermediate.crl"), intermediate, DateTimeOffset.UtcNow).ShouldBe(CrlStatus.Good);
    }

    [Fact]
    public async Task Revoke_UnknownReason_IsRefused() =>
        (await Http.PostAsJsonAsync("api/certificates/rsa-2048/revoke", new RevokeRequest("Bored"))).StatusCode.ShouldBe(HttpStatusCode.BadRequest);

    [Fact]
    public async Task Faults_ExpiredCrl_IsNotCurrent()
    {
        using var intermediate = X509CertificateLoader.LoadCertificate(await Http.GetByteArrayAsync("aia/intermediate.cer"));
        using var leaf = await LeafAsync("rsa-2048");
        byte[] crl = await WithFaultsAsync(new SandboxFaults(Crl: CrlFault.Expired), () => Http.GetByteArrayAsync("crl/intermediate.crl"));

        CrlEvaluator.Evaluate(leaf, crl, intermediate, DateTimeOffset.UtcNow).ShouldBe(CrlStatus.NotApplicable);
    }

    [Fact]
    public async Task Faults_CrlDown_Answers503AndIsLogged()
    {
        var response = await WithFaultsAsync(new SandboxFaults(Crl: CrlFault.Down), () => Http.GetAsync("crl/root.crl"));

        response.StatusCode.ShouldBe(HttpStatusCode.ServiceUnavailable);
        var log = await Http.GetFromJsonAsync<SandboxRequest[]>("api/log", SandboxFixture.Json);
        log!.ShouldContain(r => r.Path == "/crl/root.crl" && r.Status == 503 && r.Fault == "Down" && r.Service == "CRL");
    }

    [Fact]
    public async Task Tsa_Request_IsGrantedBySandboxTsa()
    {
        byte[] data = Encoding.UTF8.GetBytes("timestamp me");
        var token = await TimestampAsync("tsa/tsr", data);

        token.VerifySignatureForData(data, out var signer).ShouldBeTrue();
        signer!.Issuer.ShouldContain("SimpleSign Sandbox CA 1 (tests)");
    }

    [Fact]
    public async Task Tsa_Authenticated_NeedsBasicCredentials()
    {
        var request = Rfc3161TimestampRequest.CreateFromData(Encoding.UTF8.GetBytes("x"), HashAlgorithmName.SHA256, requestSignerCertificates: true);
        using var anonymous = new ByteArrayContent(request.Encode());
        (await Http.PostAsync("tsa/authenticated", anonymous)).StatusCode.ShouldBe(HttpStatusCode.Unauthorized);

        using var message = new HttpRequestMessage(HttpMethod.Post, "tsa/authenticated") { Content = new ByteArrayContent(request.Encode()) };
        message.Headers.Authorization = new AuthenticationHeaderValue("Basic", Convert.ToBase64String(Encoding.UTF8.GetBytes($"{fixture.Info.Tsa.User}:{fixture.Info.Tsa.Password}")));
        (await Http.SendAsync(message)).StatusCode.ShouldBe(HttpStatusCode.OK);
    }

    [Fact]
    public async Task Faults_TsaInvalidToken_DoesNotVerify()
    {
        byte[] data = Encoding.UTF8.GetBytes("timestamp me");
        bool verified = await WithFaultsAsync(new SandboxFaults(Tsa: TsaFault.InvalidToken), async () =>
        {
            try
            {
                return (await TimestampAsync("tsa/tsr", data)).VerifySignatureForData(data, out _);
            }
            catch (CryptographicException)
            {
                return false;
            }
        });

        verified.ShouldBeFalse();
    }

    [Fact]
    public async Task Tsa_Untrusted_IsSignedOutsideTheChain()
    {
        byte[] data = Encoding.UTF8.GetBytes("timestamp me");
        var token = await TimestampAsync("tsa/untrusted", data);

        token.VerifySignatureForData(data, out var signer).ShouldBeTrue();
        signer!.Issuer.ShouldBe(signer.Subject);
    }

    [Fact]
    public async Task Pfx_Download_HasTheKeyAndTheChain()
    {
        byte[] pfx = await Http.GetByteArrayAsync("api/certificates/ecdsa-p256/pfx");
        var collection = X509CertificateLoader.LoadPkcs12Collection(pfx, fixture.Info.PfxPassword);
        try
        {
            collection.Count.ShouldBe(3);
            collection.Single(c => c.HasPrivateKey).Subject.ShouldContain("Carlos Lima");
        }
        finally
        {
            foreach (var certificate in collection)
            {
                certificate.Dispose();
            }
        }
    }

    [Fact]
    public async Task Pki_Seeds_CoverTheEdgeCases()
    {
        var pki = await Http.GetFromJsonAsync<PkiView>("api/pki", SandboxFixture.Json);

        pki!.Authorities.Select(a => a.Id).ShouldBe(["root", "intermediate", "intermediate-revoked", "intermediate-expired"], ignoreOrder: true);
        pki.Certificates.Select(c => c.Id).ShouldBe(["rsa-2048", "rsa-3072", "rsa-4096", "ecdsa-p256", "ecdsa-p384", "ecdsa-p521", "expired", "not-yet-valid",
            "revoked", "revoked-ocsp", "revoked-crl-https", "revoked-crl-ldap", "good-ocsp", "good-crl-https", "good-crl-ldap", "under-revoked-ca", "under-expired-ca",
            "no-nonrepudiation", "rsa-1024", "no-signing-key-usage", "tsa", "tsa-revoked", "ocsp-responder", "tls-server"]);
        pki.Certificates.Single(c => c.Id == "revoked").RevokedAt.ShouldNotBeNull();
        DateTime.Parse(pki.Certificates.Single(c => c.Id == "expired").NotAfter, System.Globalization.CultureInfo.InvariantCulture).ShouldBeLessThan(DateTime.Now);
        DateTime.Parse(pki.Certificates.Single(c => c.Id == "not-yet-valid").NotBefore, System.Globalization.CultureInfo.InvariantCulture).ShouldBeGreaterThan(DateTime.Now);
        pki.Certificates.Where(c => c.IsUsable).Select(c => c.Id).ShouldBe(["rsa-2048", "rsa-3072", "rsa-4096", "ecdsa-p256", "ecdsa-p384", "ecdsa-p521",
            "good-ocsp", "good-crl-https", "good-crl-ldap", "no-nonrepudiation"], ignoreOrder: true);
    }

    [Fact]
    public async Task Csc_ExplicitCredential_SignsWithTheSandboxKey()
    {
        var client = new CscClient(new CscClientOptions { BaseUri = new Uri(fixture.Info.Csc.BaseUrl), AccessToken = fixture.Info.Csc.ServiceToken });
        (await client.ListCredentialsAsync()).Select(c => c.Id).ShouldContain("rsa-scal1");
        using var signer = await CscSigner.CreateAsync(client, "rsa-scal1", new ExplicitCscAuthorizer(fixture.Info.Csc.Pin));
        byte[] data = Encoding.UTF8.GetBytes("signed attributes");

        var signature = await signer.SignAsync(new ExternalSigningRequest(data, HashAlgorithmName.SHA256, "1.2.840.113549.1.1.11", ExternalSigningPayloadKind.CmsSignedAttributes), default);

        using var rsa = signer.Certificate.GetRSAPublicKey()!;
        rsa.VerifyData(data, signature.Span, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1).ShouldBeTrue();
    }

    [Fact]
    public async Task Csc_OAuthAuthorize_RedirectsBackWithACode()
    {
        using var noRedirect = new HttpClient(new HttpClientHandler { AllowAutoRedirect = false, CheckCertificateRevocationList = true }) { BaseAddress = fixture.BaseUrl };
        var response = await noRedirect.GetAsync("csc/v2/oauth2/authorize?response_type=code&client_id=testbench&scope=service&code_challenge=abc&code_challenge_method=S256&state=s1&redirect_uri=http%3A%2F%2F127.0.0.1%3A1%2Fcallback");

        response.StatusCode.ShouldBe(HttpStatusCode.Redirect);
        response.Headers.Location!.AbsoluteUri.ShouldStartWith("http://127.0.0.1:1/callback?code=");
        response.Headers.Location.Query.ShouldContain("state=s1");
    }

    private async Task<X509Certificate2> LeafAsync(string id) => X509CertificateLoader.LoadCertificate(await Http.GetByteArrayAsync($"api/certificates/{id}/cer"));

    private async Task<Rfc3161TimestampToken> TimestampAsync(string path, byte[] data)
    {
        var request = Rfc3161TimestampRequest.CreateFromData(data, HashAlgorithmName.SHA256, nonce: new byte[] { 1, 2, 3, 4 }, requestSignerCertificates: true);
        using var content = new ByteArrayContent(request.Encode());
        content.Headers.ContentType = new MediaTypeHeaderValue("application/timestamp-query");
        var response = await Http.PostAsync(path, content);
        response.EnsureSuccessStatusCode();
        return request.ProcessResponse(await response.Content.ReadAsByteArrayAsync(), out _);
    }

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
