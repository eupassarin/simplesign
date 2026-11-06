using Shouldly;
using SimpleSign.Core.Constants;
using SimpleSign.Core.Signing;
using SimpleSign.Core.Validation;
using SimpleSign.Signers.Cloud.Psc;
using SimpleSign.Signers.Cloud.Tests.Fakes;
using Xunit;

namespace SimpleSign.Signers.Cloud.Tests.Psc;

[Trait("Category", "Unit")]
public sealed class PscSignerTests : IDisposable
{
    private readonly TestPki _pki = new();

    public void Dispose() => _pki.Dispose();

    private async Task<(FakePscServer Server, PscClient Client, OAuthToken Token)> AuthorizeAsync(
        PscWireFormat? wire = null, PscScope scope = PscScope.SignatureSession, Action<FakePscServer>? configure = null)
    {
        var server = new FakePscServer(_pki, wire);
        configure?.Invoke(server);
        var client = server.CreateClient();
        var token = await client.AuthorizeAsync(server, scope, TimeSpan.FromMinutes(10), FakePscServer.Cpf);
        return (server, client, token);
    }

    [Fact]
    public async Task SignAsync_AuthorizationCodeFlow_ProducesValidPades()
    {
        var (_, client, token) = await AuthorizeAsync();
        using var signer = await PscSigner.CreateAsync(client, token);

        var result = await SigningAssert.SignPdfAsync(signer, signer.Certificate, signer.Chain, _pki.Ca);

        result.Indication.ShouldBe(SignatureIndication.Valid, string.Join("; ", result.Errors));
        result.SignerCertificate!.Thumbprint.ShouldBe(_pki.RsaCertificate.Thumbprint);
        token.AuthorizedIdentification.ShouldBe(FakePscServer.Cpf);
    }

    [Fact]
    public async Task SignAsync_Cades_ProducesValidSignature()
    {
        var (_, client, token) = await AuthorizeAsync();
        using var signer = await PscSigner.CreateAsync(client, token);

        var result = await SigningAssert.SignCadesAsync(signer, signer.Certificate, signer.Chain, _pki.Ca);

        result.IsSignatureValid.ShouldBeTrue(string.Join("; ", result.Errors));
    }

    [Fact]
    public async Task AuthorizeAsync_AuthorizationUri_CarriesPkceScopeLifetimeAndHint()
    {
        var (server, _, _) = await AuthorizeAsync();
        var uri = server.LastAuthorizationUri!;

        uri.AbsoluteUri.ShouldStartWith("https://psc.example/v0/oauth/authorize?");
        FakePscServer.Query(uri, "response_type").ShouldBe("code");
        FakePscServer.Query(uri, "scope").ShouldBe("signature_session");
        FakePscServer.Query(uri, "lifetime").ShouldBe("600");
        FakePscServer.Query(uri, "login_hint").ShouldBe(FakePscServer.Cpf);
        FakePscServer.Query(uri, "code_challenge_method").ShouldBe("S256");
        FakePscServer.Query(uri, "redirect_uri").ShouldBe("http://127.0.0.1:43821/callback");
    }

    [Fact]
    public async Task SignAsync_SignatureRequest_UsesWireFormatFields()
    {
        var (server, client, token) = await AuthorizeAsync();
        using var signer = await PscSigner.CreateAsync(client, token);
        await SigningAssert.SignPdfAsync(signer, signer.Certificate, signer.Chain, _pki.Ca);

        var request = server.LastSignatureRequest!;
        request["certificate_alias"]!.GetValue<string>().ShouldBe("rsa-1");
        var hash = request["hashes"]!.AsArray().Single()!;
        hash["hash_algorithm"]!.GetValue<string>().ShouldBe(Oids.Sha256);
        hash["signature_format"]!.GetValue<string>().ShouldBe("RAW");
        Convert.FromBase64String(hash["hash"]!.GetValue<string>()).Length.ShouldBe(32);
    }

    [Fact]
    public async Task SignAsync_HexEncodingAndRenamedFields_Works()
    {
        var wire = PscWireFormat.Default with
        {
            HashEncoding = PscBinaryEncoding.Hex,
            SignatureEncoding = PscBinaryEncoding.Hex,
            SignatureField = "signature",
            SignaturePath = "oauth/sign",
        };
        var (server, client, token) = await AuthorizeAsync(wire);
        using var signer = await PscSigner.CreateAsync(client, token);

        var result = await SigningAssert.SignPdfAsync(signer, signer.Certificate, signer.Chain, _pki.Ca);

        result.Indication.ShouldBe(SignatureIndication.Valid);
        server.LastSignatureRequest!["hashes"]![0]!["hash"]!.GetValue<string>().ShouldMatch("^[0-9a-f]{64}$");
    }

    [Fact]
    public async Task SignAsync_SessionToken_SignsSeveralDocuments()
    {
        var (server, client, token) = await AuthorizeAsync();
        using var signer = await PscSigner.CreateAsync(client, token);

        for (int i = 0; i < 3; i++)
        {
            (await SigningAssert.SignPdfAsync(signer, signer.Certificate, signer.Chain, _pki.Ca)).Indication.ShouldBe(SignatureIndication.Valid);
        }

        server.SignatureCalls.ShouldBe(3);
    }

    [Fact]
    public async Task SignAsync_SingleSignatureTokenUsedTwice_FailsTheSecondTime()
    {
        var (_, client, token) = await AuthorizeAsync(scope: PscScope.SingleSignature);
        using var signer = await PscSigner.CreateAsync(client, token);
        await SigningAssert.SignPdfAsync(signer, signer.Certificate, signer.Chain, _pki.Ca);

        var ex = await Should.ThrowAsync<SigningException>(() => SigningAssert.SignPdfAsync(signer, signer.Certificate, signer.Chain, _pki.Ca));

        ex.InnerException.ShouldBeOfType<CloudSigningException>().Error.ShouldBe("invalid_token");
    }

    [Fact]
    public async Task SignAsync_ExpiredToken_ThrowsWithoutCallingProvider()
    {
        var time = new ManualTimeProvider(DateTimeOffset.UtcNow);
        var server = new FakePscServer(_pki);
        var client = server.CreateClient(time);
        var token = await client.AuthorizeAsync(server, PscScope.SignatureSession, TimeSpan.FromMinutes(10));
        using var signer = await PscSigner.CreateAsync(client, token, timeProvider: time);
        time.Advance(TimeSpan.FromHours(1));

        var ex = await Should.ThrowAsync<SigningException>(() => SigningAssert.SignPdfAsync(signer, signer.Certificate, signer.Chain, _pki.Ca));

        ex.InnerException.ShouldBeOfType<CloudSigningException>().Message.ShouldContain("expired");
        server.SignatureCalls.ShouldBe(0);
    }

    [Fact]
    public async Task SignAsync_EcdsaRequest_IsNotSupported()
    {
        var (_, client, token) = await AuthorizeAsync();
        using var signer = await PscSigner.CreateAsync(client, token);
        var request = new ExternalSigningRequest(new byte[] { 1 }, System.Security.Cryptography.HashAlgorithmName.SHA256,
            Oids.EcdsaSha256, ExternalSigningPayloadKind.CmsSignedAttributes);

        var ex = await Should.ThrowAsync<NotSupportedException>(async () => await signer.SignAsync(request, CancellationToken.None));
        ex.Message.ShouldContain("RSA PKCS#1 v1.5 only");
    }

    [Fact]
    public async Task SignAsync_RsaPssRequest_IsNotSupported()
    {
        var (_, client, token) = await AuthorizeAsync();
        using var signer = await PscSigner.CreateAsync(client, token);

        await Should.ThrowAsync<SigningException>(() =>
            SigningAssert.SignPdfAsync(signer, signer.Certificate, signer.Chain, _pki.Ca, Oids.RsaPss));
    }

    [Fact]
    public async Task CreateAsync_TwoCertificatesWithoutAlias_IsAmbiguous()
    {
        var (_, client, token) = await AuthorizeAsync(configure: s => s.OfferTwoCertificates = true);

        var ex = await Should.ThrowAsync<CloudSigningException>(() => PscSigner.CreateAsync(client, token));

        ex.Message.ShouldContain("rsa-1");
        ex.Message.ShouldContain("rsa-2");
    }

    [Fact]
    public async Task CreateAsync_AliasSelectsCertificate()
    {
        var (_, client, token) = await AuthorizeAsync(configure: s => s.OfferTwoCertificates = true);
        using var signer = await PscSigner.CreateAsync(client, token, "rsa-2");

        var result = await SigningAssert.SignPdfAsync(signer, signer.Certificate, signer.Chain, _pki.Ca);

        result.Indication.ShouldBe(SignatureIndication.Valid);
        signer.Certificate.Thumbprint.ShouldBe(_pki.SecondRsaCertificate.Thumbprint);
    }

    [Fact]
    public async Task CreateAsync_UnknownAlias_Throws()
    {
        var (_, client, token) = await AuthorizeAsync();

        (await Should.ThrowAsync<CloudSigningException>(() => PscSigner.CreateAsync(client, token, "nope"))).Message.ShouldContain("rsa-1");
    }

    [Fact]
    public async Task GetCertificatesAsync_PemCertificates_AreRead()
    {
        var (_, client, token) = await AuthorizeAsync(configure: s => s.CertificatesAsPem = true);

        var certificates = await client.GetCertificatesAsync(token);

        certificates.Single().Certificate.Thumbprint.ShouldBe(_pki.RsaCertificate.Thumbprint);
    }

    [Fact]
    public async Task SignAsync_AfterDispose_Throws()
    {
        var (_, client, token) = await AuthorizeAsync();
        var signer = await PscSigner.CreateAsync(client, token);
        signer.Dispose();
        signer.Dispose();
        var request = new ExternalSigningRequest(new byte[] { 1 }, System.Security.Cryptography.HashAlgorithmName.SHA256,
            Oids.RsaSha256, ExternalSigningPayloadKind.CmsSignedAttributes);

        await Should.ThrowAsync<ObjectDisposedException>(async () => await signer.SignAsync(request, CancellationToken.None));
    }

    [Fact]
    public async Task SignAsync_ConcurrentCalls_AllValid()
    {
        var (_, client, token) = await AuthorizeAsync();
        using var signer = await PscSigner.CreateAsync(client, token);

        var results = await Task.WhenAll(Enumerable.Range(0, 6)
            .Select(_ => Task.Run(() => SigningAssert.SignPdfAsync(signer, signer.Certificate, signer.Chain, _pki.Ca))));

        results.ShouldAllBe(r => r.Indication == SignatureIndication.Valid);
    }
}
