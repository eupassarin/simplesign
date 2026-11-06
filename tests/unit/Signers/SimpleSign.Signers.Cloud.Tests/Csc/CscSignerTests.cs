using Shouldly;
using SimpleSign.Core.Constants;
using SimpleSign.Core.Signing;
using SimpleSign.Core.Validation;
using SimpleSign.Signers.Cloud.Csc;
using SimpleSign.Signers.Cloud.Tests.Fakes;
using Xunit;

namespace SimpleSign.Signers.Cloud.Tests.Csc;

[Trait("Category", "Unit")]
public sealed class CscSignerTests : IDisposable
{
    private readonly TestPki _pki = new();
    private readonly FakeCscServer _server;

    public CscSignerTests()
    {
        _server = new FakeCscServer(_pki);
    }

    public void Dispose()
    {
        _server.Dispose();
        _pki.Dispose();
    }

    private Task<CscSigner> SignerAsync(string credential, ICscCredentialAuthorizer? authorizer = null) =>
        CscSigner.CreateAsync(_server.CreateClient(), credential, authorizer ?? new ExplicitCscAuthorizer(FakeCscServer.Pin));

    [Fact]
    public async Task SignAsync_RsaPkcs1_ProducesValidPadesAndPrefersHashSpecificOid()
    {
        using var signer = await SignerAsync("rsa-cred");

        var result = await SigningAssert.SignPdfAsync(signer, signer.Certificate, signer.Chain, _pki.Ca);

        result.Indication.ShouldBe(SignatureIndication.Valid, string.Join("; ", result.Errors));
        _server.LastSignHashRequest!["signAlgo"]!.GetValue<string>().ShouldBe(Oids.RsaSha256);
        _server.LastSignHashRequest!["hashAlgorithmOID"]!.GetValue<string>().ShouldBe(Oids.Sha256);
        signer.Chain.Single().Thumbprint.ShouldBe(_pki.Ca.Thumbprint);
    }

    [Fact]
    public async Task SignAsync_WithLogger_LogsCredentialAuthorizationAndSignatureWithoutThePin()
    {
        var logger = new SimpleSign.TestHelpers.RecordingLogger();
        var options = _server.CreateClient().Options with { Logger = logger };
        var client = new CscClient(options, new HttpClient(_server, disposeHandler: false));
        using var signer = await CscSigner.CreateAsync(client, "rsa-cred", new ExplicitCscAuthorizer(FakeCscServer.Pin));

        await SigningAssert.SignPdfAsync(signer, signer.Certificate, signer.Chain, _pki.Ca);

        logger.EventIds.ShouldBe([7300, 7301, 7302, 7303]);
        // The PIN ("1234") also occurs inside the test CPF in the certificate subject of event 7300,
        // so the secrets are checked on the other events, and the service token on all of them.
        logger.Entries.Where(e => e.EventId != 7300).ShouldAllBe(e => !e.Message.Contains(FakeCscServer.Pin));
        logger.Entries.ShouldAllBe(e => !e.Message.Contains(FakeCscServer.ServiceToken));
    }

    [Fact]
    public async Task SignAsync_RsaPss_SendsPssParamsAndValidates()
    {
        using var signer = await SignerAsync("rsa-cred");

        var result = await SigningAssert.SignPdfAsync(signer, signer.Certificate, signer.Chain, _pki.Ca, Oids.RsaPss);

        result.Indication.ShouldBe(SignatureIndication.Valid, string.Join("; ", result.Errors));
        _server.LastSignHashRequest!["signAlgo"]!.GetValue<string>().ShouldBe(Oids.RsaPss);
        _server.LastSignHashRequest!["signAlgoParams"].ShouldNotBeNull();
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task SignAsync_Ecdsa_RawOrDerOutput_ProducesValidPades(bool serverReturnsDer)
    {
        _server.EcdsaAsDer = serverReturnsDer;
        using var signer = await SignerAsync("ec-cred");

        var result = await SigningAssert.SignPdfAsync(signer, signer.Certificate, signer.Chain, _pki.Ca);

        result.Indication.ShouldBe(SignatureIndication.Valid, string.Join("; ", result.Errors));
        _server.LastSignHashRequest!["signAlgo"]!.GetValue<string>().ShouldBe(Oids.EcdsaSha256);
    }

    [Fact]
    public async Task SignAsync_Cades_ProducesValidSignature()
    {
        using var signer = await SignerAsync("ec-cred");

        var result = await SigningAssert.SignCadesAsync(signer, signer.Certificate, signer.Chain, _pki.Ca);

        result.IsSignatureValid.ShouldBeTrue(string.Join("; ", result.Errors));
        result.IsCertificateChainValid.ShouldBeTrue(string.Join("; ", result.Errors));
    }

    [Fact]
    public async Task SignAsync_Scal1WithMultiSign_ReusesOneSad()
    {
        using var signer = await SignerAsync("rsa-cred", new ExplicitCscAuthorizer(FakeCscServer.Pin, signaturesPerAuthorization: 3));

        for (int i = 0; i < 3; i++)
        {
            (await SigningAssert.SignPdfAsync(signer, signer.Certificate, signer.Chain, _pki.Ca)).Indication.ShouldBe(SignatureIndication.Valid);
        }

        _server.AuthorizeCalls.ShouldBe(1);
        _server.SignHashCalls.ShouldBe(3);

        await SigningAssert.SignPdfAsync(signer, signer.Certificate, signer.Chain, _pki.Ca);
        _server.AuthorizeCalls.ShouldBe(2);
    }

    [Fact]
    public async Task SignAsync_Scal2_AuthorizesEverySignatureWithItsHash()
    {
        using var signer = await SignerAsync("scal2-cred", new ExplicitCscAuthorizer(FakeCscServer.Pin, signaturesPerAuthorization: 5));

        for (int i = 0; i < 2; i++)
        {
            (await SigningAssert.SignPdfAsync(signer, signer.Certificate, signer.Chain, _pki.Ca)).Indication.ShouldBe(SignatureIndication.Valid);
        }

        _server.AuthorizeCalls.ShouldBe(2);
    }

    [Fact]
    public async Task SignAsync_OAuthCredentialAuthorization_BindsHashes()
    {
        using var signer = await SignerAsync("oauth-cred", new OAuthCscAuthorizer(_server));

        var result = await SigningAssert.SignPdfAsync(signer, signer.Certificate, signer.Chain, _pki.Ca);

        result.Indication.ShouldBe(SignatureIndication.Valid, string.Join("; ", result.Errors));
        var uri = _server.LastAuthorizationUri!;
        FakePscServer.Query(uri, "scope").ShouldBe("credential");
        FakePscServer.Query(uri, "credentialID").ShouldBe("oauth-cred");
        FakePscServer.Query(uri, "numSignatures").ShouldBe("1");
        FakePscServer.Query(uri, "hashes").ShouldNotBeNullOrEmpty();
        _server.LastSignHashRequest!["SAD"].ShouldBeNull();
    }

    [Fact]
    public async Task SignAsync_WrongPin_ThrowsProviderError()
    {
        using var signer = await SignerAsync("rsa-cred", new ExplicitCscAuthorizer("0000"));

        var ex = await Should.ThrowAsync<SigningException>(() => SigningAssert.SignPdfAsync(signer, signer.Certificate, signer.Chain, _pki.Ca));

        var inner = ex.InnerException.ShouldBeOfType<CloudSigningException>();
        inner.Error.ShouldBe("invalid_pin");
        inner.Message.ShouldNotContain("0000");
    }

    [Fact]
    public async Task SignAsync_AlgorithmNotAllowedByCredential_IsNotSupported()
    {
        using var signer = await SignerAsync("pss-only-cred");

        var ex = await Should.ThrowAsync<SigningException>(() => SigningAssert.SignPdfAsync(signer, signer.Certificate, signer.Chain, _pki.Ca));

        ex.InnerException.ShouldBeOfType<NotSupportedException>().Message.ShouldContain("does not allow");
    }

    [Fact]
    public async Task SignAsync_EcdsaOnRsaCredential_IsNotSupported()
    {
        using var signer = await SignerAsync("rsa-cred");
        var request = new ExternalSigningRequest(new byte[] { 1 }, System.Security.Cryptography.HashAlgorithmName.SHA256,
            Oids.EcdsaSha256, ExternalSigningPayloadKind.CmsSignedAttributes);

        await Should.ThrowAsync<NotSupportedException>(async () => await signer.SignAsync(request, CancellationToken.None));
    }

    [Fact]
    public async Task CreateAsync_DisabledKey_Throws() =>
        (await Should.ThrowAsync<CloudSigningException>(() => SignerAsync("disabled-cred"))).Message.ShouldContain("disabled");

    [Fact]
    public async Task SignAsync_ConcurrentCalls_AreSerializedAndValid()
    {
        using var signer = await SignerAsync("rsa-cred", new ExplicitCscAuthorizer(FakeCscServer.Pin, signaturesPerAuthorization: 5));

        var results = await Task.WhenAll(Enumerable.Range(0, 5)
            .Select(_ => Task.Run(() => SigningAssert.SignPdfAsync(signer, signer.Certificate, signer.Chain, _pki.Ca))));

        results.ShouldAllBe(r => r.Indication == SignatureIndication.Valid);
        _server.AuthorizeCalls.ShouldBe(1);
    }
}
