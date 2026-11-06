using System.Security.Cryptography.X509Certificates;
using Shouldly;
using SimpleSign.CAdES;
using SimpleSign.Core.Constants;
using SimpleSign.Core.Signing;
using SimpleSign.Core.Validation;
using SimpleSign.PAdES;
using SimpleSign.PAdES.Inspection;
using SimpleSign.PAdES.Validation;
using SimpleSign.TestHelpers;
using Xunit;

namespace SimpleSign.Signers.Pkcs11.Tests;

/// <summary>
/// End-to-end signing against a real PKCS#11 module (SoftHSM2). Skipped unless
/// <c>SOFTHSM2_MODULE</c> is set; run <c>scripts/tests/pkcs11.sh</c> to execute them in Docker.
/// </summary>
[Trait("Category", "Pkcs11")]
[Collection(SoftHsmCollection.Name)]
public sealed class Pkcs11SignerSoftHsmTests(SoftHsmFixture hsm)
{
    private async Task<SignatureValidationResult> SignAndValidatePdfAsync(Pkcs11Signer token, string? signatureAlgorithmOid = null) =>
        (await SignAndValidatePdfWithBytesAsync(token, signatureAlgorithmOid)).Result;

    private async Task<(SignatureValidationResult Result, byte[] Signed)> SignAndValidatePdfWithBytesAsync(
        Pkcs11Signer token, string? signatureAlgorithmOid)
    {
        var builder = PadesSigner.Document(TestPdfFactory.CreateMinimalPdf())
            .WithExternalSigner(token.Certificate, token, token.Chain);
        if (signatureAlgorithmOid is not null)
        {
            builder = builder.WithSignatureAlgorithm(signatureAlgorithmOid);
        }

        byte[] signed = await builder.SignAsync();
        var validator = new PdfSignatureValidator(new ValidationOptions
        {
            CheckRevocation = false,
            TrustedRoots = [hsm.CaCertificate],
        });
        var results = await validator.ValidateAsync(new MemoryStream(signed));
        results.Count.ShouldBe(1);
        return (results[0], signed);
    }

    [SkippableFact]
    public async Task SignAsync_RsaPkcs1_ProducesValidPades()
    {
        Skip.If(hsm.SkipReason is not null, hsm.SkipReason);
        using var token = Pkcs11Signer.Open(hsm.Options(SoftHsmFixture.RsaKeyLabel));

        var result = await SignAndValidatePdfAsync(token);

        result.Indication.ShouldBe(SignatureIndication.Valid, string.Join("; ", result.Errors));
        result.SignerCertificate!.Thumbprint.ShouldBe(hsm.RsaCertificate.Thumbprint);
    }

    [SkippableFact]
    public async Task SignAsync_RsaPss_ProducesValidPades()
    {
        Skip.If(hsm.SkipReason is not null, hsm.SkipReason);
        using var token = Pkcs11Signer.Open(hsm.Options(SoftHsmFixture.RsaKeyLabel));

        var (result, signed) = await SignAndValidatePdfWithBytesAsync(token, Oids.RsaPss);

        result.Indication.ShouldBe(SignatureIndication.Valid, string.Join("; ", result.Errors));
        var inspection = await PdfSignatureInspector.InspectAsync(new MemoryStream(signed));
        inspection.Signatures.Single().SignatureAlgorithm.Oid.ShouldBe(Oids.RsaPss);
    }

    [SkippableFact]
    public async Task SignAsync_Ecdsa_ProducesValidPades()
    {
        Skip.If(hsm.SkipReason is not null, hsm.SkipReason);
        using var token = Pkcs11Signer.Open(hsm.Options(SoftHsmFixture.EcKeyLabel));

        var result = await SignAndValidatePdfAsync(token);

        result.Indication.ShouldBe(SignatureIndication.Valid, string.Join("; ", result.Errors));
        result.SignerCertificate!.Thumbprint.ShouldBe(hsm.EcCertificate.Thumbprint);
    }

    [SkippableFact]
    public async Task SignAsync_Cades_ProducesValidDetachedSignature()
    {
        Skip.If(hsm.SkipReason is not null, hsm.SkipReason);
        using var token = Pkcs11Signer.Open(hsm.Options(SoftHsmFixture.EcKeyLabel));
        byte[] data = "contract body"u8.ToArray();

        byte[] cms = await CadesSigner.Document(data)
            .WithExternalSigner(token.Certificate, token, token.Chain)
            .SignAsync();

        var result = new CadesSignatureValidator(new ValidationOptions { CheckRevocation = false })
            .Validate(cms, data, [hsm.CaCertificate]);
        result.IsSignatureValid.ShouldBeTrue(string.Join("; ", result.Errors));
        result.IsCertificateChainValid.ShouldBeTrue(string.Join("; ", result.Errors));
    }

    [SkippableFact]
    public void Open_KeyLabel_ExposesCertificateAndCaChain()
    {
        Skip.If(hsm.SkipReason is not null, hsm.SkipReason);
        using var token = Pkcs11Signer.Open(hsm.Options(SoftHsmFixture.RsaKeyLabel));

        token.TokenLabel.ShouldBe(hsm.TokenLabel);
        token.Certificate.Thumbprint.ShouldBe(hsm.RsaCertificate.Thumbprint);
        token.Chain.Select(c => c.Thumbprint).ShouldBe([hsm.CaCertificate.Thumbprint]);
    }

    [SkippableFact]
    public void Open_KeyId_SelectsMatchingKey()
    {
        Skip.If(hsm.SkipReason is not null, hsm.SkipReason);
        using var token = Pkcs11Signer.Open(hsm.Options() with { KeyId = SoftHsmFixture.EcKeyId });

        token.Certificate.Thumbprint.ShouldBe(hsm.EcCertificate.Thumbprint);
    }

    [SkippableFact]
    public void Open_CertificateThumbprint_SelectsMatchingKey()
    {
        Skip.If(hsm.SkipReason is not null, hsm.SkipReason);
        using var token = Pkcs11Signer.Open(hsm.Options() with { CertificateThumbprint = hsm.RsaCertificate.Thumbprint.ToLowerInvariant() });

        token.Certificate.Thumbprint.ShouldBe(hsm.RsaCertificate.Thumbprint);
    }

    [SkippableFact]
    public void Open_TwoKeysWithoutSelection_ThrowsAmbiguous()
    {
        Skip.If(hsm.SkipReason is not null, hsm.SkipReason);

        var ex = Should.Throw<Pkcs11Exception>(() => Pkcs11Signer.Open(hsm.Options()));

        ex.Message.ShouldContain("more than one signing key");
        ex.Message.ShouldContain(SoftHsmFixture.RsaKeyLabel);
        ex.Message.ShouldContain(SoftHsmFixture.EcKeyLabel);
    }

    [SkippableFact]
    public void Open_UnknownKeyLabel_ThrowsNoMatch()
    {
        Skip.If(hsm.SkipReason is not null, hsm.SkipReason);

        var ex = Should.Throw<Pkcs11Exception>(() => Pkcs11Signer.Open(hsm.Options("missing-key")));

        ex.Message.ShouldContain("matches the selection");
    }

    [SkippableFact]
    public void Open_UnknownTokenLabel_ThrowsNoMatch()
    {
        Skip.If(hsm.SkipReason is not null, hsm.SkipReason);

        var ex = Should.Throw<Pkcs11Exception>(() =>
            Pkcs11Signer.Open(hsm.Options(SoftHsmFixture.RsaKeyLabel) with { TokenLabel = "other-token" }));

        ex.Message.ShouldContain("No token matches");
        ex.Message.ShouldContain(hsm.TokenLabel);
    }

    [SkippableFact]
    public void Open_WrongPin_ThrowsPinIncorrect()
    {
        Skip.If(hsm.SkipReason is not null, hsm.SkipReason);

        var ex = Should.Throw<Pkcs11Exception>(() => Pkcs11Signer.Open(hsm.Options(SoftHsmFixture.RsaKeyLabel, pin: "9999")));

        ex.IsPinIncorrect.ShouldBeTrue();
        ex.Function.ShouldBe("C_Login");
    }

    [SkippableFact]
    public void Open_NoPin_ThrowsPinRequired()
    {
        Skip.If(hsm.SkipReason is not null, hsm.SkipReason);

        var ex = Should.Throw<Pkcs11Exception>(() =>
            Pkcs11Signer.Open(hsm.Options(SoftHsmFixture.RsaKeyLabel) with { Pin = null }));

        ex.Message.ShouldContain("requires a PIN");
    }

    [SkippableFact]
    public void ListTokens_SoftHsm_ReturnsTokenWithItsCertificates()
    {
        Skip.If(hsm.SkipReason is not null, hsm.SkipReason);

        var token = Pkcs11Signer.ListTokens(hsm.ModulePath).Single(t => t.Label == hsm.TokenLabel);

        token.IsLoginRequired.ShouldBeTrue();
        token.IsPinLocked.ShouldBeFalse();
        token.Certificates.Select(c => c.Label).OrderBy(l => l)
            .ShouldBe([SoftHsmFixture.EcKeyLabel, SoftHsmFixture.RsaKeyLabel, "test-ca"]);
        token.Certificates.Single(c => c.Label == SoftHsmFixture.RsaKeyLabel).Id.ToArray().ShouldBe(SoftHsmFixture.RsaKeyId);
        foreach (var certificate in token.Certificates)
        {
            certificate.Certificate.Dispose();
        }
    }

    [SkippableFact]
    public async Task SignAsync_ConcurrentCalls_AllProduceValidSignatures()
    {
        Skip.If(hsm.SkipReason is not null, hsm.SkipReason);
        using var token = Pkcs11Signer.Open(hsm.Options(SoftHsmFixture.RsaKeyLabel));

        var results = await Task.WhenAll(Enumerable.Range(0, 8).Select(_ => Task.Run(() => SignAndValidatePdfAsync(token))));

        results.ShouldAllBe(r => r.Indication == SignatureIndication.Valid);
    }

    [SkippableFact]
    public async Task SignAsync_TwoSignersOnSameToken_BothWork()
    {
        Skip.If(hsm.SkipReason is not null, hsm.SkipReason);
        using var rsa = Pkcs11Signer.Open(hsm.Options(SoftHsmFixture.RsaKeyLabel));
        using var ec = Pkcs11Signer.Open(hsm.Options(SoftHsmFixture.EcKeyLabel));

        (await SignAndValidatePdfAsync(rsa)).Indication.ShouldBe(SignatureIndication.Valid);
        (await SignAndValidatePdfAsync(ec)).Indication.ShouldBe(SignatureIndication.Valid);
    }

    [SkippableFact]
    public async Task SignAsync_AfterDispose_ThrowsObjectDisposed()
    {
        Skip.If(hsm.SkipReason is not null, hsm.SkipReason);
        var token = Pkcs11Signer.Open(hsm.Options(SoftHsmFixture.RsaKeyLabel));
        token.Dispose();
        token.Dispose();

        var request = new ExternalSigningRequest(new byte[] { 1 }, System.Security.Cryptography.HashAlgorithmName.SHA256,
            Oids.RsaSha256, ExternalSigningPayloadKind.CmsSignedAttributes);
        await Should.ThrowAsync<ObjectDisposedException>(async () => await token.SignAsync(request, CancellationToken.None));
    }

    [SkippableFact]
    public void Open_AfterAllSignersDisposed_ReinitializesModule()
    {
        Skip.If(hsm.SkipReason is not null, hsm.SkipReason);
        Pkcs11Signer.Open(hsm.Options(SoftHsmFixture.RsaKeyLabel)).Dispose();

        using var again = Pkcs11Signer.Open(hsm.Options(SoftHsmFixture.RsaKeyLabel));
        again.Certificate.ShouldBeOfType<X509Certificate2>();
    }
}
