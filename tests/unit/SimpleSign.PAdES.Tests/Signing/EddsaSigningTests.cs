using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Shouldly;
using SimpleSign.Core.Signing;
using SimpleSign.Core.Validation;
using SimpleSign.PAdES.Validation;
using SimpleSign.TestHelpers;
using Xunit;

namespace SimpleSign.PAdES.Tests.Signing;

[Trait("Category", "Unit")]
public sealed class EddsaSigningTests
{
    private static PdfSignatureValidator ValidatorTrusting(params X509Certificate2[] certs)
    {
        return new PdfSignatureValidator(new ValidationOptions
        {
            CheckRevocation = false,
            TrustedRoots = [.. certs]
        });
    }

    [SkippableFact(DisplayName = "Ed25519 external signer produces valid signature")]
    public async Task SignAsync_Ed25519ExternalSigner_ValidatesCorrectly()
    {
        var cert = TestCertificateFactory.TryCreateEdDsaCert("CN=Ed25519 Signer");
        Skip.If(cert is null, "Ed25519 not supported on this platform/runtime");

        using var c = cert;
        var pdf = TestPdfFactory.CreateMinimalPdf();

        using var key = c!.GetECDsaPrivateKey()!;
        byte[] signed = await PadesSigner.Document(pdf)
            .WithCertificate(c)
            .WithHashAlgorithm(HashAlgorithmName.SHA256)
            .WithExternalSigner(c, new FuncExternalSigner(async hash =>
            {
                byte[] sig = key.SignHash(hash, DSASignatureFormat.Rfc3279DerSequence);
                return await Task.FromResult(sig);
            }))
            .SignAsync();

        using var stream = new MemoryStream(signed);
        var results = await ValidatorTrusting(c).ValidateAsync(stream);
        results.Count.ShouldBe(1);
        results[0].IsIntegrityValid.ShouldBeTrue();
        results[0].IsSignatureValid.ShouldBeTrue();
    }

    [SkippableFact(DisplayName = "Ed25519 external signer with SHA3-256 validates")]
    public async Task SignAsync_Ed25519Sha3_256_ValidatesCorrectly()
    {
        var cert = TestCertificateFactory.TryCreateEdDsaCert("CN=Ed25519 SHA3-256");
        Skip.If(cert is null, "Ed25519 not supported on this platform/runtime");

        using var c = cert;
        var pdf = TestPdfFactory.CreateMinimalPdf();

        using var key = c!.GetECDsaPrivateKey()!;
        byte[] signed = await PadesSigner.Document(pdf)
            .WithCertificate(c)
            .WithHashAlgorithm(HashAlgorithmName.SHA3_256)
            .WithExternalSigner(c, new FuncExternalSigner(async hash =>
            {
                byte[] sig = key.SignHash(hash, DSASignatureFormat.Rfc3279DerSequence);
                return await Task.FromResult(sig);
            }))
            .SignAsync();

        using var stream = new MemoryStream(signed);
        var results = await ValidatorTrusting(c).ValidateAsync(stream);
        results.Count.ShouldBe(1);
        results[0].IsIntegrityValid.ShouldBeTrue();
        results[0].IsSignatureValid.ShouldBeTrue();
    }

    [SkippableFact(DisplayName = "Ed25519 external signer with auto-detected OID produces valid signature")]
    public async Task SignAsync_Ed25519AutoDetectOid_ValidatesCorrectly()
    {
        var cert = TestCertificateFactory.TryCreateEdDsaCert("CN=Ed25519 Auto");
        Skip.If(cert is null, "Ed25519 not supported on this platform/runtime");

        using var c = cert;
        var pdf = TestPdfFactory.CreateMinimalPdf();

        using var key = c!.GetECDsaPrivateKey()!;
        byte[] signed = await PadesSigner.Document(pdf)
            .WithCertificate(c)
            .WithExternalSigner(c, new FuncExternalSigner(async hash =>
            {
                byte[] sig = key.SignHash(hash, DSASignatureFormat.Rfc3279DerSequence);
                return await Task.FromResult(sig);
            }))
            .SignAsync();

        using var stream = new MemoryStream(signed);
        var results = await ValidatorTrusting(c).ValidateAsync(stream);
        results.Count.ShouldBe(1);
        results[0].IsIntegrityValid.ShouldBeTrue();
        results[0].IsSignatureValid.ShouldBeTrue();
    }

    [SkippableFact(DisplayName = "Tampering detected in Ed25519 signed document")]
    public async Task SignAsync_Ed25519_TamperDetected()
    {
        var cert = TestCertificateFactory.TryCreateEdDsaCert("CN=Ed25519 Tamper");
        Skip.If(cert is null, "Ed25519 not supported on this platform/runtime");

        using var c = cert;
        using var key = c!.GetECDsaPrivateKey()!;
        byte[] signed = await PadesSigner.Document(TestPdfFactory.CreateMinimalPdf())
            .WithCertificate(c)
            .WithExternalSigner(c, new FuncExternalSigner(async hash =>
            {
                byte[] sig = key.SignHash(hash, DSASignatureFormat.Rfc3279DerSequence);
                return await Task.FromResult(sig);
            }))
            .SignAsync();

        signed[50] ^= 0xFF;
        using var stream = new MemoryStream(signed);
        var results = await ValidatorTrusting(c).ValidateAsync(stream);
        results[0].IsIntegrityValid.ShouldBeFalse();
    }
}
