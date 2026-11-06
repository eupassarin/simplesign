using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Shouldly;
using SimpleSign.Core.Constants;
using SimpleSign.Core.Crypto;
using SimpleSign.Core.Validation;
using SimpleSign.PAdES.Validation;
using SimpleSign.TestHelpers;
using Xunit;

namespace SimpleSign.PAdES.Tests.Signing;

[Trait("Category", "Unit")]
public sealed class Sha3SigningTests
{
    private static X509Certificate2 CreateRsaCert()
    {
        using RSA key = RSA.Create(2048);
        var req = new CertificateRequest("CN=SHA-3 Test", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        req.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, critical: false));
        var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        return CertificateLoader.LoadPkcs12(cert.Export(X509ContentType.Pfx, "export"), "export");
    }

    private static PdfSignatureValidator ValidatorTrusting(params X509Certificate2[] certs)
    {
        return new PdfSignatureValidator(new ValidationOptions
        {
            CheckRevocation = false,
            TrustedRoots = [.. certs]
        });
    }

    private static bool IsSha3Available()
    {
        try
        {
            SHA3_256.HashData("test"u8);
            return true;
        }
        catch (PlatformNotSupportedException)
        {
            return false;
        }
    }

    [SkippableFact(DisplayName = "RSA sign with SHA3-256 produces valid integrity and signature")]
    public async Task SignAsync_RsaSha3_256_ValidatesCorrectly()
    {
        Skip.If(!IsSha3Available(), "SHA-3 not supported on this platform/runtime");

        using var cert = CreateRsaCert();
        byte[] pdf = TestPdfFactory.CreateMinimalPdf();
        using var stream = new MemoryStream(await PadesSigner
            .Document(pdf).WithCertificate(cert)
            .WithHashAlgorithm(HashAlgorithmName.SHA3_256)
            .SignAsync());

        var results = await ValidatorTrusting(cert).ValidateAsync(stream);
        results.Count.ShouldBe(1);
        results[0].IsIntegrityValid.ShouldBeTrue();
        results[0].IsSignatureValid.ShouldBeTrue();
        results[0].DigestAlgorithmOid.ShouldBe(Oids.Sha3_256);
    }

    [SkippableFact(DisplayName = "RSA sign with SHA3-384 produces valid integrity and signature")]
    public async Task SignAsync_RsaSha3_384_ValidatesCorrectly()
    {
        Skip.If(!IsSha3Available(), "SHA-3 not supported on this platform/runtime");

        using var cert = CreateRsaCert();
        byte[] pdf = TestPdfFactory.CreateMinimalPdf();
        using var stream = new MemoryStream(await PadesSigner
            .Document(pdf).WithCertificate(cert)
            .WithHashAlgorithm(HashAlgorithmName.SHA3_384)
            .SignAsync());

        var results = await ValidatorTrusting(cert).ValidateAsync(stream);
        results.Count.ShouldBe(1);
        results[0].IsIntegrityValid.ShouldBeTrue();
        results[0].IsSignatureValid.ShouldBeTrue();
        results[0].DigestAlgorithmOid.ShouldBe(Oids.Sha3_384);
    }

    [SkippableFact(DisplayName = "RSA sign with SHA3-512 produces valid integrity and signature")]
    public async Task SignAsync_RsaSha3_512_ValidatesCorrectly()
    {
        Skip.If(!IsSha3Available(), "SHA-3 not supported on this platform/runtime");

        using var cert = CreateRsaCert();
        byte[] pdf = TestPdfFactory.CreateMinimalPdf();
        using var stream = new MemoryStream(await PadesSigner
            .Document(pdf).WithCertificate(cert)
            .WithHashAlgorithm(HashAlgorithmName.SHA3_512)
            .SignAsync());

        var results = await ValidatorTrusting(cert).ValidateAsync(stream);
        results.Count.ShouldBe(1);
        results[0].IsIntegrityValid.ShouldBeTrue();
        results[0].IsSignatureValid.ShouldBeTrue();
        results[0].DigestAlgorithmOid.ShouldBe(Oids.Sha3_512);
    }

    [SkippableFact(DisplayName = "Multiple SHA-3 signers both validate correctly")]
    public async Task SignAsync_MultipleSha3Signers_BothValidate()
    {
        Skip.If(!IsSha3Available(), "SHA-3 not supported on this platform/runtime");

        using var cert1 = CreateRsaCert();
        using var cert2 = CreateRsaCert();
        byte[] pdf = TestPdfFactory.CreateMinimalPdf();

        var once = await PadesSigner.Document(pdf).WithCertificate(cert1)
            .WithHashAlgorithm(HashAlgorithmName.SHA3_256).WithFieldName("Sig1").SignAsync();
        using var stream = new MemoryStream(await PadesSigner.Document(once).WithCertificate(cert2)
            .WithHashAlgorithm(HashAlgorithmName.SHA3_384).WithFieldName("Sig2").SignAsync());

        var results = await ValidatorTrusting(cert1, cert2).ValidateAsync(stream);
        results.Count.ShouldBe(2);
        foreach (var r in results)
        {
            r.IsIntegrityValid.ShouldBeTrue();
            r.IsSignatureValid.ShouldBeTrue();
        }
    }

    [SkippableFact(DisplayName = "Tampering detected in SHA3-256 signed document")]
    public async Task SignAsync_Sha3_256_TamperDetected()
    {
        Skip.If(!IsSha3Available(), "SHA-3 not supported on this platform/runtime");

        using var cert = CreateRsaCert();
        byte[] signed = await PadesSigner
            .Document(TestPdfFactory.CreateMinimalPdf()).WithCertificate(cert)
            .WithHashAlgorithm(HashAlgorithmName.SHA3_256)
            .SignAsync();
        signed[50] ^= 0xFF;

        using var stream = new MemoryStream(signed);
        var results = await ValidatorTrusting(cert).ValidateAsync(stream);
        results[0].IsIntegrityValid.ShouldBeFalse();
    }

    [SkippableFact(DisplayName = "ECDSA sign with SHA3-256 validates correctly")]
    public async Task SignAsync_EcdsaSha3_256_ValidatesCorrectly()
    {
        Skip.If(!IsSha3Available(), "SHA-3 not supported on this platform/runtime");

        using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var req = new CertificateRequest("CN=ECDSA SHA3-256", key, HashAlgorithmName.SHA256);
        req.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, critical: false));
        var raw = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        using var cert = CertificateLoader.LoadPkcs12(raw.Export(X509ContentType.Pfx, "export"), "export");

        byte[] pdf = TestPdfFactory.CreateMinimalPdf();
        using var stream = new MemoryStream(await PadesSigner
            .Document(pdf).WithCertificate(cert)
            .WithHashAlgorithm(HashAlgorithmName.SHA3_256)
            .SignAsync());

        var results = await ValidatorTrusting(cert).ValidateAsync(stream);
        results.Count.ShouldBe(1);
        results[0].IsIntegrityValid.ShouldBeTrue();
        results[0].IsSignatureValid.ShouldBeTrue();
        results[0].DigestAlgorithmOid.ShouldBe(Oids.Sha3_256);
    }

    [Fact(DisplayName = "SHA3-256 OID mapped to friendly name in DigestAlgorithmName")]
    public void DigestAlgorithmName_Sha3_256_ReturnsFriendlyName()
    {
        var result = new SignatureValidationResult { DigestAlgorithmOid = Oids.Sha3_256 };
        result.DigestAlgorithmName.ShouldBe("SHA3-256");
    }

    [Fact(DisplayName = "SHA3-384 OID mapped to friendly name in DigestAlgorithmName")]
    public void DigestAlgorithmName_Sha3_384_ReturnsFriendlyName()
    {
        var result = new SignatureValidationResult { DigestAlgorithmOid = Oids.Sha3_384 };
        result.DigestAlgorithmName.ShouldBe("SHA3-384");
    }

    [Fact(DisplayName = "SHA3-512 OID mapped to friendly name in DigestAlgorithmName")]
    public void DigestAlgorithmName_Sha3_512_ReturnsFriendlyName()
    {
        var result = new SignatureValidationResult { DigestAlgorithmOid = Oids.Sha3_512 };
        result.DigestAlgorithmName.ShouldBe("SHA3-512");
    }
}
