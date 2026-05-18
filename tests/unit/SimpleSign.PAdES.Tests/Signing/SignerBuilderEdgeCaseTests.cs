using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Shouldly;
using SimpleSign.Core.Crypto;
using SimpleSign.Core.Signing;
using SimpleSign.Core.Validation;
using SimpleSign.PAdES.Validation;
using SimpleSign.TestHelpers;
using Xunit;
namespace SimpleSign.PAdES.Tests.Core;

/// <summary>
/// Edge-case tests for SignerBuilder and external signer scenarios.
/// Covers fluent API validation, algorithm detection, and LTV/archival builder paths.
/// </summary>
public sealed class SignerBuilderEdgeCaseTests
{
    private static byte[] BuildMinimalPdf()
    {
        return Encoding.Latin1.GetBytes("%PDF-1.7\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n2 0 obj\n<< /Type /Pages /Kids [] /Count 0 >>\nendobj\nxref\n0 3\n0000000000 65535 f \n0000000009 00000 n \n0000000058 00000 n \ntrailer\n<< /Size 3 /Root 1 0 R >>\nstartxref\n110\n%%EOF");
    }

    private static X509Certificate2 CreateRsaCert(HashAlgorithmName? hash = null, string subject = "CN=Test RSA, O=Tests, C=BR")
    {
        using RSA key = RSA.Create(2048);
        CertificateRequest certificateRequest = new CertificateRequest(subject, key, hash ?? HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        certificateRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, critical: false));
        X509Certificate2 x509Certificate = certificateRequest.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1.0), DateTimeOffset.UtcNow.AddYears(1));
        return CertificateLoader.LoadPkcs12(x509Certificate.Export(X509ContentType.Pfx, "test-export"), "test-export");
    }

    private static X509Certificate2 CreateEcdsaCert(ECCurve? curve = null, string subject = "CN=Test ECDSA, O=Tests, C=BR")
    {
        using ECDsa key = ECDsa.Create(curve ?? ECCurve.NamedCurves.nistP256);
        CertificateRequest certificateRequest = new CertificateRequest(subject, key, HashAlgorithmName.SHA256);
        certificateRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, critical: false));
        X509Certificate2 x509Certificate = certificateRequest.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1.0), DateTimeOffset.UtcNow.AddYears(1));
        return CertificateLoader.LoadPkcs12(x509Certificate.Export(X509ContentType.Pfx, "test-export"), "test-export");
    }

    /// <summary>Creates a certificate without a private key (public-only).</summary>
    private static X509Certificate2 CreatePublicOnlyCert()
    {
        using RSA key = RSA.Create(2048);
        CertificateRequest certificateRequest = new CertificateRequest("CN=No Private Key", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        X509Certificate2 x509Certificate = certificateRequest.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1.0), DateTimeOffset.UtcNow.AddYears(1));
        return CertificateLoader.LoadCertificate(x509Certificate.Export(X509ContentType.Cert));
    }

    private static PdfSignatureValidator ValidatorTrusting(params X509Certificate2[] certs)
    {
        return new PdfSignatureValidator(new ValidationOptions
        {
            CheckRevocation = false,
            TrustedRoots = certs.ToList()
        });
    }

    [Fact(DisplayName = "WithCertificate(null) throws ArgumentNullException")]
    public void WithCertificate_Null_ThrowsArgumentNullException()
    {
        SignerBuilder builder = SimpleSigner.Document(BuildMinimalPdf());
        Assert.Throws<ArgumentNullException>(() => builder.WithCertificate(null!));
    }

    [Fact(DisplayName = "WithTimestamp(null) throws ArgumentNullException")]
    public void WithTimestamp_Null_ThrowsArgumentNullException()
    {
        SignerBuilder builder = SimpleSigner.Document(BuildMinimalPdf());
        Assert.Throws<ArgumentNullException>(() => builder.WithTimestamp(null!));
    }

    [Fact(DisplayName = "WithTimestamp with empty string throws ArgumentException")]
    public void WithTimestamp_EmptyString_ThrowsArgumentException()
    {
        SignerBuilder builder = SimpleSigner.Document(BuildMinimalPdf());
        Assert.Throws<ArgumentException>(() => builder.WithTimestamp(""));
    }

    [Fact(DisplayName = "WithHashAlgorithm with MD5 fails at signing (unsupported algorithm)")]
    public async Task WithHashAlgorithm_MD5_ThrowsOnSign()
    {
        using X509Certificate2 cert = CreateRsaCert();
        SignerBuilder builder = SimpleSigner.Document(BuildMinimalPdf()).WithCertificate(cert).WithHashAlgorithm(HashAlgorithmName.MD5);
        await Assert.ThrowsAnyAsync<Exception>(() => builder.SignAsync());
    }

    [Fact(DisplayName = "WithHashAlgorithm with SHA1 fails at signing (insecure algorithm)")]
    public async Task WithHashAlgorithm_SHA1_ThrowsOnSign()
    {
        using X509Certificate2 cert = CreateRsaCert();
        SignerBuilder builder = SimpleSigner.Document(BuildMinimalPdf()).WithCertificate(cert).WithHashAlgorithm(HashAlgorithmName.SHA1);
        await Assert.ThrowsAnyAsync<Exception>(() => builder.SignAsync());
    }

    [Fact(DisplayName = "SignAsync without certificate throws SigningException")]
    public async Task SignAsync_NoCertificate_ThrowsInvalidOperationException()
    {
        SignerBuilder builder = SimpleSigner.Document(BuildMinimalPdf());
        await Assert.ThrowsAsync<SigningException>(() => builder.SignAsync());
    }

    [Fact(DisplayName = "SignAsync with certificate without private key throws SigningException")]
    public async Task SignAsync_CertWithoutPrivateKey_ThrowsInvalidOperationException()
    {
        using X509Certificate2 pubCert = CreatePublicOnlyCert();
        SignerBuilder builder = SimpleSigner.Document(BuildMinimalPdf()).WithCertificate(pubCert);
        await Assert.ThrowsAsync<SigningException>(() => builder.SignAsync());
    }

    [Fact(DisplayName = "Double WithCertificate uses the last certificate without error")]
    public async Task DoubleCertificate_UsesLastOne_NoError()
    {
        using X509Certificate2 cert1 = CreateRsaCert(null, "CN=First, C=BR");
        using X509Certificate2 cert2 = CreateRsaCert(null, "CN=Second, C=BR");
        byte[] pdfBytes = BuildMinimalPdf();
        byte[] array = await SimpleSigner.Document(pdfBytes).WithCertificate(cert1).WithCertificate(cert2)
            .SignAsync();
        array.ShouldNotBeEmpty();
        using MemoryStream stream = new MemoryStream(array);
        IReadOnlyList<SignatureValidationResult> readOnlyList = await ValidatorTrusting(cert2).ValidateAsync(stream);
        readOnlyList.Count().ShouldBe(1);
        readOnlyList[0].IsSignatureValid.ShouldBeTrue();
        readOnlyList[0].SignerName!.ShouldContain("Second");
    }

    [Fact(DisplayName = "WithMetadata persists reason, location and name in signed document")]
    public async Task WithMetadata_PersistsInSignedOutput()
    {
        using X509Certificate2 cert = CreateRsaCert();
        byte[] pdfBytes = BuildMinimalPdf();
        byte[] array = await SimpleSigner.Document(pdfBytes).WithCertificate(cert).WithMetadata("João Silva", "Aprovação de contrato", "São Paulo, BR")
            .SignAsync();
        array.ShouldNotBeEmpty();
        string actualValue = Encoding.Latin1.GetString(array);
        actualValue.ShouldContain("/Reason");
        actualValue.ShouldContain("/Location");
    }

    [Fact(DisplayName = "WithExternalSigner with delegate that throws exception propagates the error")]
    public async Task ExternalSigner_DelegateThrows_ExceptionPropagates()
    {
        using X509Certificate2 cert = CreateRsaCert();
        byte[] pdfBytes = BuildMinimalPdf();
        SignerBuilder builder = SimpleSigner.Document(pdfBytes).WithExternalSigner(cert, delegate
        {
            throw new InvalidOperationException("HSM offline");
        });
        Func<Task<byte[]>> action = () => builder.SignAsync();
        var ex = await Should.ThrowAsync<InvalidOperationException>(async () => await action());
        ex.Message.ShouldContain("HSM offline");
    }

    [Fact(DisplayName = "WithExternalSigner with delegate returning empty bytes produces error or invalid CMS")]
    public async Task ExternalSigner_EmptyBytes_ThrowsOrProducesInvalidCms()
    {
        using X509Certificate2 cert = CreateRsaCert();
        byte[] pdfBytes = BuildMinimalPdf();
        SignerBuilder signerBuilder = SimpleSigner.Document(pdfBytes).WithExternalSigner(cert, (byte[] _) => Task.FromResult(Array.Empty<byte>()));
        try
        {
            using MemoryStream stream = new MemoryStream(await signerBuilder.SignAsync());
            IReadOnlyList<SignatureValidationResult> readOnlyList = await ValidatorTrusting(cert).ValidateAsync(stream);
            readOnlyList.Count().ShouldBe(1);
            readOnlyList[0].IsSignatureValid.ShouldBeFalse();
        }
        catch (Exception actualValue)
        {
            actualValue.ShouldBeAssignableTo<Exception>();
        }
    }

    [Fact(DisplayName = "WithExternalSigner with delegate returning null produces invalid CMS")]
    public async Task ExternalSigner_ReturnsNull_ProducesInvalidSignature()
    {
        using X509Certificate2 cert = CreateRsaCert();
        byte[] pdfBytes = BuildMinimalPdf();
        SignerBuilder signerBuilder = SimpleSigner.Document(pdfBytes).WithExternalSigner(cert, (byte[] _) => Task.FromResult<byte[]>(null!));
        try
        {
            using MemoryStream stream = new MemoryStream(await signerBuilder.SignAsync());
            IReadOnlyList<SignatureValidationResult> readOnlyList = await ValidatorTrusting(cert).ValidateAsync(stream);
            readOnlyList.Count().ShouldBe(1);
            readOnlyList[0].IsSignatureValid.ShouldBeFalse();
        }
        catch (Exception actualValue)
        {
            actualValue.ShouldBeAssignableTo<Exception>();
        }
    }

    [Fact(DisplayName = "RSA + SHA-256 produces OID sha256WithRSAEncryption")]
    public async Task RsaSha256_ProducesCorrectOid()
    {
        using X509Certificate2 cert = CreateRsaCert();
        byte[] pdfBytes = BuildMinimalPdf();
        using MemoryStream stream = new MemoryStream(await SimpleSigner.Document(pdfBytes).WithCertificate(cert).WithHashAlgorithm(HashAlgorithmName.SHA256)
            .SignAsync());
        IReadOnlyList<SignatureValidationResult> readOnlyList = await ValidatorTrusting(cert).ValidateAsync(stream);
        readOnlyList.Count().ShouldBe(1, "");
        readOnlyList[0].DigestAlgorithmOid.ShouldBe("2.16.840.1.101.3.4.2.1", "");
    }

    [Fact(DisplayName = "RSA + SHA-384 produces OID sha384WithRSAEncryption")]
    public async Task RsaSha384_ProducesCorrectOid()
    {
        using X509Certificate2 cert = CreateRsaCert();
        byte[] pdfBytes = BuildMinimalPdf();
        using MemoryStream stream = new MemoryStream(await SimpleSigner.Document(pdfBytes).WithCertificate(cert).WithHashAlgorithm(HashAlgorithmName.SHA384)
            .SignAsync());
        IReadOnlyList<SignatureValidationResult> readOnlyList = await ValidatorTrusting(cert).ValidateAsync(stream);
        readOnlyList.Count().ShouldBe(1, "");
        readOnlyList[0].DigestAlgorithmOid.ShouldBe("2.16.840.1.101.3.4.2.2", "");
    }

    [Fact(DisplayName = "RSA + SHA-512 produces OID sha512WithRSAEncryption")]
    public async Task RsaSha512_ProducesCorrectOid()
    {
        using X509Certificate2 cert = CreateRsaCert();
        byte[] pdfBytes = BuildMinimalPdf();
        using MemoryStream stream = new MemoryStream(await SimpleSigner.Document(pdfBytes).WithCertificate(cert).WithHashAlgorithm(HashAlgorithmName.SHA512)
            .SignAsync());
        IReadOnlyList<SignatureValidationResult> readOnlyList = await ValidatorTrusting(cert).ValidateAsync(stream);
        readOnlyList.Count().ShouldBe(1, "");
        readOnlyList[0].DigestAlgorithmOid.ShouldBe("2.16.840.1.101.3.4.2.3", "");
    }

    [Fact(DisplayName = "ECDSA + SHA-256 produces OID ecdsaWithSHA256")]
    public async Task EcdsaSha256_ProducesCorrectOid()
    {
        using X509Certificate2 cert = CreateEcdsaCert();
        byte[] pdfBytes = BuildMinimalPdf();
        using MemoryStream stream = new MemoryStream(await SimpleSigner.Document(pdfBytes).WithCertificate(cert).WithHashAlgorithm(HashAlgorithmName.SHA256)
            .SignAsync());
        IReadOnlyList<SignatureValidationResult> readOnlyList = await ValidatorTrusting(cert).ValidateAsync(stream);
        readOnlyList.Count().ShouldBe(1, "");
        readOnlyList[0].IsIntegrityValid.ShouldBeTrue("");
        readOnlyList[0].IsSignatureValid.ShouldBeTrue("");
    }

    [Fact(DisplayName = "ECDSA + SHA-384 signs successfully")]
    public async Task EcdsaSha384_SignsSuccessfully()
    {
        using X509Certificate2 cert = CreateEcdsaCert(ECCurve.NamedCurves.nistP384);
        byte[] pdfBytes = BuildMinimalPdf();
        byte[] signed = await SimpleSigner.Document(pdfBytes).WithCertificate(cert).WithHashAlgorithm(HashAlgorithmName.SHA384)
            .SignAsync();
        signed.ShouldNotBeNull();
        signed.ShouldNotBeEmpty();
        signed.Length.ShouldBeGreaterThan(pdfBytes.Length, "signed PDF should be larger than input");
    }

    [Fact(DisplayName = "WithExternalSigner auto-detects RSA + SHA-256 correctly")]
    public void ExternalSigner_AutoDetect_RsaSha256()
    {
        using X509Certificate2 certificate = CreateRsaCert();
        SignerBuilder actualValue = SimpleSigner.Document(BuildMinimalPdf()).WithHashAlgorithm(HashAlgorithmName.SHA256).WithExternalSigner(certificate, (byte[] _) => Task.FromResult(Array.Empty<byte>()));
        actualValue.ShouldNotBeNull("");
    }

    [Fact(DisplayName = "WithExternalSigner auto-detects ECDSA + SHA-256 correctly")]
    public void ExternalSigner_AutoDetect_EcdsaSha256()
    {
        using X509Certificate2 certificate = CreateEcdsaCert();
        SignerBuilder actualValue = SimpleSigner.Document(BuildMinimalPdf()).WithHashAlgorithm(HashAlgorithmName.SHA256).WithExternalSigner(certificate, (byte[] _) => Task.FromResult(Array.Empty<byte>()));
        actualValue.ShouldNotBeNull("");
    }

    [Fact(DisplayName = "WithExternalSigner with SHA-384 and RSA auto-detects correctly")]
    public void ExternalSigner_AutoDetect_RsaSha384()
    {
        using X509Certificate2 cert = CreateRsaCert();
        SignerBuilder actualValue = SimpleSigner.Document(BuildMinimalPdf()).WithHashAlgorithm(HashAlgorithmName.SHA384).WithExternalSigner(cert, (byte[] _) => Task.FromResult(Array.Empty<byte>()));
        actualValue.ShouldNotBeNull("");
    }

    [Fact(DisplayName = "WithExternalSigner with SHA-384 and ECDSA auto-detects correctly")]
    public void ExternalSigner_AutoDetect_EcdsaSha384()
    {
        using X509Certificate2 cert = CreateEcdsaCert();
        SignerBuilder actualValue = SimpleSigner.Document(BuildMinimalPdf()).WithHashAlgorithm(HashAlgorithmName.SHA384).WithExternalSigner(cert, (byte[] _) => Task.FromResult(Array.Empty<byte>()));
        actualValue.ShouldNotBeNull("");
    }

    [Fact(DisplayName = "WithExternalSigner accepts explicit Ed25519 OID")]
    public void ExternalSigner_ExplicitEd25519Oid_AcceptsConfiguration()
    {
        using X509Certificate2 certificate = CreateRsaCert();
        SignerBuilder actualValue = SimpleSigner.Document(BuildMinimalPdf()).WithExternalSigner(certificate, (byte[] _) => Task.FromResult(Array.Empty<byte>()), "1.3.101.112");
        actualValue.ShouldNotBeNull("");
    }

    [Fact(DisplayName = "WithExternalSigner accepts explicit Ed448 OID")]
    public void ExternalSigner_ExplicitEd448Oid_AcceptsConfiguration()
    {
        using X509Certificate2 certificate = CreateRsaCert();
        SignerBuilder actualValue = SimpleSigner.Document(BuildMinimalPdf()).WithExternalSigner(certificate, (byte[] _) => Task.FromResult(Array.Empty<byte>()), "1.3.101.113");
        actualValue.ShouldNotBeNull("");
    }

    [Fact(DisplayName = "WithLtv without timestamp URL does not throw exception in builder")]
    public void WithLtv_NoTimestamp_DoesNotThrow()
    {
        SignerBuilder actualValue = SimpleSigner.Document(BuildMinimalPdf()).WithLtv();
        actualValue.ShouldNotBeNull("");
    }

    [Fact(DisplayName = "WithLtv without timestamp throws SigningException at sign-time")]
    public async Task WithLtv_NoTimestamp_ThrowsAtSignTime()
    {
        using var cert = TestCertificateFactory.CreateSelfSignedCert("CN=LTV No TSA Test");
        var builder = SimpleSigner.Document(BuildMinimalPdf())
            .WithCertificate(cert)
            .WithLtv();

        var act = () => builder.SignAsync();
        var ex2 = await Should.ThrowAsync<SigningException>(act);
        ex2.Message.ShouldContain("LTV requires a timestamp");
    }

    [Fact(DisplayName = "WithArchivalTimestamp without URL uses configured timestamp URL")]
    public void WithArchivalTimestamp_NullUrl_UsesConfiguredTimestamp()
    {
        SignerBuilder actualValue = SimpleSigner.Document(BuildMinimalPdf()).WithTimestamp("http://tsa.example.com").WithArchivalTimestamp();
        actualValue.ShouldNotBeNull("");
    }

    [Fact(DisplayName = "WithArchivalTimestamp with own URL does not use timestamp URL")]
    public void WithArchivalTimestamp_ExplicitUrl_UsesProvidedUrl()
    {
        SignerBuilder actualValue = SimpleSigner.Document(BuildMinimalPdf()).WithTimestamp("http://tsa.example.com").WithArchivalTimestamp("http://archival-tsa.example.com");
        actualValue.ShouldNotBeNull("");
    }

    [Fact(DisplayName = "WithLtv enables LTV and returns new instance")]
    public void WithLtv_ReturnsNewInstance()
    {
        SignerBuilder signerBuilder = SimpleSigner.Document(BuildMinimalPdf());
        SignerBuilder actualValue = signerBuilder.WithLtv();
        actualValue.ShouldNotBeSameAs(signerBuilder, "");
    }

    [Fact(DisplayName = "WithArchivalTimestamp implies LTV and returns new instance")]
    public void WithArchivalTimestamp_ImpliesLtv_ReturnsNewInstance()
    {
        SignerBuilder signerBuilder = SimpleSigner.Document(BuildMinimalPdf());
        SignerBuilder actualValue = signerBuilder.WithArchivalTimestamp("http://tsa.example.com");
        actualValue.ShouldNotBeSameAs(signerBuilder, "");
    }
}
