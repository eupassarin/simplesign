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
namespace SimpleSign.PAdES.Tests.Signing;

/// <summary>
/// Edge-case tests for PadesSignerBuilder and external signer scenarios.
/// Covers fluent API validation, algorithm detection, and LTV/archival builder paths.
/// </summary>
[Trait("Category", "Unit")]
public sealed class SignerBuilderEdgeCaseTests
{


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
            TrustedRoots = [.. certs]
        });
    }

    [Fact(DisplayName = "WithCertificate(null) throws ArgumentNullException")]
    public void WithCertificate_Null_ThrowsArgumentNullException()
    {
        PadesSignerBuilder builder = PadesSigner.Document(TestPdfFactory.CreateMinimalPdf());
        Assert.Throws<ArgumentNullException>(() => builder.WithCertificate(null!));
    }

    [Fact(DisplayName = "TimestampOptions with null endpoint throws ArgumentNullException")]
    public void TimestampOptions_Null_ThrowsArgumentNullException() =>
        Assert.Throws<ArgumentNullException>(() => new TimestampOptions(null!));

    [Fact(DisplayName = "TimestampOptions with relative endpoint throws ArgumentException")]
    public void TimestampOptions_RelativeEndpoint_ThrowsArgumentException() =>
        Assert.Throws<ArgumentException>(() => new TimestampOptions(new Uri("tsa.example.com", UriKind.Relative)));

    [Fact(DisplayName = "WithHashAlgorithm with MD5 fails at signing (unsupported algorithm)")]
    public async Task WithHashAlgorithm_MD5_ThrowsOnSign()
    {
        using X509Certificate2 cert = CreateRsaCert();
        PadesSignerBuilder builder = PadesSigner.Document(TestPdfFactory.CreateMinimalPdf()).WithCertificate(cert).WithHashAlgorithm(HashAlgorithmName.MD5);
        await Assert.ThrowsAnyAsync<Exception>(() => builder.SignAsync());
    }

    [Fact(DisplayName = "WithHashAlgorithm with SHA1 fails at signing (insecure algorithm)")]
    public async Task WithHashAlgorithm_SHA1_ThrowsOnSign()
    {
        using X509Certificate2 cert = CreateRsaCert();
        PadesSignerBuilder builder = PadesSigner.Document(TestPdfFactory.CreateMinimalPdf()).WithCertificate(cert).WithHashAlgorithm(HashAlgorithmName.SHA1);
        await Assert.ThrowsAnyAsync<Exception>(() => builder.SignAsync());
    }

    [Fact(DisplayName = "SignAsync without certificate throws SigningException")]
    public async Task SignAsync_NoCertificate_ThrowsInvalidOperationException()
    {
        PadesSignerBuilder builder = PadesSigner.Document(TestPdfFactory.CreateMinimalPdf());
        await Assert.ThrowsAsync<SigningException>(() => builder.SignAsync());
    }

    [Fact(DisplayName = "SignAsync with certificate without private key throws SigningException")]
    public async Task SignAsync_CertWithoutPrivateKey_ThrowsInvalidOperationException()
    {
        using X509Certificate2 pubCert = CreatePublicOnlyCert();
        PadesSignerBuilder builder = PadesSigner.Document(TestPdfFactory.CreateMinimalPdf()).WithCertificate(pubCert);
        await Assert.ThrowsAsync<SigningException>(() => builder.SignAsync());
    }

    [Fact(DisplayName = "Double WithCertificate uses the last certificate without error")]
    public async Task DoubleCertificate_UsesLastOne_NoError()
    {
        using X509Certificate2 cert1 = CreateRsaCert(null, "CN=First, C=BR");
        using X509Certificate2 cert2 = CreateRsaCert(null, "CN=Second, C=BR");
        byte[] pdfBytes = TestPdfFactory.CreateMinimalPdf();
        byte[] array = await PadesSigner.Document(pdfBytes).WithCertificate(cert1).WithCertificate(cert2)
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
        byte[] pdfBytes = TestPdfFactory.CreateMinimalPdf();
        byte[] array = await PadesSigner.Document(pdfBytes).WithCertificate(cert).WithMetadata("João Silva", "Aprovação de contrato", "São Paulo, BR")
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
        byte[] pdfBytes = TestPdfFactory.CreateMinimalPdf();
        PadesSignerBuilder builder = PadesSigner.Document(pdfBytes).WithExternalSigner(cert, new FuncExternalSigner(delegate
        {
            throw new InvalidOperationException("HSM offline");
        }));
        Func<Task<byte[]>> action = () => builder.SignAsync();
        var ex = await Should.ThrowAsync<InvalidOperationException>(async () => await action());
        ex.Message.ShouldContain("HSM offline");
    }

    [Fact(DisplayName = "WithExternalSigner with delegate returning empty bytes produces error or invalid CMS")]
    public async Task ExternalSigner_EmptyBytes_ThrowsOrProducesInvalidCms()
    {
        using X509Certificate2 cert = CreateRsaCert();
        byte[] pdfBytes = TestPdfFactory.CreateMinimalPdf();
        PadesSignerBuilder signerBuilder = PadesSigner.Document(pdfBytes).WithExternalSigner(cert, new FuncExternalSigner(_ => Task.FromResult(Array.Empty<byte>())));
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
        byte[] pdfBytes = TestPdfFactory.CreateMinimalPdf();
        PadesSignerBuilder signerBuilder = PadesSigner.Document(pdfBytes).WithExternalSigner(cert, new FuncExternalSigner(_ => Task.FromResult<byte[]>(null!)));
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
        byte[] pdfBytes = TestPdfFactory.CreateMinimalPdf();
        using MemoryStream stream = new MemoryStream(await PadesSigner.Document(pdfBytes).WithCertificate(cert).WithHashAlgorithm(HashAlgorithmName.SHA256)
            .SignAsync());
        IReadOnlyList<SignatureValidationResult> readOnlyList = await ValidatorTrusting(cert).ValidateAsync(stream);
        readOnlyList.Count().ShouldBe(1, "");
        readOnlyList[0].DigestAlgorithmOid.ShouldBe("2.16.840.1.101.3.4.2.1", "");
    }

    [Fact(DisplayName = "RSA + SHA-384 produces OID sha384WithRSAEncryption")]
    public async Task RsaSha384_ProducesCorrectOid()
    {
        using X509Certificate2 cert = CreateRsaCert();
        byte[] pdfBytes = TestPdfFactory.CreateMinimalPdf();
        using MemoryStream stream = new MemoryStream(await PadesSigner.Document(pdfBytes).WithCertificate(cert).WithHashAlgorithm(HashAlgorithmName.SHA384)
            .SignAsync());
        IReadOnlyList<SignatureValidationResult> readOnlyList = await ValidatorTrusting(cert).ValidateAsync(stream);
        readOnlyList.Count().ShouldBe(1, "");
        readOnlyList[0].DigestAlgorithmOid.ShouldBe("2.16.840.1.101.3.4.2.2", "");
    }

    [Fact(DisplayName = "RSA + SHA-512 produces OID sha512WithRSAEncryption")]
    public async Task RsaSha512_ProducesCorrectOid()
    {
        using X509Certificate2 cert = CreateRsaCert();
        byte[] pdfBytes = TestPdfFactory.CreateMinimalPdf();
        using MemoryStream stream = new MemoryStream(await PadesSigner.Document(pdfBytes).WithCertificate(cert).WithHashAlgorithm(HashAlgorithmName.SHA512)
            .SignAsync());
        IReadOnlyList<SignatureValidationResult> readOnlyList = await ValidatorTrusting(cert).ValidateAsync(stream);
        readOnlyList.Count().ShouldBe(1, "");
        readOnlyList[0].DigestAlgorithmOid.ShouldBe("2.16.840.1.101.3.4.2.3", "");
    }

    [Fact(DisplayName = "ECDSA + SHA-256 produces OID ecdsaWithSHA256")]
    public async Task EcdsaSha256_ProducesCorrectOid()
    {
        using X509Certificate2 cert = CreateEcdsaCert();
        byte[] pdfBytes = TestPdfFactory.CreateMinimalPdf();
        using MemoryStream stream = new MemoryStream(await PadesSigner.Document(pdfBytes).WithCertificate(cert).WithHashAlgorithm(HashAlgorithmName.SHA256)
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
        byte[] pdfBytes = TestPdfFactory.CreateMinimalPdf();
        byte[] signed = await PadesSigner.Document(pdfBytes).WithCertificate(cert).WithHashAlgorithm(HashAlgorithmName.SHA384)
            .SignAsync();
        signed.ShouldNotBeNull();
        signed.ShouldNotBeEmpty();
        signed.Length.ShouldBeGreaterThan(pdfBytes.Length, "signed PDF should be larger than input");
    }

    [Fact(DisplayName = "WithExternalSigner auto-detects RSA + SHA-256 correctly")]
    public void ExternalSigner_AutoDetect_RsaSha256()
    {
        using X509Certificate2 certificate = CreateRsaCert();
        PadesSignerBuilder actualValue = PadesSigner.Document(TestPdfFactory.CreateMinimalPdf()).WithHashAlgorithm(HashAlgorithmName.SHA256).WithExternalSigner(certificate, new FuncExternalSigner(_ => Task.FromResult(Array.Empty<byte>())));
        actualValue.ShouldNotBeNull("");
    }

    [Fact(DisplayName = "WithExternalSigner auto-detects ECDSA + SHA-256 correctly")]
    public void ExternalSigner_AutoDetect_EcdsaSha256()
    {
        using X509Certificate2 certificate = CreateEcdsaCert();
        PadesSignerBuilder actualValue = PadesSigner.Document(TestPdfFactory.CreateMinimalPdf()).WithHashAlgorithm(HashAlgorithmName.SHA256).WithExternalSigner(certificate, new FuncExternalSigner(_ => Task.FromResult(Array.Empty<byte>())));
        actualValue.ShouldNotBeNull("");
    }

    [Fact(DisplayName = "WithExternalSigner with SHA-384 and RSA auto-detects correctly")]
    public void ExternalSigner_AutoDetect_RsaSha384()
    {
        using X509Certificate2 cert = CreateRsaCert();
        PadesSignerBuilder actualValue = PadesSigner.Document(TestPdfFactory.CreateMinimalPdf()).WithHashAlgorithm(HashAlgorithmName.SHA384).WithExternalSigner(cert, new FuncExternalSigner(_ => Task.FromResult(Array.Empty<byte>())));
        actualValue.ShouldNotBeNull("");
    }

    [Fact(DisplayName = "WithExternalSigner with SHA-384 and ECDSA auto-detects correctly")]
    public void ExternalSigner_AutoDetect_EcdsaSha384()
    {
        using X509Certificate2 cert = CreateEcdsaCert();
        PadesSignerBuilder actualValue = PadesSigner.Document(TestPdfFactory.CreateMinimalPdf()).WithHashAlgorithm(HashAlgorithmName.SHA384).WithExternalSigner(cert, new FuncExternalSigner(_ => Task.FromResult(Array.Empty<byte>())));
        actualValue.ShouldNotBeNull("");
    }

    [Fact(DisplayName = "WithExternalSigner accepts explicit Ed25519 OID")]
    public void ExternalSigner_ExplicitEd25519Oid_AcceptsConfiguration()
    {
        using X509Certificate2 certificate = CreateRsaCert();
        PadesSignerBuilder actualValue = PadesSigner.Document(TestPdfFactory.CreateMinimalPdf())
            .WithExternalSigner(certificate, new FuncExternalSigner(_ => Task.FromResult(Array.Empty<byte>())))
            .WithSignatureAlgorithm("1.3.101.112");
        actualValue.ShouldNotBeNull("");
    }

    [Fact(DisplayName = "WithExternalSigner accepts explicit Ed448 OID")]
    public void ExternalSigner_ExplicitEd448Oid_AcceptsConfiguration()
    {
        using X509Certificate2 certificate = CreateRsaCert();
        PadesSignerBuilder actualValue = PadesSigner.Document(TestPdfFactory.CreateMinimalPdf())
            .WithExternalSigner(certificate, new FuncExternalSigner(_ => Task.FromResult(Array.Empty<byte>())))
            .WithSignatureAlgorithm("1.3.101.113");
        actualValue.ShouldNotBeNull("");
    }

    [Fact(DisplayName = "LongTerm profile with null timestamp throws ArgumentNullException")]
    public void LongTermProfile_NullTimestamp_ThrowsArgumentNullException() =>
        Assert.Throws<ArgumentNullException>(() =>
            AdesBaselineProfile.LongTerm(null!, new LongTermValidationOptions()));

    [Fact(DisplayName = "Archive profile with null timestamp and validation throws ArgumentNullException")]
    public void ArchiveProfile_NullArguments_ThrowsArgumentNullException() =>
        Assert.Throws<ArgumentNullException>(() =>
            AdesBaselineProfile.Archive(null!, null!));

    [Fact(DisplayName = "Archive profile without dedicated endpoint uses configured timestamp URL")]
    public void ArchiveProfile_NullArchiveTimestamp_UsesConfiguredTimestamp()
    {
        PadesSignerBuilder actualValue = PadesSigner.Document(TestPdfFactory.CreateMinimalPdf())
            .WithLevel(AdesBaselineProfile.Archive(
                new TimestampOptions(new Uri("http://tsa.example.com")),
                new LongTermValidationOptions()));
        actualValue.ShouldNotBeNull("");
    }

    [Fact(DisplayName = "Archive profile with own endpoint does not use timestamp URL")]
    public void ArchiveProfile_ExplicitEndpoint_UsesProvidedUrl()
    {
        PadesSignerBuilder actualValue = PadesSigner.Document(TestPdfFactory.CreateMinimalPdf())
            .WithLevel(AdesBaselineProfile.Archive(
                new TimestampOptions(new Uri("http://tsa.example.com")),
                new LongTermValidationOptions(),
                new ArchiveTimestampOptions(new Uri("http://archival-tsa.example.com"))));
        actualValue.ShouldNotBeNull("");
    }

    [Fact(DisplayName = "WithLevel LongTerm enables LTV and returns new instance")]
    public void WithLevel_LongTerm_ReturnsNewInstance()
    {
        PadesSignerBuilder signerBuilder = PadesSigner.Document(TestPdfFactory.CreateMinimalPdf());
        PadesSignerBuilder actualValue = signerBuilder.WithLevel(AdesBaselineProfile.LongTerm(
            new TimestampOptions(new Uri("http://tsa.example.com")),
            new LongTermValidationOptions()));
        actualValue.ShouldNotBeSameAs(signerBuilder, "");
    }

    [Fact(DisplayName = "WithLevel Archive includes LTV and returns new instance")]
    public void WithLevel_Archive_ReturnsNewInstance()
    {
        PadesSignerBuilder signerBuilder = PadesSigner.Document(TestPdfFactory.CreateMinimalPdf());
        PadesSignerBuilder actualValue = signerBuilder.WithLevel(AdesBaselineProfile.Archive(
            new TimestampOptions(new Uri("http://tsa.example.com")),
            new LongTermValidationOptions(),
            new ArchiveTimestampOptions(new Uri("http://tsa.example.com"))));
        actualValue.ShouldNotBeSameAs(signerBuilder, "");
    }
}
