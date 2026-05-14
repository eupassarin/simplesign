using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using FluentAssertions;
using SimpleSign.Core.Crypto;
using SimpleSign.Core.Validation;
using SimpleSign.PAdES.Signing;
using SimpleSign.PAdES.Validation;
using Xunit;
namespace SimpleSign.PAdES.Tests.Signing;

/// <summary>
/// Tests for the two-phase deferred signing API (<see cref="DeferredSigner" />).
/// Simulates the web scenario: server prepares → external signer signs → server completes.
/// </summary>
public sealed class DeferredSignerTests
{
    private static byte[] BuildMinimalPdf()
    {
        return Encoding.Latin1.GetBytes("%PDF-1.7\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n2 0 obj\n<< /Type /Pages /Kids [] /Count 0 >>\nendobj\nxref\n0 3\n0000000000 65535 f \n0000000009 00000 n \n0000000058 00000 n \ntrailer\n<< /Size 3 /Root 1 0 R >>\nstartxref\n110\n%%EOF");
    }

    private static X509Certificate2 CreateRsaCertWithPrivateKey()
    {
        using RSA key = RSA.Create(2048);
        CertificateRequest certificateRequest = new CertificateRequest("CN=Deferred RSA Signer", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        certificateRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, critical: false));
        X509Certificate2 x509Certificate = certificateRequest.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1.0), DateTimeOffset.UtcNow.AddYears(1));
        return CertificateLoader.LoadPkcs12(x509Certificate.Export(X509ContentType.Pfx, "test-export"), "test-export");
    }

    private static X509Certificate2 CreateEcdsaCertWithPrivateKey()
    {
        using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        CertificateRequest certificateRequest = new CertificateRequest("CN=Deferred ECDSA Signer", key, HashAlgorithmName.SHA256);
        certificateRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, critical: false));
        X509Certificate2 x509Certificate = certificateRequest.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1.0), DateTimeOffset.UtcNow.AddYears(1));
        return CertificateLoader.LoadPkcs12(x509Certificate.Export(X509ContentType.Pfx, "test-export"), "test-export");
    }

    private static X509Certificate2 GetPublicCertOnly(X509Certificate2 fullCert)
    {
        return CertificateLoader.LoadCertificate(fullCert.Export(X509ContentType.Cert));
    }

    private static PdfSignatureValidator ValidatorTrusting(params X509Certificate2[] certs)
    {
        return new PdfSignatureValidator(new ValidationOptions
        {
            CheckRevocation = false,
            TrustedRoots = certs.ToList()
        });
    }

    [Fact(DisplayName = "Deferred signing with RSA produces valid PDF")]
    public async Task PrepareAndComplete_Rsa_ProducesValidSignature()
    {
        using X509Certificate2 fullCert = CreateRsaCertWithPrivateKey();
        using X509Certificate2 publicCert = GetPublicCertOnly(fullCert);
        byte[] pdf = BuildMinimalPdf();
        DeferredSigningPrepareResult deferredSigningPrepareResult = await DeferredSigner.PrepareAsync(pdf, publicCert);
        deferredSigningPrepareResult.HashToSign.Should().NotBeEmpty("should contain DER-encoded signed attributes");
        deferredSigningPrepareResult.SessionData.Should().NotBeEmpty("should contain serialized session");
        deferredSigningPrepareResult.DigestAlgorithm.Should().Be("SHA256", "");
        deferredSigningPrepareResult.SignatureAlgorithmOid.Should().NotBeNullOrEmpty("");
        using RSA? rsa = fullCert.GetRSAPrivateKey();
        byte[] rawSignature = rsa!.SignData(deferredSigningPrepareResult.HashToSign, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        byte[] array = await DeferredSigner.CompleteAsync(deferredSigningPrepareResult.SessionData, rawSignature);
        array.Should().NotBeEmpty("");
        array.Length.Should().BeGreaterThan(pdf.Length, "");
        using MemoryStream stream = new MemoryStream(array);
        IReadOnlyList<SignatureValidationResult> readOnlyList = await ValidatorTrusting(fullCert).ValidateAsync(stream);
        readOnlyList.Should().ContainSingle("");
        readOnlyList[0].IsValid.Should().BeTrue("deferred-signed PDF should be valid");
    }

    [Fact(DisplayName = "Deferred signing with ECDSA produces valid PDF")]
    public async Task PrepareAndComplete_Ecdsa_ProducesValidSignature()
    {
        using X509Certificate2 fullCert = CreateEcdsaCertWithPrivateKey();
        using X509Certificate2 publicCert = GetPublicCertOnly(fullCert);
        byte[] pdfBytes = BuildMinimalPdf();
        DeferredSigningPrepareResult deferredSigningPrepareResult = await DeferredSigner.PrepareAsync(pdfBytes, publicCert);
        using ECDsa? ecdsa = fullCert.GetECDsaPrivateKey();
        byte[] rawSignature = ecdsa!.SignData(deferredSigningPrepareResult.HashToSign, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);
        using MemoryStream stream = new MemoryStream(await DeferredSigner.CompleteAsync(deferredSigningPrepareResult.SessionData, rawSignature));
        IReadOnlyList<SignatureValidationResult> readOnlyList = await ValidatorTrusting(fullCert).ValidateAsync(stream);
        readOnlyList.Should().ContainSingle("");
        readOnlyList[0].IsValid.Should().BeTrue("ECDSA deferred-signed PDF should be valid");
    }

    [Fact(DisplayName = "Session serializes and deserializes correctly")]
    public async Task SessionData_RoundTrip_PreservesState()
    {
        using X509Certificate2 fullCert = CreateRsaCertWithPrivateKey();
        using X509Certificate2 publicCert = GetPublicCertOnly(fullCert);
        byte[] pdfBytes = BuildMinimalPdf();
        DeferredSigningPrepareResult deferredSigningPrepareResult = await DeferredSigner.PrepareAsync(pdfBytes, publicCert);
        DeferredSigningSession deferredSigningSession = DeferredSigningSession.Deserialize(deferredSigningPrepareResult.SessionData);
        deferredSigningSession.SignedAttributes.Should().BeEquivalentTo(deferredSigningPrepareResult.HashToSign, "");
        deferredSigningSession.DigestOid.Should().NotBeNullOrEmpty("");
        deferredSigningSession.SignatureAlgorithmOid.Should().NotBeNullOrEmpty("");
        deferredSigningSession.CertificateDer.Should().BeEquivalentTo(publicCert.RawData, "");
        deferredSigningSession.PreparedPdf.Should().NotBeEmpty("");
        deferredSigningSession.ContentsReservedBytes.Should().BeGreaterThan(0, "");
        byte[] sessionData = deferredSigningSession.Serialize();
        using RSA? rsa = fullCert.GetRSAPrivateKey();
        byte[] rawSignature = rsa!.SignData(deferredSigningPrepareResult.HashToSign, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        byte[] array = await DeferredSigner.CompleteAsync(sessionData, rawSignature);
        array.Should().NotBeEmpty("");
        using MemoryStream stream = new MemoryStream(array);
        (await ValidatorTrusting(fullCert).ValidateAsync(stream))[0].IsValid.Should().BeTrue("re-serialized session should produce valid signature");
    }

    [Fact(DisplayName = "Invalid signature produces invalid validation result")]
    public async Task CompleteAsync_InvalidSignature_ProducesInvalidResult()
    {
        using X509Certificate2 fullCert = CreateRsaCertWithPrivateKey();
        using X509Certificate2 publicCert = GetPublicCertOnly(fullCert);
        byte[] pdfBytes = BuildMinimalPdf();
        DeferredSigningPrepareResult deferredSigningPrepareResult = await DeferredSigner.PrepareAsync(pdfBytes, publicCert);
        byte[] array = new byte[256];
        Random.Shared.NextBytes(array);
        byte[] array2 = await DeferredSigner.CompleteAsync(deferredSigningPrepareResult.SessionData, array);
        array2.Should().NotBeEmpty("");
        using MemoryStream stream = new MemoryStream(array2);
        IReadOnlyList<SignatureValidationResult> readOnlyList = await ValidatorTrusting(fullCert).ValidateAsync(stream);
        readOnlyList.Should().ContainSingle("");
        readOnlyList[0].IsValid.Should().BeFalse("garbage signature should fail validation");
    }

    [Fact(DisplayName = "Empty signature is rejected")]
    public async Task CompleteAsync_EmptySignature_ThrowsArgumentException()
    {
        using X509Certificate2 fullCert = CreateRsaCertWithPrivateKey();
        using X509Certificate2 publicCert = GetPublicCertOnly(fullCert);
        byte[] pdfBytes = BuildMinimalPdf();
        DeferredSigningPrepareResult prepResult = await DeferredSigner.PrepareAsync(pdfBytes, publicCert);
        Func<Task<byte[]>> action = () => DeferredSigner.CompleteAsync(prepResult.SessionData, Array.Empty<byte>());
        await action.Should().ThrowAsync<ArgumentException>("", Array.Empty<object>()).WithMessage("*empty*", "");
    }

    [Fact(DisplayName = "Expired certificate is rejected at prepare phase")]
    public async Task PrepareAsync_ExpiredCert_ThrowsSigningException()
    {
        using RSA rsa = RSA.Create(2048);
        CertificateRequest certificateRequest = new CertificateRequest("CN=Expired", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        certificateRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, critical: false));
        X509Certificate2 x509Certificate = certificateRequest.CreateSelfSigned(DateTimeOffset.UtcNow.AddYears(-2), DateTimeOffset.UtcNow.AddDays(-1.0));
        X509Certificate2 expiredCert = CertificateLoader.LoadCertificate(x509Certificate.Export(X509ContentType.Cert));
        try
        {
            byte[] pdf = BuildMinimalPdf();
            Func<Task<DeferredSigningPrepareResult>> action = () => DeferredSigner.PrepareAsync(pdf, expiredCert);
            await action.Should().ThrowAsync<CertificateValidationException>("", Array.Empty<object>()).WithMessage("*expired*", "");
        }
        finally
        {
            if (expiredCert != null)
            {
                ((IDisposable)expiredCert).Dispose();
            }
        }
    }

    [Fact(DisplayName = "Null pdfBytes throws ArgumentNullException")]
    public async Task PrepareAsync_NullPdf_ThrowsArgumentNullException()
    {
        using X509Certificate2 cert = CreateRsaCertWithPrivateKey();
        X509Certificate2 publicCert = GetPublicCertOnly(cert);
        try
        {
            Func<Task<DeferredSigningPrepareResult>> action = () => DeferredSigner.PrepareAsync(null!, publicCert);
            await action.Should().ThrowAsync<ArgumentNullException>("", Array.Empty<object>());
        }
        finally
        {
            if (publicCert != null)
            {
                ((IDisposable)publicCert).Dispose();
            }
        }
    }

    [Fact(DisplayName = "Null certificate throws ArgumentNullException")]
    public async Task PrepareAsync_NullCert_ThrowsArgumentNullException()
    {
        Func<Task<DeferredSigningPrepareResult>> action = () => DeferredSigner.PrepareAsync(BuildMinimalPdf(), null!);
        await action.Should().ThrowAsync<ArgumentNullException>("", Array.Empty<object>());
    }

    [Fact(DisplayName = "Null sessionData throws ArgumentNullException")]
    public async Task CompleteAsync_NullSession_ThrowsArgumentNullException()
    {
        Func<Task<byte[]>> action = () => DeferredSigner.CompleteAsync(null!, new byte[1] { 1 });
        await action.Should().ThrowAsync<ArgumentNullException>("", Array.Empty<object>());
    }

    [Fact(DisplayName = "Deferred signing with metadata produces valid PDF")]
    public async Task PrepareAndComplete_WithMetadata_ProducesValidSignature()
    {
        using X509Certificate2 fullCert = CreateRsaCertWithPrivateKey();
        using X509Certificate2 publicCert = GetPublicCertOnly(fullCert);
        byte[] pdfBytes = BuildMinimalPdf();
        DeferredSigningOptions options = new DeferredSigningOptions
        {
            FieldOptions = new SignatureFieldOptions
            {
                SignerName = "André Almeida",
                Reason = "Aprovação",
                Location = "Vitória/ES"
            }
        };
        DeferredSigningPrepareResult deferredSigningPrepareResult = await DeferredSigner.PrepareAsync(pdfBytes, publicCert, options);
        using RSA? rsa = fullCert.GetRSAPrivateKey();
        byte[] rawSignature = rsa!.SignData(deferredSigningPrepareResult.HashToSign, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using MemoryStream stream = new MemoryStream(await DeferredSigner.CompleteAsync(deferredSigningPrepareResult.SessionData, rawSignature));
        (await ValidatorTrusting(fullCert).ValidateAsync(stream))[0].IsValid.Should().BeTrue("");
    }

    [Fact(DisplayName = "Full web flow: prepare on server, sign externally, complete on server")]
    public async Task FullWebFlow_PrepareSignComplete_ProducesValidPdf()
    {
        using X509Certificate2 fullCert = CreateRsaCertWithPrivateKey();
        using X509Certificate2 publicCert = GetPublicCertOnly(fullCert);
        byte[] pdfBytes = BuildMinimalPdf();
        DeferredSigningPrepareResult deferredSigningPrepareResult = await DeferredSigner.PrepareAsync(pdfBytes, publicCert);
        byte[] sessionData = deferredSigningPrepareResult.SessionData;
        byte[] hashToSign = deferredSigningPrepareResult.HashToSign;
        using RSA? rsa = fullCert.GetRSAPrivateKey();
        byte[] rawSignature = rsa!.SignData(hashToSign, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using MemoryStream stream = new MemoryStream(await DeferredSigner.CompleteAsync(sessionData, rawSignature));
        IReadOnlyList<SignatureValidationResult> readOnlyList = await ValidatorTrusting(fullCert).ValidateAsync(stream);
        readOnlyList.Should().ContainSingle("");
        readOnlyList[0].IsValid.Should().BeTrue("");
        readOnlyList[0].SignerCertificate?.Subject.Should().Contain("Deferred RSA Signer", "");
    }
}
