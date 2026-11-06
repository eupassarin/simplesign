using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Shouldly;
using SimpleSign.Core.Crypto;
using SimpleSign.Core.Signing;
using SimpleSign.Core.Validation;
using SimpleSign.PAdES.Signing;
using SimpleSign.PAdES.Validation;
using SimpleSign.TestHelpers;
using Xunit;
namespace SimpleSign.PAdES.Tests.Signing;

/// <summary>
/// Tests for the two-phase deferred signing API (<see cref="DeferredSigner" />).
/// Simulates the web scenario: server prepares → external signer signs → server completes.
/// </summary>
[Trait("Category", "Unit")]
public sealed class DeferredSignerTests
{


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

    private static X509Certificate2 GetPublicCertOnly(X509Certificate2 fullCert) => CertificateLoader.LoadCertificate(fullCert.Export(X509ContentType.Cert));

    private static PdfSignatureValidator ValidatorTrusting(params X509Certificate2[] certs)
    {
        return new PdfSignatureValidator(new ValidationOptions
        {
            CheckRevocation = false,
            TrustedRoots = [.. certs]
        });
    }

    [Fact(DisplayName = "Deferred signing with RSA produces valid PDF")]
    public async Task PrepareAndComplete_Rsa_ProducesValidSignature()
    {
        using X509Certificate2 fullCert = CreateRsaCertWithPrivateKey();
        using X509Certificate2 publicCert = GetPublicCertOnly(fullCert);
        byte[] pdf = TestPdfFactory.CreateMinimalPdf();
        DeferredSigningPrepareResult deferredSigningPrepareResult = await DeferredSigningEngineTestAdapter.PrepareAsync(pdf, publicCert);
        deferredSigningPrepareResult.HashToSign.ShouldNotBeEmpty("should contain DER-encoded signed attributes");
        deferredSigningPrepareResult.SessionData.ShouldNotBeEmpty("should contain serialized session");
        deferredSigningPrepareResult.DigestAlgorithm.ShouldBe("SHA256", "");
        deferredSigningPrepareResult.SignatureAlgorithmOid.ShouldNotBeNullOrEmpty("");
        using RSA? rsa = fullCert.GetRSAPrivateKey();
        byte[] rawSignature = rsa!.SignData(deferredSigningPrepareResult.HashToSign, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        byte[] array = await DeferredSigningEngineTestAdapter.CompleteAsync(deferredSigningPrepareResult.SessionData, rawSignature);
        array.ShouldNotBeEmpty("");
        array.Length.ShouldBeGreaterThan(pdf.Length, "");
        using MemoryStream stream = new MemoryStream(array);
        IReadOnlyList<SignatureValidationResult> readOnlyList = await ValidatorTrusting(fullCert).ValidateAsync(stream);
        readOnlyList.Count().ShouldBe(1, "");
        readOnlyList[0].Indication.ShouldBe(SignatureIndication.Valid, "deferred-signed PDF should be valid");
    }

    [Fact(DisplayName = "Deferred signing with ECDSA produces valid PDF")]
    public async Task PrepareAndComplete_Ecdsa_ProducesValidSignature()
    {
        using X509Certificate2 fullCert = CreateEcdsaCertWithPrivateKey();
        using X509Certificate2 publicCert = GetPublicCertOnly(fullCert);
        byte[] pdfBytes = TestPdfFactory.CreateMinimalPdf();
        DeferredSigningPrepareResult deferredSigningPrepareResult = await DeferredSigningEngineTestAdapter.PrepareAsync(pdfBytes, publicCert);
        using ECDsa? ecdsa = fullCert.GetECDsaPrivateKey();
        byte[] rawSignature = ecdsa!.SignData(deferredSigningPrepareResult.HashToSign, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);
        using MemoryStream stream = new MemoryStream(await DeferredSigningEngineTestAdapter.CompleteAsync(deferredSigningPrepareResult.SessionData, rawSignature));
        IReadOnlyList<SignatureValidationResult> readOnlyList = await ValidatorTrusting(fullCert).ValidateAsync(stream);
        readOnlyList.Count().ShouldBe(1, "");
        readOnlyList[0].Indication.ShouldBe(SignatureIndication.Valid, "ECDSA deferred-signed PDF should be valid");
    }

    [Fact(DisplayName = "Session serializes and deserializes correctly")]
    public async Task SessionData_RoundTrip_PreservesState()
    {
        using X509Certificate2 fullCert = CreateRsaCertWithPrivateKey();
        using X509Certificate2 publicCert = GetPublicCertOnly(fullCert);
        byte[] pdfBytes = TestPdfFactory.CreateMinimalPdf();
        DeferredSigningPrepareResult deferredSigningPrepareResult = await DeferredSigningEngineTestAdapter.PrepareAsync(pdfBytes, publicCert);
        DeferredSigningSession deferredSigningSession = DeferredSigningSession.Deserialize(
            deferredSigningPrepareResult.SessionData,
            DeferredSigningEngineTestAdapter.SessionIntegrityKey);
        deferredSigningSession.SignedAttributes.ShouldBe(deferredSigningPrepareResult.HashToSign, "");
        deferredSigningSession.DigestOid.ShouldNotBeNullOrEmpty("");
        deferredSigningSession.SignatureAlgorithmOid.ShouldNotBeNullOrEmpty("");
        deferredSigningSession.CertificateDer.ShouldBe(publicCert.RawData, "");
        deferredSigningSession.PreparedPdf.ShouldNotBeEmpty("");
        deferredSigningSession.ContentsReservedBytes.ShouldBeGreaterThan(0, "");
        byte[] sessionData = deferredSigningSession.Serialize(DeferredSigningEngineTestAdapter.SessionIntegrityKey);
        using RSA? rsa = fullCert.GetRSAPrivateKey();
        byte[] rawSignature = rsa!.SignData(deferredSigningPrepareResult.HashToSign, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        byte[] array = await DeferredSigningEngineTestAdapter.CompleteAsync(sessionData, rawSignature);
        array.ShouldNotBeEmpty("");
        using MemoryStream stream = new MemoryStream(array);
        (await ValidatorTrusting(fullCert).ValidateAsync(stream))[0].Indication.ShouldBe(SignatureIndication.Valid, "re-serialized session should produce valid signature");
    }

    [Fact(DisplayName = "Invalid signature is rejected before CMS packaging")]
    public async Task CompleteAsync_InvalidSignature_ThrowsStableSigningException()
    {
        using X509Certificate2 fullCert = CreateRsaCertWithPrivateKey();
        using X509Certificate2 publicCert = GetPublicCertOnly(fullCert);
        byte[] pdfBytes = TestPdfFactory.CreateMinimalPdf();
        DeferredSigningPrepareResult deferredSigningPrepareResult = await DeferredSigningEngineTestAdapter.PrepareAsync(pdfBytes, publicCert);
        byte[] array = new byte[256];
        Random.Shared.NextBytes(array);
        var exception = await Should.ThrowAsync<SigningException>(
            () => DeferredSigningEngineTestAdapter.CompleteAsync(deferredSigningPrepareResult.SessionData, array));
        exception.Reason.ShouldBe(SigningErrorReason.ExternalSignerReturnedInvalidSignature);
    }

    [Fact(DisplayName = "Empty signature is rejected")]
    public async Task CompleteAsync_EmptySignature_ThrowsArgumentException()
    {
        using X509Certificate2 fullCert = CreateRsaCertWithPrivateKey();
        using X509Certificate2 publicCert = GetPublicCertOnly(fullCert);
        byte[] pdfBytes = TestPdfFactory.CreateMinimalPdf();
        DeferredSigningPrepareResult prepResult = await DeferredSigningEngineTestAdapter.PrepareAsync(pdfBytes, publicCert);
        Func<Task<byte[]>> action = () => DeferredSigningEngineTestAdapter.CompleteAsync(prepResult.SessionData, []);
        var ex = await Should.ThrowAsync<ArgumentException>(async () => await action());
        ex.Message.ShouldContain("empty");
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
            byte[] pdf = TestPdfFactory.CreateMinimalPdf();
            Func<Task<DeferredSigningPrepareResult>> action = () => DeferredSigningEngineTestAdapter.PrepareAsync(pdf, expiredCert);
            var ex = await Should.ThrowAsync<SigningException>(async () => await action());
            ex.Reason.ShouldBe(SigningErrorReason.CertificateExpired);
            ex.Message.ShouldContain("expired");
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
            Func<Task<DeferredSigningPrepareResult>> action = () => DeferredSigningEngineTestAdapter.PrepareAsync(null!, publicCert);
            await Should.ThrowAsync<ArgumentNullException>(async () => await action());
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
        Func<Task<DeferredSigningPrepareResult>> action = () => DeferredSigningEngineTestAdapter.PrepareAsync(TestPdfFactory.CreateMinimalPdf(), null!);
        await Should.ThrowAsync<ArgumentNullException>(async () => await action());
    }

    [Fact(DisplayName = "Null sessionData throws ArgumentNullException")]
    public async Task CompleteAsync_NullSession_ThrowsArgumentNullException()
    {
        Func<Task<byte[]>> action = () => DeferredSigningEngineTestAdapter.CompleteAsync(null!, [1]);
        await Should.ThrowAsync<ArgumentNullException>(async () => await action());
    }

    [Fact(DisplayName = "Deferred signing with metadata produces valid PDF")]
    public async Task PrepareAndComplete_WithMetadata_ProducesValidSignature()
    {
        using X509Certificate2 fullCert = CreateRsaCertWithPrivateKey();
        using X509Certificate2 publicCert = GetPublicCertOnly(fullCert);
        byte[] pdfBytes = TestPdfFactory.CreateMinimalPdf();
        DeferredSigningOptions options = new DeferredSigningOptions
        {
            FieldOptions = new SignatureFieldOptions
            {
                SignerName = "André Almeida",
                Reason = "Aprovação",
                Location = "Vitória/ES"
            }
        };
        DeferredSigningPrepareResult deferredSigningPrepareResult = await DeferredSigningEngineTestAdapter.PrepareAsync(pdfBytes, publicCert, options);
        using RSA? rsa = fullCert.GetRSAPrivateKey();
        byte[] rawSignature = rsa!.SignData(deferredSigningPrepareResult.HashToSign, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using MemoryStream stream = new MemoryStream(await DeferredSigningEngineTestAdapter.CompleteAsync(deferredSigningPrepareResult.SessionData, rawSignature));
        (await ValidatorTrusting(fullCert).ValidateAsync(stream))[0].Indication.ShouldBe(SignatureIndication.Valid, "");
    }

    [Fact(DisplayName = "Full web flow: prepare on server, sign externally, complete on server")]
    public async Task FullWebFlow_PrepareSignComplete_ProducesValidPdf()
    {
        using X509Certificate2 fullCert = CreateRsaCertWithPrivateKey();
        using X509Certificate2 publicCert = GetPublicCertOnly(fullCert);
        byte[] pdfBytes = TestPdfFactory.CreateMinimalPdf();
        DeferredSigningPrepareResult deferredSigningPrepareResult = await DeferredSigningEngineTestAdapter.PrepareAsync(pdfBytes, publicCert);
        byte[] sessionData = deferredSigningPrepareResult.SessionData;
        byte[] hashToSign = deferredSigningPrepareResult.HashToSign;
        using RSA? rsa = fullCert.GetRSAPrivateKey();
        byte[] rawSignature = rsa!.SignData(hashToSign, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using MemoryStream stream = new MemoryStream(await DeferredSigningEngineTestAdapter.CompleteAsync(sessionData, rawSignature));
        IReadOnlyList<SignatureValidationResult> readOnlyList = await ValidatorTrusting(fullCert).ValidateAsync(stream);
        readOnlyList.Count().ShouldBe(1);
        readOnlyList[0].Indication.ShouldBe(SignatureIndication.Valid);
        readOnlyList[0].SignerCertificate?.Subject.ShouldContain("Deferred RSA Signer");
    }
}
