using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using FluentAssertions;
using SimpleSign.Core.Crypto;
using SimpleSign.Core.Validation;
using SimpleSign.PAdES.Signing;
using SimpleSign.PAdES.Validation;
using SimpleSign.Pdf;
using SimpleSign.Pdf.Enums;
using SimpleSign.Pdf.Exceptions;
using Xunit;
namespace SimpleSign.PAdES.Tests;

/// <summary>
/// Tests for public APIs without coverage.
/// Covers: SimpleSigner.Document(string), SignerBuilder.WithTimestamp(string, HttpClient),
/// PdfStructureReader, LtvEmbedder, BatchValidationResult, SignatureValidationResult,
/// EncryptedPdfException, and concurrent signing.
/// </summary>
public sealed class MissingCoverageTests
{
    private static byte[] BuildMinimalPdf()
    {
        return Encoding.Latin1.GetBytes("%PDF-1.7\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n2 0 obj\n<< /Type /Pages /Kids [] /Count 0 >>\nendobj\nxref\n0 3\n0000000000 65535 f \n0000000009 00000 n \n0000000058 00000 n \ntrailer\n<< /Size 3 /Root 1 0 R >>\nstartxref\n110\n%%EOF");
    }

    private static X509Certificate2 CreateRsaCert(string subject = "CN=Test RSA, O=Tests, C=BR")
    {
        using RSA key = RSA.Create(2048);
        CertificateRequest certificateRequest = new CertificateRequest(subject, key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        certificateRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, critical: false));
        X509Certificate2 x509Certificate = certificateRequest.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1.0), DateTimeOffset.UtcNow.AddYears(1));
        return CertificateLoader.LoadPkcs12(x509Certificate.Export(X509ContentType.Pfx, "test-export"), "test-export");
    }

    private static PdfSignatureValidator ValidatorTrusting(params X509Certificate2[] certs)
    {
        return new PdfSignatureValidator(new ValidationOptions
        {
            CheckRevocation = false,
            TrustedRoots = certs.ToList()
        });
    }

    [Fact(DisplayName = "DocumentAsync(string) with valid temp file returns builder")]
    public async Task DocumentAsync_ValidTempFilePath_ReturnsSignerBuilder()
    {
        string tempFile = Path.GetTempFileName();
        try
        {
            await File.WriteAllBytesAsync(tempFile, BuildMinimalPdf());
            (await SimpleSigner.DocumentAsync(tempFile)).Should().NotBeNull("");
        }
        finally
        {
            File.Delete(tempFile);
        }
    }

    [Fact(DisplayName = "DocumentAsync(string) with non-existent path throws FileNotFoundException")]
    public async Task DocumentAsync_NonExistentPath_ThrowsFileNotFoundException()
    {
        string fakePath = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString() + ".pdf");
        await Assert.ThrowsAsync<FileNotFoundException>(() => SimpleSigner.DocumentAsync(fakePath));
    }

    [Fact(DisplayName = "DocumentAsync(string) with empty string throws ArgumentException")]
    public async Task DocumentAsync_EmptyString_ThrowsArgumentException()
    {
        Func<Task<SignerBuilder>> action = () => SimpleSigner.DocumentAsync("");
        await action.Should().ThrowExactlyAsync<ArgumentException>("", Array.Empty<object>());
    }

    [Fact(DisplayName = "WithTimestamp(url, HttpClient) accepts custom HttpClient without error")]
    public void WithTimestamp_CustomHttpClient_BuildsWithoutError()
    {
        using HttpClient httpClient = new HttpClient();
        SignerBuilder actualValue = SimpleSigner.Document(BuildMinimalPdf()).WithTimestamp("http://tsa.example.com", httpClient);
        actualValue.Should().NotBeNull("");
    }

    [Fact(DisplayName = "IsDocMdpLockedAsync with unsigned PDF returns false")]
    public async Task IsDocMdpLockedAsync_UnsignedPdf_ReturnsFalse()
    {
        using MemoryStream stream = new MemoryStream(BuildMinimalPdf());
        (await PdfStructureReader.IsDocMdpLockedAsync(stream)).Should().BeFalse("");
    }

    [Fact(DisplayName = "IsDocMdpLockedAsync with NoChanges certification returns true")]
    public async Task IsDocMdpLockedAsync_CertificationNoChanges_ReturnsTrue()
    {
        using X509Certificate2 cert = CreateRsaCert();
        using MemoryStream stream = new MemoryStream(await SimpleSigner.Document(BuildMinimalPdf()).WithCertificate(cert).AsCertification(CertificationLevel.NoChanges)
            .SignAsync());
        (await PdfStructureReader.IsDocMdpLockedAsync(stream)).Should().BeTrue("");
    }

    [Fact(DisplayName = "IsDocMdpLockedAsync with regular signature (no certification) returns false")]
    public async Task IsDocMdpLockedAsync_RegularSignature_ReturnsFalse()
    {
        using X509Certificate2 cert = CreateRsaCert();
        using MemoryStream stream = new MemoryStream(await SimpleSigner.Document(BuildMinimalPdf()).WithCertificate(cert).SignAsync());
        (await PdfStructureReader.IsDocMdpLockedAsync(stream)).Should().BeFalse("");
    }

    [Fact(DisplayName = "DetectPdfALevelAsync with regular PDF returns PdfALevel.None")]
    public async Task DetectPdfALevelAsync_RegularPdf_ReturnsNone()
    {
        using MemoryStream stream = new MemoryStream(BuildMinimalPdf());
        (await PdfStructureReader.DetectPdfALevelAsync(stream)).Should().Be(PdfALevel.None, "");
    }

    [Fact(DisplayName = "DetectPdfALevelAsync works on signed PDF without error")]
    public async Task DetectPdfALevelAsync_SignedPdf_DoesNotThrow()
    {
        using X509Certificate2 cert = CreateRsaCert();
        using MemoryStream stream = new MemoryStream(await SimpleSigner.Document(BuildMinimalPdf()).WithCertificate(cert).SignAsync());
        (await PdfStructureReader.DetectPdfALevelAsync(stream)).Should().Be(PdfALevel.None, "");
    }

    [Fact(DisplayName = "ExtractSignatureContentHashes with signed PDF returns non-empty hex hash list")]
    public async Task ExtractSignatureContentHashes_SignedPdf_ReturnsNonEmptyList()
    {
        using X509Certificate2 cert = CreateRsaCert();
        List<string> list = LtvEmbedder.ExtractSignatureContentHashes(await SimpleSigner.Document(BuildMinimalPdf()).WithCertificate(cert).SignAsync());
        list.Should().NotBeEmpty("");
        list.Should().AllSatisfy(delegate (string h)
        {
            h.Should().NotBeNullOrWhiteSpace("");
            h.Should().MatchRegex("^[0-9A-F]+$", "");
        }, "");
    }

    [Fact(DisplayName = "ExtractSignatureContentHashes with unsigned PDF returns empty list")]
    public void ExtractSignatureContentHashes_UnsignedPdf_ReturnsEmptyList()
    {
        List<string> list = LtvEmbedder.ExtractSignatureContentHashes(BuildMinimalPdf());
        list.Should().BeEmpty("");
    }

    [Fact(DisplayName = "BatchValidationResult with non-null Results → IsProcessed is true")]
    public void BatchValidationResult_WithResults_IsProcessedTrue()
    {
        BatchValidationResult batchValidationResult = new BatchValidationResult
        {
            Index = 0,
            Identifier = "test.pdf",
            Results = new List<SignatureValidationResult>()
        };
        batchValidationResult.IsProcessed.Should().BeTrue("");
    }

    [Fact(DisplayName = "BatchValidationResult with Error → IsProcessed is false")]
    public void BatchValidationResult_WithError_IsProcessedFalse()
    {
        BatchValidationResult batchValidationResult = new BatchValidationResult
        {
            Index = 1,
            Identifier = "bad.pdf",
            Error = "Corrupted file"
        };
        batchValidationResult.IsProcessed.Should().BeFalse("");
    }

    [Fact(DisplayName = "BatchValidationResult without Results and without Error → IsProcessed is true")]
    public void BatchValidationResult_NullResultsNullError_IsProcessedTrue()
    {
        BatchValidationResult batchValidationResult = new BatchValidationResult
        {
            Index = 2,
            Results = null,
            Error = null
        };
        batchValidationResult.IsProcessed.Should().BeTrue("");
    }

    [Fact(DisplayName = "EmbeddedCertificates after self-signed PDF validation contains at least the signer certificate")]
    public async Task EmbeddedCertificates_SelfSignedPdf_ContainsSignerCert()
    {
        X509Certificate2 cert = CreateRsaCert();
        try
        {
            using MemoryStream stream = new MemoryStream(await SimpleSigner.Document(BuildMinimalPdf()).WithCertificate(cert).SignAsync());
            IReadOnlyList<SignatureValidationResult> readOnlyList = await ValidatorTrusting(cert).ValidateAsync(stream);
            readOnlyList.Should().ContainSingle("");
            readOnlyList[0].EmbeddedCertificates.Should().NotBeEmpty("");
            readOnlyList[0].EmbeddedCertificates.Should().Contain((X509Certificate2 c) => c.Thumbprint == cert.Thumbprint, "");
        }
        finally
        {
            if (cert != null)
            {
                ((IDisposable)cert).Dispose();
            }
        }
    }

    [Fact(DisplayName = "DigestAlgorithmName with SHA-256 OID returns 'SHA-256'")]
    public void DigestAlgorithmName_Sha256Oid_ReturnsSha256()
    {
        SignatureValidationResult signatureValidationResult = new SignatureValidationResult
        {
            DigestAlgorithmOid = "2.16.840.1.101.3.4.2.1"
        };
        signatureValidationResult.DigestAlgorithmName.Should().Be("SHA-256", "");
    }

    [Fact(DisplayName = "DigestAlgorithmName with null OID returns null")]
    public void DigestAlgorithmName_NullOid_ReturnsNull()
    {
        SignatureValidationResult signatureValidationResult = new SignatureValidationResult
        {
            DigestAlgorithmOid = null
        };
        signatureValidationResult.DigestAlgorithmName.Should().BeNull("");
    }

    [Fact(DisplayName = "EncryptedPdfException with message preserves Message")]
    public void EncryptedPdfException_WithMessage_PreservesMessage()
    {
        EncryptedPdfException ex = new EncryptedPdfException("PDF is encrypted");
        ex.Message.Should().Be("PDF is encrypted", "");
    }

    [Fact(DisplayName = "EncryptedPdfException with message and inner exception preserves InnerException")]
    public void EncryptedPdfException_WithInnerException_PreservesInnerException()
    {
        InvalidOperationException ex = new InvalidOperationException("detail");
        EncryptedPdfException ex2 = new EncryptedPdfException("PDF protected", ex);
        ex2.Message.Should().Be("PDF protected", "");
        ex2.InnerException.Should().BeSameAs(ex, "");
    }

    [Fact(DisplayName = "Parallel signing with two different certificates does not corrupt the PDF")]
    public async Task ConcurrentSigning_TwoCerts_BothSucceedWithoutCorruption()
    {
        using X509Certificate2 cert1 = CreateRsaCert("CN=Concurrent A, C=BR");
        using X509Certificate2 cert2 = CreateRsaCert("CN=Concurrent B, C=BR");
        byte[] pdfBytes = BuildMinimalPdf();
        Task<byte[]> task = SimpleSigner.Document(pdfBytes).WithCertificate(cert1).SignAsync();
        Task<byte[]> task2 = SimpleSigner.Document(pdfBytes).WithCertificate(cert2).SignAsync();
        byte[][] results = await Task.WhenAll(task, task2);
        results[0].Should().NotBeEmpty("");
        results[1].Should().NotBeEmpty("");
        using MemoryStream stream1 = new MemoryStream(results[0]);
        IReadOnlyList<SignatureValidationResult> readOnlyList = await ValidatorTrusting(cert1).ValidateAsync(stream1);
        readOnlyList.Should().ContainSingle("");
        readOnlyList[0].IsSignatureValid.Should().BeTrue("");
        using MemoryStream stream2 = new MemoryStream(results[1]);
        IReadOnlyList<SignatureValidationResult> readOnlyList2 = await ValidatorTrusting(cert2).ValidateAsync(stream2);
        readOnlyList2.Should().ContainSingle("");
        readOnlyList2[0].IsSignatureValid.Should().BeTrue("");
    }
}
