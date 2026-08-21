using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Shouldly;
using SimpleSign.Core.Crypto;
using SimpleSign.Core.Validation;
using SimpleSign.PAdES.Validation;
using SimpleSign.Pdf;
using SimpleSign.Pdf.Exceptions;
using Xunit;

namespace SimpleSign.PAdES.Tests.Validation;

/// <summary>
/// Tests for encrypted PDF detection and batch validation.
/// </summary>
[Trait("Category", "Unit")]
public sealed class EncryptedPdfAndBatchValidationTests
{
    private static X509Certificate2 CreateCert(string subject = "CN=EncryptedBatch Test")
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest(subject, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        req.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, false));
        var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        return CertificateLoader.LoadPkcs12(cert.Export(X509ContentType.Pkcs12, "test-export"), "test-export");
    }

    private static byte[] CreateMinimalPdf()
    {
        var sb = new StringBuilder();
        sb.AppendLine("%PDF-1.4");
        sb.AppendLine("1 0 obj <</Type /Catalog /Pages 2 0 R>> endobj");
        sb.AppendLine("2 0 obj <</Type /Pages /Kids [3 0 R] /Count 1>> endobj");
        sb.AppendLine("3 0 obj <</Type /Page /Parent 2 0 R /MediaBox [0 0 612 792]>> endobj");
        sb.AppendLine("xref");
        sb.AppendLine("0 4");
        sb.AppendLine("0000000000 65535 f ");
        sb.AppendLine("0000000009 00000 n ");
        sb.AppendLine("0000000058 00000 n ");
        sb.AppendLine("0000000115 00000 n ");
        sb.AppendLine("trailer <</Size 4 /Root 1 0 R>>");
        sb.AppendLine("startxref");
        sb.AppendLine("183");
        sb.AppendLine("%%EOF");
        return Encoding.ASCII.GetBytes(sb.ToString());
    }

    // ── Encrypted PDF detection ───────────────────────────────────────────

    [Fact(DisplayName = "Encrypted PDF throws EncryptedPdfException")]
    public async Task EncryptedPdf_ReadSignatureFields_ThrowsEncryptedPdfException()
    {
        // Create a fake encrypted PDF with /Encrypt in the trailer
        var pdf = Encoding.ASCII.GetBytes(
            "%PDF-1.4\n" +
            "1 0 obj <</Type /Catalog /Pages 2 0 R>> endobj\n" +
            "xref\n0 2\n0000000000 65535 f \n0000000009 00000 n \n" +
            "trailer <</Size 2 /Root 1 0 R /Encrypt 3 0 R>>\n" +
            "startxref\n57\n%%EOF");

        using var stream = new MemoryStream(pdf);
        var act = () => PdfStructureReader.ReadSignatureFieldsAsync(stream);

        await Should.ThrowAsync<EncryptedPdfException>(act);
    }

    [Fact(DisplayName = "Normal PDF is not detected as encrypted")]
    public async Task IsEncryptedAsync_NormalPdf_ReturnsFalse()
    {
        var pdf = CreateMinimalPdf();
        using var stream = new MemoryStream(pdf);

        var result = await PdfStructureReader.IsEncryptedAsync(stream);

        result.ShouldBeFalse();
    }

    [Fact(DisplayName = "Encrypted PDF is detected correctly")]
    public async Task IsEncryptedAsync_EncryptedPdf_ReturnsTrue()
    {
        var pdf = Encoding.ASCII.GetBytes(
            "%PDF-1.4\n" +
            "trailer <</Size 1 /Encrypt 2 0 R>>\n" +
            "startxref\n10\n%%EOF");
        using var stream = new MemoryStream(pdf);

        var result = await PdfStructureReader.IsEncryptedAsync(stream);

        result.ShouldBeTrue();
    }

    // ── Batch validation ──────────────────────────────────────────────────

    [Fact(DisplayName = "Batch validation with empty list returns empty")]
    public async Task ValidateBatchAsync_EmptyList_ReturnsEmpty()
    {
        var validator = new PdfSignatureValidator(new ValidationOptions { CheckRevocation = false });
        var items = new List<(Stream, string?)>();

        var results = await validator.ValidateBatchAsync(items);

        results.ShouldBeEmpty();
    }

    [Fact(DisplayName = "Batch validation returns result for each PDF")]
    public async Task ValidateBatchAsync_MultiplePdfs_ReturnsResultForEach()
    {
        using var cert = CreateCert();
        byte[] signedPdf = await PadesSigner.Document(CreateMinimalPdf())
            .WithCertificate(cert)
            .SignAsync();

        var items = new List<(Stream Stream, string? Identifier)>
        {
            (new MemoryStream(signedPdf), "doc1.pdf"),
            (new MemoryStream(signedPdf), "doc2.pdf"),
            (new MemoryStream(signedPdf), "doc3.pdf")
        };

        var validator = new PdfSignatureValidator(new ValidationOptions { CheckRevocation = false });
        var results = await validator.ValidateBatchAsync(items, maxConcurrency: 2);

        results.Count().ShouldBe(3);
        foreach (var r in results)
            r.IsProcessed.ShouldBeTrue();
        results.Select(r => r.Identifier).ShouldBe(["doc1.pdf", "doc2.pdf", "doc3.pdf"]);
    }

    [Fact(DisplayName = "Invalid PDF in batch returns error without throwing")]
    public async Task ValidateBatchAsync_InvalidPdf_ReturnsErrorNotException()
    {
        var items = new List<(Stream Stream, string? Identifier)>
        {
            (new MemoryStream("not a pdf"u8.ToArray()), "bad.pdf")
        };

        var validator = new PdfSignatureValidator(new ValidationOptions { CheckRevocation = false });
        var results = await validator.ValidateBatchAsync(items);

        results.Count().ShouldBe(1);
        results[0].IsProcessed.ShouldBeFalse();
        results[0].Error.ShouldNotBeNullOrEmpty();
        results[0].Identifier.ShouldBe("bad.pdf");
    }

    [Fact(DisplayName = "Invalid concurrency throws ArgumentOutOfRangeException")]
    public async Task ValidateBatchAsync_InvalidConcurrency_Throws()
    {
        var validator = new PdfSignatureValidator();

        var act = () => validator.ValidateBatchAsync([], maxConcurrency: 0);

        await Should.ThrowAsync<ArgumentOutOfRangeException>(act);
    }

    [Fact(DisplayName = "Batch validation preserves document index")]
    public async Task ValidateBatchAsync_PreservesIndex()
    {
        using var cert = CreateCert();
        byte[] signedPdf = await PadesSigner.Document(CreateMinimalPdf())
            .WithCertificate(cert)
            .SignAsync();

        var items = new List<(Stream Stream, string? Identifier)>
        {
            (new MemoryStream(signedPdf), "first"),
            (new MemoryStream(signedPdf), "second")
        };

        var validator = new PdfSignatureValidator(new ValidationOptions { CheckRevocation = false });
        var results = await validator.ValidateBatchAsync(items);

        results[0].Index.ShouldBe(0);
        results[0].Identifier.ShouldBe("first");
        results[1].Index.ShouldBe(1);
        results[1].Identifier.ShouldBe("second");
    }
}
