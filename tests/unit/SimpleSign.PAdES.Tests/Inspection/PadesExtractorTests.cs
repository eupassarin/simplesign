using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Shouldly;
using SimpleSign.Core.Crypto;
using SimpleSign.PAdES.Inspection;
using SimpleSign.Pdf.Exceptions;
using Xunit;
namespace SimpleSign.PAdES.Tests.Inspection;

public sealed class PadesExtractorTests : IDisposable
{
    private readonly X509Certificate2 _cert;

    public PadesExtractorTests()
    {
        _cert = CreateRsaCert();
    }

    public void Dispose() => _cert.Dispose();

    // ── 1. Sign then extract — CMS is parseable ─────────────────────

    [Fact(DisplayName = "Extracted CMS signature is parseable by CmsParser")]
    public async Task ExtractAsync_SignedPdf_CmsIsParseable()
    {
        byte[] signed = await SignMinimalPdfAsync();

        var signatures = await PadesExtractor.ExtractAsync(signed);

        signatures.Count().ShouldBe(1);
        var sig = signatures[0];
        sig.CmsSignature.ShouldNotBeEmpty();
        sig.SignedData.ShouldNotBeEmpty();

        // CmsParser is internal but visible to tests
        var cms = CmsParser.Parse(sig.CmsSignature);
        cms.SignerCertificate.ShouldNotBeNull();
        cms.MessageDigest.ShouldNotBeNull();
    }

    // ── 2. Extracted signed data hash matches messageDigest ──────────

    [Fact(DisplayName = "SignedData SHA-256 matches CMS messageDigest")]
    public async Task ExtractAsync_SignedDataHash_MatchesCmsMessageDigest()
    {
        byte[] signed = await SignMinimalPdfAsync();

        var signatures = await PadesExtractor.ExtractAsync(signed);
        var sig = signatures[0];
        var cms = CmsParser.Parse(sig.CmsSignature);

        byte[] computedHash = SHA256.HashData(sig.SignedData);

        cms.MessageDigest.ShouldNotBeNull();
        computedHash.ShouldBe(cms.MessageDigest!);
    }

    // ── 4. Multiple signatures ───────────────────────────────────────

    [Fact(DisplayName = "Multiple signatures extracted from double-signed PDF")]
    public async Task ExtractAsync_DoubleSigned_ReturnsTwoSignatures()
    {
        byte[] firstSigned = await SignMinimalPdfAsync();
        byte[] doubleSigned = await SimpleSigner
            .Document(firstSigned)
            .WithCertificate(_cert)
            .SignAsync();

        var signatures = await PadesExtractor.ExtractAsync(doubleSigned);

        signatures.Count().ShouldBe(2);
        signatures[0].CmsSignature.ShouldNotBeEmpty();
        signatures[1].CmsSignature.ShouldNotBeEmpty();
        signatures[0].FieldName.ShouldNotBe(signatures[1].FieldName);
    }

    // ── 5. Field name preserved ──────────────────────────────────────

    [Fact(DisplayName = "FieldName is non-empty and consistent")]
    public async Task ExtractAsync_FieldName_IsNonEmptyAndConsistent()
    {
        byte[] signed = await SignMinimalPdfAsync();

        var signatures = await PadesExtractor.ExtractAsync(signed);

        signatures.Count().ShouldBe(1);
        signatures[0].FieldName.ShouldNotBeNullOrEmpty();
        signatures[0].FieldName.ShouldStartWith("Signature_");
    }

    // ── 6. SubFilter preserved ───────────────────────────────────────

    [Fact(DisplayName = "SubFilter is extracted (adbe.pkcs7.detached)")]
    public async Task ExtractAsync_SubFilter_IsExtracted()
    {
        byte[] signed = await SignMinimalPdfAsync();

        var signatures = await PadesExtractor.ExtractAsync(signed);

        signatures.Count().ShouldBe(1);
        signatures[0].SubFilter.ShouldNotBeNullOrEmpty();
        // PAdES always uses one of these sub-filters
        signatures[0].SubFilter.ShouldBeOneOf(
            "adbe.pkcs7.detached",
            "ETSI.CAdES.detached");
    }

    // ── 7. SaveSignatureAsync works ──────────────────────────────────

    [Fact(DisplayName = "SaveSignatureAsync writes correct .p7s content")]
    public async Task SaveSignatureAsync_WritesCorrectContent()
    {
        byte[] signed = await SignMinimalPdfAsync();
        var signatures = await PadesExtractor.ExtractAsync(signed);
        var sig = signatures[0];

        var tempPath = Path.Combine(
            Path.GetDirectoryName(typeof(PadesExtractorTests).Assembly.Location)!,
            $"test_save_{Guid.NewGuid():N}.p7s");
        try
        {
            await sig.SaveSignatureAsync(tempPath);

            byte[] savedBytes = await File.ReadAllBytesAsync(tempPath);
            savedBytes.ShouldBe(sig.CmsSignature);
        }
        finally
        {
            File.Delete(tempPath);
        }
    }

    // ── 8. SaveSignedDataAsync works ─────────────────────────────────

    [Fact(DisplayName = "SaveSignedDataAsync writes correct .bin content")]
    public async Task SaveSignedDataAsync_WritesCorrectContent()
    {
        byte[] signed = await SignMinimalPdfAsync();
        var signatures = await PadesExtractor.ExtractAsync(signed);
        var sig = signatures[0];

        var tempPath = Path.Combine(
            Path.GetDirectoryName(typeof(PadesExtractorTests).Assembly.Location)!,
            $"test_save_{Guid.NewGuid():N}.bin");
        try
        {
            await sig.SaveSignedDataAsync(tempPath);

            byte[] savedBytes = await File.ReadAllBytesAsync(tempPath);
            savedBytes.ShouldBe(sig.SignedData);
        }
        finally
        {
            File.Delete(tempPath);
        }
    }

    // ── 9. Empty/invalid PDF ─────────────────────────────────────────

    [Fact(DisplayName = "Invalid PDF throws PdfStructureException")]
    public async Task ExtractAsync_InvalidPdf_Throws()
    {
        byte[] garbage = "This is not a PDF"u8.ToArray();

        Func<Task> act = () => PadesExtractor.ExtractAsync(garbage);

        await Should.ThrowAsync<PdfStructureException>(act);
    }

    [Fact(DisplayName = "Unsigned PDF returns empty list")]
    public async Task ExtractAsync_UnsignedPdf_ReturnsEmptyList()
    {
        byte[] pdf = BuildMinimalPdf();

        var signatures = await PadesExtractor.ExtractAsync(pdf);

        signatures.ShouldBeEmpty();
    }

    // ── 10. Stream overload works ────────────────────────────────────

    [Fact(DisplayName = "Stream overload returns same results as byte array overload")]
    public async Task ExtractAsync_StreamOverload_ReturnsResults()
    {
        byte[] signed = await SignMinimalPdfAsync();

        using var stream = new MemoryStream(signed);
        var signatures = await PadesExtractor.ExtractAsync(stream);

        signatures.Count().ShouldBe(1);
        signatures[0].CmsSignature.ShouldNotBeEmpty();
        signatures[0].SignedData.ShouldNotBeEmpty();
    }

    // ── 11. File overload works ──────────────────────────────────────

    [Fact(DisplayName = "ExtractFromFileAsync works with a file on disk")]
    public async Task ExtractFromFileAsync_ReturnsResults()
    {
        byte[] signed = await SignMinimalPdfAsync();
        var tempPath = Path.Combine(
            Path.GetDirectoryName(typeof(PadesExtractorTests).Assembly.Location)!,
            $"test_extract_{Guid.NewGuid():N}.pdf");
        try
        {
            await File.WriteAllBytesAsync(tempPath, signed);

            var signatures = await PadesExtractor.ExtractFromFileAsync(tempPath);

            signatures.Count().ShouldBe(1);
            signatures[0].CmsSignature.ShouldNotBeEmpty();
        }
        finally
        {
            File.Delete(tempPath);
        }
    }

    // ── 12. PDF revision contains valid PDF ──────────────────────────

    [Fact(DisplayName = "PDF revision starts with %PDF- header")]
    public async Task ExtractAsync_PdfRevision_ContainsValidPdfHeader()
    {
        byte[] signed = await SignMinimalPdfAsync();

        var signatures = await PadesExtractor.ExtractAsync(signed);

        signatures.Count().ShouldBe(1);
        var revision = signatures[0].PdfRevision;
        revision.ShouldNotBeEmpty();
        Encoding.Latin1.GetString(revision, 0, 5).ShouldBe("%PDF-");
    }

    // ── 13. PDF revision size matches ByteRange ──────────────────────

    [Fact(DisplayName = "PDF revision length equals Offset2 + Length2")]
    public async Task ExtractAsync_PdfRevisionSize_MatchesByteRange()
    {
        byte[] signed = await SignMinimalPdfAsync();

        var signatures = await PadesExtractor.ExtractAsync(signed);

        signatures.Count().ShouldBe(1);
        var sig = signatures[0];
        long expectedLength = sig.ByteRange.Offset2 + sig.ByteRange.Length2;
        sig.PdfRevision.Length.ShouldBe((int)expectedLength);
    }

    // ── 14. Multiple signatures have different revision sizes ────────

    [Fact(DisplayName = "Double-signed PDF has increasing revision sizes")]
    public async Task ExtractAsync_DoubleSigned_IncreasingRevisionSizes()
    {
        byte[] firstSigned = await SignMinimalPdfAsync();
        byte[] doubleSigned = await SimpleSigner
            .Document(firstSigned)
            .WithCertificate(_cert)
            .SignAsync();

        var signatures = await PadesExtractor.ExtractAsync(doubleSigned);

        signatures.Count().ShouldBe(2);
        signatures[0].PdfRevision.Length.ShouldBeLessThan(signatures[1].PdfRevision.Length);
        signatures[1].PdfRevision.Length.ShouldBeLessThanOrEqualTo(doubleSigned.Length);
    }

    // ── 15. PDF revision is a valid standalone PDF ───────────────────

    [Fact(DisplayName = "PDF revision can be re-extracted as standalone PDF")]
    public async Task ExtractAsync_PdfRevision_IsValidStandalonePdf()
    {
        byte[] signed = await SignMinimalPdfAsync();

        var signatures = await PadesExtractor.ExtractAsync(signed);
        var revision = signatures[0].PdfRevision;

        // The revision itself should be a valid signed PDF that can be re-extracted
        var reExtracted = await PadesExtractor.ExtractAsync(revision);
        reExtracted.Count().ShouldBe(1);
        reExtracted[0].CmsSignature.ShouldNotBeEmpty();
    }

    // ── 16. SavePdfRevisionAsync works ───────────────────────────────

    [Fact(DisplayName = "SavePdfRevisionAsync writes correct PDF revision content")]
    public async Task SavePdfRevisionAsync_WritesCorrectContent()
    {
        byte[] signed = await SignMinimalPdfAsync();
        var signatures = await PadesExtractor.ExtractAsync(signed);
        var sig = signatures[0];

        var tempPath = Path.Combine(
            Path.GetDirectoryName(typeof(PadesExtractorTests).Assembly.Location)!,
            $"test_save_{Guid.NewGuid():N}.pdf");
        try
        {
            await sig.SavePdfRevisionAsync(tempPath);

            byte[] savedBytes = await File.ReadAllBytesAsync(tempPath);
            savedBytes.ShouldBe(sig.PdfRevision);
        }
        finally
        {
            File.Delete(tempPath);
        }
    }

    // ── Helpers ──────────────────────────────────────────────────────

    private async Task<byte[]> SignMinimalPdfAsync()
    {
        return await SimpleSigner
            .Document(BuildMinimalPdf())
            .WithCertificate(_cert)
            .SignAsync();
    }

    private static byte[] BuildMinimalPdf()
    {
        return Encoding.Latin1.GetBytes(
            "%PDF-1.7\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n" +
            "2 0 obj\n<< /Type /Pages /Kids [] /Count 0 >>\nendobj\nxref\n" +
            "0 3\n0000000000 65535 f \n0000000009 00000 n \n0000000058 00000 n \n" +
            "trailer\n<< /Size 3 /Root 1 0 R >>\nstartxref\n110\n%%EOF");
    }

    private static X509Certificate2 CreateRsaCert(string subject = "CN=PAdES Extractor Test, O=Tests")
    {
        using RSA key = RSA.Create(2048);
        var req = new CertificateRequest(
            subject, key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        req.CertificateExtensions.Add(
            new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, critical: false));
        X509Certificate2 cert = req.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        return CertificateLoader.LoadPkcs12(
            cert.Export(X509ContentType.Pfx, "test-export"), "test-export");
    }
}
