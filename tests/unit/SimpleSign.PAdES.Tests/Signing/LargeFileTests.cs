using System.Text;
using FluentAssertions;
using SimpleSign.Core.Validation;
using SimpleSign.PAdES.Signing;
using SimpleSign.PAdES.Validation;
using SimpleSign.TestHelpers;
using Xunit;

namespace SimpleSign.PAdES.Tests.Signing;

public sealed class LargeFileTests
{
    private static byte[] CreateMinimalPdf()
    {
        const string pdf = "%PDF-1.4\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n" +
                           "2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n" +
                           "3 0 obj<</Type/Page/MediaBox[0 0 612 792]/Parent 2 0 R>>endobj\n" +
                           "xref\n0 4\n0000000000 65535 f \n0000000009 00000 n \n0000000058 00000 n \n" +
                           "0000000107 00000 n \ntrailer<</Size 4/Root 1 0 R>>\nstartxref\n176\n%%EOF";
        return Encoding.ASCII.GetBytes(pdf);
    }

    private static byte[] CreateLargePdf(int targetSizeBytes)
    {
        // Build a PDF with many page objects to reach target size
        var sb = new StringBuilder();
        sb.Append("%PDF-1.4\n");
        sb.Append("1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n");

        var pageRefs = new List<string>();
        var objNum = 3;
        var pageCount = 0;

        // Add page objects until we reach the target size
        while (sb.Length < targetSizeBytes)
        {
            pageRefs.Add($"{objNum} 0 R");
            sb.Append($"{objNum} 0 obj<</Type/Page/MediaBox[0 0 612 792]/Parent 2 0 R/Contents {objNum + 1} 0 R>>endobj\n");
            objNum++;
            // Add a stream content object with padding to increase size
            var padding = new string('X', 512);
            sb.Append($"{objNum} 0 obj<</Length {padding.Length}>>stream\n{padding}\nendstream\nendobj\n");
            objNum++;
            pageCount++;
        }

        // Pages object
        var kidsArray = string.Join(" ", pageRefs);
        sb.Append($"2 0 obj<</Type/Pages/Kids[{kidsArray}]/Count {pageCount}>>endobj\n");

        // Cross-reference table
        var xrefOffset = sb.Length;
        sb.Append($"xref\n0 {objNum}\n");
        sb.Append("0000000000 65535 f \n");
        for (var i = 1; i < objNum; i++)
        {
            sb.Append($"{i:D10} 00000 n \n");
        }

        sb.Append($"trailer<</Size {objNum}/Root 1 0 R>>\n");
        sb.Append($"startxref\n{xrefOffset}\n%%EOF");

        return Encoding.ASCII.GetBytes(sb.ToString());
    }

    [Fact(DisplayName = "SimpleSigner signs large PDF successfully")]
    [Trait("Category", "LargeFile")]
    public async Task SimpleSigner_LargePdf_SignsSuccessfully()
    {
        using var cert = TestCertificateFactory.CreateSelfSignedCert("CN=LargeFile Test");
        var largePdf = CreateLargePdf(1_000_000); // ~1MB

        largePdf.Length.Should().BeGreaterThanOrEqualTo(1_000_000);

        var signed = await SimpleSigner.Document(largePdf).WithCertificate(cert).SignAsync();

        signed.Should().NotBeNullOrEmpty();
        signed.Length.Should().BeGreaterThan(largePdf.Length);
    }

    [Fact(DisplayName = "BatchSigner signs many documents successfully")]
    [Trait("Category", "LargeFile")]
    public async Task BatchSigner_ManyDocuments_AllSucceed()
    {
        using var cert = TestCertificateFactory.CreateSelfSignedCert("CN=LargeFile Test");
        await using var signer = BatchSigner.Create(cert)
            .WithMaxConcurrency(4)
            .Build();

        var results = new List<BatchSignResult>();
        await foreach (var result in signer.SignAllAsync(GenerateInputs(50)))
        {
            results.Add(result);
        }

        results.Should().HaveCount(50);
        results.Should().OnlyContain(r => r.IsSuccess);
        results.Should().OnlyContain(r => r.SignedPdf != null);
        signer.SuccessCount.Should().Be(50);
        signer.FailureCount.Should().Be(0);
    }

    [Fact(DisplayName = "Signed PDF can be validated")]
    [Trait("Category", "LargeFile")]
    public async Task SimpleSigner_SignedPdf_CanBeValidated()
    {
        using var cert = TestCertificateFactory.CreateSelfSignedCert("CN=LargeFile Test");
        var pdfBytes = CreateMinimalPdf();

        var signed = await SimpleSigner.Document(pdfBytes).WithCertificate(cert).SignAsync();

        using var stream = new MemoryStream(signed);
        var validator = new PdfSignatureValidator(new ValidationOptions
        {
            CheckRevocation = false,
            TrustedRoots = [cert]
        });

        var validationResults = await validator.ValidateAsync(stream);

        validationResults.Should().NotBeEmpty();
        validationResults[0].IsIntegrityValid.Should().BeTrue();
        validationResults[0].IsSignatureValid.Should().BeTrue();
    }

    private static async IAsyncEnumerable<(string Id, byte[] PdfBytes)> GenerateInputs(int count)
    {
        for (var i = 0; i < count; i++)
        {
            await Task.CompletedTask;
            yield return ($"doc-{i}", CreateMinimalPdf());
        }
    }
}
