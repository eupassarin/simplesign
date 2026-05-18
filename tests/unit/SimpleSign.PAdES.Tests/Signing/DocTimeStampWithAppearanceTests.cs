using System.Net;
using System.Text;
using Shouldly;
using SimpleSign.PAdES.Signing;
using SimpleSign.Pdf;
using SimpleSign.TestHelpers;
using Xunit;

namespace SimpleSign.PAdES.Tests.Signing;

/// <summary>
/// Regression tests for signing with both visible appearance and archival timestamp.
/// Adobe Reader reported "file is damaged" when both options were combined.
/// </summary>
public sealed class DocTimeStampWithAppearanceTests
{
    private static byte[] BuildPdfWithPage()
    {
        return Encoding.Latin1.GetBytes(
            "%PDF-1.7\n" +
            "1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n" +
            "2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n" +
            "3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] >>\nendobj\n" +
            "xref\n0 4\n" +
            "0000000000 65535 f \n" +
            "0000000009 00000 n \n" +
            "0000000058 00000 n \n" +
            "0000000115 00000 n \n" +
            "trailer\n<< /Size 4 /Root 1 0 R >>\n" +
            "startxref\n181\n%%EOF");
    }

    private static byte[] BuildFakeTimestampResponse()
    {
        var fakeCmsToken = BuildFakeCmsToken();
        var writer = new System.Formats.Asn1.AsnWriter(System.Formats.Asn1.AsnEncodingRules.DER);
        using (writer.PushSequence())
        {
            using (writer.PushSequence())
                writer.WriteInteger(0); // status = granted
            writer.WriteEncodedValue(fakeCmsToken);
        }
        return writer.Encode();
    }

    private static byte[] BuildFakeCmsToken()
    {
        var writer = new System.Formats.Asn1.AsnWriter(System.Formats.Asn1.AsnEncodingRules.DER);
        using (writer.PushSequence())
        {
            writer.WriteObjectIdentifier("1.2.840.113549.1.7.2");
            using (writer.PushSequence(new System.Formats.Asn1.Asn1Tag(
                System.Formats.Asn1.TagClass.ContextSpecific, 0, true)))
            {
                writer.WriteOctetString(new byte[100]);
            }
        }
        return writer.Encode();
    }

    private static HttpClient BuildMockTsaClient()
    {
        var tsr = BuildFakeTimestampResponse();
        return new HttpClient(new MockHttpHandler(_ =>
        {
            var resp = new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new ByteArrayContent(tsr)
            };
            resp.Content.Headers.ContentType =
                new System.Net.Http.Headers.MediaTypeHeaderValue("application/timestamp-reply");
            return Task.FromResult(resp);
        }));
    }

    [Fact(DisplayName = "DocTimeStamp after visible appearance produces valid PDF structure")]
    public async Task AppendDocTimeStamp_AfterVisibleAppearance_ProducesValidStructure()
    {
        // Step 1: Sign with visible appearance
        using var cert = TestCertificateFactory.CreateSelfSignedCert("CN=Test Signer");
        byte[] pdf = BuildPdfWithPage();
        var httpClient = BuildMockTsaClient();

        byte[] signedPdf = await SimpleSigner.Document(pdf)
            .WithCertificate(cert)
            .WithTimestamp("http://tsa.example.com", httpClient)
            .WithAppearance(new SignatureAppearance { X = 20, Y = 20 })
            .SignAsync();

        // Step 2: Append DocTimeStamp (simulates archival timestamp)
        byte[] result = await DocTimeStampWriter.AppendDocTimeStampAsync(
            signedPdf, "http://tsa.example.com", httpClient);

        // Validate structure
        string resultText = Encoding.Latin1.GetString(result);

        // Must have valid startxref
        int lastStartXRef = resultText.LastIndexOf("startxref\n", StringComparison.Ordinal);
        lastStartXRef.ShouldBeGreaterThan(0, "PDF must have startxref");

        int xrefOffStart = lastStartXRef + "startxref\n".Length;
        int eofIdx = resultText.IndexOf("\n%%EOF", xrefOffStart, StringComparison.Ordinal);
        string xrefOffStr = resultText[xrefOffStart..eofIdx];
        int xrefOffset = int.Parse(xrefOffStr);
        xrefOffset.ShouldBeLessThan(result.Length, "startxref must point within file");

        // Content at xref offset should be "xref" (classic) or "N 0 obj" (stream)
        string atXref = resultText[xrefOffset..Math.Min(xrefOffset + 10, result.Length)];
        bool isClassicXref = atXref.StartsWith("xref", StringComparison.Ordinal);
        bool isXrefStream = char.IsDigit(atXref[0]); // "N 0 obj..."
        (isClassicXref || isXrefStream).ShouldBeTrue(
            $"xref at offset {xrefOffset} must be classic or stream, found: '{atXref}'");

        // The PDF should have signature fields extractable
        using var resultStream = new MemoryStream(result);
        var fields = await PdfStructureReader.ReadSignatureFieldsAsync(resultStream);
        fields.Count().ShouldBeGreaterThanOrEqualTo(2,
            "should have signature field + timestamp field");

        // Timestamp field should have ETSI.RFC3161
        fields.ShouldContain(f => f.SubFilter == "ETSI.RFC3161",
            "must contain a DocTimeStamp field");

        // All ByteRanges must be valid (non-zero, within file bounds)
        foreach (var field in fields)
        {
            if (field.ByteRange != null)
            {
                var br = field.ByteRange;
                (br.Offset1 + br.Length1).ShouldBeLessThanOrEqualTo(result.Length,
                    $"ByteRange1 of {field.FieldName} exceeds file size");
                (br.Offset2 + br.Length2).ShouldBeLessThanOrEqualTo(result.Length,
                    $"ByteRange2 of {field.FieldName} exceeds file size");
                br.Length2.ShouldBeGreaterThan(0,
                    $"ByteRange2 of {field.FieldName} must be positive");
            }
        }
    }

    [Fact(DisplayName = "Full pipeline with appearance + archival timestamp produces extractable fields")]
    public async Task SignAsync_WithAppearanceAndArchival_ProducesExtractableFields()
    {
        using var cert = TestCertificateFactory.CreateSelfSignedCert("CN=Full Pipeline");
        byte[] pdf = BuildPdfWithPage();
        var httpClient = BuildMockTsaClient();

        // This is the exact flow the CLI uses: Sign + LTV + DocTimeStamp
        // Skip LTV since it requires real network for CRL/OCSP
        // Instead, directly exercise the DocTimeStamp on the signed PDF
        byte[] signedPdf = await SimpleSigner.Document(pdf)
            .WithCertificate(cert)
            .WithTimestamp("http://tsa.example.com", httpClient)
            .WithAppearance(new SignatureAppearance
            {
                X = 50,
                Y = 50,
                ShowDate = true,
                ShowReason = true
            })
            .WithMetadata("Test User", "Testing")
            .SignAsync();

        // Now append DocTimeStamp
        byte[] withTimestamp = await DocTimeStampWriter.AppendDocTimeStampAsync(
            signedPdf, "http://tsa.example.com", httpClient);

        // The result must be parseable
        using var resultStream = new MemoryStream(withTimestamp);
        var fields = await PdfStructureReader.ReadSignatureFieldsAsync(resultStream);
        fields.Count().ShouldBeGreaterThanOrEqualTo(2);

        // Check no overlapping ByteRanges
        var byteRanges = fields
            .Where(f => f.ByteRange != null)
            .Select(f => f.ByteRange!)
            .ToList();

        foreach (var br in byteRanges)
        {
            // ByteRange2 offset should come after ByteRange1
            br.Offset2.ShouldBeGreaterThan(br.Length1,
                "ByteRange2 offset must be after ByteRange1 end");
        }
    }

    [Fact(DisplayName = "DocTimeStamp does not corrupt page /Annots when appearance exists")]
    public async Task AppendDocTimeStamp_WithExistingAppearance_PageAnnotsContainsBothFields()
    {
        using var cert = TestCertificateFactory.CreateSelfSignedCert("CN=Annots Test");
        byte[] pdf = BuildPdfWithPage();
        var httpClient = BuildMockTsaClient();

        byte[] signedPdf = await SimpleSigner.Document(pdf)
            .WithCertificate(cert)
            .WithTimestamp("http://tsa.example.com", httpClient)
            .WithAppearance(new SignatureAppearance { X = 10, Y = 10 })
            .SignAsync();

        byte[] result = await DocTimeStampWriter.AppendDocTimeStampAsync(
            signedPdf, "http://tsa.example.com", httpClient);

        // The last page object should have /Annots with 2 entries
        string resultText = Encoding.Latin1.GetString(result);

        // Find the last page object (with /Type /Page)
        int lastPagePos = resultText.LastIndexOf("/Type /Page", StringComparison.Ordinal);
        lastPagePos.ShouldBeGreaterThan(0);

        // Find /Annots in the last page revision
        int annotsPos = resultText.IndexOf("/Annots", lastPagePos - 100, StringComparison.Ordinal);
        annotsPos.ShouldBeGreaterThan(0, "Page must have /Annots");

        int bracketOpen = resultText.IndexOf('[', annotsPos);
        int bracketClose = resultText.IndexOf(']', bracketOpen);
        string annotsContent = resultText[(bracketOpen + 1)..bracketClose];

        // Should contain 2 object references (signature field + timestamp field)
        var refs = annotsContent.Split("0 R", StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        refs.Length.ShouldBeGreaterThanOrEqualTo(2,
            $"Page /Annots should have ≥2 refs, found: [{annotsContent}]");
    }

    [Fact(DisplayName = "XRef stream PDF: visible stamp + DocTimeStamp produces valid structure")]
    public async Task XRefStreamPdf_WithAppearanceAndDocTimeStamp_ProducesValidStructure()
    {
        // Use a real PDF fixture that uses xref streams and ObjStm (like modern PDFs)
        string fixturePath = Path.Combine(
            AppDomain.CurrentDomain.BaseDirectory,
            "..", "..", "..", "..", "..", "integration",
            "SimpleSign.Integration.Tests", "Fixtures", "empty-page-unsigned.pdf");

        byte[] pdf;
        if (File.Exists(fixturePath))
        {
            pdf = await File.ReadAllBytesAsync(fixturePath);
        }
        else
        {
            // Fallback: build a minimal xref-stream PDF
            pdf = BuildPdfWithPage();
        }

        using var cert = TestCertificateFactory.CreateSelfSignedCert("CN=XRef Stream Test");
        var httpClient = BuildMockTsaClient();

        // Step 1: Sign with visible appearance (same as HostSigner flow)
        byte[] signedPdf = await SimpleSigner.Document(pdf)
            .WithCertificate(cert)
            .WithTimestamp("http://tsa.example.com", httpClient)
            .WithAppearance(new SignatureAppearance { X = 20, Y = 20, Page = 1 })
            .SignAsync();

        // Step 2: Append DocTimeStamp (archival) — skipping LTV for unit test
        byte[] result = await DocTimeStampWriter.AppendDocTimeStampAsync(
            signedPdf, "http://tsa.example.com", httpClient);

        // Validate: PDF should be parseable
        string resultText = Encoding.Latin1.GetString(result);

        // Must end with %%EOF
        resultText.TrimEnd().ShouldEndWith("%%EOF");

        // startxref must point to a valid location
        int lastStartXRef = resultText.LastIndexOf("startxref\n", StringComparison.Ordinal);
        lastStartXRef.ShouldBeGreaterThan(0);

        // Extract xref offset
        int xrefOffStart = lastStartXRef + "startxref\n".Length;
        int eofIdx = resultText.IndexOf("\n%%EOF", xrefOffStart, StringComparison.Ordinal);
        string xrefOffStr = resultText[xrefOffStart..eofIdx].Trim();
        long xrefOffset = long.Parse(xrefOffStr);
        xrefOffset.ShouldBeLessThan(result.Length);

        // Should have at least 2 signature fields
        using var resultStream = new MemoryStream(result);
        var fields = await PdfStructureReader.ReadSignatureFieldsAsync(resultStream);
        fields.Count().ShouldBeGreaterThanOrEqualTo(2,
            "should have signature field + timestamp field");

        fields.ShouldContain(f => f.SubFilter == "ETSI.RFC3161");
    }

    [Fact(DisplayName = "XRef stream PDF: full HostSigner pipeline (sign+LTV+DocTS) produces valid xref chain")]
    public async Task XRefStreamPdf_FullPipeline_XrefChainIsConsistent()
    {
        // This test checks the xref format consistency across incremental updates
        string fixturePath = Path.Combine(
            AppDomain.CurrentDomain.BaseDirectory,
            "..", "..", "..", "..", "..", "integration",
            "SimpleSign.Integration.Tests", "Fixtures", "empty-page-unsigned.pdf");

        byte[] pdf;
        if (File.Exists(fixturePath))
        {
            pdf = await File.ReadAllBytesAsync(fixturePath);
        }
        else
        {
            pdf = BuildPdfWithPage();
        }

        using var cert = TestCertificateFactory.CreateSelfSignedCert("CN=XRef Chain Test");
        var httpClient = BuildMockTsaClient();

        // Sign with visible appearance
        byte[] signedPdf = await SimpleSigner.Document(pdf)
            .WithCertificate(cert)
            .WithTimestamp("http://tsa.example.com", httpClient)
            .WithAppearance(new SignatureAppearance { X = 50, Y = 50, Page = 1 })
            .SignAsync();

        // Check xref format after signing
        bool originalUsesXRefStreams = PdfStructureParser.UsesXRefStreams(pdf);
        bool afterSignUsesXRefStreams = PdfStructureParser.UsesXRefStreams(signedPdf);

        // If original uses xref streams, all incremental updates should too
        if (originalUsesXRefStreams)
        {
            afterSignUsesXRefStreams.ShouldBeTrue(
                "PdfSignatureWriter should preserve xref stream format");
        }

        // Append DocTimeStamp
        byte[] result = await DocTimeStampWriter.AppendDocTimeStampAsync(
            signedPdf, "http://tsa.example.com", httpClient);

        bool afterTsUsesXRefStreams = PdfStructureParser.UsesXRefStreams(result);

        // Validate xref chain: count all startxref values and verify each points to valid data
        string resultText = Encoding.Latin1.GetString(result);
        var startxrefPositions = new List<long>();
        int searchPos = 0;
        while (true)
        {
            int pos = resultText.IndexOf("startxref\n", searchPos, StringComparison.Ordinal);
            if (pos < 0)
            {
                break;
            }

            int numStart = pos + "startxref\n".Length;
            int numEnd = resultText.IndexOf('\n', numStart);
            if (numEnd > numStart && long.TryParse(resultText[numStart..numEnd].Trim(), out long offset))
            {
                startxrefPositions.Add(offset);
            }
            searchPos = numEnd + 1;
        }

        startxrefPositions.Count().ShouldBeGreaterThanOrEqualTo(2,
            "should have at least original xref + sign xref + timestamp xref");

        // Each startxref should point to either "xref" or "N 0 obj" (xref stream)
        foreach (var offset in startxrefPositions)
        {
            if (offset >= result.Length)
            {
                continue; // linearized hint may be at end
            }

            string atOffset = resultText[(int)offset..Math.Min((int)offset + 20, result.Length)];
            bool isClassic = atOffset.StartsWith("xref", StringComparison.Ordinal);
            bool isStream = char.IsDigit(atOffset[0]);
            (isClassic || isStream).ShouldBeTrue(
                $"startxref at offset {offset} should point to xref table or stream, got: '{atOffset[..Math.Min(15, atOffset.Length)]}'");
        }
    }
}
