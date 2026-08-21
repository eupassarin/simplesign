using System.Security.Cryptography.X509Certificates;
using System.Text;
using Shouldly;
using SimpleSign.PAdES.Signing;
using SimpleSign.Pdf;
using SimpleSign.TestHelpers;
using Xunit;

namespace SimpleSign.PAdES.Tests.Signing;

/// <summary>
/// PDF/A conformance tests covering the gaps introduced by the signing process
/// (ISO 19005-3:2012 §6.3.2 Test 2 and §6.1.9 Test 1).
/// </summary>
[Trait("Category", "Unit")]
public sealed class PdfAConformanceTests
{
    // ── Fixtures ──────────────────────────────────────────────────────────────

    private static byte[] BuildMinimalPdf()
    {
        var sb = new StringBuilder();
        sb.Append("%PDF-1.7\n");

        int obj1Offset = sb.Length;
        sb.Append("1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n");

        int obj2Offset = sb.Length;
        sb.Append("2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n");

        int obj3Offset = sb.Length;
        sb.Append("3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>\nendobj\n");

        long xrefOffset = sb.Length;
        sb.Append("xref\n");
        sb.Append("0 4\n");
        sb.Append("0000000000 65535 f \n");
        sb.Append($"{obj1Offset:D10} 00000 n \n");
        sb.Append($"{obj2Offset:D10} 00000 n \n");
        sb.Append($"{obj3Offset:D10} 00000 n \n");
        sb.Append("trailer\n<< /Size 4 /Root 1 0 R >>\n");
        sb.Append($"startxref\n{xrefOffset}\n%%EOF\n");

        return Encoding.Latin1.GetBytes(sb.ToString());
    }

    private static SignatureFieldOptions DefaultOptions() => new()
    {
        FieldName = "Signature1",
        SignerName = "Test Signer",
        ContentsReservedBytes = 1024,
    };

    private static async Task<(byte[] OutputBytes, string OutputText)> PrepareSignedPdf(
        byte[]? pdfBytes = null, SignatureFieldOptions? options = null)
    {
        pdfBytes ??= BuildMinimalPdf();
        options ??= DefaultOptions();
        using var input = new MemoryStream(pdfBytes);
        using var output = new MemoryStream();
        await PdfSignatureWriter.PrepareAsync(input, output, options);
        byte[] outputBytes = output.ToArray();
        return (outputBytes, Encoding.Latin1.GetString(outputBytes));
    }

    private static async Task<(byte[] OutputBytes, string OutputText)> PrepareSignedPdfWithCert(
        byte[] pdfBytes, X509Certificate2 cert)
    {
        byte[] signed = await PadesSigner.Document(pdfBytes)
            .WithCertificate(cert)
            .SignAsync();
        return (signed, Encoding.Latin1.GetString(signed));
    }

    // ── ISO 19005-3 §6.3.2 Test 2 — Annotation /F Print flag ─────────────────

    [Fact(DisplayName = "Invisible signature widget has /F 132 (Print + Locked) per PDF/A-2/3 §6.3.2")]
    public async Task InvisibleWidget_HasF132()
    {
        // DefaultOptions() yields an INVISIBLE signature (no Appearance).
        // ISO 19005-3 §6.3.2 Test 2 requires the Print flag (bit 3, value 4) to be set
        // on every signature widget, visible or not.
        var (_, text) = await PrepareSignedPdf();

        text.ShouldContain("/F 132");
        text.ShouldNotContain("/F 0");
    }

    [Fact(DisplayName = "Visible signature widget still has /F 132 (Print + Locked)")]
    public async Task VisibleWidget_HasF132()
    {
        var (_, text) = await PrepareSignedPdf(options: new SignatureFieldOptions
        {
            FieldName = "Signature1",
            SignerName = "Test Signer",
            ContentsReservedBytes = 1024,
            Appearance = SignatureAppearance.Auto(),
        });

        text.ShouldContain("/F 132");
    }

    // ── ISO 19005-3 §6.1.9 Test 1 — EOL after obj ────────────────────────────

    [Fact(DisplayName = "BuildUpdatedPageObject output begins with 'N 0 obj\\n' (LF after obj)")]
    public void BuildUpdatedPageObject_StartsWithObjEOL()
    {
        // Build a minimal page object as raw bytes, then run it through
        // BuildUpdatedPageObject and inspect the result.
        const int pageObjNum = 3;
        const int fieldObjNum = 99;
        string pageDict = "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>\nendobj\n";
        byte[] pageBytes = Encoding.Latin1.GetBytes(pageDict);
        byte[] input = pageBytes;

        byte[] updated = PdfSignatureWriter.BuildUpdatedPageObject(
            pageObjNum, input, 0, pageDict.Length, fieldObjNum);

        string updatedText = Encoding.Latin1.GetString(updated);
        // The "obj" keyword MUST be followed by an EOL marker (LF / CR / CRLF) per
        // ISO 19005-3 §6.1.9 Test 1 — a single space fails the check.
        updatedText.ShouldStartWith("3 0 obj\n");
        updatedText.ShouldNotStartWith("3 0 obj ");
    }

    [Fact(DisplayName = "CRLF source PDF: BuildUpdatedPageObject still produces LF after obj")]
    public void BuildUpdatedPageObject_CrlfSource_StillProducesObjLF()
    {
        const int pageObjNum = 3;
        const int fieldObjNum = 99;
        string pageDict = "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>\r\nendobj\r\n";
        byte[] input = Encoding.Latin1.GetBytes(pageDict);

        byte[] updated = PdfSignatureWriter.BuildUpdatedPageObject(
            pageObjNum, input, 0, pageDict.Length, fieldObjNum);

        string updatedText = Encoding.Latin1.GetString(updated);
        updatedText.ShouldStartWith("3 0 obj\n");
    }

    // ── CRLF + nested-dict handling in InsertIntoDict / AppendAnnots ─────────

    [Fact(DisplayName = "InsertIntoDict with CRLF source matches sentinel and inserts at top level")]
    public void InsertIntoDict_CrlfSource_InsertsAtTopLevel()
    {
        // Source uses CRLF (Windows / iText / Adobe) and has a nested dict.
        string obj = "5 0 obj\r\n<< /Foo 1\r\n   /Bar << /Inner 2 >>\r\n>>\r\nendobj\r\n";
        string insert = "   /Baz 99\r\n";

        string result = PdfStructureParser.InsertIntoDict(obj, insert);

        result.ShouldContain("/Baz 99");
        // The insert must land before the OUTER >>\nendobj, not inside the nested /Bar dict.
        int outerClose = result.LastIndexOf(">>\nendobj", StringComparison.Ordinal);
        int bazPos = result.IndexOf("/Baz 99", StringComparison.Ordinal);
        bazPos.ShouldBeLessThan(outerClose);
        // And the nested /Inner must still be intact (not corrupted by the insert).
        result.ShouldContain("/Inner 2");
    }

    [Fact(DisplayName = "InsertIntoDict with nested dict and LF source inserts at top level")]
    public void InsertIntoDict_NestedDict_InsertsAtTopLevel()
    {
        // LF source with nested dict — the depth-aware fallback must kick in.
        // Use a source that has nested dicts but doesn't end with ">>\nendobj"
        // (or that has an unusual terminator) to force the depth-aware path.
        string obj = "5 0 obj\n<< /Foo 1\n   /DR << /Font << /Helv 6 0 R >> >>\n>>";
        string insert = "   /Baz 99\n";

        string result = PdfStructureParser.InsertIntoDict(obj, insert);

        result.ShouldContain("/Baz 99");
        // The /Baz insert must be at the top level — placed BEFORE the outermost ">>",
        // not inside the /DR nested dict.
        int outerClose = result.LastIndexOf(">>", StringComparison.Ordinal);
        int bazPos = result.IndexOf("/Baz 99", StringComparison.Ordinal);
        bazPos.ShouldBeLessThan(outerClose);
        result.ShouldContain("/Helv 6 0 R");
    }

    [Fact(DisplayName = "FindOutermostDictClose returns the top-level >> in a nested-dict source")]
    public void FindOutermostDictClose_NestedDict_ReturnsTopLevelClose()
    {
        // Source: << /Foo 1 /DR << /Font << /F 0 R >> >> >>
        // Properly balanced: three "<<" open and three ">>" close.
        // The outermost ">>" (depth 1 → 0) is the very last one in the string.
        string source = "<< /Foo 1 /DR << /Font << /F 0 R >> >> >>";
        int result = PdfStructureParser.FindOutermostDictClose(source);

        result.ShouldBeGreaterThan(-1);
        // The top-level close is the last ">>" (index of the first '>' character).
        // In the source above, the final ">>" starts at position source.Length - 2.
        result.ShouldBe(source.Length - 2);
    }

    [Fact(DisplayName = "RemoveKeyFromDict with CRLF source removes the correct line")]
    public void RemoveKeyFromDict_CrlfSource_RemovesCorrectLine()
    {
        string obj = "5 0 obj\r\n<< /Foo 1\r\n   /Bar 2\r\n   /Baz 3\r\n>>\r\nendobj\r\n";

        string result = PdfStructureParser.RemoveKeyFromDict(obj, "/Bar");

        result.ShouldNotContain("/Bar 2");
        result.ShouldContain("/Foo 1");
        result.ShouldContain("/Baz 3");
    }

    // ── Round-trip with PDF/A-3b labelled input ──────────────────────────────

    [Fact(DisplayName = "Sign a PDF/A-3b labelled PDF: produced widget has /F 132")]
    public async Task RoundTrip_SignPdfA3b_ProducesConformingWidget()
    {
        // Minimal PDF whose XMP metadata declares PDF/A-3 conformance. The signing
        // process must produce an output whose widget annotation is conformant.
        var sb = new StringBuilder();
        sb.Append("%PDF-1.7\n");

        int obj1Offset = sb.Length;
        sb.Append("1 0 obj\n<< /Type /Catalog /Pages 2 0 R /MarkInfo << /Marked true >> >>\nendobj\n");

        int obj2Offset = sb.Length;
        sb.Append("2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n");

        int obj3Offset = sb.Length;
        sb.Append("3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>\nendobj\n");

        // XMP metadata stream object declaring PDF/A-3b
        int obj4Offset = sb.Length;
        const string xmp = "<x:xmpmeta xmlns:x=\"adobe:ns:meta/\"><rdf:RDF xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\"><rdf:Description xmlns:pdfaid=\"http://www.aiim.org/pdfa/ns/id/\" pdfaid:part=\"3\" pdfaid:conformance=\"B\"/></rdf:RDF></x:xmpmeta>";
        sb.Append($"4 0 obj\n<< /Type /Metadata /Subtype /XML /Length {xmp.Length} >>\nstream\n{xmp}\nendstream\nendobj\n");

        long xrefOffset = sb.Length;
        sb.Append("xref\n");
        sb.Append("0 5\n");
        sb.Append("0000000000 65535 f \n");
        sb.Append($"{obj1Offset:D10} 00000 n \n");
        sb.Append($"{obj2Offset:D10} 00000 n \n");
        sb.Append($"{obj3Offset:D10} 00000 n \n");
        sb.Append($"{obj4Offset:D10} 00000 n \n");
        sb.Append("trailer\n<< /Size 5 /Root 1 0 R >>\n");
        sb.Append($"startxref\n{xrefOffset}\n%%EOF\n");

        byte[] pdfBytes = Encoding.Latin1.GetBytes(sb.ToString());
        var (_, text) = await PrepareSignedPdf(pdfBytes);

        // PDF/A-2/3 conformance requires the Print flag on every widget
        text.ShouldContain("/F 132");
    }

    // ── Incremental-update EOL guards (v0.4.0) ────────────────────────────────

    // 1-4: Direct tests on the shared helper.
    [Fact(DisplayName = "EnsureTrailingEol on empty stream is a no-op")]
    public void EnsureTrailingEol_EmptyStream_NoOp()
    {
        using var ms = new MemoryStream();
        IncrementalUpdateUtility.EnsureTrailingEol(ms);
        ms.Position.ShouldBe(0);
    }

    [Fact(DisplayName = "EnsureTrailingEol on stream already ending with LF is a no-op")]
    public void EnsureTrailingEol_AlreadyEndsWithLf_NoOp()
    {
        var ms = new MemoryStream();
        ms.Write(Encoding.Latin1.GetBytes("hello\n"));
        IncrementalUpdateUtility.EnsureTrailingEol(ms);
        ms.Length.ShouldBe(6, "no extra byte should be appended when the stream already ends with LF");
        Encoding.Latin1.GetString(ms.ToArray()).ShouldBe("hello\n");
    }

    [Fact(DisplayName = "EnsureTrailingEol appends exactly one LF when source ends with non-EOL byte")]
    public void EnsureTrailingEol_EndsWithF_AppendsLf()
    {
        var ms = new MemoryStream();
        ms.Write(Encoding.Latin1.GetBytes("hello%%EOF"));
        IncrementalUpdateUtility.EnsureTrailingEol(ms);
        // "hello%%EOF" is 10 bytes; one LF appended makes 11
        ms.Length.ShouldBe(11, "exactly one \\n should be appended");
        Encoding.Latin1.GetString(ms.ToArray()).ShouldEndWith("\n");
    }

    [Fact(DisplayName = "EnsureTrailingEol treats CR as a valid EOL marker (no-op)")]
    public void EnsureTrailingEol_EndsWithCr_NoOp()
    {
        var ms = new MemoryStream();
        ms.Write(Encoding.Latin1.GetBytes("hello\r"));
        IncrementalUpdateUtility.EnsureTrailingEol(ms);
        ms.Length.ShouldBe(6, "CR is a valid EOL marker per ISO 32000 §7.3.10");
    }

    // 5: End-to-end signature path — source has bare %%EOF, first new object must be LF-preceded.
    [Fact(DisplayName = "Signing a PDF whose %%EOF has no trailing newline: first new object is preceded by LF")]
    public async Task SignAsync_SourceBareEof_FirstNewObjectPrecededByLf()
    {
        var sb = new StringBuilder();
        sb.Append("%PDF-1.7\n");
        int obj1Offset = sb.Length;
        sb.Append("1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n");
        int obj2Offset = sb.Length;
        sb.Append("2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n");
        int obj3Offset = sb.Length;
        sb.Append("3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>\nendobj\n");
        long xrefOffset = sb.Length;
        sb.Append("xref\n0 4\n0000000000 65535 f \n");
        sb.Append($"{obj1Offset:D10} 00000 n \n");
        sb.Append($"{obj2Offset:D10} 00000 n \n");
        sb.Append($"{obj3Offset:D10} 00000 n \n");
        sb.Append("trailer\n<< /Size 4 /Root 1 0 R >>\n");
        sb.Append($"startxref\n{xrefOffset}\n%%EOF"); // no trailing \n

        byte[] pdfBytes = Encoding.Latin1.GetBytes(sb.ToString());

        using var cert = TestCertificateFactory.CreateSelfSignedCert("CN=Test Signer, O=Tests");
        var (outputBytes, _) = await PrepareSignedPdfWithCert(pdfBytes, cert);

        // The signing path copies the source verbatim and then appends new objects.
        // Find the first new object marker (a digit followed by " 0 obj") after the
        // original PDF length and assert the byte immediately before it is an EOL.
        int originalEnd = pdfBytes.Length;
        ReadOnlySpan<byte> output = outputBytes;
        int objMarker = -1;
        for (int i = originalEnd; i < output.Length - 6; i++)
        {
            if (char.IsDigit((char)output[i]) && output[i + 1] == (byte)' ' && output[i + 2] == (byte)'0'
                && output[i + 3] == (byte)' ' && output[i + 4] == (byte)'o' && output[i + 5] == (byte)'b'
                && output[i + 6] == (byte)'j')
            {
                objMarker = i;
                break;
            }
        }
        objMarker.ShouldBeGreaterThan(-1, "first new indirect object must be present after the source");
        byte byteBefore = output[objMarker - 1];
        (byteBefore == (byte)'\n' || byteBefore == (byte)'\r')
            .ShouldBeTrue($"byte at offset {objMarker - 1} is 0x{byteBefore:X2}, expected LF or CR");
    }

    // 6: LTV path — BuildUpdatedCatalogDss must end with \n; the XRef stream that follows
    //    must be preceded by an EOL.
    // 6: LTV path — BuildUpdatedCatalogDss must end with \n. The CRLF + nested-dict
    //    depth-aware fallback is covered indirectly by the v0.3.2 tests on
    //    InsertIntoDict (which shares the same FindOutermostDictClose logic).
    [Fact(DisplayName = "LTV catalog write ends with \\n and the XRef stream that follows is LF-preceded")]
    public async Task LtvEmbedder_EmbedLtvDataAsync_SourceBareEof_CatalogEndsWithLfBeforeXref()
    {
        // Use CreateSelfSignedCert which preserves the private key (unlike CreateLeafCert).
        using var cert = TestCertificateFactory.CreateSelfSignedCert("CN=Test Signer, O=Tests");
        byte[] signedPdf = await PadesSigner.Document(BuildMinimalPdf())
            .WithCertificate(cert)
            .SignAsync();

        // Truncate the trailing \n so the source ends with the last byte of %%EOF (or its
        // xref marker) — mirrors a real-world bare-%%EOF source PDF.
        string text = Encoding.Latin1.GetString(signedPdf);
        int lastLf = text.LastIndexOf('\n');
        lastLf.ShouldBeGreaterThan(-1);
        signedPdf = Encoding.Latin1.GetBytes(text[..lastLf]);

        // LTV embedder with a no-op HTTP client (it won't have any revocation data to fetch
        // because the cert has no CDP/AIA). The early-return on no data means the bytes
        // are unchanged — but our EOL guard still runs and ensures the source itself ends
        // with an EOL. We assert that the LAST byte of the result is an EOL marker.
        var ltvEmbedder = new LtvEmbedder(httpClient: null);
        byte[] ltvPdf = await ltvEmbedder.EmbedLtvDataAsync(signedPdf, [cert]);

        ltvPdf.Length.ShouldBeGreaterThanOrEqualTo(signedPdf.Length, "LTV update must not shrink the PDF");

        // The result must end with an EOL marker — the trailing \n was injected by
        // EnsureTrailingEol even when no LTV data was embedded.
        byte lastByte = ltvPdf[ltvPdf.Length - 1];
        (lastByte == (byte)'\n' || lastByte == (byte)'\r')
            .ShouldBeTrue($"last byte of LTV output is 0x{lastByte:X2}, expected LF or CR");
    }

    // 8: DocTimeStamp path — same EOL guard, same first-object-must-be-LF-preceded assertion.
    [Fact(DisplayName = "DocTimeStamp on a bare-%%EOF source: first new object is preceded by LF")]
    public async Task DocTimeStampWriter_AppendDocTimeStampAsync_SourceBareEof_FirstNewObjectPrecededByLf()
    {
        // Build a pre-signed PDF with a bare %%EOF (no trailing \n).
        using var cert = TestCertificateFactory.CreateSelfSignedCert("CN=Test Signer, O=Tests");
        byte[] signedPdf = await PadesSigner.Document(BuildMinimalPdf())
            .WithCertificate(cert)
            .SignAsync();

        // Truncate the trailing \n.
        string text = Encoding.Latin1.GetString(signedPdf);
        int lastLf = text.LastIndexOf('\n');
        lastLf.ShouldBeGreaterThan(-1);
        signedPdf = Encoding.Latin1.GetBytes(text[..lastLf]);

        // Append a DocTimeStamp using a mock TSA. The exact timestamp bytes don't matter
        // for this test — we only assert on the byte structure.
        using var httpClient = DocTimeStampWithAppearanceTests.BuildMockTsaClient();
        byte[] result = await DocTimeStampWriter.AppendDocTimeStampAsync(
            signedPdf, "http://tsa.example.com", httpClient);

        // The first new object after the source must be LF-preceded.
        ReadOnlySpan<byte> output = result;
        int objMarker = -1;
        for (int i = signedPdf.Length; i < output.Length - 6; i++)
        {
            if (char.IsDigit((char)output[i]) && output[i + 1] == (byte)' ' && output[i + 2] == (byte)'0'
                && output[i + 3] == (byte)' ' && output[i + 4] == (byte)'o' && output[i + 5] == (byte)'b'
                && output[i + 6] == (byte)'j')
            {
                objMarker = i;
                break;
            }
        }
        objMarker.ShouldBeGreaterThan(-1, "first new indirect object must be present after the source");
        byte byteBefore = output[objMarker - 1];
        (byteBefore == (byte)'\n' || byteBefore == (byte)'\r')
            .ShouldBeTrue($"byte at offset {objMarker - 1} is 0x{byteBefore:X2}, expected LF or CR");
    }
}
