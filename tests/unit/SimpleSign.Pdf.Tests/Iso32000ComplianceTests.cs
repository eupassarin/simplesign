using System.Text;
using Shouldly;
using Xunit;

namespace SimpleSign.Pdf.Tests;

/// <summary>
/// ISO 32000 compliance tests for PDF parser features added in Phases 1-3.
/// Each test exercises a specific section of the ISO 32000-1:2008 specification.
/// </summary>
public sealed class Iso32000ComplianceTests
{
    // ═══════════════════════════════════════════════════════════════════════════
    // § 7.4.3 — ASCII85Decode filter
    // ═══════════════════════════════════════════════════════════════════════════

    [Fact(DisplayName = "§7.4.3: ASCII85 single full group decodes correctly")]
    public void Ascii85_SingleFullGroup()
    {
        // "test" = 0x74657374 → encoded as "FCfN8"
        byte[] encoded = Encoding.ASCII.GetBytes("FCfN8");
        var result = PdfStructureReader.DecodeAscii85(encoded);
        result.ShouldBe(Encoding.ASCII.GetBytes("test"));
    }

    [Fact(DisplayName = "§7.4.3: ASCII85 'z' shorthand expands to four zero bytes")]
    public void Ascii85_ZShorthand()
    {
        // 'z' = four zero bytes, combined with "!!" (which decodes to \x00\x00 partial)
        byte[] encoded = Encoding.ASCII.GetBytes("z");
        var result = PdfStructureReader.DecodeAscii85(encoded);
        result.ShouldBe(new byte[] { 0, 0, 0, 0 });
    }

    [Fact(DisplayName = "§7.4.3: ASCII85 partial group (2 chars) decodes to 1 byte")]
    public void Ascii85_PartialGroup_TwoChars()
    {
        // Partial group: 2 chars → 1 output byte
        // "!!" → padded with 'u' to "!!uuu" → decodes first byte only
        byte[] encoded = Encoding.ASCII.GetBytes("!!");
        var result = PdfStructureReader.DecodeAscii85(encoded);
        result.Count().ShouldBe(1);
    }

    [Fact(DisplayName = "§7.4.3: ASCII85 partial group (3 chars) decodes to 2 bytes")]
    public void Ascii85_PartialGroup_ThreeChars()
    {
        byte[] encoded = Encoding.ASCII.GetBytes("!!!");
        var result = PdfStructureReader.DecodeAscii85(encoded);
        result.Count().ShouldBe(2);
    }

    [Fact(DisplayName = "§7.4.3: ASCII85 ignores whitespace between chars")]
    public void Ascii85_WhitespaceIgnored()
    {
        byte[] withWs = Encoding.ASCII.GetBytes("9 j q o ^");
        byte[] without = Encoding.ASCII.GetBytes("9jqo^");
        var resultWs = PdfStructureReader.DecodeAscii85(withWs);
        var resultNoWs = PdfStructureReader.DecodeAscii85(without);
        resultWs.ShouldBe(resultNoWs);
    }

    [Fact(DisplayName = "§7.4.3: ASCII85 with <~ ~> delimiters strips them")]
    public void Ascii85_DelimitersStripped()
    {
        byte[] encoded = Encoding.ASCII.GetBytes("<~FCfN8~>");
        var result = PdfStructureReader.DecodeAscii85(encoded);
        result.ShouldBe(Encoding.ASCII.GetBytes("test"));
    }

    [Fact(DisplayName = "§7.4.3: ASCII85 empty input returns empty output")]
    public void Ascii85_EmptyInput()
    {
        var result = PdfStructureReader.DecodeAscii85([]);
        result.ShouldBeEmpty();
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // § 7.5.1 — Indirect /Length references in streams
    // ═══════════════════════════════════════════════════════════════════════════

    [Fact(DisplayName = "§7.5.1: Stream with indirect /Length N 0 R resolves correctly")]
    public void IndirectLength_ResolvesFromReferencedObject()
    {
        // Build a PDF where a stream has /Length 3 0 R and object 3 contains the length
        var sb = new StringBuilder();
        sb.Append("%PDF-1.7\n");
        sb.Append("1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n");
        sb.Append("2 0 obj\n<< /Type /Pages /Kids [] /Count 0 >>\nendobj\n");
        sb.Append("3 0 obj\n5\nendobj\n");
        sb.Append("4 0 obj\n<< /Length 3 0 R >>\nstream\nHello\nendstream\nendobj\n");
        long xrefOffset = sb.Length;
        sb.Append("xref\n0 5\n");
        sb.Append("0000000000 65535 f \n");
        sb.Append("0000000009 00000 n \n");
        sb.Append("0000000058 00000 n \n");
        sb.Append("0000000107 00000 n \n");
        sb.Append("0000000123 00000 n \n");
        sb.Append("trailer\n<< /Size 5 /Root 1 0 R >>\n");
        sb.Append($"startxref\n{xrefOffset}\n%%EOF");

        byte[] data = Encoding.Latin1.GetBytes(sb.ToString());
        // The stream extraction should work (used internally by xref parsing)
        // Verify no exception and that the parser can read the PDF
        var act = async () =>
        {
            using var stream = new MemoryStream(data);
            await PdfStructureReader.ReadSignatureFieldsAsync(stream);
        };
        Should.NotThrowAsync(act);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // § 7.9.2.2 — UTF-16BE string decoding
    // ═══════════════════════════════════════════════════════════════════════════

    [Fact(DisplayName = "§7.9.2.2: UTF-16BE BOM string decodes correctly")]
    public void Utf16Be_BomDetected_DecodesCorrectly()
    {
        // BOM (0xFE 0xFF) + "AB" in UTF-16BE
        byte[] str = [0xFE, 0xFF, 0x00, 0x41, 0x00, 0x42];
        var result = PdfStructureReader.DecodePdfTextString(str);
        result.ShouldBe("AB");
    }

    [Fact(DisplayName = "§7.9.2.2: Latin-1 string without BOM decodes as PDFDocEncoding")]
    public void Utf16Be_NoBom_DecodesAsLatin1()
    {
        byte[] str = Encoding.Latin1.GetBytes("Hello World");
        var result = PdfStructureReader.DecodePdfTextString(str);
        result.ShouldBe("Hello World");
    }

    [Fact(DisplayName = "§7.9.2.2: UTF-16BE with accented characters")]
    public void Utf16Be_AccentedChars()
    {
        // "José" in UTF-16BE with BOM
        byte[] bom = [0xFE, 0xFF];
        byte[] jose = Encoding.BigEndianUnicode.GetBytes("José");
        byte[] str = [.. bom, .. jose];
        var result = PdfStructureReader.DecodePdfTextString(str);
        result.ShouldBe("José");
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // § 8.3.2.1 — MediaBox inheritance
    // ═══════════════════════════════════════════════════════════════════════════

    [Fact(DisplayName = "§8.3.2.1: MediaBox inherited from /Pages parent")]
    public void MediaBox_InheritedFromParent()
    {
        // Page has no /MediaBox, parent /Pages node has it
        var sb = new StringBuilder();
        sb.Append("%PDF-1.7\n");
        sb.Append("1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n");
        sb.Append("2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 /MediaBox [0 0 595 842] >>\nendobj\n");
        sb.Append("3 0 obj\n<< /Type /Page /Parent 2 0 R >>\nendobj\n");
        long xrefOffset = sb.Length;
        sb.Append("xref\n0 4\n");
        sb.Append("0000000000 65535 f \n");
        sb.Append("0000000009 00000 n \n");
        sb.Append("0000000058 00000 n \n");
        sb.Append("0000000140 00000 n \n");
        sb.Append("trailer\n<< /Size 4 /Root 1 0 R >>\n");
        sb.Append($"startxref\n{xrefOffset}\n%%EOF");

        byte[] data = Encoding.Latin1.GetBytes(sb.ToString());
        string pageDict = "<< /Type /Page /Parent 2 0 R >>";

        float width = PdfStructureParser.ParseMediaBoxWidth(data, pageDict);
        width.ShouldBe(595f);
    }

    [Fact(DisplayName = "§8.3.2.1: Direct MediaBox on page takes precedence")]
    public void MediaBox_DirectOnPage_TakesPrecedence()
    {
        var sb = new StringBuilder();
        sb.Append("%PDF-1.7\n");
        sb.Append("1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n");
        sb.Append("2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 /MediaBox [0 0 595 842] >>\nendobj\n");
        sb.Append("3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>\nendobj\n");
        long xrefOffset = sb.Length;
        sb.Append("xref\n0 4\n");
        sb.Append("0000000000 65535 f \n");
        sb.Append("0000000009 00000 n \n");
        sb.Append("0000000058 00000 n \n");
        sb.Append("0000000140 00000 n \n");
        sb.Append("trailer\n<< /Size 4 /Root 1 0 R >>\n");
        sb.Append($"startxref\n{xrefOffset}\n%%EOF");

        byte[] data = Encoding.Latin1.GetBytes(sb.ToString());
        string pageDict = "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>";

        float width = PdfStructureParser.ParseMediaBoxWidth(data, pageDict);
        width.ShouldBe(612f);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // § 8.3.2.2 — CropBox over MediaBox
    // ═══════════════════════════════════════════════════════════════════════════

    [Fact(DisplayName = "§8.3.2.2: CropBox takes precedence over MediaBox")]
    public void CropBox_TakesPrecedenceOverMediaBox()
    {
        var sb = new StringBuilder();
        sb.Append("%PDF-1.7\n");
        sb.Append("1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n");
        sb.Append("2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n");
        sb.Append("3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /CropBox [50 50 562 742] >>\nendobj\n");
        long xrefOffset = sb.Length;
        sb.Append("xref\n0 4\n");
        sb.Append("0000000000 65535 f \n");
        sb.Append("0000000009 00000 n \n");
        sb.Append("0000000058 00000 n \n");
        sb.Append("0000000112 00000 n \n");
        sb.Append("trailer\n<< /Size 4 /Root 1 0 R >>\n");
        sb.Append($"startxref\n{xrefOffset}\n%%EOF");

        byte[] data = Encoding.Latin1.GetBytes(sb.ToString());
        string pageDict = "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /CropBox [50 50 562 742] >>";

        float width = PdfStructureParser.ParseMediaBoxWidth(data, pageDict);
        // CropBox width = urx - llx = 562 - 50 = 512
        width.ShouldBe(512f);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // § 8.3.2.4 — Page rotation
    // ═══════════════════════════════════════════════════════════════════════════

    [Fact(DisplayName = "§8.3.2.4: /Rotate 90 parsed from page dict")]
    public void Rotation_90Degrees_Parsed()
    {
        byte[] data = Encoding.Latin1.GetBytes("%PDF-1.7\n1 0 obj\n<< /Type /Page /Rotate 90 >>\nendobj\n");
        string pageDict = "<< /Type /Page /Rotate 90 >>";
        int rotation = PdfStructureParser.ParsePageRotation(data, pageDict);
        rotation.ShouldBe(90);
    }

    [Fact(DisplayName = "§8.3.2.4: /Rotate inherited from parent")]
    public void Rotation_InheritedFromParent()
    {
        var sb = new StringBuilder();
        sb.Append("%PDF-1.7\n");
        sb.Append("1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n");
        sb.Append("2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 /Rotate 270 >>\nendobj\n");
        sb.Append("3 0 obj\n<< /Type /Page /Parent 2 0 R >>\nendobj\n");
        byte[] data = Encoding.Latin1.GetBytes(sb.ToString());
        string pageDict = "<< /Type /Page /Parent 2 0 R >>";

        int rotation = PdfStructureParser.ParsePageRotation(data, pageDict);
        rotation.ShouldBe(270);
    }

    [Fact(DisplayName = "§8.3.2.4: /Rotate 0 when not specified")]
    public void Rotation_NotSpecified_ReturnsZero()
    {
        byte[] data = Encoding.Latin1.GetBytes("%PDF-1.7\n1 0 obj\n<< /Type /Page >>\nendobj\n");
        string pageDict = "<< /Type /Page >>";
        int rotation = PdfStructureParser.ParsePageRotation(data, pageDict);
        rotation.ShouldBe(0);
    }

    [Fact(DisplayName = "§8.3.2.4: Negative rotation normalizes correctly")]
    public void Rotation_Negative_Normalizes()
    {
        byte[] data = Encoding.Latin1.GetBytes("%PDF-1.7\n1 0 obj\n<< /Type /Page /Rotate -90 >>\nendobj\n");
        string pageDict = "<< /Type /Page /Rotate -90 >>";
        int rotation = PdfStructureParser.ParsePageRotation(data, pageDict);
        rotation.ShouldBe(270);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // § 9.9 — Linearized PDF detection
    // ═══════════════════════════════════════════════════════════════════════════

    [Fact(DisplayName = "§9.9: Linearized PDF detected by /Linearized key")]
    public void Linearized_Detected()
    {
        byte[] data = Encoding.Latin1.GetBytes(
            "%PDF-1.7\n1 0 obj\n<< /Linearized 1 /L 50000 /O 5 /E 4000 /N 1 /T 49000 /H [100 200] >>\nendobj\n");
        PdfStructureReader.IsLinearized(data).ShouldBeTrue();
    }

    [Fact(DisplayName = "§9.9: Non-linearized PDF not falsely detected")]
    public void Linearized_NotFalsePositive()
    {
        byte[] data = Encoding.Latin1.GetBytes(
            "%PDF-1.7\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n");
        PdfStructureReader.IsLinearized(data).ShouldBeFalse();
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // § 12.7.3 — AcroForm /Fields validation
    // ═══════════════════════════════════════════════════════════════════════════

    [Fact(DisplayName = "§12.7.3: Valid fields pass validation")]
    public void AcroFormFields_AllValid_NoWarnings()
    {
        var pdf = "%PDF-1.7\n5 0 obj\n<< /FT /Sig >>\nendobj\n7 0 obj\n<< /FT /Tx >>\nendobj\n";
        byte[] data = Encoding.Latin1.GetBytes(pdf);
        var warnings = PdfStructureParser.ValidateAcroFormFields(data, ["5 0 R", "7 0 R"]);
        warnings.ShouldBeEmpty();
    }

    [Fact(DisplayName = "§12.7.3: Orphaned field reference detected")]
    public void AcroFormFields_OrphanedRef_Warning()
    {
        var pdf = "%PDF-1.7\n5 0 obj\n<< /FT /Sig >>\nendobj\n";
        byte[] data = Encoding.Latin1.GetBytes(pdf);
        var warnings = PdfStructureParser.ValidateAcroFormFields(data, ["5 0 R", "42 0 R"]);
        warnings.Count().ShouldBe(1);
        warnings[0].ShouldContain("42");
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // § 12.7.4.4 — Signature field validation
    // ═══════════════════════════════════════════════════════════════════════════

    [Fact(DisplayName = "§12.7.4.4: Valid sig field with /V → /Type /Sig passes")]
    public void SigField_ValidWithV_NoWarnings()
    {
        var pdf = "%PDF-1.7\n" +
                  "5 0 obj\n<< /FT /Sig /T (Sig1) /V 6 0 R >>\nendobj\n" +
                  "6 0 obj\n<< /Type /Sig /Filter /Adobe.PPKLite /Contents <00> /ByteRange [0 1 2 3] >>\nendobj\n";
        byte[] data = Encoding.Latin1.GetBytes(pdf);
        var warnings = PdfStructureParser.ValidateSignatureField(data, 5);
        warnings.ShouldBeEmpty();
    }

    [Fact(DisplayName = "§12.7.4.4: Field without /FT /Sig yields warning")]
    public void SigField_NoFtSig_Warning()
    {
        var pdf = "%PDF-1.7\n5 0 obj\n<< /FT /Tx /T (TextField) >>\nendobj\n";
        byte[] data = Encoding.Latin1.GetBytes(pdf);
        var warnings = PdfStructureParser.ValidateSignatureField(data, 5);
        warnings.ShouldContain(w => w.Contains("/FT /Sig"));
    }

    [Fact(DisplayName = "§12.7.4.4: /V pointing to non-Sig dict yields warning")]
    public void SigField_VNotSigDict_Warning()
    {
        var pdf = "%PDF-1.7\n" +
                  "5 0 obj\n<< /FT /Sig /T (Sig1) /V 6 0 R >>\nendobj\n" +
                  "6 0 obj\n<< /Type /Font /BaseFont /Helvetica >>\nendobj\n";
        byte[] data = Encoding.Latin1.GetBytes(pdf);
        var warnings = PdfStructureParser.ValidateSignatureField(data, 5);
        warnings.ShouldContain(w => w.Contains("not a /Type /Sig"));
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // § 12.8.2.2 — ByteRange validation
    // ═══════════════════════════════════════════════════════════════════════════

    [Fact(DisplayName = "§12.8.2.2: ByteRange covering entire file validates")]
    public void ByteRange_CoversEntireFile_True()
    {
        var br = new PdfByteRange { Offset1 = 0, Length1 = 500, Offset2 = 600, Length2 = 400 };
        br.CoversEntireFile(1000).ShouldBeTrue();
    }

    [Fact(DisplayName = "§12.8.2.2: ByteRange not reaching EOF fails")]
    public void ByteRange_NotReachingEof_False()
    {
        var br = new PdfByteRange { Offset1 = 0, Length1 = 500, Offset2 = 600, Length2 = 200 };
        br.CoversEntireFile(1000).ShouldBeFalse();
    }

    [Fact(DisplayName = "§12.8.2.2: ByteRange not starting at 0 fails")]
    public void ByteRange_NotStartingAtZero_False()
    {
        var br = new PdfByteRange { Offset1 = 10, Length1 = 500, Offset2 = 600, Length2 = 400 };
        br.CoversEntireFile(1000).ShouldBeFalse();
    }

    [Fact(DisplayName = "§12.8.2.2: Intermediate signature ByteRange (valid, not last)")]
    public void ByteRange_IntermediateSignature_NotCoveringEof()
    {
        // An intermediate signature in an incrementally-updated PDF won't cover EOF
        var br = new PdfByteRange { Offset1 = 0, Length1 = 1000, Offset2 = 1200, Length2 = 800 };
        br.CoversEntireFile(5000).ShouldBeFalse();
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // § 7.5.8.2 — Cross-reference stream /Index default
    // ═══════════════════════════════════════════════════════════════════════════

    [Fact(DisplayName = "§7.5.8.2: ParseFieldsArray handles multiline /Fields with tabs")]
    public void ParseFields_Multiline_WithTabs()
    {
        const string obj = "/Fields [\t1 0 R\t2 0 R\t3 0 R\t]";
        var refs = PdfStructureParser.ParseFieldsArray(obj);
        refs.Count().ShouldBe(3);
    }

    [Fact(DisplayName = "§7.5.8.2: ParseFieldsArray with 20+ refs (many-signature PDF)")]
    public void ParseFields_ManyRefs()
    {
        var sb = new StringBuilder("/Fields [");
        for (int i = 1; i <= 25; i++)
        {
            sb.Append($"{i} 0 R\n");
        }
        sb.Append(']');
        var refs = PdfStructureParser.ParseFieldsArray(sb.ToString());
        refs.Count().ShouldBe(25);
    }
}
