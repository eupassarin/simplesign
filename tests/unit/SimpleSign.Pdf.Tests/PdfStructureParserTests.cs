using Shouldly;
using Xunit;

namespace SimpleSign.Pdf.Tests;

/// <summary>
/// Tests for PdfStructureParser helper methods.
/// </summary>
public sealed class PdfStructureParserTests
{
    [Fact]
    public void ParseFieldsArray_SpaceSeparated_ReturnsAllRefs()
    {
        const string obj = "5 0 obj\n<< /Fields [1 0 R 2 0 R 3 0 R] >>\nendobj\n";
        var refs = PdfStructureParser.ParseFieldsArray(obj);
        refs.ShouldBe(["1 0 R", "2 0 R", "3 0 R"]);
    }

    [Fact]
    public void ParseFieldsArray_NewlineSeparated_ReturnsAllRefs()
    {
        const string obj = "5 0 obj\n<< /Fields [1 0 R\n2 0 R\n3 0 R] >>\nendobj\n";
        var refs = PdfStructureParser.ParseFieldsArray(obj);
        refs.ShouldBe(["1 0 R", "2 0 R", "3 0 R"]);
    }

    [Fact]
    public void ParseFieldsArray_CrLfSeparated_ReturnsAllRefs()
    {
        const string obj = "5 0 obj\n<< /Fields [1 0 R\r\n2 0 R\r\n3 0 R] >>\nendobj\n";
        var refs = PdfStructureParser.ParseFieldsArray(obj);
        refs.ShouldBe(["1 0 R", "2 0 R", "3 0 R"]);
    }

    [Fact]
    public void ParseFieldsArray_TabSeparated_ReturnsAllRefs()
    {
        const string obj = "5 0 obj\n<< /Fields [1 0 R\t2 0 R\t3 0 R] >>\nendobj\n";
        var refs = PdfStructureParser.ParseFieldsArray(obj);
        refs.ShouldBe(["1 0 R", "2 0 R", "3 0 R"]);
    }

    [Fact]
    public void ParseFieldsArray_MixedWhitespace_ReturnsAllRefs()
    {
        const string obj = "5 0 obj\n<< /Fields [1 0 R \n 2 0 R\r\n\t3 0 R] >>\nendobj\n";
        var refs = PdfStructureParser.ParseFieldsArray(obj);
        refs.ShouldBe(["1 0 R", "2 0 R", "3 0 R"]);
    }

    [Fact]
    public void ParseFieldsArray_EmptyArray_ReturnsEmpty()
    {
        const string obj = "5 0 obj\n<< /Fields [] >>\nendobj\n";
        var refs = PdfStructureParser.ParseFieldsArray(obj);
        refs.ShouldBeEmpty();
    }

    [Fact]
    public void ParseFieldsArray_NoFields_ReturnsEmpty()
    {
        const string obj = "5 0 obj\n<< /Type /AcroForm >>\nendobj\n";
        var refs = PdfStructureParser.ParseFieldsArray(obj);
        refs.ShouldBeEmpty();
    }

    [Fact]
    public void ParseFieldsArray_ManyFields_ReturnsAll()
    {
        // Simulate a PDF with 22 signature fields across multiple lines
        var fieldsContent = string.Join("\n", Enumerable.Range(10, 22).Select(i => $"{i} 0 R"));
        var obj = $"5 0 obj\n<< /Fields [{fieldsContent}] >>\nendobj\n";
        var refs = PdfStructureParser.ParseFieldsArray(obj);
        refs.Count().ShouldBe(22);
        refs[0].ShouldBe("10 0 R");
        refs[21].ShouldBe("31 0 R");
    }

    [Fact]
    public void ExtractInlineAcroFormFields_InlineDict_ReturnsFields()
    {
        var pdf = "%PDF-1.7\n" +
                  "1 0 obj\n<< /Type /Catalog /AcroForm << /Fields [10 0 R 20 0 R] /SigFlags 3 >> >>\nendobj\n" +
                  "xref\n0 2\n0000000000 65535 f\r\n0000000009 00000 n\r\n" +
                  "trailer\n<< /Size 2 /Root 1 0 R >>\nstartxref\n109\n%%EOF\n";
        var data = System.Text.Encoding.Latin1.GetBytes(pdf);
        var refs = PdfStructureParser.ExtractInlineAcroFormFields(data, 1);
        refs.ShouldBe(["10 0 R", "20 0 R"]);
    }

    [Fact]
    public void ExtractInlineAcroFormFields_IndirectRef_ReturnsEmpty()
    {
        var pdf = "%PDF-1.7\n" +
                  "1 0 obj\n<< /Type /Catalog /AcroForm 5 0 R >>\nendobj\n" +
                  "xref\n0 2\n0000000000 65535 f\r\n0000000009 00000 n\r\n" +
                  "trailer\n<< /Size 2 /Root 1 0 R >>\nstartxref\n80\n%%EOF\n";
        var data = System.Text.Encoding.Latin1.GetBytes(pdf);
        var refs = PdfStructureParser.ExtractInlineAcroFormFields(data, 1);
        refs.ShouldBeEmpty();
    }

    // ── ASCII85 Decode Tests ─────────────────────────────────────────────────

    [Fact]
    public void DecodeAscii85_SimpleString_DecodesCorrectly()
    {
        // "Man " encoded in ASCII85 = "9jqo^"
        byte[] encoded = System.Text.Encoding.ASCII.GetBytes("9jqo^");
        var result = PdfStructureReader.DecodeAscii85(encoded);
        result.ShouldBe(System.Text.Encoding.ASCII.GetBytes("Man "));
    }

    [Fact]
    public void DecodeAscii85_WithDelimiters_DecodesCorrectly()
    {
        byte[] encoded = System.Text.Encoding.ASCII.GetBytes("<~9jqo^~>");
        var result = PdfStructureReader.DecodeAscii85(encoded);
        result.ShouldBe(System.Text.Encoding.ASCII.GetBytes("Man "));
    }

    [Fact]
    public void DecodeAscii85_ZShorthand_ProducesFourZeroBytes()
    {
        byte[] encoded = System.Text.Encoding.ASCII.GetBytes("<~z~>");
        var result = PdfStructureReader.DecodeAscii85(encoded);
        result.ShouldBe(new byte[] { 0, 0, 0, 0 });
    }

    [Fact]
    public void DecodeAscii85_WithWhitespace_IgnoresWhitespace()
    {
        byte[] encoded = System.Text.Encoding.ASCII.GetBytes("<~9jqo ^\r\n~>");
        var result = PdfStructureReader.DecodeAscii85(encoded);
        result.ShouldBe(System.Text.Encoding.ASCII.GetBytes("Man "));
    }

    [Fact]
    public void DecodeAscii85_PartialGroup_DecodesCorrectly()
    {
        // "Ma" = 2 bytes, encoded as "9jq" (3 chars, partial group)
        byte[] encoded = System.Text.Encoding.ASCII.GetBytes("<~9jq~>");
        var result = PdfStructureReader.DecodeAscii85(encoded);
        result.ShouldBe(System.Text.Encoding.ASCII.GetBytes("Ma"));
    }

    [Fact]
    public void DecodeAscii85_Empty_ReturnsEmpty()
    {
        byte[] encoded = System.Text.Encoding.ASCII.GetBytes("<~~>");
        var result = PdfStructureReader.DecodeAscii85(encoded);
        result.ShouldBeEmpty();
    }

    [Fact]
    public void DecodeAscii85_LongerText_DecodesCorrectly()
    {
        // Known test vector: "Man is distinguished..." (from Wikipedia)
        string input = "Man is distinguished, not only by his reason, but by this singular passion from other animals, which is a lust of the mind, that by a perseverance of delight in the continued and indefatigable generation of knowledge, exceeds the short vehemence of any carnal pleasure.";
        string encoded85 = "9jqo^BlbD-BleB1DJ+*+F(f,q/0JhKF<GL>Cj@.4Gp$d7F!,L7@<6@)/0JDEF<G%<+EV:2F!,O<DJ+*.@<*K0@<6L(Df-\\0Ec5e;DffZ(EZee.Bl.9pF\"AGXBPCsi+DGm>@3BB/F*&OCAfu2/AKYi(DIb:@FD,*)+C]U=@3BN#EcYf8ATD3s@q?d$AftVqCh[NqF<G:8+EV:.+Cf>-FD5W8ARlolDIal(DId<j@<?3r@:F%a+D58'ATD4$Bl@l3De:,-DJs`8ARoFb/0JMK@qB4^F!,R<AKZ&-DfTqBG%G>uD.RTpAKYo'+CT/5+Cei#DII?(E,9)oF*2M7/c";
        byte[] encodedBytes = System.Text.Encoding.ASCII.GetBytes(encoded85);
        var result = PdfStructureReader.DecodeAscii85(encodedBytes);
        System.Text.Encoding.ASCII.GetString(result).ShouldBe(input);
    }

    // ── Linearized Detection Tests ──────────────────────────────────────────

    [Fact]
    public void IsLinearized_WithLinearizedDict_ReturnsTrue()
    {
        var pdf = "%PDF-1.7\n1 0 obj\n<< /Linearized 1 /L 12345 /O 5 /E 1000 /N 1 /T 12000 /H [100 200] >>\nendobj\n"u8;
        PdfStructureReader.IsLinearized(pdf).ShouldBeTrue();
    }

    [Fact]
    public void IsLinearized_NormalPdf_ReturnsFalse()
    {
        var pdf = "%PDF-1.7\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"u8;
        PdfStructureReader.IsLinearized(pdf).ShouldBeFalse();
    }

    // ── Signature Field Validation Tests ────────────────────────────────────

    [Fact]
    public void ValidateSignatureField_ValidField_ReturnsNoWarnings()
    {
        var pdf = "%PDF-1.7\n" +
                  "5 0 obj\n<< /FT /Sig /T (Signature1) /V 6 0 R >>\nendobj\n" +
                  "6 0 obj\n<< /Type /Sig /Filter /Adobe.PPKLite /SubFilter /adbe.pkcs7.detached /ByteRange [0 100 200 300] /Contents <0000> >>\nendobj\n";
        var data = System.Text.Encoding.Latin1.GetBytes(pdf);
        var warnings = PdfStructureParser.ValidateSignatureField(data, 5);
        warnings.ShouldBeEmpty();
    }

    [Fact]
    public void ValidateSignatureField_MissingFtSig_ReturnsWarning()
    {
        var pdf = "%PDF-1.7\n5 0 obj\n<< /FT /Tx /T (TextField1) >>\nendobj\n";
        var data = System.Text.Encoding.Latin1.GetBytes(pdf);
        var warnings = PdfStructureParser.ValidateSignatureField(data, 5);
        warnings.ShouldContain(w => w.Contains("/FT /Sig"));
    }

    [Fact]
    public void ValidateSignatureField_OrphanedVRef_ReturnsWarning()
    {
        var pdf = "%PDF-1.7\n5 0 obj\n<< /FT /Sig /T (Sig1) /V 99 0 R >>\nendobj\n";
        var data = System.Text.Encoding.Latin1.GetBytes(pdf);
        var warnings = PdfStructureParser.ValidateSignatureField(data, 5);
        warnings.ShouldContain(w => w.Contains("99") && w.Contains("does not exist"));
    }

    [Fact]
    public void ValidateSignatureField_ObjectNotFound_ReturnsWarning()
    {
        var pdf = "%PDF-1.7\n1 0 obj\n<< /Type /Catalog >>\nendobj\n";
        var data = System.Text.Encoding.Latin1.GetBytes(pdf);
        var warnings = PdfStructureParser.ValidateSignatureField(data, 99);
        warnings.ShouldContain(w => w.Contains("99") && w.Contains("not found"));
    }

    // ── AcroForm Fields Validation Tests ────────────────────────────────────

    [Fact]
    public void ValidateAcroFormFields_AllExist_ReturnsNoWarnings()
    {
        var pdf = "%PDF-1.7\n" +
                  "5 0 obj\n<< /FT /Sig >>\nendobj\n" +
                  "6 0 obj\n<< /FT /Sig >>\nendobj\n";
        var data = System.Text.Encoding.Latin1.GetBytes(pdf);
        var warnings = PdfStructureParser.ValidateAcroFormFields(data, ["5 0 R", "6 0 R"]);
        warnings.ShouldBeEmpty();
    }

    [Fact]
    public void ValidateAcroFormFields_OrphanedRef_ReturnsWarning()
    {
        var pdf = "%PDF-1.7\n5 0 obj\n<< /FT /Sig >>\nendobj\n";
        var data = System.Text.Encoding.Latin1.GetBytes(pdf);
        var warnings = PdfStructureParser.ValidateAcroFormFields(data, ["5 0 R", "99 0 R"]);
        warnings.Count().ShouldBe(1);
        warnings[0].ShouldContain("99");
        warnings[0].ShouldContain("orphaned");
    }

    [Fact]
    public void ValidateAcroFormFields_EmptyList_ReturnsNoWarnings()
    {
        var pdf = "%PDF-1.7\n1 0 obj\n<< >>\nendobj\n";
        var data = System.Text.Encoding.Latin1.GetBytes(pdf);
        var warnings = PdfStructureParser.ValidateAcroFormFields(data, []);
        warnings.ShouldBeEmpty();
    }

    // ── ByteRange Validation Tests ──────────────────────────────────────────

    [Fact]
    public void CoversEntireFile_ExactCoverage_ReturnsTrue()
    {
        var br = new PdfByteRange { Offset1 = 0, Length1 = 100, Offset2 = 200, Length2 = 300 };
        br.CoversEntireFile(500).ShouldBeTrue();
    }

    [Fact]
    public void CoversEntireFile_NotFullCoverage_ReturnsFalse()
    {
        var br = new PdfByteRange { Offset1 = 0, Length1 = 100, Offset2 = 200, Length2 = 100 };
        br.CoversEntireFile(500).ShouldBeFalse();
    }

    [Fact]
    public void ExtractFieldsFromCompressedAcroForm_FindsFieldsInObjStm()
    {
        // Build a synthetic PDF with an ObjStm containing an AcroForm (object 50)
        // ObjStm header: "50 0 51 120\n" means obj 50 starts at offset 0, obj 51 at offset 120
        // Object 50 data: "<< /Fields [10 0 R 20 0 R 30 0 R] /SigFlags 3 >>"
        string objData50 = "<< /Fields [10 0 R 20 0 R 30 0 R] /SigFlags 3 >>";
        string objData51 = "<< /Type /Page /MediaBox [0 0 612 792] >>";
        string header = $"50 0 51 {objData50.Length}\n";
        string uncompressed = header + objData50 + objData51;
        byte[] uncompressedBytes = System.Text.Encoding.Latin1.GetBytes(uncompressed);

        // Compress with zlib (2-byte header + deflate)
        byte[] compressed;
        using (var ms = new System.IO.MemoryStream())
        {
            // zlib header: CMF=0x78 (deflate, window=32K), FLG=0x01 (no dict, check)
            ms.WriteByte(0x78);
            ms.WriteByte(0x01);
            using (var deflate = new System.IO.Compression.DeflateStream(ms, System.IO.Compression.CompressionLevel.Fastest, leaveOpen: true))
            {
                deflate.Write(uncompressedBytes);
            }
            compressed = ms.ToArray();
        }

        // Build the ObjStm object
        string objStmDict = $"100 0 obj\n<< /Type /ObjStm /N 2 /First {header.Length} /Filter /FlateDecode /Length {compressed.Length} >>\nstream\n";
        string objStmEnd = "\nendstream\nendobj\n";

        // Build minimal PDF with header, the ObjStm, and a trailer
        string pdfHeader = "%PDF-1.7\n";
        byte[] pdfBytes = System.Text.Encoding.Latin1.GetBytes(pdfHeader + objStmDict)
            .Concat(compressed)
            .Concat(System.Text.Encoding.Latin1.GetBytes(objStmEnd))
            .ToArray();

        // Act
        var fields = PdfStructureParser.ExtractFieldsFromCompressedAcroForm(pdfBytes, 50);

        // Assert
        fields.ShouldBe(["10 0 R", "20 0 R", "30 0 R"]);
    }

    [Fact]
    public void ExtractFieldsFromCompressedAcroForm_ReturnsEmptyWhenObjectNotInObjStm()
    {
        // Build a minimal PDF with no ObjStm containing the target object
        byte[] pdfBytes = System.Text.Encoding.Latin1.GetBytes("%PDF-1.7\n1 0 obj\n<< /Type /Catalog >>\nendobj\n");

        var fields = PdfStructureParser.ExtractFieldsFromCompressedAcroForm(pdfBytes, 999);
        fields.ShouldBeEmpty();
    }

    [Fact]
    public void ResolveIndirectFields_ResolvesIndirectFieldsReference()
    {
        // AcroForm has /Fields 50 0 R (indirect reference to array object)
        string pdf = "%PDF-1.7\n" +
                     "50 0 obj\n[10 0 R 20 0 R 30 0 R]\nendobj\n" +
                     "5 0 obj\n<< /Type /AcroForm /Fields 50 0 R /SigFlags 3 >>\nendobj\n";
        byte[] pdfBytes = System.Text.Encoding.Latin1.GetBytes(pdf);

        string acroFormText = "5 0 obj\n<< /Type /AcroForm /Fields 50 0 R /SigFlags 3 >>\nendobj\n";
        var refs = PdfStructureParser.ResolveIndirectFields(pdfBytes, acroFormText);
        refs.ShouldBe(["10 0 R", "20 0 R", "30 0 R"]);
    }

    [Fact]
    public void ResolveIndirectFields_ReturnsEmptyForInlineArray()
    {
        // /Fields is an inline array, not an indirect reference
        string acroFormText = "5 0 obj\n<< /Type /AcroForm /Fields [10 0 R 20 0 R] /SigFlags 3 >>\nendobj\n";
        byte[] pdfBytes = System.Text.Encoding.Latin1.GetBytes(acroFormText);

        var refs = PdfStructureParser.ResolveIndirectFields(pdfBytes, acroFormText);
        refs.ShouldBeEmpty();
    }

    [Fact]
    public void ResolveIndirectFields_ReturnsEmptyWhenNoFields()
    {
        string acroFormText = "5 0 obj\n<< /Type /AcroForm /SigFlags 3 >>\nendobj\n";
        byte[] pdfBytes = System.Text.Encoding.Latin1.GetBytes(acroFormText);

        var refs = PdfStructureParser.ResolveIndirectFields(pdfBytes, acroFormText);
        refs.ShouldBeEmpty();
    }

    [Fact]
    public void ResolveIndirectFields_HandlesMultilineArray()
    {
        // Array object spans multiple lines
        string pdf = "%PDF-1.7\n" +
                     "50 0 obj\n[\n10 0 R\n20 0 R\n30 0 R\n40 0 R\n]\nendobj\n" +
                     "5 0 obj\n<< /Type /AcroForm /Fields 50 0 R /SigFlags 3 >>\nendobj\n";
        byte[] pdfBytes = System.Text.Encoding.Latin1.GetBytes(pdf);

        string acroFormText = "5 0 obj\n<< /Type /AcroForm /Fields 50 0 R /SigFlags 3 >>\nendobj\n";
        var refs = PdfStructureParser.ResolveIndirectFields(pdfBytes, acroFormText);
        refs.ShouldBe(["10 0 R", "20 0 R", "30 0 R", "40 0 R"]);
    }

    // ── UsesXRefStreams Tests ───────────────────────────────────────────────

    [Fact]
    public void UsesXRefStreams_ClassicXRefTable_ReturnsFalse()
    {
        var pdf = "%PDF-1.7\n" +
                  "1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n" +
                  "xref\n0 2\n0000000000 65535 f\r\n0000000009 00000 n\r\n" +
                  "trailer\n<< /Size 2 /Root 1 0 R >>\n" +
                  "startxref\n60\n%%EOF\n";
        var data = System.Text.Encoding.Latin1.GetBytes(pdf);
        PdfStructureParser.UsesXRefStreams(data).ShouldBeFalse();
    }

    [Fact]
    public void UsesXRefStreams_XRefStreamObject_ReturnsTrue()
    {
        // Simulate a PDF whose last startxref points to an xref stream object
        var pdfHeader = "%PDF-1.7\n";
        var catalog = "1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n";
        var xrefStream = "3 0 obj\n<< /Type /XRef /Size 4 /Root 1 0 R /W [1 2 1] /Filter /FlateDecode /Length 0 >>\nstream\n\nendstream\nendobj\n";
        int xrefOffset = System.Text.Encoding.Latin1.GetByteCount(pdfHeader + catalog);
        var pdf = pdfHeader + catalog + xrefStream + $"startxref\n{xrefOffset}\n%%EOF\n";
        var data = System.Text.Encoding.Latin1.GetBytes(pdf);
        PdfStructureParser.UsesXRefStreams(data).ShouldBeTrue();
    }

    [Fact]
    public void UsesXRefStreams_NoStartxref_ReturnsFalse()
    {
        var data = System.Text.Encoding.Latin1.GetBytes("%PDF-1.7\n1 0 obj\n<< >>\nendobj\n");
        PdfStructureParser.UsesXRefStreams(data).ShouldBeFalse();
    }

    [Fact]
    public void UsesXRefStreams_XRefStreamWithoutSpace_ReturnsTrue()
    {
        // /Type/XRef without space
        var pdfHeader = "%PDF-1.7\n";
        var catalog = "1 0 obj\n<< /Type /Catalog >>\nendobj\n";
        var xrefStream = "3 0 obj\n<< /Type/XRef /Size 4 /Root 1 0 R /W [1 2 1] /Length 0 >>\nstream\n\nendstream\nendobj\n";
        int xrefOffset = System.Text.Encoding.Latin1.GetByteCount(pdfHeader + catalog);
        var pdf = pdfHeader + catalog + xrefStream + $"startxref\n{xrefOffset}\n%%EOF\n";
        var data = System.Text.Encoding.Latin1.GetBytes(pdf);
        PdfStructureParser.UsesXRefStreams(data).ShouldBeTrue();
    }
}
