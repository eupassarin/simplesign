using Shouldly;
using Xunit;
using SimpleSign.PAdES.Pdf;

namespace SimpleSign.PAdES.Tests.Pdf;

/// <summary>
/// Tests for PdfStructureParser helper methods.
/// </summary>
[Trait("Category", "Unit")]
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
        result.ShouldBe([0, 0, 0, 0]);
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
        byte[] pdfBytes = [.. System.Text.Encoding.Latin1.GetBytes(pdfHeader + objStmDict)
, .. compressed, .. System.Text.Encoding.Latin1.GetBytes(objStmEnd)];

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

    // ── Page Tree (/Kids) Parsing Tests ─────────────────────────────────────

    /// <summary>
    /// Builds a 3-page PDF whose /Pages object embeds the given dictionary entries
    /// (normally a /Kids array plus /Count), for page-tree traversal tests.
    /// </summary>
    private static byte[] BuildPdfWithPagesObject(string pagesEntries)
    {
        return System.Text.Encoding.Latin1.GetBytes(
            "%PDF-1.7\n" +
            "1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n" +
            $"2 0 obj\n<< /Type /Pages {pagesEntries} >>\nendobj\n" +
            "3 0 obj\n<< /Type /Page /Parent 2 0 R >>\nendobj\n" +
            "4 0 obj\n<< /Type /Page /Parent 2 0 R >>\nendobj\n" +
            "5 0 obj\n<< /Type /Page /Parent 2 0 R >>\nendobj\n" +
            "trailer\n<< /Root 1 0 R >>\n%%EOF\n");
    }

    private static void AssertPages(byte[] pdf, params (int Page, int ObjNum)[] expected)
    {
        foreach (var (page, objNum) in expected)
        {
            PdfStructureParser.FindNthPageObjNum(pdf, page).ShouldBe(objNum, $"page {page}");
        }
    }

    [Fact]
    public void FindNthPageObjNum_CompactKidsArray_ReturnsCorrectPages()
    {
        byte[] pdf = BuildPdfWithPagesObject("/Kids[3 0 R 4 0 R 5 0 R] /Count 3");
        AssertPages(pdf, (1, 3), (2, 4), (3, 5));
    }

    [Fact]
    public void FindNthPageObjNum_SpacedCompactKidsArray_ReturnsCorrectPages()
    {
        byte[] pdf = BuildPdfWithPagesObject("/Kids [ 3 0 R 4 0 R 5 0 R ] /Count 3");
        AssertPages(pdf, (1, 3), (2, 4), (3, 5));
    }

    [Fact]
    public void FindNthPageObjNum_MultilineKidsArray_ReturnsCorrectPages()
    {
        byte[] pdf = BuildPdfWithPagesObject("/Kids[\n3 0 R\n4 0 R\n5 0 R\n] /Count 3");
        AssertPages(pdf, (1, 3), (2, 4), (3, 5));
    }

    [Fact]
    public void FindNthPageObjNum_CommentSeparatedKidsArray_ReturnsCorrectPages()
    {
        byte[] pdf = BuildPdfWithPagesObject("/Kids[3 0 R% comment\n4 0 R 5 0 R] /Count 3");
        AssertPages(pdf, (1, 3), (2, 4), (3, 5));
    }

    [Fact]
    public void FindNthPageObjNum_MixedWhitespaceKidsArray_ReturnsCorrectPages()
    {
        byte[] pdf = BuildPdfWithPagesObject("/Kids[3 0 R\t4 0 R\r\n5 0 R] /Count 3");
        AssertPages(pdf, (1, 3), (2, 4), (3, 5));
    }

    [Fact]
    public void FindNthPageObjNum_GenerationOnSeparateLines_ReturnsCorrectPages()
    {
        // Valid PDF: whitespace (including line breaks) may appear between any tokens
        // of an indirect reference.
        byte[] pdf = BuildPdfWithPagesObject("/Kids[3\n0\nR\n4\n0\nR\n5\n0\nR] /Count 3");
        AssertPages(pdf, (1, 3), (2, 4), (3, 5));
    }

    [Fact]
    public void FindNthPageObjNum_CompactKidsArray_PageBeyondCountReturnsNegativeOne()
    {
        byte[] pdf = BuildPdfWithPagesObject("/Kids[3 0 R 4 0 R 5 0 R] /Count 3");
        PdfStructureParser.FindNthPageObjNum(pdf, 4).ShouldBe(-1);
        PdfStructureParser.FindNthPageObjNum(pdf, 0).ShouldBe(-1);
    }

    [Fact]
    public void FindFirstPageObjNumFromCatalog_CompactKidsArray_ReturnsFirstPage()
    {
        byte[] pdf = BuildPdfWithPagesObject("/Kids[3 0 R 4 0 R 5 0 R] /Count 3");
        PdfStructureParser.FindFirstPageObjNumFromCatalog(pdf).ShouldBe(3);
    }

    [Fact]
    public void FindFirstPageObjNumFromCatalog_PagesValueWithoutRefSuffix_ReturnsNegativeOne()
    {
        byte[] pdf = BuildCatalogPdf("/Pages 2 0 S");
        PdfStructureParser.FindFirstPageObjNumFromCatalog(pdf).ShouldBe(-1);
    }

    // ── Inline AcroForm Preservation Tests ───────────────────────────────────

    private static byte[] BuildCatalogPdf(string catalogEntries) =>
        System.Text.Encoding.Latin1.GetBytes(
            "%PDF-1.7\n" +
            $"1 0 obj\n<< /Type /Catalog {catalogEntries} >>\nendobj\n");

    [Fact]
    public void AppendFieldToInlineAcroForm_DirectFieldsArray_AppendsRef()
    {
        const string catalog = "1 0 obj\n<< /Type /Catalog /AcroForm << /SigFlags 3 /Fields [51 0 R] /DA (/Helv 0 Tf 0 g) >> >>\nendobj\n";

        string updated = PdfStructureParser.AppendFieldToInlineAcroForm(catalog, "62 0 R");

        updated.ShouldContain("/Fields [51 0 R 62 0 R]");
        updated.ShouldContain("/DA (/Helv 0 Tf 0 g)");
        updated.ShouldContain("/SigFlags 3");
    }

    [Fact]
    public void AppendFieldToInlineAcroForm_NoSpaceFieldsArray_AppendsRef()
    {
        const string catalog = "1 0 obj\n<< /Type /Catalog /AcroForm<< /Fields[51 0 R] /DA (/Helv 0 Tf 0 g) >> >>\nendobj\n";

        string updated = PdfStructureParser.AppendFieldToInlineAcroForm(catalog, "62 0 R");

        updated.ShouldContain("/Fields[51 0 R 62 0 R]");
    }

    [Fact]
    public void AppendFieldToInlineAcroForm_MultilineFields_PreservesNestedResources()
    {
        const string catalog = "1 0 obj\n<<\n/Type /Catalog\n/AcroForm <<\n/SigFlags 3\n/Fields [\n51 0 R\n]\n/DA (/Helv 0 Tf 0 g)\n/DR <<\n/Font <<\n/Helv 52 0 R\n>>\n>>\n>>\n>>\nendobj\n";

        string updated = PdfStructureParser.AppendFieldToInlineAcroForm(catalog, "62 0 R");

        updated.ShouldContain("51 0 R\n 62 0 R]");
        updated.ShouldContain("/DA (/Helv 0 Tf 0 g)");
        updated.ShouldContain("/Helv 52 0 R");
    }

    [Fact]
    public void AppendFieldToInlineAcroForm_EmptyFieldsArray_InsertsWithoutLeadingSpace()
    {
        const string catalog = "1 0 obj\n<< /Type /Catalog /AcroForm << /Fields [] >> >>\nendobj\n";

        string updated = PdfStructureParser.AppendFieldToInlineAcroForm(catalog, "62 0 R");

        updated.ShouldContain("/Fields [62 0 R]");
    }

    [Fact]
    public void AppendFieldToInlineAcroForm_MissingFieldsKey_InsertsNewArray()
    {
        const string catalog = "1 0 obj\n<< /Type /Catalog /AcroForm << /SigFlags 3 /DA (/Helv 0 Tf 0 g) >> >>\nendobj\n";

        string updated = PdfStructureParser.AppendFieldToInlineAcroForm(catalog, "62 0 R");

        updated.ShouldContain("/Fields [62 0 R]");
        updated.ShouldContain("/DA (/Helv 0 Tf 0 g)");
    }

    [Fact]
    public void AppendFieldToInlineAcroForm_IndirectFieldsRef_ReturnsUnchanged()
    {
        const string catalog = "1 0 obj\n<< /Type /Catalog /AcroForm << /Fields 51 0 R /DA (/Helv 0 Tf 0 g) >> >>\nendobj\n";

        PdfStructureParser.AppendFieldToInlineAcroForm(catalog, "62 0 R").ShouldBe(catalog);
    }

    [Fact]
    public void AppendFieldToInlineAcroForm_NoInlineAcroForm_ReturnsUnchanged()
    {
        const string catalog = "1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n";

        PdfStructureParser.AppendFieldToInlineAcroForm(catalog, "62 0 R").ShouldBe(catalog);
    }

    [Fact]
    public void HasUpdatableInlineAcroForm_DirectFieldsArray_ReturnsTrue()
    {
        byte[] pdf = BuildCatalogPdf("/AcroForm << /Fields [51 0 R] /DA (/Helv 0 Tf 0 g) >>");

        PdfStructureParser.HasUpdatableInlineAcroForm(pdf, 1).ShouldBeTrue();
    }

    [Fact]
    public void HasUpdatableInlineAcroForm_MissingFields_ReturnsTrue()
    {
        byte[] pdf = BuildCatalogPdf("/AcroForm << /SigFlags 3 >>");

        PdfStructureParser.HasUpdatableInlineAcroForm(pdf, 1).ShouldBeTrue();
    }

    [Fact]
    public void HasUpdatableInlineAcroForm_IndirectFieldsRef_ReturnsFalse()
    {
        byte[] pdf = BuildCatalogPdf("/AcroForm << /Fields 51 0 R >>");

        PdfStructureParser.HasUpdatableInlineAcroForm(pdf, 1).ShouldBeFalse();
    }

    [Fact]
    public void HasUpdatableInlineAcroForm_IndirectAcroForm_ReturnsFalse()
    {
        byte[] pdf = BuildCatalogPdf("/AcroForm 5 0 R");

        PdfStructureParser.HasUpdatableInlineAcroForm(pdf, 1).ShouldBeFalse();
    }

    [Fact]
    public void HasUpdatableInlineAcroForm_NoAcroForm_ReturnsFalse()
    {
        byte[] pdf = BuildCatalogPdf("/Pages 2 0 R");

        PdfStructureParser.HasUpdatableInlineAcroForm(pdf, 1).ShouldBeFalse();
    }

    // ── String/Comment-Aware Dictionary Scanning Tests ───────────────────────

    [Fact]
    public void FindOutermostDictClose_LiteralStringWithDoubleAngle_ReturnsTopLevelClose()
    {
        string source = "<< /DA (a >> b) /DR << /Font << /F 0 R >> >> >>";

        int result = PdfStructureParser.FindOutermostDictClose(source);

        result.ShouldBe(source.Length - 2);
    }

    [Fact]
    public void FindOutermostDictClose_CommentWithAngleBrackets_ReturnsTopLevelClose()
    {
        string source = "<< /Foo 1\n% fake << >>\n/Bar 2 >>";

        int result = PdfStructureParser.FindOutermostDictClose(source);

        result.ShouldBe(source.LastIndexOf(">>", StringComparison.Ordinal));
    }

    [Fact]
    public void FindNextTopLevelKey_LiteralStringWithAngleBrackets_FindsNextKey()
    {
        string text = "/DA (a >> b) /DR << /Font << /F 0 R >> >>";

        int pos = PdfStructureParser.FindNextTopLevelKey(text, "/DA ".Length);

        text[pos..].ShouldStartWith("/DR");
    }

    [Fact]
    public void AppendFieldToInlineAcroForm_CommentedCloseBracket_AppendsAfterRealBracket()
    {
        // The '%' comments out the first ']'; the real array close is the second one.
        const string catalog = "1 0 obj\n<< /Type /Catalog /AcroForm << /SigFlags 3 /Fields [51 0 R % ]\n52 0 R] /DA (/Helv 0 Tf 0 g) >> >>\nendobj\n";

        string updated = PdfStructureParser.AppendFieldToInlineAcroForm(catalog, "62 0 R");

        updated.ShouldContain("52 0 R 62 0 R]");
        updated.ShouldContain("/DA (/Helv 0 Tf 0 g)");
    }

    [Fact]
    public void ParseFieldsArray_IndirectFieldsRef_ReturnsEmpty()
    {
        const string obj = "5 0 obj\n<< /Fields 50 0 R /DR << /Font [1 0 R] >> >>\nendobj\n";
        var refs = PdfStructureParser.ParseFieldsArray(obj);
        refs.ShouldBeEmpty();
    }

    [Fact]
    public void ParseFieldsArray_CompactNoSpace_ReturnsRefs()
    {
        const string obj = "5 0 obj\n<< /Fields[51 0 R 52 0 R] >>\nendobj\n";
        var refs = PdfStructureParser.ParseFieldsArray(obj);
        refs.ShouldBe(["51 0 R", "52 0 R"]);
    }

    [Fact]
    public void ParseFieldsArray_CommentInsideArray_SkipsComment()
    {
        const string obj = "5 0 obj\n<< /Fields [1 0 R % ]\n2 0 R] >>\nendobj\n";
        var refs = PdfStructureParser.ParseFieldsArray(obj);
        refs.ShouldBe(["1 0 R", "2 0 R"]);
    }

    // ── RemoveKeyFromDict Token-Aware Tests ─────────────────────────────────

    [Fact]
    public void RemoveKeyFromDict_MultilineInlineDict_RemovesWholeEntry()
    {
        const string obj = "1 0 obj\n<< /Type /Catalog /Pages 2 0 R\n   /AcroForm <<\n      /SigFlags 3\n      /Fields [51 0 R]\n      /DA (/Helv 0 Tf 0 g)\n   >>\n>>\nendobj\n";

        string result = PdfStructureParser.RemoveKeyFromDict(obj, "/AcroForm");

        result.ShouldNotContain("/SigFlags 3");
        result.ShouldNotContain("/Fields [51 0 R]");
        result.ShouldNotContain("/DA (/Helv 0 Tf 0 g)");
        result.ShouldContain("/Type /Catalog");
        result.ShouldContain("/Pages 2 0 R");
    }

    [Fact]
    public void RemoveKeyFromDict_MultilinePermsDict_RemovesWholeEntry()
    {
        const string obj = "1 0 obj\n<< /Type /Catalog\n   /Perms << /DocMDP 5 0 R\n             /UR3 6 0 R >>\n   /Pages 2 0 R\n>>\nendobj\n";

        string result = PdfStructureParser.RemoveKeyFromDict(obj, "/Perms");

        result.ShouldNotContain("/DocMDP 5 0 R");
        result.ShouldNotContain("/UR3 6 0 R");
        result.ShouldContain("/Pages 2 0 R");
    }

    [Fact]
    public void RemoveKeyFromDict_IndirectReference_RemovesWholeRef()
    {
        const string obj = "1 0 obj\n<< /Type /Catalog /Pages 2 0 R /AcroForm 56 0 R >>\nendobj\n";

        string result = PdfStructureParser.RemoveKeyFromDict(obj, "/AcroForm");

        result.ShouldNotContain("56 0 R");
        result.ShouldContain("/Pages 2 0 R");
    }

    [Fact]
    public void RemoveKeyFromDict_NameValue_RemovesWholeEntry()
    {
        const string obj = "1 0 obj\n<< /Type /Catalog /Foo /Bar /Pages 2 0 R >>\nendobj\n";

        string result = PdfStructureParser.RemoveKeyFromDict(obj, "/Foo");

        result.ShouldNotContain("/Bar");
        result.ShouldContain("/Pages 2 0 R");
    }

    [Fact]
    public void RemoveKeyFromDict_KeyInsideLiteralString_IsNotRemoved()
    {
        const string obj = "1 0 obj\n<< /Type /Catalog /Pages 2 0 R /Note (see /AcroForm here) /AcroForm 5 0 R >>\nendobj\n";

        string result = PdfStructureParser.RemoveKeyFromDict(obj, "/AcroForm");

        // The key inside the literal string must stay; only the real entry is removed.
        result.ShouldContain("(see /AcroForm here)");
        result.ShouldNotContain("/AcroForm 5 0 R");
        result.ShouldContain("/Pages 2 0 R");
    }

    [Fact]
    public void RemoveKeyFromDict_MissingKey_ReturnsUnchanged()
    {
        const string obj = "1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n";

        PdfStructureParser.RemoveKeyFromDict(obj, "/AcroForm").ShouldBe(obj);
    }

    // ── FindEmptySignatureField Tests ────────────────────────────────────────

    private static byte[] BuildFieldPdf(string tEntry, string vEntry) =>
        System.Text.Encoding.Latin1.GetBytes(
            "%PDF-1.7\n" +
            "1 0 obj\n<< /Type /Catalog /Pages 2 0 R /AcroForm 4 0 R >>\nendobj\n" +
            "2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n" +
            "3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Annots [5 0 R] >>\nendobj\n" +
            "4 0 obj\n<< /Fields [5 0 R] /SigFlags 3 >>\nendobj\n" +
            $"5 0 obj\n<< /Type /Annot /Subtype /Widget /FT /Sig {tEntry} {vEntry} /Rect [0 0 0 0] >>\nendobj\n" +
            "xref\n0 6\n0000000000 65535 f \n0000000009 00000 n \n0000000058 00000 n \n0000000115 00000 n \n0000000172 00000 n \n0000000238 00000 n \ntrailer\n<< /Size 6 /Root 1 0 R >>\nstartxref\n300\n%%EOF\n");

    [Fact]
    public void FindEmptySignatureField_EmptyLiteralV_ReturnsField() =>
        PdfStructureParser.FindEmptySignatureField(BuildFieldPdf("/T (Sig1)", "/V ()"), "Sig1").ShouldBe(5);

    [Fact]
    public void FindEmptySignatureField_NullV_ReturnsField() =>
        PdfStructureParser.FindEmptySignatureField(BuildFieldPdf("/T (Sig1)", "/V null"), "Sig1").ShouldBe(5);

    [Fact]
    public void FindEmptySignatureField_NameV_ReturnsField() =>
        PdfStructureParser.FindEmptySignatureField(BuildFieldPdf("/T (Sig1)", "/V /SigEmpty"), "Sig1").ShouldBe(5);

    [Fact]
    public void FindEmptySignatureField_ReferenceV_ThrowsAlreadySigned()
    {
        void Act() => PdfStructureParser.FindEmptySignatureField(BuildFieldPdf("/T (Sig1)", "/V 12 0 R"), "Sig1");

        Should.Throw<InvalidOperationException>(Act);
    }

    [Fact]
    public void FindEmptySignatureField_HexTName_FindsField() =>
        // "/T <53696731>" is the hexadecimal form of "Sig1".
        PdfStructureParser.FindEmptySignatureField(BuildFieldPdf("/T <53696731>", "/V null"), "Sig1").ShouldBe(5);

    [Fact]
    public void FindEmptySignatureField_MismatchedName_ReturnsNegative() =>
        PdfStructureParser.FindEmptySignatureField(BuildFieldPdf("/T (Other)", "/V null"), "Sig1").ShouldBe(-1);

    // ── CountVisibleSignatureAnnotations Tests ───────────────────────────────

    private static byte[] BuildPdfWithSigWidgets(params string[] widgetBodies) =>
        System.Text.Encoding.Latin1.GetBytes(
            "%PDF-1.7\n" +
            "1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n" +
            "2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n" +
            $"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Annots [{string.Join(' ', Enumerable.Range(0, widgetBodies.Length).Select(i => $"{4 + i} 0 R"))}] >>\nendobj\n" +
            string.Concat(widgetBodies.Select((body, i) => $"{4 + i} 0 obj\n<< {body} >>\nendobj\n")) +
            "xref\n0 4\ntrailer\n<< /Size 4 /Root 1 0 R >>\nstartxref\n0\n%%EOF\n");

    [Fact]
    public void CountVisibleSignatureAnnotations_LongDaBeforeRect_CountsWidget()
    {
        // /Rect lies more than 256 bytes after /FT /Sig (the old fixed-window limit).
        string body = "/Type /Annot /Subtype /Widget /FT /Sig /T (Sig1) /DA (" +
                      new string('x', 400) + ") /Rect [10 10 200 50]";

        PdfStructureParser.CountVisibleSignatureAnnotations(BuildPdfWithSigWidgets(body)).ShouldBe(1);
    }

    [Fact]
    public void CountVisibleSignatureAnnotations_ZeroRect_NotCounted()
    {
        string body = "/Type /Annot /Subtype /Widget /FT /Sig /T (Sig1) /Rect [0 0 0 0]";

        PdfStructureParser.CountVisibleSignatureAnnotations(BuildPdfWithSigWidgets(body)).ShouldBe(0);
    }

    [Fact]
    public void CountVisibleSignatureAnnotations_TwoVisibleWidgets_CountsBoth()
    {
        string body1 = "/Type /Annot /Subtype /Widget /FT /Sig /T (Sig1) /Rect [10 10 200 50]";
        string body2 = "/Type /Annot /Subtype /Widget /FT /Sig /T (Sig2) /Rect [10 100 200 140]";

        PdfStructureParser.CountVisibleSignatureAnnotations(BuildPdfWithSigWidgets(body1, body2)).ShouldBe(2);
    }

    [Fact]
    public void CountVisibleSignatureAnnotations_RectOnlyInNestedDict_NotCounted()
    {
        // /Rect belongs to the nested /MK dictionary, not the widget itself.
        string body = "/Type /Annot /Subtype /Widget /FT /Sig /T (Sig1) /MK << /Rect [10 10 200 50] >>";

        PdfStructureParser.CountVisibleSignatureAnnotations(BuildPdfWithSigWidgets(body)).ShouldBe(0);
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
