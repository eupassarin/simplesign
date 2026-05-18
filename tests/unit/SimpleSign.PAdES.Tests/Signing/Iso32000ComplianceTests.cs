using System.Text;
using System.Text.RegularExpressions;
using Shouldly;
using SimpleSign.PAdES.Signing;
using Xunit;

namespace SimpleSign.PAdES.Tests.Signing;

/// <summary>
/// Unit tests that verify ISO 32000-1:2008 compliance for PDF digital signatures.
/// Each test maps to a specific section of the standard.
/// </summary>
public sealed class Iso32000ComplianceTests
{
    // ── Minimal PDF builders ───────────────────────────────────────────────────

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

    /// <summary>
    /// Builds a minimal PDF that uses cross-reference streams (PDF 1.5+).
    /// </summary>
    private static byte[] BuildMinimalXRefStreamPdf()
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

        // Build xref stream entries: type(1) + offset(4) + gen(1) = 6 bytes per entry
        byte[] entries = new byte[4 * 6];
        entries[0] = 0;
        entries[1] = 0;
        entries[2] = 0;
        entries[3] = 0;
        entries[4] = 0;
        entries[5] = 0xFF;
        entries[6] = 1;
        entries[7] = (byte)((obj1Offset >> 24) & 0xFF);
        entries[8] = (byte)((obj1Offset >> 16) & 0xFF);
        entries[9] = (byte)((obj1Offset >> 8) & 0xFF);
        entries[10] = (byte)(obj1Offset & 0xFF);
        entries[11] = 0;
        entries[12] = 1;
        entries[13] = (byte)((obj2Offset >> 24) & 0xFF);
        entries[14] = (byte)((obj2Offset >> 16) & 0xFF);
        entries[15] = (byte)((obj2Offset >> 8) & 0xFF);
        entries[16] = (byte)(obj2Offset & 0xFF);
        entries[17] = 0;
        entries[18] = 1;
        entries[19] = (byte)((obj3Offset >> 24) & 0xFF);
        entries[20] = (byte)((obj3Offset >> 16) & 0xFF);
        entries[21] = (byte)((obj3Offset >> 8) & 0xFF);
        entries[22] = (byte)(obj3Offset & 0xFF);
        entries[23] = 0;

        sb.Append("4 0 obj\n");
        sb.Append("<< /Type /XRef\n");
        sb.Append("   /Size 5\n");
        sb.Append("   /Root 1 0 R\n");
        sb.Append("   /W [1 4 1]\n");
        sb.Append("   /Index [0 4]\n");
        sb.Append($"   /Length {entries.Length}\n");
        sb.Append(">>\n");
        sb.Append("stream\n");

        byte[] headerBytes = Encoding.Latin1.GetBytes(sb.ToString());
        byte[] footerText = Encoding.Latin1.GetBytes($"\nendstream\nendobj\nstartxref\n{xrefOffset}\n%%EOF\n");

        byte[] result = new byte[headerBytes.Length + entries.Length + footerText.Length];
        Buffer.BlockCopy(headerBytes, 0, result, 0, headerBytes.Length);
        Buffer.BlockCopy(entries, 0, result, headerBytes.Length, entries.Length);
        Buffer.BlockCopy(footerText, 0, result, headerBytes.Length + entries.Length, footerText.Length);

        return result;
    }

    /// <summary>
    /// Builds a minimal PDF with existing AcroForm containing /DR (default resources).
    /// </summary>
    private static byte[] BuildPdfWithAcroFormDR()
    {
        var sb = new StringBuilder();
        sb.Append("%PDF-1.7\n");

        int obj1Offset = sb.Length;
        sb.Append("1 0 obj\n<< /Type /Catalog /Pages 2 0 R /AcroForm 4 0 R >>\nendobj\n");

        int obj2Offset = sb.Length;
        sb.Append("2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n");

        int obj3Offset = sb.Length;
        sb.Append("3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>\nendobj\n");

        int obj4Offset = sb.Length;
        sb.Append("4 0 obj\n<< /Fields [] /SigFlags 3 /DR << /Font << /Helv 5 0 R >> >> /DA (/Helv 0 Tf 0 g) >>\nendobj\n");

        int obj5Offset = sb.Length;
        sb.Append("5 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n");

        long xrefOffset = sb.Length;
        sb.Append("xref\n");
        sb.Append("0 6\n");
        sb.Append("0000000000 65535 f \n");
        sb.Append($"{obj1Offset:D10} 00000 n \n");
        sb.Append($"{obj2Offset:D10} 00000 n \n");
        sb.Append($"{obj3Offset:D10} 00000 n \n");
        sb.Append($"{obj4Offset:D10} 00000 n \n");
        sb.Append($"{obj5Offset:D10} 00000 n \n");
        sb.Append("trailer\n<< /Size 6 /Root 1 0 R >>\n");
        sb.Append($"startxref\n{xrefOffset}\n%%EOF\n");

        return Encoding.Latin1.GetBytes(sb.ToString());
    }

    private static SignatureFieldOptions DefaultOptions() => new()
    {
        FieldName = "Signature1",
        SignerName = "Test Signer",
        ContentsReservedBytes = 1024,
    };

    private static SignatureFieldOptions VisibleOptions() => new()
    {
        FieldName = "Signature1",
        SignerName = "Test Signer",
        ContentsReservedBytes = 1024,
        Appearance = SignatureAppearance.Auto(),
    };

    private static SignatureFieldOptions DocMdpOptions(CertificationLevel level) => new()
    {
        FieldName = "Signature1",
        SignerName = "Test Signer",
        ContentsReservedBytes = 1024,
        CertificationLevel = level,
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

    // ── §7.9.4: Date string format ─────────────────────────────────────────────

    [Fact(DisplayName = "§7.9.4: /M date uses PDF date format D:YYYYMMDDHHmmss+HH'mm'")]
    public async Task DateFormat_UsesIso32000PdfDateFormat()
    {
        var (_, text) = await PrepareSignedPdf();

        // ISO 32000 §7.9.4: D:YYYYMMDDHHmmSSOHH'mm' where O is + or -
        text.ShouldMatch(@"/M \(D:\d{14}\+00'00'\)");
        text.ShouldNotMatch(@"/M \(D:\d{14}Z\)"); // must NOT use Z suffix
    }

    // ── §12.8.1: Signature dictionary entries ──────────────────────────────────

    [Fact(DisplayName = "§12.8.1: Signature dict has /Type /Sig")]
    public async Task SigDict_HasTypeSig()
    {
        var (_, text) = await PrepareSignedPdf();
        text.ShouldContain("/Type /Sig");
    }

    [Fact(DisplayName = "§12.8.1: Signature dict has /Filter /Adobe.PPKLite")]
    public async Task SigDict_HasFilter()
    {
        var (_, text) = await PrepareSignedPdf();
        text.ShouldContain("/Filter /Adobe.PPKLite");
    }

    [Theory(DisplayName = "§12.8.1: SubFilter is valid ISO value")]
    [InlineData(PdfSignatureSubFilter.EtsiCadesDetached, "ETSI.CAdES.detached")]
    [InlineData(PdfSignatureSubFilter.AdbePkcs7Detached, "adbe.pkcs7.detached")]
    public async Task SigDict_SubFilterIsValid(PdfSignatureSubFilter subFilter, string expected)
    {
        var options = new SignatureFieldOptions
        {
            FieldName = "Signature1",
            ContentsReservedBytes = 1024,
            SubFilter = subFilter,
        };
        var (_, text) = await PrepareSignedPdf(options: options);
        text.ShouldContain($"/SubFilter /{expected}");
    }

    [Fact(DisplayName = "§12.8.1: Signature dict has /ByteRange with 4 integers")]
    public async Task SigDict_HasByteRangeWith4Integers()
    {
        var (_, text) = await PrepareSignedPdf();
        text.ShouldMatch(@"/ByteRange \[\d+ \d+ \d+ \d+\s*\]");
    }

    [Fact(DisplayName = "§12.8.1: /Contents is hex string")]
    public async Task SigDict_ContentsIsHexString()
    {
        var (_, text) = await PrepareSignedPdf();
        text.ShouldMatch(@"/Contents <[0-9A-Fa-f]+>");
    }

    [Fact(DisplayName = "§12.8.1: /Name is properly escaped PDF string")]
    public async Task SigDict_NameIsEscapedPdfString()
    {
        var options = new SignatureFieldOptions
        {
            FieldName = "Signature1",
            SignerName = "Test (Signer) With\\Special",
            ContentsReservedBytes = 1024,
        };
        var (_, text) = await PrepareSignedPdf(options: options);
        text.ShouldContain(@"/Name (Test \(Signer\) With\\Special)");
    }

    // ── §12.8.1: ByteRange covers entire file ─────────────────────────────────

    [Fact(DisplayName = "§12.8.1: ByteRange[0]=0 and ranges cover entire file minus Contents")]
    public async Task ByteRange_CoversEntireFileMinusContents()
    {
        var (outputBytes, text) = await PrepareSignedPdf();

        var match = Regex.Match(text, @"/ByteRange \[(\d+) (\d+) (\d+) (\d+)\s*\]");
        match.Success.ShouldBeTrue();

        long offset1 = long.Parse(match.Groups[1].Value);
        long length1 = long.Parse(match.Groups[2].Value);
        long offset2 = long.Parse(match.Groups[3].Value);
        long length2 = long.Parse(match.Groups[4].Value);

        offset1.ShouldBe(0, "ByteRange must start at beginning of file");
        (offset2 + length2).ShouldBe(outputBytes.Length,
            "ByteRange must cover to end of file");
        offset2.ShouldBeGreaterThan(length1,
            "second range must start after first range");

        // The gap between ranges is the /Contents hex value (including < >)
        long contentsHexLength = offset2 - length1 - 2; // -2 for < and >
        contentsHexLength.ShouldBe(1024 * 2,
            "gap should equal ContentsReservedBytes * 2");
    }

    // ── §7.3.4.2: PDF string escaping ─────────────────────────────────────────

    [Fact(DisplayName = "§7.3.4.2: EscapePdfString escapes backslash, parens, and control chars")]
    public void EscapePdfString_EscapesAllSpecialChars()
    {
        string input = "Hello\\World(test)\nLine2\rLine3\tTab\bBack\fFeed";
        string escaped = SignatureAppearanceRenderer.EscapePdfString(input);

        escaped.ShouldContain("\\\\"); // backslash
        escaped.ShouldContain("\\("); // open paren
        escaped.ShouldContain("\\)"); // close paren
        escaped.ShouldContain("\\n"); // newline
        escaped.ShouldContain("\\r"); // carriage return
        escaped.ShouldContain("\\t"); // tab
        escaped.ShouldContain("\\b"); // backspace
        escaped.ShouldContain("\\f"); // form feed
        escaped.ShouldNotContain("\n"); // no raw newline
        escaped.ShouldNotContain("\r"); // no raw CR
    }

    [Fact(DisplayName = "§7.3.4.2: EscapePdfString preserves normal characters")]
    public void EscapePdfString_PreservesNormalChars()
    {
        string input = "Simple Name 123";
        string escaped = SignatureAppearanceRenderer.EscapePdfString(input);
        escaped.ShouldBe(input);
    }

    // ── §12.7: Interactive forms (AcroForm) ────────────────────────────────────

    [Fact(DisplayName = "§12.7: AcroForm has /SigFlags 3 (SignaturesExist + AppendOnly)")]
    public async Task AcroForm_HasSigFlags3()
    {
        var (_, text) = await PrepareSignedPdf();
        text.ShouldContain("/SigFlags 3");
    }

    [Fact(DisplayName = "§12.7: AcroForm has /Fields array with field reference")]
    public async Task AcroForm_HasFieldsArray()
    {
        var (_, text) = await PrepareSignedPdf();
        text.ShouldMatch(@"/Fields \[.*\d+ 0 R.*\]");
    }

    [Fact(DisplayName = "§12.7: AcroForm does NOT add /Type key (Adobe diff analysis)")]
    public async Task AcroForm_DoesNotHaveTypeKey()
    {
        var (_, text) = await PrepareSignedPdf();

        // Find the AcroForm object in the incremental update
        int acroFormStart = text.IndexOf("/Fields [", StringComparison.Ordinal);
        acroFormStart.ShouldBeGreaterThan(0);

        int objStart = text.LastIndexOf(" 0 obj\n", acroFormStart, StringComparison.Ordinal);
        int objEnd = text.IndexOf("endobj", acroFormStart, StringComparison.Ordinal);
        string acroFormObj = text.Substring(objStart, objEnd - objStart + 6);

        acroFormObj.ShouldNotContain("/Type /AcroForm");
    }

    [Fact(DisplayName = "§12.7: AcroForm preserves /DR (default resources) from original")]
    public async Task AcroForm_PreservesDR()
    {
        byte[] pdfBytes = BuildPdfWithAcroFormDR();
        var (_, text) = await PrepareSignedPdf(pdfBytes);

        text.ShouldContain("/DR");
        text.ShouldContain("/Font");
    }

    [Fact(DisplayName = "§12.7: AcroForm preserves /DA (default appearance) from original")]
    public async Task AcroForm_PreservesDA()
    {
        byte[] pdfBytes = BuildPdfWithAcroFormDR();
        var (_, text) = await PrepareSignedPdf(pdfBytes);

        text.ShouldContain("/DA");
    }

    // ── §12.7.4.5: Signature fields ────────────────────────────────────────────

    [Fact(DisplayName = "§12.7.4.5: Field has /FT /Sig")]
    public async Task Field_HasFTSig()
    {
        var (_, text) = await PrepareSignedPdf();
        text.ShouldContain("/FT /Sig");
    }

    [Fact(DisplayName = "§12.7.4.5: Field has /V pointing to sig dict")]
    public async Task Field_HasVReference()
    {
        var (_, text) = await PrepareSignedPdf();
        text.ShouldMatch(@"/V \d+ 0 R");
    }

    [Fact(DisplayName = "§12.7.4.5: Field has /T with field name")]
    public async Task Field_HasTFieldName()
    {
        var (_, text) = await PrepareSignedPdf();
        text.ShouldMatch(@"/T \(.+\)");
    }

    [Fact(DisplayName = "§12.7.4.5: Unique field names when signing multiple times")]
    public async Task Field_UniqueFieldNamesOnMultipleSign()
    {
        byte[] pdf1 = BuildMinimalPdf();
        using var input1 = new MemoryStream(pdf1);
        using var output1 = new MemoryStream();
        await PdfSignatureWriter.PrepareAsync(input1, output1, DefaultOptions());
        byte[] signed1 = output1.ToArray();

        using var input2 = new MemoryStream(signed1);
        using var output2 = new MemoryStream();
        await PdfSignatureWriter.PrepareAsync(input2, output2, DefaultOptions());
        string text = Encoding.Latin1.GetString(output2.ToArray());

        text.ShouldContain("/T (Signature1)");
        text.ShouldContain("/T (Signature2)");
    }

    // ── §8.6.5: Widget annotation ──────────────────────────────────────────────

    [Fact(DisplayName = "§8.6.5: Widget has /Type /Annot /Subtype /Widget")]
    public async Task Widget_HasTypeAnnotSubtypeWidget()
    {
        var (_, text) = await PrepareSignedPdf();
        text.ShouldContain("/Type /Annot");
        text.ShouldContain("/Subtype /Widget");
    }

    [Fact(DisplayName = "§8.6.5: Invisible widget has /F 0 and /Rect [0 0 0 0]")]
    public async Task Widget_InvisibleHasF0AndZeroRect()
    {
        var (_, text) = await PrepareSignedPdf();
        text.ShouldContain("/F 0");
        text.ShouldContain("/Rect [0 0 0 0]");
    }

    [Fact(DisplayName = "§8.6.5: Visible widget has /F 132 (Print + Locked)")]
    public async Task Widget_VisibleHasF132()
    {
        var (_, text) = await PrepareSignedPdf(options: VisibleOptions());

        // F 132 = Print (4) + Locked (128)
        text.ShouldContain("/F 132");
    }

    [Fact(DisplayName = "§8.6.5: Widget has /P page reference")]
    public async Task Widget_HasPageReference()
    {
        var (_, text) = await PrepareSignedPdf();
        text.ShouldMatch(@"/P \d+ 0 R");
    }

    // ── §8.7: Page /Annots updated ─────────────────────────────────────────────

    [Fact(DisplayName = "§8.7: Page object /Annots contains the new field reference")]
    public async Task Page_AnnotsContainsFieldRef()
    {
        var (_, text) = await PrepareSignedPdf();

        text.ShouldContain("/Annots [");

        int pageCount = Regex.Count(text, @"/Type /Page\b");
        pageCount.ShouldBeGreaterThanOrEqualTo(2, "page should be rewritten in incremental update");
    }

    // ── §7.5.4-6: Incremental update structure ────────────────────────────────

    [Fact(DisplayName = "§7.5.4: Incremental update preserves original PDF bytes")]
    public async Task IncrementalUpdate_PreservesOriginalBytes()
    {
        byte[] original = BuildMinimalPdf();
        var (outputBytes, _) = await PrepareSignedPdf(original);

        outputBytes.AsSpan(0, original.Length).ToArray()
            .ShouldBe(original);
    }

    [Fact(DisplayName = "§7.5.4: Xref table has /Prev pointing to original xref")]
    public async Task IncrementalUpdate_HasPrev()
    {
        var (_, text) = await PrepareSignedPdf();
        text.ShouldMatch(@"/Prev \d+");
    }

    [Fact(DisplayName = "§7.5.4: Trailer has /Size >= highest obj num + 1")]
    public async Task IncrementalUpdate_TrailerSizeCorrect()
    {
        var (_, text) = await PrepareSignedPdf();

        var sizeMatches = Regex.Matches(text, @"/Size (\d+)");
        sizeMatches.Count().ShouldBeGreaterThanOrEqualTo(2);
        int trailerSize = int.Parse(sizeMatches[^1].Groups[1].Value);

        var objMatches = Regex.Matches(text, @"(\d+) 0 obj\b");
        int highestObj = 0;
        foreach (Match m in objMatches)
        {
            int objNum = int.Parse(m.Groups[1].Value);
            if (objNum > highestObj)
            {
                highestObj = objNum;
            }
        }

        trailerSize.ShouldBeGreaterThanOrEqualTo(highestObj + 1,
            "trailer /Size must be >= highest object number + 1");
    }

    [Fact(DisplayName = "§7.5.4: File ends with %%EOF")]
    public async Task IncrementalUpdate_EndsWithEOF()
    {
        var (_, text) = await PrepareSignedPdf();
        text.TrimEnd().ShouldEndWith("%%EOF");
    }

    [Fact(DisplayName = "§7.5.4: Has startxref before %%EOF")]
    public async Task IncrementalUpdate_HasStartxref()
    {
        var (_, text) = await PrepareSignedPdf();
        text.ShouldMatch(@"startxref\n\d+\n%%EOF");
    }

    // ── §7.5.4: Xref table entry format ────────────────────────────────────────

    [Fact(DisplayName = "§7.5.4: Xref table entries are exactly 20 bytes")]
    public async Task XrefTable_EntriesAre20Bytes()
    {
        var (_, text) = await PrepareSignedPdf();

        // Find the last standalone xref table (not inside "startxref")
        int lastXref = -1;
        int searchFrom = 0;
        while (true)
        {
            int idx = text.IndexOf("xref\n", searchFrom, StringComparison.Ordinal);
            if (idx < 0)
            {
                break;
            }
            // Only match standalone "xref\n", not "startxref\n"
            if (idx == 0 || text[idx - 1] != 't')
            {
                lastXref = idx;
            }
            searchFrom = idx + 1;
        }
        lastXref.ShouldBeGreaterThan(0);

        int pos = text.IndexOf('\n', lastXref) + 1; // after "xref\n"
        pos = text.IndexOf('\n', pos) + 1; // after first group header

        while (pos < text.Length && !text[pos..].StartsWith("trailer", StringComparison.Ordinal))
        {
            string lineContent = text[pos..text.IndexOf('\n', pos)];
            if (Regex.IsMatch(lineContent, @"^\d+ \d+$"))
            {
                pos = text.IndexOf('\n', pos) + 1;
                continue;
            }

            int entryEnd = text.IndexOf('\n', pos) + 1;
            int entryLength = entryEnd - pos;
            entryLength.ShouldBe(20,
                $"xref entry at offset {pos} should be exactly 20 bytes, got {entryLength}");
            pos = entryEnd;
        }
    }

    // ── §7.5.8: Cross-reference streams ────────────────────────────────────────

    [Fact(DisplayName = "§7.5.8: Xref stream has /Type /XRef")]
    public async Task XrefStream_HasTypeXRef()
    {
        byte[] pdf = BuildMinimalXRefStreamPdf();
        var (_, text) = await PrepareSignedPdf(pdf);
        text.ShouldContain("/Type /XRef");
    }

    [Fact(DisplayName = "§7.5.8: Xref stream has /W array")]
    public async Task XrefStream_HasWArray()
    {
        byte[] pdf = BuildMinimalXRefStreamPdf();
        var (_, text) = await PrepareSignedPdf(pdf);
        text.ShouldMatch(@"/W \[\d+ \d+ \d+\]");
    }

    [Fact(DisplayName = "§7.5.8: Xref stream has /Index array")]
    public async Task XrefStream_HasIndexArray()
    {
        byte[] pdf = BuildMinimalXRefStreamPdf();
        var (_, text) = await PrepareSignedPdf(pdf);
        text.ShouldMatch(@"/Index \[[\d\s]+\]");
    }

    [Fact(DisplayName = "§7.5.8: Xref stream includes self-entry")]
    public async Task XrefStream_IncludesSelfEntry()
    {
        byte[] pdf = BuildMinimalXRefStreamPdf();
        var (_, text) = await PrepareSignedPdf(pdf);

        var xrefObjMatches = Regex.Matches(text, @"(\d+) 0 obj\n<< /Type /XRef");
        xrefObjMatches.Count().ShouldBeGreaterThanOrEqualTo(1);
        int xrefObjNum = int.Parse(xrefObjMatches[^1].Groups[1].Value);

        var indexMatches = Regex.Matches(text, @"/Index \[([\d\s]+)\]");
        indexMatches.Count().ShouldBeGreaterThanOrEqualTo(1);

        string[] indexParts = indexMatches[^1].Groups[1].Value.Trim().Split(' ', StringSplitOptions.RemoveEmptyEntries);
        bool covered = false;
        for (int i = 0; i < indexParts.Length - 1; i += 2)
        {
            int start = int.Parse(indexParts[i]);
            int count = int.Parse(indexParts[i + 1]);
            if (xrefObjNum >= start && xrefObjNum < start + count)
            {
                covered = true;
                break;
            }
        }

        covered.ShouldBeTrue($"xref stream obj {xrefObjNum} must be in /Index array (self-entry)");
    }

    [Fact(DisplayName = "§7.5.8: Xref stream has /Filter /FlateDecode")]
    public async Task XrefStream_HasFlateDecode()
    {
        byte[] pdf = BuildMinimalXRefStreamPdf();
        var (_, text) = await PrepareSignedPdf(pdf);
        text.ShouldContain("/Filter /FlateDecode");
    }

    [Fact(DisplayName = "§7.5.8: Xref stream has /Size, /Root, /Prev (trailer keys)")]
    public async Task XrefStream_HasTrailerKeys()
    {
        byte[] pdf = BuildMinimalXRefStreamPdf();
        var (_, text) = await PrepareSignedPdf(pdf);

        int xrefDictStart = text.LastIndexOf("/Type /XRef", StringComparison.Ordinal);
        xrefDictStart.ShouldBeGreaterThan(0);

        string xrefSection = text[xrefDictStart..];
        xrefSection.ShouldMatch(@"/Size \d+");
        xrefSection.ShouldMatch(@"/Root \d+ 0 R");
        xrefSection.ShouldMatch(@"/Prev \d+");
    }

    // ── §12.8.3: Signature appearance ──────────────────────────────────────────

    [Fact(DisplayName = "§12.8.3: Visible signature has /AP << /N objNum 0 R >>")]
    public async Task Appearance_VisibleHasAPNormal()
    {
        var (_, text) = await PrepareSignedPdf(options: VisibleOptions());
        text.ShouldMatch(@"/AP << /N \d+ 0 R >>");
    }

    [Fact(DisplayName = "§12.8.3: Appearance stream is Form XObject with /Subtype /Form")]
    public async Task Appearance_IsFormXObject()
    {
        var (_, text) = await PrepareSignedPdf(options: VisibleOptions());
        text.ShouldContain("/Subtype /Form");
        text.ShouldMatch(@"/BBox \[[\d\.\s]+\]");
    }

    // ── §12.8.2: DocMDP transform ──────────────────────────────────────────────

    [Theory(DisplayName = "§12.8.2: DocMDP /Reference has correct /P level")]
    [InlineData(CertificationLevel.NoChanges, 1)]
    [InlineData(CertificationLevel.FormFillingAndAnnotations, 3)]
    [InlineData(CertificationLevel.FormFilling, 2)]
    public async Task DocMDP_HasCorrectLevel(CertificationLevel level, int expectedP)
    {
        var (_, text) = await PrepareSignedPdf(options: DocMdpOptions(level));

        text.ShouldContain("/TransformMethod /DocMDP");
        text.ShouldContain($"/P {expectedP}");
    }

    [Fact(DisplayName = "§12.8.2: DocMDP adds /Perms to catalog")]
    public async Task DocMDP_AddsPermsToCatalog()
    {
        var (_, text) = await PrepareSignedPdf(options: DocMdpOptions(CertificationLevel.NoChanges));
        text.ShouldMatch(@"/Perms << /DocMDP \d+ 0 R >>");
    }

    // ── BuildXrefStream unit tests ─────────────────────────────────────────────

    [Fact(DisplayName = "§7.5.8: BuildXrefStream includes all objects in output")]
    public void BuildXrefStream_IncludesAllObjects()
    {
        var offsets = new SortedDictionary<int, long>
        {
            [5] = 1000,
            [6] = 2000,
            [7] = 3000
        };

        var (bytes, xrefObjNum) = PdfSignatureWriter.BuildXrefStream(
            offsets, xrefObjNum: 8, newTrailerSize: 9,
            catalogObjNum: 1, prevXRef: 500, xrefStreamOffset: 4000);

        string text = Encoding.Latin1.GetString(bytes);
        text.ShouldContain("/Type /XRef");
        text.ShouldContain("/Size 9");
        text.ShouldContain("/Root 1 0 R");
        text.ShouldContain("/Prev 500");
        text.ShouldContain("/W [1 4 1]");
        text.ShouldContain("/Filter /FlateDecode");
        text.ShouldContain("stream");
        text.ShouldContain("endstream");
        xrefObjNum.ShouldBe(8);
    }

    [Fact(DisplayName = "§7.5.8: BuildXrefStream preserves trailer /ID")]
    public void BuildXrefStream_PreservesTrailerId()
    {
        var offsets = new SortedDictionary<int, long> { [5] = 1000 };
        string trailerId = "/ID [<abc123> <def456>]";

        var (bytes, _) = PdfSignatureWriter.BuildXrefStream(
            offsets, 6, 7, 1, 500, 2000, trailerId: trailerId);

        string text = Encoding.Latin1.GetString(bytes);
        text.ShouldContain(trailerId);
    }

    // ── Cross-cutting: endobj markers ──────────────────────────────────────────

    [Fact(DisplayName = "ISO: Every 'N 0 obj' in incremental update has matching 'endobj'")]
    public async Task IncrementalUpdate_AllObjectsHaveEndobj()
    {
        var (outputBytes, _) = await PrepareSignedPdf();
        byte[] originalPdf = BuildMinimalPdf();

        string updateText = Encoding.Latin1.GetString(
            outputBytes.AsSpan(originalPdf.Length).ToArray());

        int objCount = Regex.Count(updateText, @"\d+ 0 obj\b");
        int endobjCount = Regex.Count(updateText, @"\bendobj\b");

        objCount.ShouldBeGreaterThan(0);
        endobjCount.ShouldBeGreaterThanOrEqualTo(objCount,
            "every object must have a matching endobj");
    }
}
