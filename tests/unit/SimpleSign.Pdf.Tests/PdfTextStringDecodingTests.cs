using System.Text;
using Shouldly;
using Xunit;

namespace SimpleSign.Pdf.Tests;

/// <summary>
/// Tests for PDF text-string decoding (ISO 32000-1 §7.3.4 / §7.9.2.2) used for
/// signature dictionary metadata such as /Reason, /Location, /Name and /ContactInfo.
/// </summary>
[Trait("Category", "Unit")]
public sealed class PdfTextStringDecodingTests
{
    // ── Direct decoder tests ─────────────────────────────────────────────────

    [Fact]
    public void DecodePdfTextString_Utf16BeBom_DecodesAsBigEndian()
    {
        byte[] raw = [0xFE, 0xFF, 0x00, 0x41, 0x00, 0x42];
        PdfStructureReader.DecodePdfTextString(raw).ShouldBe("AB");
    }

    [Fact]
    public void DecodePdfTextString_Utf16LeBom_DecodesAsLittleEndian()
    {
        byte[] raw = [0xFF, 0xFE, 0x41, 0x00, 0x42, 0x00];
        PdfStructureReader.DecodePdfTextString(raw).ShouldBe("AB");
    }

    [Fact]
    public void DecodePdfTextString_Utf16BeOddTrailingByte_IsDropped()
    {
        byte[] raw = [0xFE, 0xFF, 0x00, 0x41, 0x00];
        PdfStructureReader.DecodePdfTextString(raw).ShouldBe("A");
    }

    [Fact]
    public void DecodePdfTextString_PdfDocEncoding_MapsAnnexDRange()
    {
        byte[] raw = [0x80, 0xA0, 0x92, 0xE3];
        PdfStructureReader.DecodePdfTextString(raw).ShouldBe("\u2022\u20AC\u2122\u00E3");
    }

    [Fact]
    public void DecodePdfHexString_WhitespaceIgnoredAndOddNibblePadded()
    {
        byte[] hex = Encoding.ASCII.GetBytes("4 1 42 0");
        PdfStructureReader.DecodePdfHexString(hex).ShouldBe([0x41, 0x42, 0x00]);
    }

    // ── Signature-dictionary extraction tests ────────────────────────────────

    /// <summary>
    /// Builds a PDF with a Catalog, a page and one signature dictionary per body.
    /// Each signature dictionary is wrapped as "N 0 obj &lt;&lt; {body} &gt;&gt; endobj"
    /// and referenced by a widget annotation (/V). The /Reason entry of each body
    /// appears before /Contents, and /ByteRange after /Contents, as in the issue.
    /// Bodies must contain the literal "/ByteRange [0 100 200 300]" which is replaced
    /// by a placeholder and back-filled with the real byte ranges around /Contents.
    /// Returns the PDF bytes and the signature object numbers in order.
    /// </summary>
    internal static (byte[] Pdf, int[] SigObjNums) BuildPdfWithSignatures(params string[] sigDictBodies)
    {
        int count = sigDictBodies.Length;
        var sigObjNums = new int[count];
        for (int i = 0; i < count; i++)
        {
            sigObjNums[i] = 5 + (i * 2);
        }

        var annotRefs = new List<string>(count);
        for (int i = 0; i < count; i++)
        {
            annotRefs.Add($"{4 + (i * 2)} 0 R");
        }

        var sb = new StringBuilder();
        sb.Append("%PDF-1.7\n");

        var offsets = new long[3 + (count * 2) + 1];
        offsets[1] = sb.Length;
        sb.Append("1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n");

        offsets[2] = sb.Length;
        sb.Append("2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n");

        offsets[3] = sb.Length;
        sb.Append($"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Annots [{string.Join(' ', annotRefs)}] >>\nendobj\n");

        var byteRangeValuePositions = new int[count];
        var contentsHexStarts = new int[count];
        for (int i = 0; i < count; i++)
        {
            offsets[4 + (i * 2)] = sb.Length;
            sb.Append($"{4 + (i * 2)} 0 obj\n<< /Type /Annot /Subtype /Widget /FT /Sig /T (Sig{i + 1}) /V {sigObjNums[i]} 0 R >>\nendobj\n");

            string body = sigDictBodies[i].Replace(
                "/ByteRange [0 100 200 300]",
                $"/ByteRange {byteRangePlaceholder}",
                StringComparison.Ordinal);
            int objStart = sb.Length;
            sb.Append($"{sigObjNums[i]} 0 obj\n<< {body} >>\nendobj\n");
            offsets[sigObjNums[i]] = objStart;

            string textSoFar = sb.ToString();
            int contentsKey = textSoFar.IndexOf("/Contents <", objStart, StringComparison.Ordinal);
            contentsHexStarts[i] = contentsKey + "/Contents <".Length;
            int byteRangeKey = textSoFar.IndexOf("/ByteRange ", objStart, StringComparison.Ordinal);
            byteRangeValuePositions[i] = byteRangeKey + "/ByteRange ".Length;
        }

        long xrefOffset = sb.Length;
        sb.Append("xref\n");
        sb.Append($"0 {offsets.Length}\n");
        sb.Append("0000000000 65535 f \n");
        for (int num = 1; num < offsets.Length; num++)
        {
            sb.Append($"{offsets[num]:D10} 00000 n \n");
        }

        sb.Append($"trailer\n<< /Size {offsets.Length} /Root 1 0 R >>\n");
        sb.Append($"startxref\n{xrefOffset}\n%%EOF\n");

        byte[] pdf = Encoding.Latin1.GetBytes(sb.ToString());
        for (int i = 0; i < count; i++)
        {
            int hexStart = contentsHexStarts[i];
            int hexEnd = hexStart;
            while (hexEnd < pdf.Length && pdf[hexEnd] != (byte)'>')
            {
                hexEnd++;
            }

            long length1 = hexStart - 1;
            long offset2 = hexEnd + 1;
            long length2 = pdf.Length - offset2;
            string values = $"[{0:D10} {length1:D10} {offset2:D10} {length2:D10}]";
            Encoding.Latin1.GetBytes(values).CopyTo(pdf, byteRangeValuePositions[i]);
        }

        return (pdf, sigObjNums);
    }

    private const string byteRangePlaceholder = "[0000000000 0000000000 0000000000 0000000000]";

    [Fact]
    public async Task ReadSignatureFields_DictDelimitersInsideLiteralStrings_DoNotBreakParsing()
    {
        var (pdf, _) = BuildPdfWithSignatures(
            SigPrefix +
            "/Reason (merged >> streams << here)\n" +
            "% a comment with << fake dict open\n" +
            "/Contents <00>\n" +
            "/ByteRange [0 100 200 300]");

        using var stream = new MemoryStream(pdf);
        var fields = await PdfStructureReader.ReadSignatureFieldsAsync(stream);

        fields.Count.ShouldBe(1);
        fields[0].Reason.ShouldBe("merged >> streams << here");
    }

    [Fact]
    public async Task ReadSignatureFields_HexMDate_DecodesSigningTime()
    {
        const string dateStr = "D:20261013120000+00'00'";
        string hex = Convert.ToHexString(Encoding.ASCII.GetBytes(dateStr));
        var (pdf, _) = BuildPdfWithSignatures(
            SigPrefix +
            $"/M <{hex}>\n" +
            "/Contents <00>\n" +
            "/ByteRange [0 100 200 300]");

        using var stream = new MemoryStream(pdf);
        var fields = await PdfStructureReader.ReadSignatureFieldsAsync(stream);

        fields.Count.ShouldBe(1);
        fields[0].PdfSigningTime.ShouldBe(new DateTimeOffset(2026, 10, 13, 12, 0, 0, TimeSpan.Zero));
    }

    [Fact]
    public async Task ReadSignatureFields_Utf16HexMDate_DecodesSigningTime()
    {
        const string dateStr = "D:20261013120000+00'00'";
        byte[] utf16 = [0xFE, 0xFF, .. Encoding.BigEndianUnicode.GetBytes(dateStr)];
        string hex = Convert.ToHexString(utf16);
        var (pdf, _) = BuildPdfWithSignatures(
            SigPrefix +
            $"/M <{hex}>\n" +
            "/Contents <00>\n" +
            "/ByteRange [0 100 200 300]");

        using var stream = new MemoryStream(pdf);
        var fields = await PdfStructureReader.ReadSignatureFieldsAsync(stream);

        fields.Count.ShouldBe(1);
        fields[0].PdfSigningTime.ShouldBe(new DateTimeOffset(2026, 10, 13, 12, 0, 0, TimeSpan.Zero));
    }

    private const string SigPrefix = "/Type /Sig /Filter /Adobe.PPKLite /SubFilter /adbe.pkcs7.detached\n";

    [Fact]
    public async Task ReadSignatureFields_AsciiLiteralReason_ReturnsReason()
    {
        var (pdf, _) = BuildPdfWithSignatures(
            SigPrefix + "/Reason (Document approved)\n/Contents <00>\n/ByteRange [0 100 200 300]");

        using var stream = new MemoryStream(pdf);
        var fields = await PdfStructureReader.ReadSignatureFieldsAsync(stream);

        fields.Count.ShouldBe(1);
        fields[0].Reason.ShouldBe("Document approved");
    }

    [Fact]
    public async Task ReadSignatureFields_Utf16BeHexReason_DecodesUnicode()
    {
        var (pdf, _) = BuildPdfWithSignatures(
            SigPrefix +
            "/Name (Example signer)\n" +
            "/Reason <FEFF005A0061017C00F301420107002000670119015B006C01050020006A0061017A0144>\n" +
            "/Contents <00>\n" +
            "/ByteRange [0 100 200 300]");

        using var stream = new MemoryStream(pdf);
        var fields = await PdfStructureReader.ReadSignatureFieldsAsync(stream);

        fields.Count.ShouldBe(1);
        fields[0].Reason.ShouldBe("Zażółć gęślą jaźń");
        fields[0].SignerName.ShouldBe("Example signer");
    }

    [Fact]
    public async Task ReadSignatureFields_PdfDocHexReasonWithoutBom_DecodesUnicode()
    {
        // "Aprovação — 100%" in PDFDocEncoding without a BOM: Latin-1 range
        // (E7=ç, E3=ã) plus the Annex D em dash (0x84 = U+2014).
        var (pdf, _) = BuildPdfWithSignatures(
            SigPrefix +
            "/Reason <4170726F7661E7E36F20842031303025>\n" +
            "/Contents <00>\n" +
            "/ByteRange [0 100 200 300]");

        using var stream = new MemoryStream(pdf);
        var fields = await PdfStructureReader.ReadSignatureFieldsAsync(stream);

        fields.Count.ShouldBe(1);
        fields[0].Reason.ShouldBe("Aprovação — 100%");
    }

    [Fact]
    public async Task ReadSignatureFields_LiteralReasonWithEscapes_Unescapes()
    {
        // \( \) and octal escapes (\157 = 'o', \343 = 'ã' in Latin-1).
        var (pdf, _) = BuildPdfWithSignatures(
            SigPrefix +
            "/Reason (Approved \\050by\\051 J\\157\\343o)\n" +
            "/Contents <00>\n" +
            "/ByteRange [0 100 200 300]");

        using var stream = new MemoryStream(pdf);
        var fields = await PdfStructureReader.ReadSignatureFieldsAsync(stream);

        fields.Count.ShouldBe(1);
        fields[0].Reason.ShouldBe("Approved (by) João");
    }

    [Fact]
    public async Task ReadSignatureFields_MultipleUnicodeReasons_AssociatedWithCorrectSignatures()
    {
        var (pdf, sigObjNums) = BuildPdfWithSignatures(
            SigPrefix +
            "/Reason <FEFF005A0061017C00F301420107002000670119015B006C01050020006A0061017A0144>\n" +
            "/Contents <00>\n" +
            "/ByteRange [0 100 200 300]",
            SigPrefix +
            "/Reason (Document approved)\n" +
            "/Contents <00>\n" +
            "/ByteRange [0 100 200 300]",
            SigPrefix +
            "/Reason <FEFF00520061007A00E3006F00200064006100200061007300730069006E00610074007500720061>\n" +
            "/Contents <00>\n" +
            "/ByteRange [0 100 200 300]");

        using var stream = new MemoryStream(pdf);
        var fields = await PdfStructureReader.ReadSignatureFieldsAsync(stream);

        fields.Count.ShouldBe(3);
        fields[0].Reason.ShouldBe("Zażółć gęślą jaźń");
        fields[1].Reason.ShouldBe("Document approved");
        fields[2].Reason.ShouldBe("Razão da assinatura");
        fields.Select(f => f.SigDictObjectNumber).ShouldBe(sigObjNums);
    }
}
