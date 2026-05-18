using System.Text;
using Shouldly;
using SimpleSign.Pdf.Exceptions;
using Xunit;

namespace SimpleSign.Pdf.Tests;

/// <summary>
/// Unit tests for PdfStructureReader.
/// We use synthetic PDFs built as byte arrays — no external dependencies.
/// </summary>
public sealed class PdfStructureReaderTests
{
    // ── Synthetic PDF fixtures ─────────────────────────────────────────────────

    /// <summary>
    /// Minimal valid PDF without signature fields.
    /// Structure: header + catalog + pages + xref + trailer.
    /// </summary>
    private static byte[] BuildMinimalPdf()
    {
        var sb = new StringBuilder();
        sb.Append("%PDF-1.7\n");
        sb.Append("1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n");
        sb.Append("2 0 obj\n<< /Type /Pages /Kids [] /Count 0 >>\nendobj\n");

        long xrefOffset = sb.Length;
        sb.Append("xref\n");
        sb.Append("0 3\n");
        sb.Append("0000000000 65535 f \n");
        sb.Append($"{9:D10} 00000 n \n");
        sb.Append($"{59:D10} 00000 n \n");
        sb.Append("trailer\n<< /Size 3 /Root 1 0 R >>\n");
        sb.Append($"startxref\n{xrefOffset}\n%%EOF");
        return Encoding.Latin1.GetBytes(sb.ToString());
    }

    /// <summary>
    /// PDF with a filled /Sig field — simulated ByteRange and Contents.
    /// Returns the real offsets for validation in tests.
    /// </summary>
    private static byte[] BuildSignedPdf(out long offset1, out long length1,
                                          out long offset2, out long length2,
                                          out byte[] cmsBytes)
    {
        cmsBytes = new byte[] { 0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02 };
        string cmsHex = Convert.ToHexString(cmsBytes).ToLowerInvariant();
        // Padding to 32 hex chars (16 bytes reserved)
        string contentsPadded = cmsHex.PadRight(32, '0');

        var full = new StringBuilder();
        full.Append("%PDF-1.7\n");
        full.Append("1 0 obj\n<< /Type /Catalog /Pages 2 0 R /AcroForm << /Fields [3 0 R] /SigFlags 3 >> >>\nendobj\n");
        full.Append("2 0 obj\n<< /Type /Pages /Kids [] /Count 0 >>\nendobj\n");

        int sigObjStart = full.Length;
        full.Append("3 0 obj\n");
        full.Append("<< /Type /Sig /Filter /Adobe.PPKLite /SubFilter /adbe.pkcs7.detached\n");

        // Position where ByteRange array value begins (after "[")
        // We use a fixed 40-char placeholder for each number (4 x 10 chars + 3 spaces + [])
        const string byteRangePlaceholder = "[0000000000 0000000000 0000000000 0000000000]";
        int byteRangePlaceholderPos = full.Length + "/ByteRange ".Length;
        full.Append($"/ByteRange {byteRangePlaceholder}\n");

        string contentsPrefix = "/Contents <";
        full.Append(contentsPrefix);
        int contentsHexStart = full.Length;  // index where hex chars begin
        full.Append(contentsPadded);
        full.Append(">\n>>\nendobj\n");

        int afterSigObj = full.Length;
        full.Append("4 0 obj\n<< /Type /Page /Parent 2 0 R >>\nendobj\n");

        long xrefOffset = full.Length;
        full.Append("xref\n0 5\n");
        full.Append("0000000000 65535 f \n");
        full.Append($"0000000009 00000 n \n");
        full.Append($"0000000090 00000 n \n");
        full.Append($"{sigObjStart:D10} 00000 n \n");
        full.Append($"{afterSigObj:D10} 00000 n \n");
        full.Append("trailer\n<< /Size 5 /Root 1 0 R >>\n");
        full.Append($"startxref\n{xrefOffset}\n%%EOF");

        // Calculates real ByteRange:
        // offset1=0, length1=position of '<' of /Contents
        // offset2=position after '>' of /Contents, length2=remainder
        offset1 = 0;
        length1 = contentsHexStart - contentsPrefix.Length; // position of '<'
        offset2 = contentsHexStart + contentsPadded.Length + 1; // after '>'
        length2 = full.Length - offset2;

        // Replaces placeholder with the real ByteRange
        string byteRangeValue = $"[{offset1,-10} {length1,-10} {offset2,-10} {length2,-10}]";
        string finalStr = full.ToString().Remove(byteRangePlaceholderPos, byteRangePlaceholder.Length)
                                         .Insert(byteRangePlaceholderPos, byteRangeValue);

        return Encoding.Latin1.GetBytes(finalStr);
    }

    // ── Tests ─────────────────────────────────────────────────────────────────

    [Fact(DisplayName = "Minimal PDF without signature returns empty list")]
    public async Task ReadSignatureFields_MinimalPdf_ReturnsEmptyList()
    {
        var pdf = BuildMinimalPdf();
        using var stream = new MemoryStream(pdf);
        var reader = new PdfStructureReader();

        var fields = await PdfStructureReader.ReadSignatureFieldsAsync(stream);

        fields.ShouldBeEmpty();
    }

    [Fact(DisplayName = "Null stream throws ArgumentNullException")]
    public async Task ReadSignatureFields_NullStream_ThrowsArgumentNullException()
    {
        var reader = new PdfStructureReader();
        await Assert.ThrowsAsync<ArgumentNullException>(
            () => PdfStructureReader.ReadSignatureFieldsAsync(null!));
    }

    [Fact(DisplayName = "Non-seekable stream throws ArgumentException")]
    public async Task ReadSignatureFields_NonSeekableStream_ThrowsArgumentException()
    {
        var reader = new PdfStructureReader();
        var nonSeekable = new NonSeekableStream(new byte[] { 0x25, 0x50, 0x44, 0x46 });
        await Assert.ThrowsAsync<ArgumentException>(
            () => PdfStructureReader.ReadSignatureFieldsAsync(nonSeekable));
    }

    [Fact(DisplayName = "Invalid PDF throws PdfStructureException")]
    public async Task ReadSignatureFields_InvalidPdf_ThrowsInvalidDataException()
    {
        var reader = new PdfStructureReader();
        var notPdf = Encoding.UTF8.GetBytes("This is not a PDF file");
        using var stream = new MemoryStream(notPdf);
        await Assert.ThrowsAsync<PdfStructureException>(
            () => PdfStructureReader.ReadSignatureFieldsAsync(stream));
    }

    [Fact(DisplayName = "Signed PDF returns one signature field")]
    public async Task ReadSignatureFields_SignedPdf_ReturnsOneField()
    {
        var pdf = BuildSignedPdf(out _, out _, out _, out _, out _);
        using var stream = new MemoryStream(pdf);
        var reader = new PdfStructureReader();

        var fields = await PdfStructureReader.ReadSignatureFieldsAsync(stream);

        fields.Count().ShouldBe(1);
        fields[0].IsSigned.ShouldBeTrue();
    }

    [Fact(DisplayName = "Signed PDF ByteRange is valid and correct")]
    public async Task ReadSignatureFields_SignedPdf_ByteRangeIsValid()
    {
        var pdf = BuildSignedPdf(out long o1, out long l1, out long o2, out long l2, out _);
        using var stream = new MemoryStream(pdf);
        var reader = new PdfStructureReader();

        var fields = await PdfStructureReader.ReadSignatureFieldsAsync(stream);

        var br = fields[0].ByteRange;
        br.IsValid.ShouldBeTrue();
        br.Offset1.ShouldBe(o1);
        br.Length1.ShouldBe(l1);
        br.Offset2.ShouldBe(o2);
        br.Length2.ShouldBe(l2);
    }

    [Fact(DisplayName = "Extracted Contents matches CMS bytes")]
    public async Task ReadSignatureFields_SignedPdf_ContentsMatchCmsBytes()
    {
        var pdf = BuildSignedPdf(out _, out _, out _, out _, out byte[] expected);
        using var stream = new MemoryStream(pdf);
        var reader = new PdfStructureReader();

        var fields = await PdfStructureReader.ReadSignatureFieldsAsync(stream);

        fields[0].ContentsBytes.Take(expected.Length).ToArray().ShouldBe(expected);
    }

    [Fact(DisplayName = "ReadSignedBytes returns correct byte count")]
    public async Task ReadSignedBytes_ValidByteRange_ReturnsCorrectByteCount()
    {
        var pdf = BuildSignedPdf(out long o1, out long l1, out long o2, out long l2, out _);
        using var stream = new MemoryStream(pdf);

        var byteRange = new PdfByteRange
        {
            Offset1 = o1,
            Length1 = l1,
            Offset2 = o2,
            Length2 = l2
        };

        var signedBytes = await PdfStructureReader.ReadSignedBytesAsync(stream, byteRange);

        signedBytes.Count().ShouldBe((int)(l1 + l2));
        signedBytes[0].ShouldBe((byte)'%');
    }

    [Fact(DisplayName = "Invalid ByteRange throws ArgumentException")]
    public async Task ReadSignedBytes_InvalidByteRange_ThrowsArgumentException()
    {
        using var stream = new MemoryStream(new byte[100]);
        var invalid = new PdfByteRange { Offset1 = -1, Length1 = 0, Offset2 = 0, Length2 = 0 };
        await Assert.ThrowsAsync<ArgumentException>(
            () => PdfStructureReader.ReadSignedBytesAsync(stream, invalid));
    }

    [Fact(DisplayName = "Null ByteRange throws ArgumentNullException")]
    public async Task ReadSignedBytes_NullByteRange_ThrowsArgumentNullException()
    {
        using var stream = new MemoryStream(new byte[100]);
        await Assert.ThrowsAsync<ArgumentNullException>(
            () => PdfStructureReader.ReadSignedBytesAsync(stream, null!));
    }

    [Fact(DisplayName = "Valid PdfByteRange returns IsValid true")]
    public void PdfByteRange_ValidRange_IsValidReturnsTrue()
    {
        var br = new PdfByteRange { Offset1 = 0, Length1 = 100, Offset2 = 200, Length2 = 50 };
        br.IsValid.ShouldBeTrue();
    }

    [Fact(DisplayName = "PdfByteRange with zero Length returns IsValid false")]
    public void PdfByteRange_ZeroLength_IsValidReturnsFalse()
    {
        var br = new PdfByteRange { Offset1 = 0, Length1 = 0, Offset2 = 100, Length2 = 50 };
        br.IsValid.ShouldBeFalse();
    }

    [Fact(DisplayName = "Field without Contents returns IsSigned false")]
    public void PdfSignatureField_WithoutContents_IsSignedReturnsFalse()
    {
        var field = new PdfSignatureField { ContentsBytes = [] };
        field.IsSigned.ShouldBeFalse();
    }

    [Fact(DisplayName = "Field with Contents returns IsSigned true")]
    public void PdfSignatureField_WithContents_IsSignedReturnsTrue()
    {
        var field = new PdfSignatureField { ContentsBytes = new byte[] { 0x30 } };
        field.IsSigned.ShouldBeTrue();
    }

    // ── SubFilter extraction ──────────────────────────────────────────────────

    [Fact(DisplayName = "Extracts SubFilter adbe.pkcs7.detached correctly")]
    public async Task ReadSignatureFieldsAsync_SignedPdf_ExtractsSubFilter()
    {
        var pdf = BuildPdfWithSubFilter("adbe.pkcs7.detached");
        using var stream = new MemoryStream(pdf);
        var reader = new PdfStructureReader();

        var fields = await PdfStructureReader.ReadSignatureFieldsAsync(stream);

        fields.Count().ShouldBe(1);
        fields[0].SubFilter.ShouldBe("adbe.pkcs7.detached");
    }

    [Fact(DisplayName = "Extracts SubFilter ETSI.CAdES.detached correctly")]
    public async Task ReadSignatureFieldsAsync_EtsiSubFilter_ExtractsCorrectly()
    {
        var pdf = BuildPdfWithSubFilter("ETSI.CAdES.detached");
        using var stream = new MemoryStream(pdf);
        var reader = new PdfStructureReader();

        var fields = await PdfStructureReader.ReadSignatureFieldsAsync(stream);

        fields.Count().ShouldBe(1);
        fields[0].SubFilter.ShouldBe("ETSI.CAdES.detached");
    }

    // ── Fixtures helpers ──────────────────────────────────────────────────────

    private static byte[] BuildPdfWithSubFilter(string subFilter)
    {
        var sb = new StringBuilder();
        sb.Append("%PDF-1.7\n");
        sb.Append("1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n");
        sb.Append("2 0 obj\n<< /Type /Pages /Kids [] /Count 0 >>\nendobj\n");
        sb.Append($"3 0 obj\n<< /Type /Sig /Filter /Adobe.PPKLite /SubFilter /{subFilter}\n");
        sb.Append("/ByteRange [0 100 200 50]\n");
        sb.Append("/Contents <" + "00".PadRight(20, '0') + ">\n");
        sb.Append(">>\nendobj\n");

        long xrefOffset = sb.Length;
        sb.Append("xref\n0 4\n");
        sb.Append("0000000000 65535 f \n");
        sb.Append("0000000009 00000 n \n");
        sb.Append("0000000060 00000 n \n");
        sb.Append("0000000110 00000 n \n");
        sb.Append("trailer\n<< /Size 4 /Root 1 0 R >>\n");
        sb.Append($"startxref\n{xrefOffset}\n%%EOF");
        return Encoding.Latin1.GetBytes(sb.ToString());
    }

}
internal sealed class NonSeekableStream(byte[] data) : Stream
{
    private readonly MemoryStream _inner = new(data);
    public override bool CanRead => true;
    public override bool CanSeek => false;
    public override bool CanWrite => false;
    public override long Length => throw new NotSupportedException();
    public override long Position
    {
        get => throw new NotSupportedException();
        set => throw new NotSupportedException();
    }
    public override void Flush() => _inner.Flush();
    public override int Read(byte[] buffer, int offset, int count) => _inner.Read(buffer, offset, count);
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();
    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
}
