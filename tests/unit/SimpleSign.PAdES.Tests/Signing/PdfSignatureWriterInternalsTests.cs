using System.Text;
using FluentAssertions;
using SimpleSign.PAdES.Signing;
using SimpleSign.Pdf;
using Xunit;

namespace SimpleSign.PAdES.Tests.Signing;

/// <summary>
/// Tests for PdfStructureParser public methods (formerly PdfSignatureWriter internals).
/// </summary>
public sealed class PdfSignatureWriterInternalsTests
{
    // ── FindHighestObjectNumber tests ──────────────────────────────────────────

    [Fact(DisplayName = "Returns highest object number among multiple objects")]
    public void FindHighestObjectNumber_WithMultipleObjects_ReturnsHighest()
    {
        byte[] data = Encoding.Latin1.GetBytes(
            "1 0 obj\n<< >>\nendobj\n5 0 obj\n<< >>\nendobj\n10 0 obj\n<< >>\nendobj\n");

        PdfStructureParser.FindHighestObjectNumber(data).Should().Be(10);
    }

    [Fact(DisplayName = "Returns zero when there are no objects in the PDF")]
    public void FindHighestObjectNumber_WithNoObjects_ReturnsZero()
    {
        byte[] data = Encoding.Latin1.GetBytes("%PDF-1.7\nsome random content\n");

        PdfStructureParser.FindHighestObjectNumber(data).Should().Be(0);
    }

    [Fact(DisplayName = "Returns highest number with sequential objects")]
    public void FindHighestObjectNumber_WithSequentialObjects_ReturnsHighest()
    {
        byte[] data = Encoding.Latin1.GetBytes(
            "1 0 obj\n<< >>\nendobj\n2 0 obj\n<< >>\nendobj\n3 0 obj\n<< >>\nendobj\n4 0 obj\n<< >>\nendobj\n");

        PdfStructureParser.FindHighestObjectNumber(data).Should().Be(4);
    }

    [Fact(DisplayName = "Does not confuse substring when searching for object number")]
    public void FindHighestObjectNumber_DoesNotMatchSubstring()
    {
        byte[] data = Encoding.Latin1.GetBytes("12 0 obj\n<< >>\nendobj\n");

        PdfStructureParser.FindHighestObjectNumber(data).Should().Be(12);
    }

    // ── FindTrailerSize tests ──────────────────────────────────────────────────

    [Fact(DisplayName = "Returns /Size value from trailer")]
    public void FindTrailerSize_WithSizeValue_ReturnsIt()
    {
        byte[] data = Encoding.Latin1.GetBytes("trailer\n<< /Size 42 /Root 1 0 R >>\n");

        PdfStructureParser.FindTrailerSize(data).Should().Be(42);
    }

    [Fact(DisplayName = "Returns fallback when trailer has no /Size")]
    public void FindTrailerSize_WithNoSize_ReturnsFallback()
    {
        byte[] data = Encoding.Latin1.GetBytes("trailer\n<< /Root 1 0 R >>\n");

        PdfStructureParser.FindTrailerSize(data).Should().Be(10);
    }

    [Fact(DisplayName = "Returns last /Size with multiple trailers")]
    public void FindTrailerSize_WithMultipleSizeEntries_ReturnsLast()
    {
        byte[] data = Encoding.Latin1.GetBytes(
            "trailer\n<< /Size 5 /Root 1 0 R >>\nstartxref\n100\n%%EOF\n" +
            "trailer\n<< /Size 20 /Root 1 0 R >>\nstartxref\n200\n%%EOF\n");

        PdfStructureParser.FindTrailerSize(data).Should().Be(20);
    }

    [Fact(DisplayName = "Correctly parses large /Size value")]
    public void FindTrailerSize_WithLargeValue_ParsesCorrectly()
    {
        byte[] data = Encoding.Latin1.GetBytes("trailer\n<< /Size 9999 >>\n");

        PdfStructureParser.FindTrailerSize(data).Should().Be(9999);
    }

    // ── FindRootObjectNumber tests ─────────────────────────────────────────────

    [Fact(DisplayName = "Returns /Root object number from trailer")]
    public void FindRootObjectNumber_WithRootReference_ReturnsObjNum()
    {
        byte[] data = Encoding.Latin1.GetBytes("trailer\n<< /Size 3 /Root 1 0 R >>\n");

        PdfStructureParser.FindRootObjectNumber(data).Should().Be(1);
    }

    [Fact(DisplayName = "Returns high /Root object number")]
    public void FindRootObjectNumber_WithHigherObjNum_ReturnsIt()
    {
        byte[] data = Encoding.Latin1.GetBytes("trailer\n<< /Size 50 /Root 42 0 R >>\n");

        PdfStructureParser.FindRootObjectNumber(data).Should().Be(42);
    }

    [Fact(DisplayName = "Returns fallback when trailer has no /Root")]
    public void FindRootObjectNumber_WithNoRoot_ReturnsFallback()
    {
        byte[] data = Encoding.Latin1.GetBytes("trailer\n<< /Size 3 >>\n");

        PdfStructureParser.FindRootObjectNumber(data).Should().Be(1);
    }

    [Fact(DisplayName = "Returns last /Root with multiple trailers")]
    public void FindRootObjectNumber_WithMultipleTrailers_ReturnsLast()
    {
        byte[] data = Encoding.Latin1.GetBytes(
            "trailer\n<< /Root 1 0 R >>\n%%EOF\ntrailer\n<< /Root 7 0 R >>\n%%EOF\n");

        PdfStructureParser.FindRootObjectNumber(data).Should().Be(7);
    }

    // ── BuildXrefStream Tests ──────────────────────────────────────────────

    [Fact(DisplayName = "BuildXrefStream produces valid xref stream with /Type /XRef")]
    public void BuildXrefStream_ProducesValidXrefStream()
    {
        var offsets = new SortedDictionary<int, long>
        {
            { 100, 5000L },
            { 101, 5200L },
            { 102, 5400L }
        };

        var (bytes, xrefObjNum) = PdfSignatureWriter.BuildXrefStream(
            offsets, xrefObjNum: 103, newTrailerSize: 104,
            catalogObjNum: 1, prevXRef: 4000L, xrefStreamOffset: 5500L,
            trailerId: "/ID [<aabb> <ccdd>]", trailerInfo: "/Info 2 0 R");

        string text = Encoding.Latin1.GetString(bytes);

        // Should contain xref stream markers
        text.Should().Contain("/Type /XRef");
        text.Should().Contain("/Size 104");
        text.Should().Contain("/Root 1 0 R");
        text.Should().Contain("/Prev 4000");
        text.Should().Contain("/W [1 4 1]");
        text.Should().Contain("/Filter /FlateDecode");
        // 4 contiguous objects: 100,101,102 + self-entry 103 (ISO 32000 §7.5.8)
        text.Should().Contain("/Index [100 4]");
        text.Should().Contain("/ID [<aabb> <ccdd>]");
        text.Should().Contain("/Info 2 0 R");
        text.Should().Contain("startxref\n5500");
        text.Should().Contain("%%EOF");

        xrefObjNum.Should().Be(103);

        // Verify the compressed data is valid zlib
        int streamStart = text.IndexOf("stream\n") + "stream\n".Length;
        int streamEnd = text.IndexOf("\nendstream");
        byte[] compressedData = bytes[streamStart..streamEnd];

        // Zlib header: first byte should be 0x78
        compressedData[0].Should().Be(0x78);

        // Decompress and verify entries (4 objects × 6 bytes each = 24 bytes)
        using var ms = new System.IO.MemoryStream(compressedData);
        using var zlib = new System.IO.Compression.ZLibStream(ms, System.IO.Compression.CompressionMode.Decompress);
        using var output = new System.IO.MemoryStream();
        zlib.CopyTo(output);
        byte[] rawEntries = output.ToArray();
        rawEntries.Should().HaveCount(24); // 4 entries × 6 bytes (includes self-entry)

        // First entry: type=1, offset=5000 (big-endian), gen=0
        rawEntries[0].Should().Be(1);
        var offset1 = (rawEntries[1] << 24) | (rawEntries[2] << 16) | (rawEntries[3] << 8) | rawEntries[4];
        offset1.Should().Be(5000);
        rawEntries[5].Should().Be(0);

        // Last entry (self): type=1, offset=5500, gen=0
        rawEntries[18].Should().Be(1);
        var selfOffset = (rawEntries[19] << 24) | (rawEntries[20] << 16) | (rawEntries[21] << 8) | rawEntries[22];
        selfOffset.Should().Be(5500);
        rawEntries[23].Should().Be(0);
    }

    [Fact(DisplayName = "BuildXrefStream handles non-contiguous object numbers")]
    public void BuildXrefStream_NonContiguousObjects_CorrectIndex()
    {
        var offsets = new SortedDictionary<int, long>
        {
            { 5, 1000L },
            { 6, 2000L },
            { 50, 3000L }
        };

        var (bytes, _) = PdfSignatureWriter.BuildXrefStream(
            offsets, xrefObjNum: 51, newTrailerSize: 52,
            catalogObjNum: 1, prevXRef: 500L, xrefStreamOffset: 4000L);

        string text = Encoding.Latin1.GetString(bytes);

        // Should have two groups: "5 2" (objects 5,6) and "50 2" (objects 50 + self-entry 51)
        text.Should().Contain("/Index [5 2 50 2]");
    }
}
