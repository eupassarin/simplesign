using System.Text;
using FluentAssertions;
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
}
