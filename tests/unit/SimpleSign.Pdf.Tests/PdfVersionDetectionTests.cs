using Shouldly;
using Xunit;

namespace SimpleSign.Pdf.Tests;

/// <summary>
/// Unit tests for PdfStructureReader.DetectPdfVersion.
/// </summary>
public sealed class PdfVersionDetectionTests
{
    [Theory]
    [InlineData("%PDF-1.7\n", PdfVersion.Pdf17)]
    [InlineData("%PDF-2.0\n", PdfVersion.Pdf20)]
    [InlineData("%PDF-1.4\n", PdfVersion.Pdf14)]
    [InlineData("%PDF-1.0\n", PdfVersion.Pdf10)]
    [InlineData("%PDF-1.5\n", PdfVersion.Pdf15)]
    [InlineData("%PDF-1.6\n", PdfVersion.Pdf16)]
    public void DetectPdfVersion_ValidHeaders_ReturnsExpectedVersion(string header, PdfVersion expected)
    {
        var data = System.Text.Encoding.ASCII.GetBytes(header);
        PdfStructureReader.DetectPdfVersion(data).ShouldBe(expected);
    }

    [Theory]
    [InlineData("")]
    [InlineData("not a pdf")]
    [InlineData("%PDF")]
    [InlineData("%PDF-")]
    [InlineData("%PDF-1")]
    [InlineData("%PDF-1.")]
    [InlineData("%PDF-X.Y")]
    [InlineData("%PDF-3.0")]
    public void DetectPdfVersion_InvalidHeaders_ReturnsUnknown(string header)
    {
        var data = System.Text.Encoding.ASCII.GetBytes(header);
        PdfStructureReader.DetectPdfVersion(data).ShouldBe(PdfVersion.Unknown);
    }

    [Fact]
    public void DetectPdfVersion_SpanOverload_WorksWithReadOnlySpan()
    {
        ReadOnlySpan<byte> data = "%PDF-2.0\n%some binary"u8;
        PdfStructureReader.DetectPdfVersion(data).ShouldBe(PdfVersion.Pdf20);
    }

    [Fact]
    public void DetectPdfVersion_NullByteArray_ThrowsArgumentNullException()
    {
        byte[]? nullData = null;
        var act = () => { PdfStructureReader.DetectPdfVersion(nullData!); };
        Should.Throw<ArgumentNullException>(act);
    }
}
