using System.Text;
using Shouldly;
using SimpleSign.PAdES.Pdf.Writing;
using Xunit;

namespace SimpleSign.PAdES.Tests.Pdf.Writing;

[Trait("Category", "Unit")]
public sealed class PdfXmpPatchTests
{
    [Theory]
    [InlineData("<pdfaid:part>2</pdfaid:part>", "<pdfaid:part>3</pdfaid:part>")]
    [InlineData("<pdfaid:part>\n 2 </pdfaid:part>", "<pdfaid:part>\n 3 </pdfaid:part>")]
    [InlineData("pdfaid:part=\"2\"", "pdfaid:part=\"3\"")]
    [InlineData("pdfaid:part = '2'", "pdfaid:part = '3'")]
    [InlineData("xmlns:pdfaid=\"x\" pdfaid:part='2'", "xmlns:pdfaid=\"x\" pdfaid:part='3'")]
    public void SetPdfAPart_ElementOrAttribute_ChangesOnlyTheDigit(string xmp, string expected) =>
        Encoding.ASCII.GetString(PdfXmpPatch.SetPdfAPart(Encoding.ASCII.GetBytes(xmp), 3)!).ShouldBe(expected);

    [Theory]
    [InlineData("<pdfaid:conformance>B</pdfaid:conformance>")]
    [InlineData("<pdfaid:part>12</pdfaid:part>")]
    [InlineData("<pdfaid:part>x</pdfaid:part>")]
    public void SetPdfAPart_NoSingleDigitPart_ReturnsNull(string xmp) =>
        PdfXmpPatch.SetPdfAPart(Encoding.ASCII.GetBytes(xmp), 3).ShouldBeNull();
}
