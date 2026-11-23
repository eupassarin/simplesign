using Shouldly;
using SimpleSign.PAdES.Pdf.Model;
using Xunit;

namespace SimpleSign.PAdES.Tests.Pdf.Model;

[Trait("Category", "Unit")]
public sealed class PdfTextTests
{
    [Fact]
    public void Decode_Utf16BeBom_DecodesBigEndian() =>
        PdfText.Decode([0xFE, 0xFF, 0x00, 0x41, 0x20, 0xAC]).ShouldBe("A€");

    [Fact]
    public void Decode_Utf16LeBom_DecodesLittleEndian() =>
        PdfText.Decode([0xFF, 0xFE, 0x41, 0x00]).ShouldBe("A");

    [Fact]
    public void Decode_Utf8Bom_DecodesUtf8() =>
        PdfText.Decode([0xEF, 0xBB, 0xBF, 0xC3, 0xA9]).ShouldBe("é");

    [Fact]
    public void Decode_OddUtf16Length_DropsTheLastByte() =>
        PdfText.Decode([0xFE, 0xFF, 0x00, 0x41, 0x00]).ShouldBe("A");

    [Theory]
    [InlineData(0x80, '•')]
    [InlineData(0xA0, '€')]
    [InlineData(0x18, '˘')]
    [InlineData(0x7F, '�')]
    [InlineData(0xE9, 'é')]
    [InlineData(0x41, 'A')]
    public void Decode_PdfDocEncoding_MapsAnnexD(byte b, char expected) =>
        PdfText.Decode([b]).ShouldBe(expected.ToString());

    [Fact]
    public void Decode_Empty_IsEmpty() => PdfText.Decode([]).ShouldBeEmpty();

    [Theory]
    [InlineData("D:20261123120000-03'00'", -180)]
    [InlineData("D:20261123120000+05'30'", 330)]
    [InlineData("D:20261123120000Z", 0)]
    [InlineData("20261123120000", 0)]
    [InlineData("D:20261123120000+05", 0)]
    public void ParseDate_ValidDate_ReadsItWithItsOffset(string text, int offsetMinutes) =>
        PdfText.ParseDate(text).ShouldBe(new DateTimeOffset(2026, 11, 23, 12, 0, 0, TimeSpan.FromMinutes(offsetMinutes)));

    [Theory]
    [InlineData("D:2026")]
    [InlineData("D:2026112312000x")]
    [InlineData("D:20261399000000")]
    [InlineData("yesterday")]
    public void ParseDate_InvalidDate_ReturnsNull(string text) => PdfText.ParseDate(text).ShouldBeNull();
}
