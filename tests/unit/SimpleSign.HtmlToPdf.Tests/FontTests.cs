using FluentAssertions;
using SimpleSign.HtmlToPdf.Fonts;
using Xunit;

namespace SimpleSign.HtmlToPdf.Tests;

public class FontTests
{
    // ── StandardFonts ───────────────────────────────────────────────────

    [Theory(DisplayName = "StandardFonts.Resolve: common families")]
    [InlineData("Helvetica", false, false, "Helvetica")]
    [InlineData("Helvetica", true, false, "Helvetica-Bold")]
    [InlineData("Helvetica", false, true, "Helvetica-Oblique")]
    [InlineData("Helvetica", true, true, "Helvetica-BoldOblique")]
    [InlineData("sans-serif", false, false, "Helvetica")]
    [InlineData("Arial", false, false, "Helvetica")]
    public void StandardFonts_Resolve_ReturnsPdfFontName(
        string family, bool bold, bool italic, string expected)
    {
        var result = StandardFonts.Resolve(family, bold, italic);

        result.Should().Be(expected);
    }

    [Theory(DisplayName = "StandardFonts.Resolve: serif fonts")]
    [InlineData("serif", false, false, "Times-Roman")]
    [InlineData("Times", false, false, "Times-Roman")]
    [InlineData("Times New Roman", true, false, "Times-Bold")]
    [InlineData("Times", false, true, "Times-Italic")]
    public void StandardFonts_Resolve_SerifFonts(
        string family, bool bold, bool italic, string expected)
    {
        var result = StandardFonts.Resolve(family, bold, italic);

        result.Should().Be(expected);
    }

    [Theory(DisplayName = "StandardFonts.Resolve: monospace fonts")]
    [InlineData("Courier", false, false, "Courier")]
    [InlineData("monospace", true, false, "Courier-Bold")]
    [InlineData("Courier New", false, true, "Courier-Oblique")]
    public void StandardFonts_Resolve_MonospaceFonts(
        string family, bool bold, bool italic, string expected)
    {
        var result = StandardFonts.Resolve(family, bold, italic);

        result.Should().Be(expected);
    }

    // ── TextMeasurer ────────────────────────────────────────────────────

    [Fact(DisplayName = "MeasureWidth: empty string returns zero")]
    public void MeasureWidth_EmptyString_ReturnsZero()
    {
        var width = TextMeasurer.MeasureWidth("", "Helvetica", 12f, false, false);

        width.Should().Be(0);
    }

    [Fact(DisplayName = "MeasureWidth: non-empty string returns positive value")]
    public void MeasureWidth_NonEmptyString_ReturnsPositiveValue()
    {
        var width = TextMeasurer.MeasureWidth("Hello World", "Helvetica", 12f, false, false);

        width.Should().BeGreaterThan(0);
    }

    [Fact(DisplayName = "MeasureWidth: larger font size produces wider text")]
    public void MeasureWidth_LargerFont_ProducesWiderText()
    {
        var small = TextMeasurer.MeasureWidth("Test", "Helvetica", 12f, false, false);
        var large = TextMeasurer.MeasureWidth("Test", "Helvetica", 24f, false, false);

        large.Should().BeGreaterThan(small);
    }

    [Fact(DisplayName = "MeasureWidth: longer text is wider")]
    public void MeasureWidth_LongerText_IsWider()
    {
        var short_ = TextMeasurer.MeasureWidth("Hi", "Helvetica", 12f, false, false);
        var long_ = TextMeasurer.MeasureWidth("Hello World", "Helvetica", 12f, false, false);

        long_.Should().BeGreaterThan(short_);
    }

    // ── WrapText ────────────────────────────────────────────────────────

    [Fact(DisplayName = "WrapText: text fits in single line")]
    public void WrapText_TextFits_ReturnsSingleLine()
    {
        var lines = TextMeasurer.WrapText("Hi", 200f, "Helvetica", 12f, false, false);

        lines.Should().ContainSingle();
        lines[0].Should().Be("Hi");
    }

    [Fact(DisplayName = "WrapText: long text wraps into multiple lines")]
    public void WrapText_LongText_WrapsIntoMultipleLines()
    {
        var lines = TextMeasurer.WrapText(
            "This is a very long sentence that should definitely wrap across multiple lines when given a narrow width",
            100f, "Helvetica", 12f, false, false);

        lines.Should().HaveCountGreaterThan(1);
    }

    [Fact(DisplayName = "WrapText: empty text returns empty or single empty")]
    public void WrapText_EmptyText_HandlesGracefully()
    {
        var lines = TextMeasurer.WrapText("", 200f, "Helvetica", 12f, false, false);

        lines.Should().NotBeNull();
    }

    [Fact(DisplayName = "WrapText: single long word")]
    public void WrapText_SingleLongWord_DoesNotCrash()
    {
        var lines = TextMeasurer.WrapText(
            "Supercalifragilisticexpialidocious", 50f, "Helvetica", 12f, false, false);

        lines.Should().NotBeNull();
        lines.Should().NotBeEmpty();
    }

    // ── FitChars ────────────────────────────────────────────────────────

    [Fact(DisplayName = "FitChars: returns chars that fit in width")]
    public void FitChars_ReturnsCharsThatFit()
    {
        var count = TextMeasurer.FitChars("Hello World", 0, 200f, "Helvetica", 12f, false, false);

        count.Should().BeGreaterThan(0);
        count.Should().BeLessThanOrEqualTo("Hello World".Length);
    }

    [Fact(DisplayName = "FitChars: zero width returns zero")]
    public void FitChars_ZeroWidth_ReturnsZero()
    {
        var count = TextMeasurer.FitChars("Hello", 0, 0f, "Helvetica", 12f, false, false);

        count.Should().Be(0);
    }

    // ── FontMetrics ─────────────────────────────────────────────────────

    [Fact(DisplayName = "FontMetrics: Helvetica metrics exist")]
    public void FontMetrics_Helvetica_HasMetrics()
    {
        var width = FontMetrics.GetCharWidth("Helvetica", 'A');
        width.Should().BeGreaterThan(0);
    }

    [Fact(DisplayName = "FontMetrics: different chars have different widths")]
    public void FontMetrics_DifferentChars_HaveDifferentWidths()
    {
        var wideChar = FontMetrics.GetCharWidth("Helvetica", 'W');
        var narrowChar = FontMetrics.GetCharWidth("Helvetica", 'i');

        wideChar.Should().BeGreaterThan(narrowChar);
    }
}
