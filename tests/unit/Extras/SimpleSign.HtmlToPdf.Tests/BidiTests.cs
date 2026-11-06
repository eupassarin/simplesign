// Licensed to SimpleSign under the MIT License.

using Shouldly;
using SimpleSign.HtmlToPdf.Layout;
using SimpleSign.HtmlToPdf.Parsing;
using Xunit;
using static SimpleSign.HtmlToPdf.Tests.TestSupport;

namespace SimpleSign.HtmlToPdf.Tests;

[Trait("Category", "Unit")]
public sealed class BidiTests
{
    private static readonly PageSettings Settings = new();

    private static LayoutResult Layout(string html, string css = "") =>
        LayoutHtml(html, "p { margin: 0; } " + css);

    // ── Algorithm ────────────────────────────────────────────────────────

    [Theory]
    [InlineData("hello", "L")]
    [InlineData("שלום", "R")]
    [InlineData("سلام", "R")]
    [InlineData("2024", "Number")]
    [InlineData("٢٠٢٤", "Number")]
    [InlineData("—", "Neutral")]
    [InlineData("(abc)", "L")]
    public void WordType_Classifies(string word, string expected) =>
        Bidi.WordType(word).ShouldBe(Enum.Parse<BidiType>(expected));

    [Fact]
    public void Levels_LtrParagraphWithRtlRun()
    {
        int[] levels = Bidi.ResolveLevels([BidiType.L, BidiType.R, BidiType.R, BidiType.L], rtlBase: false);

        levels.ShouldBe([0, 1, 1, 0]);
        Bidi.VisualOrder(levels).ShouldBe([0, 2, 1, 3]);
    }

    [Fact]
    public void Levels_RtlParagraphWithNumberAndLatin()
    {
        int[] levels = Bidi.ResolveLevels([BidiType.R, BidiType.Number, BidiType.L, BidiType.L], rtlBase: true);

        levels.ShouldBe([1, 2, 2, 2]);
        Bidi.VisualOrder(levels).ShouldBe([1, 2, 3, 0]);
    }

    [Fact]
    public void Levels_NeutralBetweenRtlWordsIsRtl()
    {
        int[] levels = Bidi.ResolveLevels([BidiType.R, BidiType.Neutral, BidiType.R], rtlBase: false);

        levels.ShouldBe([1, 1, 1]);
    }

    [Fact]
    public void Levels_NeutralBetweenMixedTakesBaseDirection() =>
        Bidi.ResolveLevels([BidiType.L, BidiType.Neutral, BidiType.R], rtlBase: true)[1].ShouldBe(1);

    [Fact]
    public void Mirror_SwapsBrackets() =>
        Bidi.Mirror("(a) [b] «c»").ShouldBe(")a( ]b[ »c«");

    // ── Cascade ──────────────────────────────────────────────────────────

    [Fact]
    public void DirAttribute_SetsRtlAndStartAlignsRight()
    {
        ComputedStyle style = First(Resolve("<p dir='rtl'>x</p>"), "p").ComputedStyle!;

        style.Rtl.ShouldBeTrue();
        style.EffectiveTextAlign.ShouldBe(TextAlign.Right);
    }

    [Fact]
    public void DirAuto_UsesFirstStrongCharacter()
    {
        HtmlNode root = Resolve("<p dir='auto'>123 שלום abc</p><p dir='auto'>abc שלום</p>");
        List<HtmlNode> ps = [.. root.Descendants("p")];

        ps[0].ComputedStyle!.Rtl.ShouldBeTrue();
        ps[1].ComputedStyle!.Rtl.ShouldBeFalse();
    }

    [Theory]
    [InlineData("text-align: start", TextAlign.Right)]
    [InlineData("text-align: end", TextAlign.Left)]
    [InlineData("text-align: left", TextAlign.Left)]
    [InlineData("text-align: center", TextAlign.Center)]
    public void TextAlign_LogicalValuesFollowDirection(string css, TextAlign expected) =>
        First(Resolve("<p>x</p>", $"p {{ direction: rtl; {css}; }}"), "p").ComputedStyle!.EffectiveTextAlign.ShouldBe(expected);

    [Fact]
    public void TextAlign_InheritsLogicalValue()
    {
        HtmlNode root = Resolve("<div style='text-align:end'><p dir='rtl'>x</p></div>");

        First(root, "p").ComputedStyle!.EffectiveTextAlign.ShouldBe(TextAlign.Left);
    }

    // ── Layout ───────────────────────────────────────────────────────────

    [Fact]
    public void RtlParagraph_FirstWordIsRightmost()
    {
        LayoutResult result = Layout("<p dir='rtl'>אחד שתיים שלוש</p>");

        LayoutBox first = Text(result, "אחד");
        LayoutBox last = Text(result, "שלוש");
        first.X.ShouldBeGreaterThan(last.X);
        first.Rtl.ShouldBeTrue();
        (first.X + first.Width).ShouldBe(Settings.Margins.Left + Settings.ContentWidth, 0.5f);
    }

    [Fact]
    public void LtrParagraph_RtlRunIsReversedInPlace()
    {
        LayoutResult result = Layout("<p>start אחד שתיים end</p>");

        Text(result, "start").X.ShouldBeLessThan(Text(result, "שתיים").X);
        Text(result, "שתיים").X.ShouldBeLessThan(Text(result, "אחד").X);
        Text(result, "אחד").X.ShouldBeLessThan(Text(result, "end").X);
    }

    [Fact]
    public void RtlParagraph_NumberStaysLeftToRight()
    {
        LayoutResult result = Layout("<p dir='rtl'>שנת 2024</p>");

        LayoutBox number = Text(result, "2024");
        number.Rtl.ShouldBeFalse();
        number.X.ShouldBeLessThan(Text(result, "שנת").X);
    }

    [Fact]
    public void RtlParagraph_TrailingPeriodGoesToTheLeft()
    {
        LayoutResult result = Layout("<p dir='rtl'>שנת 2024.</p>");

        Text(result, ".").X.ShouldBeLessThan(Text(result, "2024").X);
    }

    [Fact]
    public void RtlParagraph_JustifiedLastLineAlignsRight()
    {
        LayoutResult result = Layout("<p dir='rtl' style='text-align:justify'>שלום</p>");

        LayoutBox word = Text(result, "שלום");
        (word.X + word.Width).ShouldBe(Settings.Margins.Left + Settings.ContentWidth, 0.5f);
    }

    [Fact]
    public void LtrOnlyText_IsNotSplitOrReordered()
    {
        LayoutResult result = Layout("<p>Hello, world.</p>");

        Texts(result).Single().Text.ShouldBe("Hello, world.");
    }

    [Fact]
    public void Pdf_RtlWordDrawnWithMirroredBrackets()
    {
        byte[] pdf = HtmlToPdfConverter.Html("<p dir='rtl'>(سلام)</p>")
            .WithFont("Test Arabic", LoadFont("TestArabic"))
            .WithStylesheet("p { font-family: 'Test Arabic'; }")
            .Convert();

        // The shaped Arabic word is emitted as a glyph array.
        Decompressed(pdf).ShouldContain("] TJ");
    }
}
