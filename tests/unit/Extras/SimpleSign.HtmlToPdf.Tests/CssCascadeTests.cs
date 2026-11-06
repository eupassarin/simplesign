// Licensed to SimpleSign under the MIT License.

using Shouldly;
using SimpleSign.HtmlToPdf.Parsing;
using Xunit;
using static SimpleSign.HtmlToPdf.Tests.TestSupport;

namespace SimpleSign.HtmlToPdf.Tests;

[Trait("Category", "Unit")]
public sealed class CssCascadeTests
{
    private static PdfColor ColorOf(HtmlNode root, string id) =>
        root.Descendants("*").Concat(Walk(root)).First(n => n.GetAttribute("id") == id).ComputedStyle!.Color;

    private static IEnumerable<HtmlNode> Walk(HtmlNode node)
    {
        foreach (HtmlNode child in node.Children)
        {
            yield return child;
            foreach (HtmlNode descendant in Walk(child))
            {
                yield return descendant;
            }
        }
    }

    private static bool IsRed(PdfColor c) => c.R > 0.99f && c.G < 0.01f && c.B < 0.01f;

    [Theory]
    [InlineData("div > p", "<div><p id='t'>x</p></div>", true)]
    [InlineData("div > p", "<div><section><p id='t'>x</p></section></div>", false)]
    [InlineData("h1 + p", "<h1>a</h1><p id='t'>x</p>", true)]
    [InlineData("h1 + p", "<h1>a</h1><div></div><p id='t'>x</p>", false)]
    [InlineData("h1 ~ p", "<h1>a</h1><div></div><p id='t'>x</p>", true)]
    [InlineData("a[href]", "<a id='t' href='x'>x</a>", true)]
    [InlineData("a[href]", "<a id='t'>x</a>", false)]
    [InlineData("a[href^='https']", "<a id='t' href='https://x'>x</a>", true)]
    [InlineData("a[href$='.pdf']", "<a id='t' href='doc.pdf'>x</a>", true)]
    [InlineData("a[href*='exam']", "<a id='t' href='http://example.com'>x</a>", true)]
    [InlineData("[lang|=pt]", "<p id='t' lang='pt-BR'>x</p>", true)]
    [InlineData("[class~=b]", "<p id='t' class='a b c'>x</p>", true)]
    [InlineData("[data-x='Y' i]", "<p id='t' data-x='y'>x</p>", true)]
    [InlineData("li:first-child", "<ul><li id='t'>a</li><li>b</li></ul>", true)]
    [InlineData("li:last-child", "<ul><li>a</li><li id='t'>b</li></ul>", true)]
    [InlineData("li:only-child", "<ul><li id='t'>a</li></ul>", true)]
    [InlineData("li:nth-child(2)", "<ul><li>a</li><li id='t'>b</li></ul>", true)]
    [InlineData("li:nth-child(odd)", "<ul><li>a</li><li id='t'>b</li></ul>", false)]
    [InlineData("li:nth-child(even)", "<ul><li>a</li><li id='t'>b</li></ul>", true)]
    [InlineData("li:nth-child(3n+1)", "<ul><li>a</li><li>b</li><li>c</li><li id='t'>d</li></ul>", true)]
    [InlineData("li:nth-child(-n+2)", "<ul><li>a</li><li>b</li><li id='t'>c</li></ul>", false)]
    [InlineData("li:nth-last-child(1)", "<ul><li>a</li><li id='t'>b</li></ul>", true)]
    [InlineData("p:first-of-type", "<div><h1>x</h1><p id='t'>a</p><p>b</p></div>", true)]
    [InlineData("p:last-of-type", "<div><p>a</p><p id='t'>b</p><span>c</span></div>", true)]
    [InlineData("p:not(.skip)", "<p id='t' class='keep'>x</p>", true)]
    [InlineData("p:not(.skip)", "<p id='t' class='skip'>x</p>", false)]
    [InlineData("*", "<p id='t'>x</p>", true)]
    [InlineData("p:empty", "<p id='t'></p>", true)]
    [InlineData("a:hover", "<a id='t' href='x'>x</a>", false)]
    public void Selector_Matching_FollowsCss(string selector, string html, bool matches)
    {
        HtmlNode root = Resolve(html, selector + " { color: red; }");

        IsRed(ColorOf(root, "t")).ShouldBe(matches);
    }

    [Theory]
    [InlineData("#a", 100)]
    [InlineData(".a.b", 20)]
    [InlineData("div > p.x", 12)]
    [InlineData("a[href]:hover", 21)]
    [InlineData("li:not(#x)", 101)]
    [InlineData("p::before", 2)]
    public void CalculateSpecificity_ComplexSelectors_WeightsComponents(string selector, int expected) =>
        CssParser.CalculateSpecificity(selector).ShouldBe(expected);

    [Fact]
    public void Resolve_EqualSpecificity_LaterRuleWins()
    {
        HtmlNode root = Resolve("<p id='t' class='a'>x</p>", ".a { color: blue; } .a { color: red; }");

        IsRed(ColorOf(root, "t")).ShouldBeTrue();
    }

    [Fact]
    public void Resolve_HigherSpecificity_WinsOverSourceOrder()
    {
        HtmlNode root = Resolve("<p id='t' class='a'>x</p>", "#t { color: red; } .a { color: blue; }");

        IsRed(ColorOf(root, "t")).ShouldBeTrue();
    }

    [Fact]
    public void Resolve_Important_BeatsInlineStyle()
    {
        HtmlNode root = Resolve("<p id='t' style='color: blue'>x</p>", "p { color: red !important; }");

        IsRed(ColorOf(root, "t")).ShouldBeTrue();
    }

    [Fact]
    public void Resolve_InlineStyle_BeatsIdSelector()
    {
        HtmlNode root = Resolve("<p id='t' style='color: red'>x</p>", "#t { color: blue; }");

        IsRed(ColorOf(root, "t")).ShouldBeTrue();
    }

    [Fact]
    public void Resolve_CustomProperties_SubstituteAndInherit()
    {
        HtmlNode root = Resolve("<div><p id='t'>x</p></div>", ":root, html { --brand: #ff0000; } p { color: var(--brand); }");

        IsRed(ColorOf(root, "t")).ShouldBeTrue();
    }

    [Fact]
    public void Resolve_CustomPropertyFallback_UsedWhenUndefined()
    {
        HtmlNode root = Resolve("<p id='t'>x</p>", "p { color: var(--missing, red); }");

        IsRed(ColorOf(root, "t")).ShouldBeTrue();
    }

    [Fact]
    public void Resolve_CurrentColorInBorder_UsesTextColor()
    {
        HtmlNode root = Resolve("<p id='t'>x</p>", "p { color: red; border: 1px solid currentColor; }");

        HtmlNode p = First(root, "p");
        IsRed(p.ComputedStyle!.Border.TopColor).ShouldBeTrue();
    }

    [Fact]
    public void Resolve_InheritKeyword_CopiesParentValue()
    {
        HtmlNode root = Resolve("<div style='color:red'><a id='t' href='x'>x</a></div>", "a { color: inherit; }");

        IsRed(ColorOf(root, "t")).ShouldBeTrue();
    }

    [Fact]
    public void Resolve_EmUnits_UseOwnFontSizeForMargins()
    {
        HtmlNode root = Resolve("<p>x</p>", "p { font-size: 20pt; margin-top: 1em; }");

        First(root, "p").ComputedStyle!.Margin.Top.ShouldBe(20f, 0.01f);
    }

    [Fact]
    public void Resolve_FontShorthand_ExpandsAllParts()
    {
        HtmlNode root = Resolve("<p>x</p>", "p { font: italic bold 16px/2 Georgia, serif; }");

        ComputedStyle style = First(root, "p").ComputedStyle!;
        style.IsItalic.ShouldBeTrue();
        style.IsBold.ShouldBeTrue();
        style.FontSize.ShouldBe(12f, 0.01f);
        style.LineHeight.ShouldBe(2f, 0.01f);
        style.FontFamilies.ShouldBe(["Georgia", "serif"]);
    }

    [Fact]
    public void Resolve_BorderShorthandWithStyle_SetsLineStyle()
    {
        HtmlNode root = Resolve("<p>x</p>", "p { border: 2px dashed #00f; border-left: none; }");

        BorderStyle border = First(root, "p").ComputedStyle!.Border;
        border.TopStyle.ShouldBe(BorderLineStyle.Dashed);
        border.TopWidth.ShouldBe(1.5f, 0.01f);
        border.LeftWidth.ShouldBe(0f);
    }

    [Fact]
    public void Resolve_LonghandAfterShorthand_Wins()
    {
        HtmlNode root = Resolve("<p>x</p>", "p { margin: 10px; margin-left: 0; }");

        Thickness margin = First(root, "p").ComputedStyle!.Margin;
        margin.Left.ShouldBe(0f);
        margin.Top.ShouldBe(7.5f, 0.01f);
    }

    [Fact]
    public void Resolve_MarginAuto_SetsAutoFlags()
    {
        HtmlNode root = Resolve("<div>x</div>", "div { margin: 0 auto; width: 50%; }");

        ComputedStyle style = First(root, "div").ComputedStyle!;
        style.MarginLeftAuto.ShouldBeTrue();
        style.MarginRightAuto.ShouldBeTrue();
    }

    [Fact]
    public void Resolve_MediaPrint_AppliesAndMediaScreenDoesNot()
    {
        HtmlNode root = Resolve("<p id='t'>x</p>", "@media screen { p { color: blue; } } @media print { p { color: red; } }");

        IsRed(ColorOf(root, "t")).ShouldBeTrue();
    }

    [Fact]
    public void Resolve_HeadStyleScriptAndTitle_AreHidden()
    {
        HtmlNode root = Resolve("<html><head><title>T</title><style>p{}</style><script>x()</script></head><body><p>x</p></body></html>");

        First(root, "head").ComputedStyle!.Display.ShouldBe(DisplayType.None);
        First(root, "style").ComputedStyle!.Display.ShouldBe(DisplayType.None);
        First(root, "script").ComputedStyle!.Display.ShouldBe(DisplayType.None);
    }

    [Fact]
    public void Resolve_BeforeAndAfterContent_CreatePseudoElements()
    {
        HtmlNode root = Resolve("<h2 data-n='7'>Title</h2>", "h2::before { content: '§ ' attr(data-n) ' '; color: red; } h2::after { content: \"\\2713\"; }");

        HtmlNode h2 = First(root, "h2");
        h2.Children[0].IsPseudo.ShouldBeTrue();
        h2.Children[0].Children[0].Text.ShouldBe("§ 7 ");
        IsRed(h2.Children[0].ComputedStyle!.Color).ShouldBeTrue();
        h2.Children[^1].Children[0].Text.ShouldBe("✓");
    }

    [Fact]
    public void Resolve_CalledTwice_DoesNotDuplicatePseudoElements()
    {
        HtmlNode root = HtmlTokenizer.Parse("<p>x</p>");
        List<CssRule> rules = CssParser.ParseStylesheet("p::before { content: '>'; }");
        StyleResolver.Resolve(root, rules);
        StyleResolver.Resolve(root, rules);

        First(root, "p").Children.Count(c => c.IsPseudo).ShouldBe(1);
    }

    [Fact]
    public void Resolve_PresentationalAttributes_MapToStyle()
    {
        HtmlNode root = Resolve("<table border='1' cellpadding='10' bgcolor='#ff0000'><tr><td align='right' valign='bottom' width='50%'>x</td></tr></table><font color='red' size='5' face='Courier'>f</font>");

        ComputedStyle table = First(root, "table").ComputedStyle!;
        IsRed(table.BackgroundColor!.Value).ShouldBeTrue();
        table.Border.TopWidth.ShouldBeGreaterThan(0);
        ComputedStyle td = First(root, "td").ComputedStyle!;
        td.TextAlign.ShouldBe(TextAlign.Right);
        td.VerticalAlign.ShouldBe(VerticalAlign.Bottom);
        td.Width.ShouldBe(CssLength.Percent(50));
        td.Padding.Left.ShouldBe(7.5f, 0.01f);
        ComputedStyle font = First(root, "font").ComputedStyle!;
        IsRed(font.Color).ShouldBeTrue();
        font.FontSize.ShouldBe(18f);
        font.FontFamily.ShouldBe("Courier");
    }

    [Fact]
    public void Resolve_CssOverridesPresentationalAttributes()
    {
        HtmlNode root = Resolve("<p align='right'>x</p>", "p { text-align: center; }");

        First(root, "p").ComputedStyle!.TextAlign.ShouldBe(TextAlign.Center);
    }

    [Fact]
    public void Resolve_NestedUnorderedLists_UseDiscCircleSquare()
    {
        HtmlNode root = Resolve("<ul><li>a<ul><li>b<ul><li>c</li></ul></li></ul></li></ul>");

        List<HtmlNode> lists = [.. root.Descendants("ul")];
        lists.Select(l => l.ComputedStyle!.ListStyleType).ShouldBe(["disc", "circle", "square"]);
    }

    [Fact]
    public void Resolve_UnknownElements_AreInline()
    {
        HtmlNode root = Resolve("<p><x-tag>a</x-tag><label>b</label></p>");

        First(root, "x-tag").ComputedStyle!.Display.ShouldBe(DisplayType.Inline);
        First(root, "label").ComputedStyle!.Display.ShouldBe(DisplayType.Inline);
    }

    [Theory]
    [InlineData("rgba(255, 0, 0, 0)", true)]
    [InlineData("#ff000000", true)]
    [InlineData("transparent", true)]
    [InlineData("rgb(255 0 0 / 50%)", false)]
    public void PdfColor_AlphaValues_CompositeOrBecomeTransparent(string css, bool transparent) =>
        PdfColor.Parse(css).IsTransparent.ShouldBe(transparent);

    [Theory]
    [InlineData("rebeccapurple", 0.4f, 0.2f, 0.6f)]
    [InlineData("#0f0", 0f, 1f, 0f)]
    [InlineData("hsl(0deg 100% 50%)", 1f, 0f, 0f)]
    public void PdfColor_ExtendedSyntax_Parses(string css, float r, float g, float b)
    {
        PdfColor color = PdfColor.Parse(css);

        color.R.ShouldBe(r, 0.01f);
        color.G.ShouldBe(g, 0.01f);
        color.B.ShouldBe(b, 0.01f);
    }

    [Theory]
    [InlineData("1in", 72f)]
    [InlineData("2pc", 24f)]
    [InlineData("4q", 2.8346f)]
    [InlineData("thin", 0.75f)]
    public void ParseLength_AdditionalUnits_ConvertToPoints(string value, float expected) =>
        CssParser.ParseLength(value)!.Value.ShouldBe(expected, 0.01f);

    [Fact]
    public void ParseStylesheet_StringsWithBracesAndSemicolons_AreNotSplit()
    {
        List<CssRule> rules = CssParser.ParseStylesheet("p::before { content: 'a;b}c'; color: red; } span { color: blue; }");

        rules.Count.ShouldBe(2);
        rules[0].Properties["content"].ShouldBe("'a;b}c'");
        rules[0].Properties["color"].ShouldBe("red");
    }

    [Fact]
    public void ParseStylesheet_InvalidSelector_IsSkippedWithoutBreakingOthers()
    {
        List<CssRule> rules = CssParser.ParseStylesheet("p::first-line { color: red; } p { color: blue; }");

        rules.Count.ShouldBe(1);
        rules[0].Selector.ShouldBe("p");
    }

    [Fact]
    public void ParseStylesheet_PageAndFontFaceRules_AreExposed()
    {
        List<CssRule> rules = CssParser.ParseStylesheet("@page { size: A5; margin: 1cm; } @font-face { font-family: X; src: url(data:font/ttf;base64,AAAA); }");

        rules.ShouldContain(r => r.Selector == CssParser.PageRuleSelector && r.Properties["size"] == "A5");
        rules.ShouldContain(r => r.Selector == CssParser.FontFaceRuleSelector && r.Properties["src"].Contains("base64,AAAA"));
    }
}
