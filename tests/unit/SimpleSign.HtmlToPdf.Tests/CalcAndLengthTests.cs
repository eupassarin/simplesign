// Licensed to SimpleSign under the MIT License.

using Shouldly;
using SimpleSign.HtmlToPdf.Layout;
using SimpleSign.HtmlToPdf.Parsing;
using Xunit;
using static SimpleSign.HtmlToPdf.Tests.TestSupport;

namespace SimpleSign.HtmlToPdf.Tests;

[Trait("Category", "Unit")]
public sealed class CalcAndLengthTests
{
    private static readonly PageSettings Settings = new();

    private static LayoutBox Block(LayoutResult result, string id) =>
        AllBoxes(result).First(b => b.Type == LayoutBoxType.Block && b.Node?.GetAttribute("id") == id);

    // ── Parsing ──────────────────────────────────────────────────────────

    [Theory]
    [InlineData("calc(10px + 5pt)", 12.5f)]
    [InlineData("calc(2 * 3pt)", 6f)]
    [InlineData("calc(12pt / 4)", 3f)]
    [InlineData("calc((2pt + 4pt) * 2)", 12f)]
    [InlineData("calc(1em + 1pt)", 13f)]
    [InlineData("min(10pt, 20pt)", 10f)]
    [InlineData("max(10pt, 20pt, 5pt)", 20f)]
    [InlineData("clamp(10pt, 40pt, 30pt)", 30f)]
    [InlineData("clamp(10pt, 2pt, 30pt)", 10f)]
    [InlineData("calc(10pt + min(4pt, 8pt))", 14f)]
    [InlineData("CALC( 3pt  +  4pt )", 7f)]
    public void ParseLength_StaticMath_Evaluates(string value, float expected) =>
        CssParser.ParseLength(value, 12f)!.Value.ShouldBe(expected, 0.01f);

    [Theory]
    [InlineData("calc(10px +)")]
    [InlineData("calc(10px * 2px)")]
    [InlineData("calc(10px / 2px)")]
    [InlineData("calc(10px")]
    [InlineData("foo(10px)")]
    [InlineData("calc(10furlongs)")]
    [InlineData("clamp(1pt, 2pt)")]
    public void ParseLength_MalformedMath_ReturnsNull(string value) =>
        CssParser.ParseLength(value).ShouldBeNull();

    [Fact]
    public void ParseLength_PurePercentCalc_KeepsPercentEncoding()
    {
        float value = CssParser.ParseLength("calc(100% / 4)")!.Value;

        CssLength.IsPercent(value).ShouldBeTrue();
        CssLength.PercentOf(value).ShouldBe(25f, 0.01f);
    }

    [Fact]
    public void ParseLength_MixedPercentCalc_IsDeferred() =>
        CssParser.ParseLength("calc(100% - 20pt)").ShouldBeNull();

    [Fact]
    public void ParseLength_NegativeLength_IsNotAPercentage()
    {
        float value = CssParser.ParseLength("-10pt")!.Value;

        value.ShouldBe(-10f);
        CssLength.IsPercent(value).ShouldBeFalse();
    }

    [Fact]
    public void Cascade_MixedCalc_StoredUntilLayout()
    {
        HtmlNode root = Resolve("<div id='a'>x</div>", "#a { width: calc(100% - 20pt); width: 50pt; } div { margin-left: calc(10% + 1pt); }");
        ComputedStyle style = First(root, "div").ComputedStyle!;

        style.Width.ShouldBe(50f);
        style.Calcs.ShouldNotBeNull();
        style.Calcs!.Select(c => c.Key).ShouldBe(["margin-left"]);
    }

    // ── Layout ───────────────────────────────────────────────────────────

    [Fact]
    public void Width_CalcPercentMinusLength_ResolvesAgainstContainer()
    {
        LayoutResult result = LayoutHtml("<div id='a'>x</div>", "#a { width: calc(100% - 100pt); }");

        Block(result, "a").Width.ShouldBe(Settings.ContentWidth - 100f, 0.1f);
    }

    [Fact]
    public void Width_CalcInsideNestedContainer_UsesParentWidth()
    {
        LayoutResult result = LayoutHtml("<div style='width:300pt'><div id='a'>x</div></div>", "#a { width: calc(50% + 10pt); }");

        Block(result, "a").Width.ShouldBe(160f, 0.1f);
    }

    [Fact]
    public void Width_MinFunction_PicksSmaller()
    {
        LayoutResult result = LayoutHtml("<div id='a'>x</div><div style='width:200pt'><div id='b'>y</div></div>", "#a, #b { width: min(100%, 300pt); }");

        Block(result, "a").Width.ShouldBe(300f, 0.1f);
        Block(result, "b").Width.ShouldBe(200f, 0.1f);
    }

    [Fact]
    public void Width_Clamp_ResolvesPercentInMiddle()
    {
        LayoutResult result = LayoutHtml("<div id='a'>x</div>", "#a { width: clamp(100pt, 50%, 200pt); }");

        Block(result, "a").Width.ShouldBe(200f, 0.1f);
    }

    [Fact]
    public void Margin_CalcLeft_ShiftsBox()
    {
        LayoutResult result = LayoutHtml("<div style='width:400pt'><div id='a'>x</div></div>", "#a { margin-left: calc(25% + 10pt); }");

        Block(result, "a").X.ShouldBe(Settings.Margins.Left + 110f, 0.1f);
    }

    [Fact]
    public void Padding_Calc_IsResolvedForRenderer()
    {
        LayoutResult result = LayoutHtml("<div style='width:200pt'><div id='a'>x</div></div>", "#a { padding-left: calc(10% + 5pt); }");

        LayoutBox box = Block(result, "a");
        box.Style.Padding.Left.ShouldBe(25f, 0.1f);
        Text(result, "x").X.ShouldBe(Settings.Margins.Left + 25f, 0.1f);
    }

    [Fact]
    public void Flex_CalcBasis_SplitsRow()
    {
        LayoutResult result = LayoutHtml(
            "<div style='display:flex;width:400pt'><div id='a'>a</div><div id='b'>b</div></div>",
            "#a { flex: 0 0 calc(25% - 10pt); } #b { flex: 1; }");

        Block(result, "a").Width.ShouldBe(90f, 0.5f);
        Block(result, "b").X.ShouldBe(Settings.Margins.Left + 90f, 0.5f);
    }

    [Fact]
    public void SameNode_LaidOutAtTwoWidths_ResolvesEachTime()
    {
        // Intrinsic measurement lays the table cell out at probe widths first; the
        // final width must still come from the real container.
        LayoutResult result = LayoutHtml("<table style='width:400pt'><tr><td><div id='a'>x</div></td></tr></table>", "#a { width: calc(100% - 40pt); }");

        Block(result, "a").Width.ShouldBeLessThan(400f);
        Block(result, "a").Width.ShouldBeGreaterThan(300f);
    }

    [Fact]
    public void Margin_Percent_VerticalUsesWidth()
    {
        LayoutResult result = LayoutHtml("<div style='width:200pt'><div id='a'>x</div></div>", "#a { margin-top: 10%; }");

        Block(result, "a").Y.ShouldBe(20f, 0.1f);
    }

    [Fact]
    public void NegativeMargin_PullsBoxLeft()
    {
        LayoutResult result = LayoutHtml("<div style='margin-left:100pt'><div id='a'>x</div></div>", "#a { margin-left: -40pt; }");

        Block(result, "a").X.ShouldBe(Settings.Margins.Left + 60f, 0.1f);
    }

    [Fact]
    public void NegativeTextIndent_HangsFirstLine()
    {
        LayoutResult result = LayoutHtml("<p>first second</p>", "p { padding-left: 30pt; text-indent: -20pt; }");

        Text(result, "first").X.ShouldBe(Settings.Margins.Left + 10f, 0.1f);
    }

    [Fact]
    public void RelativeNegativeOffset_MovesUpAndLeft()
    {
        LayoutResult result = LayoutHtml("<p>before</p><p id='a'>moved</p>", "#a { position: relative; left: -5pt; top: -3pt; }");
        LayoutResult plain = LayoutHtml("<p>before</p><p id='a'>moved</p>");

        Text(result, "moved").X.ShouldBe(Text(plain, "moved").X - 5f, 0.1f);
        Text(result, "moved").Y.ShouldBe(Text(plain, "moved").Y - 3f, 0.1f);
    }
}
