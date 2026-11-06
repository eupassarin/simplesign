// Licensed to SimpleSign under the MIT License.

using Shouldly;
using SimpleSign.HtmlToPdf.Layout;
using Xunit;
using static SimpleSign.HtmlToPdf.Tests.TestSupport;

namespace SimpleSign.HtmlToPdf.Tests;

[Trait("Category", "Unit")]
public sealed class LayoutFeatureTests
{
    private static readonly PageSettings Settings = new();

    private const string Lorem = "Lorem ipsum dolor sit amet consectetur adipiscing elit sed do eiusmod tempor incididunt ut labore et dolore magna aliqua ";

    // ── Floats & clear ───────────────────────────────────────────────────

    [Fact]
    public void FloatRight_TextWrapsBesideIt()
    {
        LayoutResult result = LayoutHtml($"<div class='f'>FLOAT</div><p>{Lorem}{Lorem}</p>", ".f { float: right; width: 150pt; height: 60pt; }");

        LayoutBox floatText = Text(result, "FLOAT");
        floatText.X.ShouldBeGreaterThan(Settings.Margins.Left + Settings.ContentWidth - 151f);
        LayoutBox firstLine = Text(result, "Lorem");
        (firstLine.X + firstLine.Width).ShouldBeLessThanOrEqualTo(floatText.X + 0.5f);
    }

    [Fact]
    public void FloatLeft_TextStartsAfterFloat_AndReturnsBelowIt()
    {
        LayoutResult result = LayoutHtml($"<div class='f'>F</div><p>{Lorem}{Lorem}{Lorem}{Lorem}</p>", ".f { float: left; width: 100pt; height: 30pt; }");

        List<LayoutBox> lines = [.. Texts(result).Where(t => t.Text != "F")];
        lines[0].X.ShouldBeGreaterThanOrEqualTo(Settings.Margins.Left + 100f);
        lines[^1].X.ShouldBe(Settings.Margins.Left, 0.5f);
    }

    [Fact]
    public void Clear_MovesBelowFloat()
    {
        LayoutResult result = LayoutHtml("<div class='f'>F</div><p class='c'>cleared</p>", ".f { float: left; width: 50pt; height: 100pt; } .c { clear: both; margin: 0; }");

        Text(result, "cleared").Y.ShouldBeGreaterThanOrEqualTo(100f);
    }

    [Fact]
    public void Clearfix_PseudoElement_ContainsFloats()
    {
        LayoutResult result = LayoutHtml(
            "<div class='row'><div class='col'>A</div><div class='col'>B</div></div><p>after</p>",
            ".row::after { content: ''; display: table; clear: both; } .col { float: left; width: 50%; height: 80pt; } p { margin: 0; }");

        Text(result, "A").Y.ShouldBe(Text(result, "B").Y, 0.5f);
        Text(result, "B").X.ShouldBeGreaterThan(Text(result, "A").X + 200f);
        Text(result, "after").Y.ShouldBeGreaterThanOrEqualTo(80f);
    }

    [Fact]
    public void OverflowHidden_ContainsFloatsInItsHeight()
    {
        LayoutResult result = LayoutHtml("<div class='bfc'><div class='f'>F</div></div><p>after</p>", ".bfc { overflow: hidden; } .f { float: left; height: 90pt; } p { margin: 0; }");

        Text(result, "after").Y.ShouldBeGreaterThanOrEqualTo(90f);
    }

    // ── Positioning ──────────────────────────────────────────────────────

    [Fact]
    public void PositionRelative_ShiftsBoxWithoutAffectingFlow()
    {
        LayoutResult result = LayoutHtml("<p class='r'>moved</p><p>next</p>", "p { margin: 0; } .r { position: relative; left: 20pt; top: 10pt; }");

        Text(result, "moved").X.ShouldBe(Settings.Margins.Left + 20f, 0.5f);
        Text(result, "next").Y.ShouldBeLessThan(Text(result, "moved").Y + 10f);
    }

    [Fact]
    public void PositionAbsolute_PlacedInsidePositionedAncestor()
    {
        LayoutResult result = LayoutHtml(
            "<div class='box'><span class='badge'>NEW</span><p>content</p></div>",
            ".box { position: relative; margin-left: 50pt; height: 100pt; } .badge { position: absolute; right: 0; top: 0; } p { margin: 0; }");

        LayoutBox badge = Text(result, "NEW");
        (badge.X + badge.Width).ShouldBe(Settings.Margins.Left + Settings.ContentWidth, 1f);
        badge.Y.ShouldBeLessThan(5f);
        Text(result, "content").X.ShouldBe(Settings.Margins.Left + 50f, 0.5f);
    }

    [Fact]
    public void PositionFixed_RepeatsOnEveryPage()
    {
        string pages = "<p>one</p><p style='page-break-before:always'>two</p><p style='page-break-before:always'>three</p>";
        LayoutResult result = LayoutHtml($"<div class='wm'>CONFIDENTIAL</div>{pages}", ".wm { position: fixed; bottom: 0; left: 0; }");

        result.Pages.Count.ShouldBe(3);
        result.Pages.ShouldAllBe(p => p.Boxes.Any(b => b.Text == "CONFIDENTIAL"));
    }

    // ── Inline formatting ────────────────────────────────────────────────

    [Fact]
    public void TextAlignJustify_StretchesAllButLastLine()
    {
        LayoutResult result = LayoutHtml($"<p style='text-align:justify'>{Lorem}{Lorem}{Lorem}</p>");

        List<LayoutBox> boxes = Texts(result);
        float right = Settings.Margins.Left + Settings.ContentWidth;
        float firstLineY = boxes[0].Y;
        LayoutBox lastOfFirstLine = boxes.Last(b => Math.Abs(b.Y - firstLineY) < 0.01f);
        (lastOfFirstLine.X + lastOfFirstLine.Width).ShouldBe(right, 0.5f);
        LayoutBox lastBox = boxes[^1];
        (lastBox.X + lastBox.Width).ShouldBeLessThan(right - 5f);
    }

    [Fact]
    public void TextIndent_IndentsOnlyFirstLine()
    {
        LayoutResult result = LayoutHtml($"<p style='text-indent:30pt'>{Lorem}{Lorem}</p>");

        List<LayoutBox> boxes = Texts(result);
        boxes[0].X.ShouldBe(Settings.Margins.Left + 30f, 0.5f);
        boxes[^1].X.ShouldBe(Settings.Margins.Left, 0.5f);
    }

    [Fact]
    public void MixedFontSizes_ShareBaseline()
    {
        LayoutResult result = LayoutHtml("<p>small <span style='font-size:30pt'>BIG</span> tail</p>");

        LayoutBox small = Text(result, "small");
        LayoutBox big = Text(result, "BIG");
        float smallBaseline = small.Y + (small.Style.FontSize * 0.8f);
        float bigBaseline = big.Y + (big.Style.FontSize * 0.8f);
        smallBaseline.ShouldBe(bigBaseline, 0.01f);
    }

    [Fact]
    public void InlineBackground_IsRecordedOnTextBoxes()
    {
        LayoutResult result = LayoutHtml("<p>plain <span style='background:yellow'>marked text</span></p>");

        Text(result, "marked").InlineBackground.ShouldNotBeNull();
        Text(result, "plain").InlineBackground.ShouldBeNull();
    }

    [Fact]
    public void InlineBlock_IsPlacedOnTheLine()
    {
        LayoutResult result = LayoutHtml("<p>before <span class='b'>badge</span> after</p>", ".b { display: inline-block; padding: 4pt; background: #0a4; border: 1px solid #000; }");

        LayoutBox before = Text(result, "before");
        LayoutBox badge = Text(result, "badge");
        LayoutBox after = Text(result, "after");
        badge.X.ShouldBeGreaterThan(before.X + before.Width);
        after.X.ShouldBeGreaterThan(badge.X + badge.Width);
        AllBoxes(result).ShouldContain(b => b.Type == LayoutBoxType.Block && b.Node!.Tag == "span" && b.Style.BackgroundColor != null);
    }

    [Fact]
    public void InlineImage_SitsOnTheTextLine()
    {
        string src = DataUri(RgbPng());
        LayoutResult result = LayoutHtml($"<p>left <img src='{src}' width='16' height='16'> right</p>");

        LayoutBox image = AllBoxes(result).Single(b => b.Type == LayoutBoxType.Image);
        LayoutBox left = Text(result, "left");
        LayoutBox right = Text(result, "right");
        image.X.ShouldBeGreaterThan(left.X + left.Width);
        right.X.ShouldBeGreaterThan(image.X + image.Width);
        (image.Y + image.Height).ShouldBe(left.Y + (left.Style.FontSize * 0.8f), 0.5f);
    }

    [Fact]
    public void LinkedImage_CarriesLinkUrl()
    {
        LayoutResult result = LayoutHtml($"<a href='https://x.y'><img src='{DataUri(RgbPng())}'></a>");

        AllBoxes(result).Single(b => b.Type == LayoutBoxType.Image).LinkUrl.ShouldBe("https://x.y");
    }

    [Fact]
    public void NoBreakSpace_KeepsWordsTogether()
    {
        LayoutResult result = LayoutHtml("<p style='width:60pt'>R$ 1.000,00 R$ 2.000,00</p>");

        Texts(result).ShouldContain(t => t.Text!.Contains("R$ 1.000,00", StringComparison.Ordinal));
    }

    [Fact]
    public void Orphans_ParagraphNotSplitWithSingleLineAtPageBottom()
    {
        string filler = string.Concat(Enumerable.Range(0, 34).Select(i => $"<p style='margin:0'>filler {i}</p>"));
        LayoutResult result = LayoutHtml($"{filler}<p style='margin:0;orphans:3'>{Lorem}{Lorem}{Lorem}{Lorem}{Lorem}</p>");

        int firstPage = result.Pages.FindIndex(p => p.Boxes.Any(b => b.Text?.StartsWith("Lorem", StringComparison.Ordinal) == true));
        int linesOnFirstPage = result.Pages[firstPage].Boxes.Count(b => b.Text?.Contains("ipsum", StringComparison.Ordinal) == true || b.Text?.Contains("tempor", StringComparison.Ordinal) == true);
        (linesOnFirstPage == 0 || linesOnFirstPage >= 2).ShouldBeTrue();
    }

    [Fact]
    public void Widows_AtLeastTwoLinesCarriedToNextPage()
    {
        string filler = string.Concat(Enumerable.Range(0, 35).Select(i => $"<p style='margin:0'>filler {i}</p>"));
        LayoutResult result = LayoutHtml($"{filler}<p style='margin:0'>{Lorem}{Lorem}{Lorem}</p>");

        if (result.Pages.Count > 1)
        {
            int linesOnLastPage = result.Pages[^1].Boxes.Count(b => b.Type == LayoutBoxType.InlineText);
            linesOnLastPage.ShouldBeGreaterThanOrEqualTo(2);
        }
    }

    // ── Block sizing ─────────────────────────────────────────────────────

    [Fact]
    public void MarginAuto_CentersFixedWidthBlock()
    {
        LayoutResult result = LayoutHtml("<div class='c'>centered</div>", ".c { width: 200pt; margin: 0 auto; }");

        LayoutBox block = AllBoxes(result).First(b => b.Node?.Tag == "div");
        (block.X - Settings.Margins.Left).ShouldBe((Settings.ContentWidth - 200f) / 2, 0.5f);
    }

    [Fact]
    public void BoxSizingBorderBox_IncludesPaddingInWidth()
    {
        LayoutResult result = LayoutHtml("<div class='c'>x</div>", ".c { box-sizing: border-box; width: 200pt; padding: 0 20pt; }");

        AllBoxes(result).First(b => b.Node?.Tag == "div").Width.ShouldBe(160f, 0.01f);
    }

    [Fact]
    public void MinHeight_ExtendsShortBlock()
    {
        LayoutResult result = LayoutHtml("<div class='c'>x</div><p style='margin:0'>after</p>", ".c { min-height: 200pt; }");

        Text(result, "after").Y.ShouldBeGreaterThanOrEqualTo(200f);
    }

    [Fact]
    public void PercentagePadding_ResolvesAgainstContainerWidth()
    {
        LayoutResult result = LayoutHtml("<div style='padding-left:10%'>x</div>");

        Text(result, "x").X.ShouldBe(Settings.Margins.Left + (Settings.ContentWidth * 0.1f), 0.5f);
    }

    [Fact]
    public void BlockSpanningPages_BackgroundIsPaintedOnEachPageWithoutInnerBorders()
    {
        string content = string.Concat(Enumerable.Range(0, 90).Select(i => $"<p>line {i}</p>"));
        LayoutResult result = LayoutHtml($"<div class='panel'>{content}</div>", ".panel { background: #eee; border: 1px solid #000; }");

        result.Pages.Count.ShouldBeGreaterThan(2);
        foreach (PageBox page in result.Pages)
        {
            page.Boxes.ShouldContain(b => b.Node != null && b.Node.Tag == "div" && b.Style.BackgroundColor != null);
        }

        result.Pages[0].Boxes.First(b => b.Node?.Tag == "div").SuppressBottomBorder.ShouldBeTrue();
        result.Pages[^1].Boxes.First(b => b.Node?.Tag == "div").SuppressTopBorder.ShouldBeTrue();
    }

    [Fact]
    public void Heading_IsNotLeftAloneAtBottomOfPage()
    {
        string filler = string.Concat(Enumerable.Range(0, 36).Select(i => $"<p style='margin:0'>filler {i}</p>"));
        LayoutResult result = LayoutHtml($"{filler}<h2>Section</h2><p>{Lorem}</p>");

        PageOf(result, "Section").ShouldBe(PageOf(result, "Lorem"));
    }

    [Fact]
    public void PageBreakInsideAvoid_MovesBlockToNextPage()
    {
        string filler = string.Concat(Enumerable.Range(0, 34).Select(i => $"<p style='margin:0'>filler {i}</p>"));
        LayoutResult result = LayoutHtml($"{filler}<div style='page-break-inside:avoid'><p>first</p><p>second</p><p>third</p></div>");

        PageOf(result, "first").ShouldBe(PageOf(result, "third"));
    }

    [Fact]
    public void BreakBefore_Page_StartsNewPage()
    {
        LayoutResult result = LayoutHtml("<p>a</p><p style='break-before: page'>b</p>");

        PageOf(result, "b").ShouldBe(1);
    }

    [Fact]
    public void VisibilityHidden_KeepsSpaceButMarksBoxesHidden()
    {
        LayoutResult result = LayoutHtml("<p style='visibility:hidden;margin:0'>ghost</p><p style='margin:0'>after</p>");

        Text(result, "ghost").Style.IsHidden.ShouldBeTrue();
        Text(result, "after").Y.ShouldBeGreaterThan(Text(result, "ghost").Y);
    }

    // ── Lists ────────────────────────────────────────────────────────────

    [Theory]
    [InlineData("decimal", "3.")]
    [InlineData("lower-alpha", "c.")]
    [InlineData("upper-roman", "III.")]
    [InlineData("decimal-leading-zero", "03.")]
    public void OrderedList_MarkerTypes(string type, string third)
    {
        LayoutResult result = LayoutHtml($"<ol style='list-style-type:{type}'><li>a</li><li>b</li><li>c</li></ol>");

        AllBoxes(result).Where(b => b.Type == LayoutBoxType.ListMarker).Select(b => b.Marker).ShouldContain(third);
    }

    [Fact]
    public void OrderedList_StartReversedAndValue()
    {
        LayoutResult start = LayoutHtml("<ol start='5'><li>a</li><li>b</li></ol>");
        LayoutResult reversed = LayoutHtml("<ol reversed><li>a</li><li>b</li><li>c</li></ol>");
        LayoutResult value = LayoutHtml("<ol><li>a</li><li value='10'>b</li><li>c</li></ol>");

        AllBoxes(start).Where(b => b.Type == LayoutBoxType.ListMarker).Select(b => b.Marker).ShouldBe(["5.", "6."]);
        AllBoxes(reversed).Where(b => b.Type == LayoutBoxType.ListMarker).Select(b => b.Marker).ShouldBe(["3.", "2.", "1."]);
        AllBoxes(value).Where(b => b.Type == LayoutBoxType.ListMarker).Select(b => b.Marker).ShouldBe(["1.", "10.", "11."]);
    }

    [Fact]
    public void UnorderedList_BulletsAreGraphicalShapes()
    {
        LayoutResult result = LayoutHtml("<ul><li>a<ul><li>b<ul><li>c</li></ul></li></ul></li></ul>");

        AllBoxes(result).Where(b => b.Type == LayoutBoxType.ListMarker).OrderBy(b => b.Y).Select(b => b.MarkerShape)
            .ShouldBe([MarkerShape.Disc, MarkerShape.Circle, MarkerShape.Square]);
    }

    [Fact]
    public void ListStyleNone_HasNoMarkers()
    {
        LayoutResult result = LayoutHtml("<ul style='list-style:none'><li>a</li></ul>");

        AllBoxes(result).ShouldNotContain(b => b.Type == LayoutBoxType.ListMarker);
    }

    [Fact]
    public void ListMarker_AlignsWithFirstLineBaseline()
    {
        LayoutResult result = LayoutHtml("<ol><li><p style='margin-top:20pt'>para</p></li></ol>");

        LayoutBox marker = AllBoxes(result).Single(b => b.Type == LayoutBoxType.ListMarker);
        marker.Y.ShouldBe(Text(result, "para").Y, 0.5f);
    }

    [Fact]
    public void ListStyleInside_IndentsFirstLine()
    {
        LayoutResult result = LayoutHtml("<ol style='list-style-position:inside;padding:0'><li>item</li></ol>");

        LayoutBox marker = AllBoxes(result).Single(b => b.Type == LayoutBoxType.ListMarker);
        Text(result, "item").X.ShouldBeGreaterThan(marker.X + marker.Width);
        marker.X.ShouldBe(Settings.Margins.Left, 0.5f);
    }

    // ── Flex & grid ──────────────────────────────────────────────────────

    [Fact]
    public void Flex_SpaceBetween_PinsItemsToEdges()
    {
        LayoutResult result = LayoutHtml("<div style='display:flex;justify-content:space-between'><span>L</span><span>R</span></div>");

        Text(result, "L").X.ShouldBe(Settings.Margins.Left, 0.5f);
        LayoutBox right = Text(result, "R");
        (right.X + right.Width).ShouldBe(Settings.Margins.Left + Settings.ContentWidth, 0.5f);
    }

    [Fact]
    public void Flex_Shrink_NeverGoesBelowMinContent()
    {
        LayoutResult result = LayoutHtml(
            "<div style='display:flex'><div style='width:400pt'>Supercalifragilistic</div><div style='width:400pt'>Other</div></div>");

        LayoutBox first = Text(result, "Supercalifragilistic");
        Text(result, "Other").X.ShouldBeGreaterThanOrEqualTo(first.X + first.Width - 0.5f);
    }

    [Fact]
    public void Flex_AlignItemsCenter_CentersShortItem()
    {
        LayoutResult result = LayoutHtml("<div style='display:flex;align-items:center'><div>1<br>2<br>3</div><div>mid</div></div>");

        Text(result, "mid").Y.ShouldBe(Text(result, "2").Y, 1f);
    }

    [Fact]
    public void Flex_RowTallerThanRemainingSpace_MovesToNextPage()
    {
        string filler = string.Concat(Enumerable.Range(0, 37).Select(i => $"<p style='margin:0'>filler {i}</p>"));
        LayoutResult result = LayoutHtml($"{filler}<div style='display:flex'><div>a<br>b<br>c</div><div>x</div></div>");

        PageOf(result, "a").ShouldBe(PageOf(result, "c"));
    }

    [Fact]
    public void Grid_TemplateColumns_PlacesItemsInTracks()
    {
        LayoutResult result = LayoutHtml("<div class='g'><div>A</div><div>B</div><div>C</div><div>D</div></div>", ".g { display: grid; grid-template-columns: 1fr 3fr; }");

        LayoutBox a = Text(result, "A");
        Text(result, "B").X.ShouldBe(a.X + (Settings.ContentWidth / 4), 0.5f);
        Text(result, "C").X.ShouldBe(a.X, 0.5f);
        Text(result, "C").Y.ShouldBeGreaterThan(a.Y);
    }

    [Fact]
    public void Grid_RepeatAndSpan_AreSupported()
    {
        LayoutResult result = LayoutHtml(
            "<div class='g'><div class='wide'>W</div><div>A</div><div>B</div><div>C</div></div>",
            ".g { display: grid; grid-template-columns: repeat(3, 1fr); gap: 0; } .wide { grid-column: 1 / -1; }");

        Text(result, "A").Y.ShouldBeGreaterThan(Text(result, "W").Y);
        Text(result, "C").Y.ShouldBe(Text(result, "A").Y, 0.5f);
    }

    [Fact]
    public void LayoutEngine_EmptyDocument_ProducesAtMostOneBlankPage()
    {
        LayoutResult result = LayoutHtml(string.Empty);

        result.Pages.Count.ShouldBeLessThanOrEqualTo(1);
        Texts(result).ShouldBeEmpty();
    }
}
