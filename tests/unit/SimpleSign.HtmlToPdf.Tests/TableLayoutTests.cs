// Licensed to SimpleSign under the MIT License.

using Shouldly;
using SimpleSign.HtmlToPdf.Layout;
using Xunit;
using static SimpleSign.HtmlToPdf.Tests.TestSupport;

namespace SimpleSign.HtmlToPdf.Tests;

[Trait("Category", "Unit")]
public sealed class TableLayoutTests
{
    private static string Rows(int count, string extra = "") =>
        string.Concat(Enumerable.Range(1, count).Select(i => $"<tr><td>Row {i}{extra}</td><td>Value {i}</td></tr>"));

    [Fact]
    public void Layout_LongTable_ContinuesOnNextPagesWithinContentArea()
    {
        LayoutResult result = LayoutHtml($"<table>{Rows(150)}</table>");

        result.Pages.Count.ShouldBeGreaterThan(2);
        float contentHeight = new PageSettings().ContentHeight;
        foreach (LayoutBox box in Texts(result))
        {
            (box.Y + (box.Style.FontSize * 0.8f)).ShouldBeLessThanOrEqualTo(contentHeight);
        }

        Texts(result).Count(t => t.Text!.StartsWith("Row ", StringComparison.Ordinal)).ShouldBe(150);
    }

    [Fact]
    public void Layout_Thead_RepeatsOnEveryPage()
    {
        LayoutResult result = LayoutHtml($"<table><thead><tr><th>Head</th><th>H2</th></tr></thead><tbody>{Rows(150)}</tbody></table>");

        foreach (PageBox page in result.Pages)
        {
            page.Boxes.Count(b => b.Text == "Head").ShouldBe(1);
        }
    }

    [Fact]
    public void Layout_Tfoot_RendersOnceAfterBody()
    {
        LayoutResult result = LayoutHtml($"<table><tfoot><tr><td>Foot</td><td>F</td></tr></tfoot><tbody>{Rows(150)}</tbody></table>");

        Texts(result).Count(t => t.Text == "Foot").ShouldBe(1);
        PageOf(result, "Foot").ShouldBe(result.Pages.Count - 1);
        PageOf(result, "Row 150").ShouldBe(result.Pages.Count - 1);
    }

    [Fact]
    public void Layout_RowsAreNeverSplitAcrossPages()
    {
        LayoutResult result = LayoutHtml($"<table>{Rows(150, "<br>second line")}</table>");

        foreach (int i in new[] { 1, 37, 75, 149 })
        {
            int rowPage = PageOf(result, $"Row {i}");
            int pageOfSecondLine = result.Pages.FindIndex(p =>
            {
                int index = p.Boxes.FindIndex(b => b.Text == $"Row {i}");
                return index >= 0 && p.Boxes.Skip(index).Any(b => b.Text == "second line");
            });
            pageOfSecondLine.ShouldBe(rowPage);
        }
    }

    [Fact]
    public void Layout_RowTallerThanPage_IsFragmentedInsteadOfLost()
    {
        string tall = string.Concat(Enumerable.Range(1, 80).Select(i => $"Line{i}<br>"));
        LayoutResult result = LayoutHtml($"<table><tr><td>{tall}</td></tr></table>");

        result.Pages.Count.ShouldBeGreaterThan(1);
        Texts(result).Count(t => t.Text!.StartsWith("Line", StringComparison.Ordinal)).ShouldBe(80);
    }

    [Fact]
    public void Layout_CellWithMixedInlineStyles_StaysOnOneLine()
    {
        LayoutResult result = LayoutHtml("<table style='width:100%'><tr><td>Total <b>bold</b> end</td></tr></table>");

        LayoutBox total = Text(result, "Total");
        LayoutBox bold = Text(result, "bold");
        LayoutBox end = Text(result, "end");
        bold.Y.ShouldBe(total.Y, 0.5f);
        end.Y.ShouldBe(total.Y, 0.5f);
        bold.X.ShouldBeGreaterThan(total.X);
        bold.Style.IsBold.ShouldBeTrue();
    }

    [Fact]
    public void Layout_CellWithBlockContent_RendersListsAndNestedTables()
    {
        LayoutResult result = LayoutHtml("<table><tr><td><ul><li>Item A</li></ul><table><tr><td>Inner</td></tr></table></td></tr></table>");

        AllBoxes(result).ShouldContain(b => b.Type == LayoutBoxType.ListMarker);
        Text(result, "Inner").ShouldNotBeNull();
        Text(result, "Item A").Y.ShouldBeLessThan(Text(result, "Inner").Y);
    }

    [Fact]
    public void Layout_AutoWidthTable_ShrinksToContent()
    {
        LayoutResult result = LayoutHtml("<table><tr><td>a</td><td>b</td></tr></table>");

        LayoutBox frame = AllBoxes(result).First(b => b.Type == LayoutBoxType.Block && b.Node is null);
        frame.Width.ShouldBeLessThan(100f);
    }

    [Fact]
    public void Layout_FullWidthTable_UsesAvailableWidth()
    {
        LayoutResult result = LayoutHtml("<table style='width:100%'><tr><td>a</td><td>b</td></tr></table>");

        LayoutBox frame = AllBoxes(result).First(b => b.Type == LayoutBoxType.Block && b.Node is null);
        frame.Width.ShouldBe(new PageSettings().ContentWidth, 0.5f);
    }

    [Fact]
    public void Layout_ColumnWidths_FollowContentProportions()
    {
        LayoutResult result = LayoutHtml("<table style='width:100%'><tr><td>x</td><td>a much much longer cell text that needs room</td></tr></table>");

        LayoutBox x = Text(result, "x");
        LayoutBox longer = Text(result, "much");
        (longer.X - x.X).ShouldBeLessThan(150f);
    }

    [Fact]
    public void Layout_ExplicitCellWidth_IsRespected()
    {
        LayoutResult result = LayoutHtml("<table style='width:100%'><tr><td style='width:100pt'>a</td><td>b</td></tr></table>");

        // content-box width (100) + padding (2 × 4pt) + border-spacing (1.5pt)
        (Text(result, "b").X - Text(result, "a").X).ShouldBe(100f + 8f + 1.5f, 0.5f);
    }

    [Fact]
    public void Layout_PercentageCellWidth_IsRespected()
    {
        LayoutResult result = LayoutHtml("<table style='width:400pt;border-collapse:collapse'><tr><td style='width:25%'>a</td><td>b</td></tr></table>");

        (Text(result, "b").X - Text(result, "a").X).ShouldBe(100f, 2f);
    }

    [Fact]
    public void Layout_ColElementWidth_IsRespected()
    {
        LayoutResult result = LayoutHtml("<table style='width:400pt;border-collapse:collapse'><colgroup><col width='300'><col></colgroup><tr><td>a</td><td>b</td></tr></table>");

        (Text(result, "b").X - Text(result, "a").X).ShouldBe(225f, 2f);
    }

    [Fact]
    public void Layout_Colspan_CellSpansBothColumns()
    {
        LayoutResult result = LayoutHtml("<table style='border-collapse:collapse'><tr><td colspan='2'>Spanning header text</td></tr><tr><td>a</td><td>b</td></tr></table>");

        LayoutBox span = Text(result, "Spanning");
        span.Text.ShouldBe("Spanning header text");
        Text(result, "b").X.ShouldBeGreaterThan(Text(result, "a").X);
    }

    [Fact]
    public void Layout_Rowspan_TallCellGrowsSpannedRows()
    {
        string tall = "1<br>2<br>3<br>4<br>5<br>6";
        LayoutResult result = LayoutHtml($"<table style='border-collapse:collapse'><tr><td rowspan='2'>{tall}</td><td>top</td></tr><tr><td>bottom</td></tr></table><p>after</p>");

        Text(result, "after").Y.ShouldBeGreaterThan(Text(result, "6").Y);
    }

    [Fact]
    public void Layout_VerticalAlignMiddle_CentersShortCell()
    {
        LayoutResult result = LayoutHtml("<table><tr><td>1<br>2<br>3</td><td style='vertical-align:middle'>mid</td><td style='vertical-align:top'>top</td></tr></table>");

        Text(result, "mid").Y.ShouldBe(Text(result, "2").Y, 1f);
        Text(result, "top").Y.ShouldBe(Text(result, "1").Y, 1f);
    }

    [Fact]
    public void Layout_BorderCollapse_DrawsCenteredSharedBorders()
    {
        LayoutResult result = LayoutHtml("<table style='border-collapse:collapse'><tr><td style='border:1px solid black'>a</td><td style='border:1px solid black'>b</td></tr></table>");

        List<LayoutBox> borders = [.. AllBoxes(result).Where(b => b.Type == LayoutBoxType.Block && b.Style.Border.HasBorder)];
        borders.ShouldAllBe(b => b.BorderCentered);
        (borders[0].X + borders[0].Width).ShouldBe(borders[1].X, 0.01f);
    }

    [Fact]
    public void Layout_BorderSpacing_SeparatesCells()
    {
        LayoutResult result = LayoutHtml("<table style='border-spacing:10pt'><tr><td style='border:1px solid black'>a</td><td style='border:1px solid black'>b</td></tr></table>");

        List<LayoutBox> borders = [.. AllBoxes(result).Where(b => b.Type == LayoutBoxType.Block && b.Style.Border.HasBorder)];
        float firstRight = borders[0].X + borders[0].Width + 1.5f;
        (borders[1].X - firstRight).ShouldBe(10f, 0.1f);
    }

    [Fact]
    public void Layout_ZebraStripingViaNthChild_PaintsEvenRows()
    {
        LayoutResult result = LayoutHtml($"<table>{Rows(4)}</table>", "tr:nth-child(even) td { background: #eee; }");

        AllBoxes(result).Count(b => b.Type == LayoutBoxType.Block && b.Style.BackgroundColor is { IsTransparent: false }).ShouldBe(4);
    }

    [Fact]
    public void Layout_RowBackground_PaintsCellsWithoutOwnBackground()
    {
        LayoutResult result = LayoutHtml("<table><tr style='background:#eee'><td>a</td><td style='background:#f00'>b</td></tr></table>");

        List<LayoutBox> backgrounds = [.. AllBoxes(result).Where(b => b.Type == LayoutBoxType.Block && b.Style.BackgroundColor is { IsTransparent: false })];
        backgrounds.Count.ShouldBe(2);
        backgrounds.ShouldContain(b => b.Style.BackgroundColor!.Value.R > 0.99f && b.Style.BackgroundColor!.Value.G < 0.01f);
    }

    [Fact]
    public void Layout_CenteredTable_HasEqualSideSpace()
    {
        LayoutResult result = LayoutHtml("<table style='width:200pt;margin:0 auto'><tr><td>x</td></tr></table>");

        LayoutBox frame = AllBoxes(result).First(b => b.Type == LayoutBoxType.Block && b.Node is null);
        var settings = new PageSettings();
        float left = frame.X - settings.Margins.Left;
        float right = settings.ContentWidth - left - frame.Width;
        left.ShouldBe(right, 0.5f);
    }

    [Fact]
    public void Layout_CaptionWiderThanColumns_WidensTable()
    {
        LayoutResult result = LayoutHtml("<table><caption>A rather long caption for a tiny table</caption><tr><td>x</td></tr></table>");

        Text(result, "A rather").Text.ShouldBe("A rather long caption for a tiny table");
    }

    [Fact]
    public void Layout_PageBreakInsideAvoid_MovesWholeTable()
    {
        string filler = string.Concat(Enumerable.Range(0, 38).Select(i => $"<p>filler {i}</p>"));
        LayoutResult result = LayoutHtml($"{filler}<table style='page-break-inside:avoid'>{Rows(12)}</table>");

        PageOf(result, "Row 1").ShouldBe(PageOf(result, "Row 12"));
    }

    [Fact]
    public void Layout_EmptyTable_DoesNotThrow()
    {
        LayoutResult result = LayoutHtml("<table></table><p>after</p>");

        Text(result, "after").ShouldNotBeNull();
    }

    [Fact]
    public void Layout_RaggedRows_FillMissingCells()
    {
        LayoutResult result = LayoutHtml("<table><tr><td>a</td><td>b</td><td>c</td></tr><tr><td>d</td></tr></table>");

        Text(result, "d").X.ShouldBe(Text(result, "a").X, 0.01f);
    }
}
