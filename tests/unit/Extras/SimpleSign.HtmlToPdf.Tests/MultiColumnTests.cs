// Licensed to SimpleSign under the MIT License.

using Shouldly;
using SimpleSign.HtmlToPdf.Layout;
using SimpleSign.HtmlToPdf.Parsing;
using Xunit;
using static SimpleSign.HtmlToPdf.Tests.TestSupport;

namespace SimpleSign.HtmlToPdf.Tests;

[Trait("Category", "Unit")]
public sealed class MultiColumnTests
{
    private static readonly PageSettings Settings = new();

    private static string Paragraphs(int count) =>
        string.Concat(Enumerable.Range(1, count).Select(i => $"<p>Item {i} lorem ipsum dolor sit amet</p>"));

    private static List<float> DistinctColumnsX(LayoutResult result) =>
        [.. Texts(result).Where(t => t.Text!.StartsWith("Item", StringComparison.Ordinal)).Select(t => MathF.Round(t.X)).Distinct().Order()];

    [Fact]
    public void Cascade_ColumnsShorthand()
    {
        ComputedStyle style = First(Resolve("<div>x</div>", "div { columns: 12em 3; column-rule: 2pt dashed red; }"), "div").ComputedStyle!;

        style.ColumnCount.ShouldBe(3);
        style.ColumnWidth.ShouldBe(144f);
        style.ColumnRuleWidth.ShouldBe(2f);
        style.ColumnRuleStyle.ShouldBe(BorderLineStyle.Dashed);
    }

    [Fact]
    public void ColumnCount_DistributesContentAcrossColumns()
    {
        LayoutResult result = LayoutHtml($"<div>{Paragraphs(12)}</div>", "div { column-count: 3; column-gap: 12pt; } p { margin: 0; }");

        List<float> xs = DistinctColumnsX(result);
        xs.Count.ShouldBe(3);
        float columnWidth = (Settings.ContentWidth - 24f) / 3;
        (xs[1] - xs[0]).ShouldBe(columnWidth + 12f, 1f);
    }

    [Fact]
    public void Columns_AreBalanced()
    {
        LayoutResult result = LayoutHtml($"<div>{Paragraphs(9)}</div>", "div { column-count: 3; } p { margin: 0; }");

        List<IGrouping<float, LayoutBox>> columns = [.. Texts(result).Where(t => t.Text!.StartsWith("Item", StringComparison.Ordinal)).GroupBy(t => MathF.Round(t.X))];
        columns.Count.ShouldBe(3);
        columns.ShouldAllBe(c => c.Count() == 3);
    }

    [Fact]
    public void ContentAfterColumns_StartsBelowTallestColumn()
    {
        LayoutResult result = LayoutHtml($"<div>{Paragraphs(6)}</div><p>After</p>", "div { column-count: 2; } p { margin: 0; }");

        float lowest = Texts(result).Where(t => t.Text!.StartsWith("Item", StringComparison.Ordinal)).Max(t => t.Y + t.Height);
        Text(result, "After").Y.ShouldBeGreaterThanOrEqualTo(lowest - 0.01f);
        Text(result, "After").X.ShouldBe(Settings.Margins.Left, 0.5f);
    }

    [Fact]
    public void ColumnWidth_DerivesCount()
    {
        LayoutResult result = LayoutHtml($"<div>{Paragraphs(20)}</div>", "div { column-width: 120pt; column-gap: 0; } p { margin: 0; }");

        DistinctColumnsX(result).Count.ShouldBe((int)(Settings.ContentWidth / 120f));
    }

    [Fact]
    public void ColumnCountOne_IsNormalFlow()
    {
        LayoutResult result = LayoutHtml($"<div>{Paragraphs(3)}</div>", "div { column-count: 1; }");

        DistinctColumnsX(result).Count.ShouldBe(1);
    }

    [Fact]
    public void LongContent_FillsPagesThenBalancesLast()
    {
        LayoutResult result = LayoutHtml($"<div>{Paragraphs(400)}</div>", "div { column-count: 2; } p { margin: 0; }");

        result.Pages.Count.ShouldBeGreaterThan(1);
        PageOf(result, "Item 1 ").ShouldBe(0);
        foreach (PageBox page in result.Pages)
        {
            page.Boxes.Where(b => b.Type == LayoutBoxType.InlineText).ShouldAllBe(b => b.Y + b.Height <= Settings.ContentHeight + 0.5f);
        }

        // Every item appears exactly once.
        Texts(result).Count(t => t.Text!.StartsWith("Item ", StringComparison.Ordinal)).ShouldBe(400);
    }

    [Fact]
    public void ColumnSpanAll_BreaksColumns()
    {
        LayoutResult result = LayoutHtml($"<div>{Paragraphs(4)}<h2>Span</h2>{Paragraphs(4)}</div>", "div { column-count: 2; } h2 { column-span: all; } p { margin: 0; }");

        LayoutBox heading = Text(result, "Span");
        heading.X.ShouldBe(Settings.Margins.Left, 0.5f);
        Texts(result).Where(t => t.Text!.StartsWith("Item", StringComparison.Ordinal) && t.Y < heading.Y).Count().ShouldBe(4);
    }

    [Fact]
    public void ColumnRule_AddsRuleBoxBetweenColumns()
    {
        LayoutResult result = LayoutHtml($"<div>{Paragraphs(6)}</div>", "div { column-count: 3; column-rule: 1pt solid black; }");

        AllBoxes(result).Count(b => b.Type == LayoutBoxType.Block && b.Node is null && b.Style.Border.LeftWidth == 1f).ShouldBe(2);
    }
}
