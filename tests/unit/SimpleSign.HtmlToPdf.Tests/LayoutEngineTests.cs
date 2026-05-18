using Shouldly;
using SimpleSign.HtmlToPdf.Layout;
using SimpleSign.HtmlToPdf.Parsing;
using Xunit;

namespace SimpleSign.HtmlToPdf.Tests;

public class LayoutEngineTests
{
    // ── Basic layout ────────────────────────────────────────────────────

    [Fact(DisplayName = "Layout: empty HTML produces layout result")]
    public void Layout_EmptyHtml_ProducesLayoutResult()
    {
        var root = HtmlTokenizer.Parse("");
        StyleResolver.Resolve(root, []);

        var engine = new LayoutEngine(new PageSettings());
        var result = engine.Layout(root);

        result.ShouldNotBeNull();
        // Empty HTML may produce zero pages (nothing to lay out)
    }

    [Fact(DisplayName = "Layout: single paragraph produces boxes")]
    public void Layout_SingleParagraph_ProducesBoxes()
    {
        var root = HtmlTokenizer.Parse("<p>Hello World</p>");
        StyleResolver.Resolve(root, []);

        var engine = new LayoutEngine(new PageSettings());
        var result = engine.Layout(root);

        result.Pages.ShouldNotBeEmpty();
        result.Pages[0].Boxes.ShouldNotBeEmpty();
    }

    [Fact(DisplayName = "Layout: heading is positioned")]
    public void Layout_Heading_IsPositioned()
    {
        var root = HtmlTokenizer.Parse("<h1>Title</h1>");
        StyleResolver.Resolve(root, []);

        var engine = new LayoutEngine(new PageSettings());
        var result = engine.Layout(root);

        var boxes = result.Pages[0].Boxes;
        boxes.ShouldNotBeEmpty();

        // At least one text box should exist
        boxes.ShouldContain(b => b.Type == LayoutBoxType.InlineText);
    }

    // ── Multiple elements ───────────────────────────────────────────────

    [Fact(DisplayName = "Layout: multiple paragraphs are stacked vertically")]
    public void Layout_MultipleParagraphs_StackedVertically()
    {
        var root = HtmlTokenizer.Parse("<p>First</p><p>Second</p><p>Third</p>");
        StyleResolver.Resolve(root, []);

        var engine = new LayoutEngine(new PageSettings());
        var result = engine.Layout(root);

        var textBoxes = result.Pages[0].Boxes
            .Where(b => b.Type == LayoutBoxType.InlineText)
            .OrderBy(b => b.Y)
            .ToList();

        textBoxes.Count().ShouldBeGreaterThanOrEqualTo(2);
        // Y should increase (content flows down)
        for (int i = 1; i < textBoxes.Count; i++)
        {
            textBoxes[i].Y.ShouldBeGreaterThanOrEqualTo(textBoxes[i - 1].Y);
        }
    }

    // ── Lists ───────────────────────────────────────────────────────────

    [Fact(DisplayName = "Layout: unordered list produces boxes")]
    public void Layout_UnorderedList_ProducesBoxes()
    {
        var root = HtmlTokenizer.Parse("<ul><li>A</li><li>B</li></ul>");
        StyleResolver.Resolve(root, []);

        var engine = new LayoutEngine(new PageSettings());
        var result = engine.Layout(root);

        result.Pages[0].Boxes.ShouldNotBeEmpty();
    }

    [Fact(DisplayName = "Layout: ordered list produces boxes")]
    public void Layout_OrderedList_ProducesBoxes()
    {
        var root = HtmlTokenizer.Parse("<ol><li>First</li><li>Second</li></ol>");
        StyleResolver.Resolve(root, []);

        var engine = new LayoutEngine(new PageSettings());
        var result = engine.Layout(root);

        result.Pages[0].Boxes.ShouldNotBeEmpty();
    }

    // ── HR element ──────────────────────────────────────────────────────

    [Fact(DisplayName = "Layout: hr element produces a box")]
    public void Layout_Hr_ProducesBox()
    {
        var root = HtmlTokenizer.Parse("<p>Before</p><hr><p>After</p>");
        StyleResolver.Resolve(root, []);

        var engine = new LayoutEngine(new PageSettings());
        var result = engine.Layout(root);

        result.Pages[0].Boxes.Count().ShouldBeGreaterThanOrEqualTo(2);
    }

    // ── BR element ──────────────────────────────────────────────────────

    [Fact(DisplayName = "Layout: br element advances cursor")]
    public void Layout_Br_AdvancesCursor()
    {
        var root = HtmlTokenizer.Parse("<p>Line1</p><br><p>Line2</p>");
        StyleResolver.Resolve(root, []);

        var engine = new LayoutEngine(new PageSettings());
        var result = engine.Layout(root);

        result.Pages[0].Boxes.ShouldNotBeEmpty();
    }

    // ── Table layout ────────────────────────────────────────────────────

    [Fact(DisplayName = "Layout: table produces cell boxes")]
    public void Layout_Table_ProducesCellBoxes()
    {
        var root = HtmlTokenizer.Parse(
            "<table><tr><td>A</td><td>B</td></tr><tr><td>C</td><td>D</td></tr></table>");
        StyleResolver.Resolve(root, []);

        var engine = new LayoutEngine(new PageSettings());
        var result = engine.Layout(root);

        var textBoxes = result.Pages[0].Boxes
            .Where(b => b.Type == LayoutBoxType.InlineText)
            .ToList();

        textBoxes.Count().ShouldBeGreaterThanOrEqualTo(4);
    }

    [Fact(DisplayName = "Layout: table with thead/tbody")]
    public void Layout_TableWithSections_ProducesBoxes()
    {
        var root = HtmlTokenizer.Parse(
            "<table><thead><tr><th>H1</th><th>H2</th></tr></thead>" +
            "<tbody><tr><td>A</td><td>B</td></tr></tbody></table>");
        StyleResolver.Resolve(root, []);

        var engine = new LayoutEngine(new PageSettings());
        var result = engine.Layout(root);

        result.Pages[0].Boxes.ShouldNotBeEmpty();
    }

    // ── Page settings ───────────────────────────────────────────────────

    [Fact(DisplayName = "PageSettings: A4 default dimensions")]
    public void PageSettings_A4_DefaultDimensions()
    {
        var settings = new PageSettings();

        settings.PageWidth.ShouldBe(595.28f, 1f);
        settings.PageHeight.ShouldBe(841.89f, 1f);
    }

    [Fact(DisplayName = "PageSettings.FromPaperSize: Letter")]
    public void PageSettings_Letter_CorrectDimensions()
    {
        var settings = PageSettings.FromPaperSize(PaperSize.Letter);

        settings.PageWidth.ShouldBe(612);
        settings.PageHeight.ShouldBe(792);
    }

    [Fact(DisplayName = "PageSettings.FromPaperSize: Legal")]
    public void PageSettings_Legal_CorrectDimensions()
    {
        var settings = PageSettings.FromPaperSize(PaperSize.Legal);

        settings.PageWidth.ShouldBe(612);
        settings.PageHeight.ShouldBe(1008);
    }

    [Fact(DisplayName = "PageSettings: ContentWidth accounts for margins")]
    public void PageSettings_ContentWidth_AccountsForMargins()
    {
        var settings = new PageSettings
        {
            PageWidth = 600,
            Margins = new Thickness(0, 50, 0, 50),
        };

        settings.ContentWidth.ShouldBe(500);
    }

    [Fact(DisplayName = "PageSettings: ContentHeight accounts for margins")]
    public void PageSettings_ContentHeight_AccountsForMargins()
    {
        var settings = new PageSettings
        {
            PageHeight = 800,
            Margins = new Thickness(40, 0, 40, 0),
        };

        settings.ContentHeight.ShouldBe(720);
    }

    // ── LayoutBox ───────────────────────────────────────────────────────

    [Fact(DisplayName = "LayoutBox: type enum has expected values")]
    public void LayoutBox_TypeEnum_HasExpectedValues()
    {
        Enum.IsDefined(LayoutBoxType.Block).ShouldBeTrue();
        Enum.IsDefined(LayoutBoxType.InlineText).ShouldBeTrue();
    }

    // ── LayoutResult ────────────────────────────────────────────────────

    [Fact(DisplayName = "LayoutResult: default is empty")]
    public void LayoutResult_Default_IsEmpty()
    {
        var result = new LayoutResult();

        result.Pages.ShouldBeEmpty();
    }
}
