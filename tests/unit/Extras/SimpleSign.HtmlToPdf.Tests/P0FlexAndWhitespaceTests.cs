using Shouldly;
using SimpleSign.HtmlToPdf.Layout;
using SimpleSign.HtmlToPdf.Parsing;
using SimpleSign.HtmlToPdf.Rendering;
using Xunit;

namespace SimpleSign.HtmlToPdf.Tests;

[Trait("Category", "Unit")]
public sealed class P0FlexAndWhitespaceTests
{
    private static LayoutResult Layout(string html, string css)
    {
        HtmlNode dom = HtmlTokenizer.Parse(html);
        StyleResolver.Resolve(dom, CssParser.ParseStylesheet(css));
        return new LayoutEngine(PageSettings.FromPaperSize(PaperSize.Letter)).Layout(dom);
    }

    private static LayoutBox TextBox(LayoutResult result, string text) =>
        result.Pages.SelectMany(page => page.Boxes).Single(box => box.Type == LayoutBoxType.InlineText && box.Text == text);

    [Fact]
    public void FlexRow_LaysItemsHorizontallyWithGap()
    {
        LayoutResult result = Layout(
            "<div class='row'><div class='item'>First</div><div class='item'>Second</div></div>",
            ".row { display: flex; gap: 10px; } .item { width: 100px; }");

        LayoutBox first = TextBox(result, "First");
        LayoutBox second = TextBox(result, "Second");

        (second.X - first.X).ShouldBe(82.5f, 0.1f);
        second.Y.ShouldBe(first.Y);
    }

    [Fact]
    public void FlexColumn_LaysItemsVerticallyWithGap()
    {
        LayoutResult result = Layout(
            "<div class='column'><div>First</div><div>Second</div></div>",
            ".column { display: flex; flex-direction: column; gap: 12px; }");

        LayoutBox first = TextBox(result, "First");
        LayoutBox second = TextBox(result, "Second");

        second.X.ShouldBe(first.X);
        second.Y.ShouldBeGreaterThan(first.Y + first.Height);
    }

    [Fact]
    public void FlexWrap_MovesItemsToNextLineWhenBasesDoNotFit()
    {
        LayoutResult result = Layout(
            "<div class='row'><div class='item'>One</div><div class='item'>Two</div><div class='item'>Three</div></div>",
            ".row { display: flex; flex-wrap: wrap; gap: 4px; } .item { width: 220px; }");

        LayoutBox one = TextBox(result, "One");
        LayoutBox two = TextBox(result, "Two");
        LayoutBox three = TextBox(result, "Three");

        two.Y.ShouldBe(one.Y);
        three.Y.ShouldBeGreaterThan(two.Y);
    }

    [Fact]
    public void FlexGrow_DistributesAvailableWidth()
    {
        LayoutResult result = Layout(
            "<div class='row'><div class='item'>One</div><div class='item'>Two</div></div>",
            ".row { display: flex; gap: 10px; } .item { flex: 1; }");

        LayoutBox one = TextBox(result, "One");
        LayoutBox two = TextBox(result, "Two");

        (two.X - one.X).ShouldBeGreaterThan(one.Width);
        (two.X - one.X).ShouldBeGreaterThan(200);
    }

    [Fact]
    public void FlexAlignItemsStretch_ExpandsShortItemToLineHeight()
    {
        LayoutResult result = Layout(
            "<div class='row'><div class='item short'>One</div><div class='item tall'>one two three four five six seven eight nine</div></div>",
            ".row { display: flex; gap: 8px; } .item { width: 100px; } .tall { font-size: 20px; }");

        LayoutBox shortBox = result.Pages.SelectMany(page => page.Boxes)
            .Single(box => box.Type == LayoutBoxType.Block && box.Node?.GetAttribute("class") == "item short");
        LayoutBox tallBox = result.Pages.SelectMany(page => page.Boxes)
            .Single(box => box.Type == LayoutBoxType.Block && box.Node?.GetAttribute("class") == "item tall");

        shortBox.Height.ShouldBe(tallBox.Height);
        shortBox.Height.ShouldBeGreaterThan(20);
    }

    [Fact]
    public void WhiteSpacePre_PreservesMultipleSpacesAndExplicitLineBreaks()
    {
        LayoutResult result = Layout("<p class='pre'>A   B\nC</p>", ".pre { white-space: pre; }");
        List<LayoutBox> boxes = [.. result.Pages.SelectMany(page => page.Boxes)
            .Where(box => box.Type == LayoutBoxType.InlineText)
            ];

        boxes.Select(box => box.Text).ShouldContain("   ");
        boxes.First(box => box.Text == "C").Y.ShouldBeGreaterThan(boxes.First(box => box.Text == "A").Y);
    }

    [Fact]
    public void WhiteSpacePreWrap_PreservesSpacesAndWrapsLines()
    {
        LayoutResult result = Layout("<p class='pre'>A       B</p>", ".pre { white-space: pre-wrap; width: 40px; }");
        List<LayoutBox> boxes = [.. result.Pages.SelectMany(page => page.Boxes)
            .Where(box => box.Type == LayoutBoxType.InlineText)
            ];

        boxes.Any(box => box.Text!.Contains(' ')).ShouldBeTrue();
        boxes.Select(box => box.Y).Distinct().Count().ShouldBeGreaterThan(1);
    }

    [Fact]
    public void WhiteSpacePreWrap_WrapsLongSpaceRunsWithoutDroppingWhitespace()
    {
        const string text = "A                    B";
        LayoutResult result = Layout($"<p class='pre'>{text}</p>", ".pre { white-space: pre-wrap; width: 40px; }");
        List<LayoutBox> boxes = [.. result.Pages.SelectMany(page => page.Boxes)
            .Where(box => box.Type == LayoutBoxType.InlineText)];

        string.Join(string.Empty, boxes.Select(box => box.Text)).ShouldBe(text);
        boxes.Select(box => box.Y).Distinct().Count().ShouldBeGreaterThan(1);
    }

    [Fact]
    public void WhiteSpaceNoWrap_DoesNotWrapLongText()
    {
        LayoutResult result = Layout("<p class='nowrap'>alpha beta gamma delta</p>", ".nowrap { white-space: nowrap; width: 40px; }");
        List<LayoutBox> boxes = [.. result.Pages.SelectMany(page => page.Boxes)
            .Where(box => box.Type == LayoutBoxType.InlineText)
            ];

        boxes.Select(box => box.Y).Distinct().Count().ShouldBe(1);
    }

    [Fact]
    public void OverflowWrapAnywhere_BreaksLongUnspacedToken()
    {
        LayoutResult result = Layout("<p class='wrap'>averylongurlwithoutanyspaces</p>", ".wrap { overflow-wrap: anywhere; width: 40px; }");
        List<LayoutBox> boxes = [.. result.Pages.SelectMany(page => page.Boxes)
            .Where(box => box.Type == LayoutBoxType.InlineText)
            ];

        boxes.Count.ShouldBeGreaterThan(1);
        boxes.Select(box => box.Y).Distinct().Count().ShouldBeGreaterThan(1);
        string.Concat(boxes.Select(box => box.Text)).ShouldBe("averylongurlwithoutanyspaces");
    }

    [Fact]
    public void WordBreakBreakAll_BreaksLongUnspacedToken()
    {
        LayoutResult result = Layout("<p class='wrap'>averylongurlwithoutanyspaces</p>", ".wrap { word-break: break-all; width: 40px; }");
        List<LayoutBox> boxes = [.. result.Pages.SelectMany(page => page.Boxes)
            .Where(box => box.Type == LayoutBoxType.InlineText)
            ];

        boxes.Select(box => box.Y).Distinct().Count().ShouldBeGreaterThan(1);
    }

    [Fact]
    public void TextTransformUppercase_TransformsRenderedText()
    {
        LayoutResult result = Layout("<p class='upper'>mixed Case</p>", ".upper { text-transform: uppercase; }");

        result.Pages.SelectMany(page => page.Boxes)
            .Where(box => box.Type == LayoutBoxType.InlineText)
            .Select(box => box.Text)
            .ShouldBe(["MIXED CASE"]); // words of one run on one line are merged into a single text box
    }

    [Fact]
    public void FontWeightNumeric600_UsesBoldStyle()
    {
        HtmlNode dom = HtmlTokenizer.Parse("<p class='bold'>Semi bold</p>");
        StyleResolver.Resolve(dom, CssParser.ParseStylesheet(".bold { font-weight: 600; }"));

        dom.Descendants("p").Single().ComputedStyle!.IsBold.ShouldBeTrue();
    }

    [Fact]
    public void LetterAndWordSpacing_AreAppliedToPdfTextOperators()
    {
        var stream = new PdfContentStream();
        stream.DrawText("A B", 0, 0, "Helvetica", 12, PdfColor.Black, letterSpacing: 2, wordSpacing: 3);

        string content = System.Text.Encoding.ASCII.GetString(stream.ToBytes());
        content.ShouldContain("2.00 Tc");
        content.ShouldContain("3.00 Tw");
    }
}
