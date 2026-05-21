using SimpleSign.DocxToPdf.Fonts;
using SimpleSign.DocxToPdf.Layout;
using SimpleSign.DocxToPdf.Model;
using SimpleSign.DocxToPdf.Tests.Fixtures;
using Shouldly;

namespace SimpleSign.DocxToPdf.Tests;

public sealed class LayoutTests
{
    [Fact]
    public void ParagraphLayouter_EmptyParagraph_ReturnsHeight()
    {
        // Arrange
        var fontResolver = new FontResolver();
        var styles = new StyleMap();
        var layouter = new ParagraphLayouter(fontResolver, styles);
        var para = new DocParagraph();

        // Act
        (List<LayoutElement> elements, float height) = layouter.Layout(para, 72f, 72f, 468f);

        // Assert
        height.ShouldBeGreaterThan(0f);
        elements.ShouldBeEmpty();
    }

    [Fact]
    public void ParagraphLayouter_SingleRun_ProducesLayoutText()
    {
        // Arrange
        var fontResolver = new FontResolver();
        var styles = new StyleMap();
        var layouter = new ParagraphLayouter(fontResolver, styles);
        var para = new DocParagraph
        {
            Runs = [new DocRun { Text = "Hello", SizeHalfPoints = 24 }]
        };

        // Act
        (List<LayoutElement> elements, float height) = layouter.Layout(para, 72f, 72f, 468f);

        // Assert
        elements.ShouldNotBeEmpty();
        elements.OfType<LayoutText>().ShouldNotBeEmpty();
        height.ShouldBeGreaterThan(0f);
    }

    [Fact]
    public void ParagraphLayouter_WithSpacing_AddsSpacingToHeight()
    {
        // Arrange
        var fontResolver = new FontResolver();
        var styles = new StyleMap();
        var layouter = new ParagraphLayouter(fontResolver, styles);
        var para = new DocParagraph
        {
            Runs = [new DocRun { Text = "Test", SizeHalfPoints = 24 }],
            Spacing = new DocSpacing { BeforePt = 12f, AfterPt = 6f }
        };

        // Act
        (_, float height) = layouter.Layout(para, 0f, 0f, 468f);

        // Assert
        height.ShouldBeGreaterThan(18f); // At least spacing before + after
    }

    [Fact]
    public void TableLayouter_CalculateColumnWidths_EvenDistribution()
    {
        // Arrange
        var table = new DocTable
        {
            Rows =
            [
                new DocTableRow
                {
                    Cells =
                    [
                        new DocTableCell { WidthPt = 0 },
                        new DocTableCell { WidthPt = 0 },
                        new DocTableCell { WidthPt = 0 }
                    ]
                }
            ]
        };

        // Act
        float[] widths = TableLayouter.CalculateColumnWidths(table, 300f);

        // Assert
        widths.Length.ShouldBe(3);
        widths[0].ShouldBe(100f);
        widths[1].ShouldBe(100f);
        widths[2].ShouldBe(100f);
    }

    [Fact]
    public void TableLayouter_CalculateColumnWidths_UsesSpecifiedWidths()
    {
        // Arrange
        var table = new DocTable
        {
            Rows =
            [
                new DocTableRow
                {
                    Cells =
                    [
                        new DocTableCell { WidthPt = 100f },
                        new DocTableCell { WidthPt = 200f }
                    ]
                }
            ]
        };

        // Act
        float[] widths = TableLayouter.CalculateColumnWidths(table, 400f);

        // Assert
        widths[0].ShouldBe(100f);
        widths[1].ShouldBe(200f);
    }

    [Fact]
    public void TableLayouter_EmptyTable_ReturnsEmptyWidths()
    {
        // Arrange
        var table = new DocTable();

        // Act
        float[] widths = TableLayouter.CalculateColumnWidths(table, 300f);

        // Assert
        widths.ShouldBeEmpty();
    }

    [Fact]
    public void PageBreaker_FitsOnPage_ReturnsTrueWhenSpaceAvailable()
    {
        // Arrange
        var breaker = new PageBreaker(792f, 72f, 72f);

        // Act & Assert
        breaker.FitsOnPage(72f, 100f).ShouldBeTrue();
    }

    [Fact]
    public void PageBreaker_FitsOnPage_ReturnsFalseWhenOverflow()
    {
        // Arrange
        var breaker = new PageBreaker(792f, 72f, 72f);

        // Act & Assert
        breaker.FitsOnPage(700f, 100f).ShouldBeFalse();
    }

    [Fact]
    public void PageBreaker_ContentHeight_ReturnsCorrectValue()
    {
        // Arrange
        var breaker = new PageBreaker(792f, 72f, 72f);

        // Act & Assert
        breaker.ContentHeight.ShouldBe(648f);
    }

    [Fact]
    public void DocumentLayoutEngine_SimpleDocument_ProducesPages()
    {
        // Arrange
        byte[] docx = DocxFixtureFactory.CreateSimpleParagraph("Layout test");
        DocumentModel model = ParseDocx(docx);
        var fontResolver = new FontResolver();
        var engine = new DocumentLayoutEngine(fontResolver);

        // Act
        List<LayoutPage> pages = engine.Layout(model);

        // Assert
        pages.ShouldNotBeEmpty();
        pages[0].Width.ShouldBeGreaterThan(0f);
        pages[0].Height.ShouldBeGreaterThan(0f);
    }

    [Fact]
    public void DocumentLayoutEngine_EmptyDocument_ReturnsAtLeastOnePage()
    {
        // Arrange
        byte[] docx = DocxFixtureFactory.CreateEmpty();
        DocumentModel model = ParseDocx(docx);
        var fontResolver = new FontResolver();
        var engine = new DocumentLayoutEngine(fontResolver);

        // Act
        List<LayoutPage> pages = engine.Layout(model);

        // Assert
        pages.Count.ShouldBeGreaterThanOrEqualTo(1);
    }

    [Fact]
    public void DocumentLayoutEngine_ThrowsOnNullModel()
    {
        // Arrange
        var fontResolver = new FontResolver();
        var engine = new DocumentLayoutEngine(fontResolver);

        // Act & Assert
        Should.Throw<ArgumentNullException>(() => engine.Layout(null!));
    }

    private static DocumentModel ParseDocx(byte[] data)
    {
        using var stream = new MemoryStream(data);
        using var reader = new Parsing.OoxmlPackageReader(stream);
        return reader.Parse();
    }
}
