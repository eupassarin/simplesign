using SimpleSign.DocxToPdf.Model;
using SimpleSign.DocxToPdf.Parsing;
using SimpleSign.DocxToPdf.Tests.Fixtures;
using Shouldly;

namespace SimpleSign.DocxToPdf.Tests;

public sealed class ParsingTests
{
    [Fact]
    public void Parse_SimpleParagraph_ReturnsSingleSection()
    {
        // Arrange
        byte[] docx = DocxFixtureFactory.CreateSimpleParagraph("Test text");

        // Act
        DocumentModel model = ParseDocx(docx);

        // Assert
        model.Sections.ShouldNotBeEmpty();
        model.Sections[0].Paragraphs.ShouldNotBeEmpty();
        model.Sections[0].Paragraphs[0].Runs[0].Text.ShouldBe("Test text");
    }

    [Fact]
    public void Parse_MultipleParagraphs_ParsesAll()
    {
        // Arrange
        byte[] docx = DocxFixtureFactory.CreateMultipleParagraphs("First", "Second", "Third");

        // Act
        DocumentModel model = ParseDocx(docx);

        // Assert
        model.Sections[0].Paragraphs.Count.ShouldBe(3);
        model.Sections[0].Paragraphs[0].Runs[0].Text.ShouldBe("First");
        model.Sections[0].Paragraphs[1].Runs[0].Text.ShouldBe("Second");
        model.Sections[0].Paragraphs[2].Runs[0].Text.ShouldBe("Third");
    }

    [Fact]
    public void Parse_FormattedDocument_ParsesBoldAndItalic()
    {
        // Arrange
        byte[] docx = DocxFixtureFactory.CreateFormattedDocument();

        // Act
        DocumentModel model = ParseDocx(docx);

        // Assert
        model.Sections[0].Paragraphs[0].Runs[0].Bold.ShouldBeTrue();
        model.Sections[0].Paragraphs[1].Runs[0].Italic.ShouldBeTrue();
    }

    [Fact]
    public void Parse_FormattedDocument_ParsesColor()
    {
        // Arrange
        byte[] docx = DocxFixtureFactory.CreateFormattedDocument();

        // Act
        DocumentModel model = ParseDocx(docx);

        // Assert
        model.Sections[0].Paragraphs[2].Runs[0].Color.ShouldBe("FF0000");
    }

    [Fact]
    public void Parse_FormattedDocument_ParsesFontSize()
    {
        // Arrange
        byte[] docx = DocxFixtureFactory.CreateFormattedDocument();

        // Act
        DocumentModel model = ParseDocx(docx);

        // Assert
        model.Sections[0].Paragraphs[3].Runs[0].SizeHalfPoints.ShouldBe(48);
        model.Sections[0].Paragraphs[3].Runs[0].SizePt.ShouldBe(24f);
    }

    [Fact]
    public void Parse_SimpleTable_ParsesRowsAndCells()
    {
        // Arrange
        byte[] docx = DocxFixtureFactory.CreateSimpleTable(2, 3);

        // Act
        DocumentModel model = ParseDocx(docx);

        // Assert
        model.Sections[0].Tables.Count.ShouldBe(1);
        DocTable table = model.Sections[0].Tables[0];
        table.Rows.Count.ShouldBe(2);
        table.Rows[0].Cells.Count.ShouldBe(3);
        table.Rows[0].Cells[0].Paragraphs[0].Runs[0].Text.ShouldBe("R0C0");
    }

    [Fact]
    public void Parse_WithAlignment_ParsesCenterAndRight()
    {
        // Arrange
        byte[] docx = DocxFixtureFactory.CreateWithAlignment();

        // Act
        DocumentModel model = ParseDocx(docx);

        // Assert
        model.Sections[0].Paragraphs[0].Alignment.ShouldBe(ParagraphAlignment.Center);
        model.Sections[0].Paragraphs[1].Alignment.ShouldBe(ParagraphAlignment.Right);
    }

    [Fact]
    public void Parse_WithSpacing_ParsesBeforeAndAfter()
    {
        // Arrange
        byte[] docx = DocxFixtureFactory.CreateWithSpacing();

        // Act
        DocumentModel model = ParseDocx(docx);

        // Assert
        DocParagraph para = model.Sections[0].Paragraphs[0];
        para.Spacing.BeforePt.ShouldBe(12f); // 240 twips / 20
        para.Spacing.AfterPt.ShouldBe(6f);   // 120 twips / 20
    }

    [Fact]
    public void Parse_WithPageBreak_SetsPageBreakBefore()
    {
        // Arrange
        byte[] docx = DocxFixtureFactory.CreateWithPageBreak();

        // Act
        DocumentModel model = ParseDocx(docx);

        // Assert
        model.Sections[0].Paragraphs[0].PageBreakBefore.ShouldBeFalse();
        model.Sections[0].Paragraphs[1].PageBreakBefore.ShouldBeTrue();
    }

    [Fact]
    public void Parse_WithStyles_ParsesDefaultFont()
    {
        // Arrange
        byte[] docx = DocxFixtureFactory.CreateWithStyles();

        // Act
        DocumentModel model = ParseDocx(docx);

        // Assert
        model.Styles.DefaultFontName.ShouldBe("Times New Roman");
        model.Styles.DefaultFontSizeHalfPoints.ShouldBe(24);
    }

    [Fact]
    public void Parse_WithStyles_ParsesNamedStyle()
    {
        // Arrange
        byte[] docx = DocxFixtureFactory.CreateWithStyles();

        // Act
        DocumentModel model = ParseDocx(docx);

        // Assert
        model.Styles.ParagraphStyles.ShouldContainKey("Heading1");
        model.Styles.ParagraphStyles["Heading1"].Bold.ShouldBe(true);
        model.Styles.ParagraphStyles["Heading1"].SizeHalfPoints.ShouldBe(32);
    }

    [Fact]
    public void Parse_WithNumbering_ParsesNumberingDefinitions()
    {
        // Arrange
        byte[] docx = DocxFixtureFactory.CreateWithNumbering();

        // Act
        DocumentModel model = ParseDocx(docx);

        // Assert
        model.Numbering.AbstractDefinitions.ShouldNotBeEmpty();
        model.Numbering.NumInstances.ShouldContainKey(1);
        model.Sections[0].Paragraphs[0].NumberingId.ShouldBe(1);
        model.Sections[0].Paragraphs[0].NumberingLevel.ShouldBe(0);
    }

    [Fact]
    public void Parse_WithSectionProperties_ParsesPageSize()
    {
        // Arrange
        byte[] docx = DocxFixtureFactory.CreateWithSectionProperties();

        // Act
        DocumentModel model = ParseDocx(docx);

        // Assert
        DocSection section = model.Sections[0];
        section.PageWidthPt.ShouldBe(612f);  // 12240 / 20
        section.PageHeightPt.ShouldBe(792f); // 15840 / 20
        section.MarginTopPt.ShouldBe(72f);   // 1440 / 20
    }

    [Fact]
    public void Parse_EmptyDocument_ReturnsEmptyModel()
    {
        // Arrange
        byte[] docx = DocxFixtureFactory.CreateEmpty();

        // Act
        DocumentModel model = ParseDocx(docx);

        // Assert
        model.Sections.ShouldNotBeEmpty();
    }

    private static DocumentModel ParseDocx(byte[] data)
    {
        using var stream = new MemoryStream(data);
        using var reader = new OoxmlPackageReader(stream);
        return reader.Parse();
    }
}
