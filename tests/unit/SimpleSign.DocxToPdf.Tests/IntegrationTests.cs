using SimpleSign.DocxToPdf.Tests.Fixtures;
using Shouldly;

namespace SimpleSign.DocxToPdf.Tests;

public sealed class IntegrationTests
{
    [Fact]
    public void Convert_SimpleParagraph_ProducesValidPdf()
    {
        // Arrange
        byte[] docx = DocxFixtureFactory.CreateSimpleParagraph("Integration test");

        // Act
        byte[] pdf = DocxToPdfConverter.FromBytes(docx).Convert();

        // Assert
        AssertValidPdf(pdf);
    }

    [Fact]
    public void Convert_FormattedDocument_ProducesValidPdf()
    {
        // Arrange
        byte[] docx = DocxFixtureFactory.CreateFormattedDocument();

        // Act
        byte[] pdf = DocxToPdfConverter.FromBytes(docx).Convert();

        // Assert
        AssertValidPdf(pdf);
    }

    [Fact]
    public void Convert_SimpleTable_ProducesValidPdf()
    {
        // Arrange
        byte[] docx = DocxFixtureFactory.CreateSimpleTable(3, 3);

        // Act
        byte[] pdf = DocxToPdfConverter.FromBytes(docx).Convert();

        // Assert
        AssertValidPdf(pdf);
    }

    [Fact]
    public void Convert_WithPageBreak_ProducesMultiPagePdf()
    {
        // Arrange
        byte[] docx = DocxFixtureFactory.CreateWithPageBreak();

        // Act
        byte[] pdf = DocxToPdfConverter.FromBytes(docx).Convert();

        // Assert
        AssertValidPdf(pdf);
        string content = System.Text.Encoding.ASCII.GetString(pdf);
        content.ShouldContain("/Count 2");
    }

    [Fact]
    public void Convert_EmptyDocument_ProducesValidPdf()
    {
        // Arrange
        byte[] docx = DocxFixtureFactory.CreateEmpty();

        // Act
        byte[] pdf = DocxToPdfConverter.FromBytes(docx).Convert();

        // Assert
        AssertValidPdf(pdf);
    }

    [Fact]
    public void Convert_WithStyles_ProducesValidPdf()
    {
        // Arrange
        byte[] docx = DocxFixtureFactory.CreateWithStyles();

        // Act
        byte[] pdf = DocxToPdfConverter.FromBytes(docx).Convert();

        // Assert
        AssertValidPdf(pdf);
    }

    [Fact]
    public void Convert_WithNumbering_ProducesValidPdf()
    {
        // Arrange
        byte[] docx = DocxFixtureFactory.CreateWithNumbering();

        // Act
        byte[] pdf = DocxToPdfConverter.FromBytes(docx).Convert();

        // Assert
        AssertValidPdf(pdf);
    }

    [Fact]
    public void Convert_FromStream_ProducesValidPdf()
    {
        // Arrange
        byte[] docx = DocxFixtureFactory.CreateSimpleParagraph("Stream test");
        using var stream = new MemoryStream(docx);

        // Act
        byte[] pdf = DocxToPdfConverter.FromStream(stream).Convert();

        // Assert
        AssertValidPdf(pdf);
    }

    [Fact]
    public void Convert_WithPageSizeOverride_UsesSpecifiedSize()
    {
        // Arrange
        byte[] docx = DocxFixtureFactory.CreateSimpleParagraph("A4 test");

        // Act
        byte[] pdf = DocxToPdfConverter.FromBytes(docx)
            .WithPageSize(210f, 297f) // A4 in mm
            .Convert();

        // Assert
        AssertValidPdf(pdf);
        string content = System.Text.Encoding.ASCII.GetString(pdf);
        // A4 in points: 595.28 x 841.89
        content.ShouldContain("595.");
        content.ShouldContain("841.");
    }

    [Fact]
    public void Convert_WithFontFallback_DoesNotThrow()
    {
        // Arrange
        byte[] docx = DocxFixtureFactory.CreateSimpleParagraph("Font test");

        // Act
        byte[] pdf = DocxToPdfConverter.FromBytes(docx)
            .WithFontFallback("Arial", "Helvetica")
            .Convert();

        // Assert
        AssertValidPdf(pdf);
    }

    [Fact]
    public async Task ConvertAsync_ProducesValidPdf()
    {
        // Arrange
        byte[] docx = DocxFixtureFactory.CreateSimpleParagraph("Async test");

        // Act
        byte[] pdf = await DocxToPdfConverter.FromBytes(docx).ConvertAsync();

        // Assert
        AssertValidPdf(pdf);
    }

    [Fact]
    public void ConvertTo_WritesToStream()
    {
        // Arrange
        byte[] docx = DocxFixtureFactory.CreateSimpleParagraph("Stream output");
        using var output = new MemoryStream();

        // Act
        DocxToPdfConverter.FromBytes(docx).ConvertTo(output);

        // Assert
        output.Length.ShouldBeGreaterThan(0);
        byte[] pdf = output.ToArray();
        AssertValidPdf(pdf);
    }

    [Fact]
    public void FromBytes_NullInput_ThrowsArgumentNull() =>
        Should.Throw<ArgumentNullException>(() => DocxToPdfConverter.FromBytes(null!));

    [Fact]
    public void FromStream_NullInput_ThrowsArgumentNull() =>
        Should.Throw<ArgumentNullException>(() => DocxToPdfConverter.FromStream(null!));

    [Fact]
    public void FromFile_NullInput_ThrowsArgumentNull() =>
        Should.Throw<ArgumentNullException>(() => DocxToPdfConverter.FromFile(null!));

    [Fact]
    public void FromFile_NonexistentFile_ThrowsFileNotFound() =>
        Should.Throw<FileNotFoundException>(() => DocxToPdfConverter.FromFile("/nonexistent/file.docx"));

    private static void AssertValidPdf(byte[] pdf)
    {
        pdf.ShouldNotBeNull();
        pdf.ShouldNotBeEmpty();
        pdf.Length.ShouldBeGreaterThan(50);

        string header = System.Text.Encoding.ASCII.GetString(pdf, 0, 8);
        header.ShouldBe("%PDF-1.7");

        string content = System.Text.Encoding.ASCII.GetString(pdf);
        content.ShouldContain("%%EOF");
        content.ShouldContain("xref");
        content.ShouldContain("trailer");
        content.ShouldContain("/Type /Catalog");
    }
}
