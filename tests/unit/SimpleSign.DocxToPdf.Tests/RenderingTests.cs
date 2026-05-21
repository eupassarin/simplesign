using SimpleSign.DocxToPdf.Layout;
using SimpleSign.DocxToPdf.Rendering;
using Shouldly;

namespace SimpleSign.DocxToPdf.Tests;

public sealed class RenderingTests
{
    [Fact]
    public void PdfContentStreamBuilder_BeginEndText_ProducesValidOutput()
    {
        // Arrange
        var builder = new PdfContentStreamBuilder();

        // Act
        builder.BeginText();
        builder.SetFont("F1", 12f);
        builder.SetTextPosition(72f, 720f);
        builder.ShowText("Hello");
        builder.EndText();

        string result = builder.ToString();

        // Assert
        result.ShouldContain("BT");
        result.ShouldContain("ET");
        result.ShouldContain("/F1 12.00 Tf");
        result.ShouldContain("(Hello) Tj");
    }

    [Fact]
    public void PdfContentStreamBuilder_SetColor_ProducesValidOperators()
    {
        // Arrange
        var builder = new PdfContentStreamBuilder();

        // Act
        builder.SetFillColor(1f, 0f, 0f);
        builder.SetStrokeColor(0f, 0f, 1f);

        string result = builder.ToString();

        // Assert
        result.ShouldContain("1.000 0.000 0.000 rg");
        result.ShouldContain("0.000 0.000 1.000 RG");
    }

    [Fact]
    public void PdfContentStreamBuilder_DrawLine_ProducesPathOperators()
    {
        // Arrange
        var builder = new PdfContentStreamBuilder();

        // Act
        builder.SetLineWidth(1.5f);
        builder.MoveTo(10f, 20f);
        builder.LineTo(100f, 20f);
        builder.Stroke();

        string result = builder.ToString();

        // Assert
        result.ShouldContain("1.50 w");
        result.ShouldContain("10.00 20.00 m");
        result.ShouldContain("100.00 20.00 l");
        result.ShouldContain("S");
    }

    [Fact]
    public void PdfContentStreamBuilder_Rectangle_ProducesReOperator()
    {
        // Arrange
        var builder = new PdfContentStreamBuilder();

        // Act
        builder.Rectangle(10f, 20f, 100f, 50f);
        builder.Fill();

        string result = builder.ToString();

        // Assert
        result.ShouldContain("10.00 20.00 100.00 50.00 re");
        result.ShouldContain("f");
    }

    [Fact]
    public void PdfContentStreamBuilder_ToBytes_ReturnsNonEmpty()
    {
        // Arrange
        var builder = new PdfContentStreamBuilder();
        builder.BeginText();
        builder.ShowText("Test");
        builder.EndText();

        // Act
        byte[] bytes = builder.ToBytes();

        // Assert
        bytes.ShouldNotBeEmpty();
    }

    [Fact]
    public void PdfDocumentWriter_EmptyPage_ProducesValidPdf()
    {
        // Arrange
        var pages = new List<LayoutPage>
        {
            new() { Width = 612f, Height = 792f }
        };
        var writer = new PdfDocumentWriter(pages, new Dictionary<string, byte[]>());
        using var ms = new MemoryStream();

        // Act
        writer.WriteTo(ms);
        byte[] pdf = ms.ToArray();

        // Assert
        string header = System.Text.Encoding.ASCII.GetString(pdf, 0, 8);
        header.ShouldBe("%PDF-1.7");
        string trailer = System.Text.Encoding.ASCII.GetString(pdf, pdf.Length - 6, 5);
        trailer.ShouldContain("%%EOF");
    }

    [Fact]
    public void PdfDocumentWriter_WithTextElement_ProducesValidPdf()
    {
        // Arrange
        var page = new LayoutPage
        {
            Width = 612f,
            Height = 792f,
            Elements =
            [
                new LayoutText
                {
                    X = 72f, Y = 72f, Width = 100f, Height = 12f,
                    Text = "Hello PDF", FontSizePt = 12f, Color = "000000"
                }
            ]
        };
        var writer = new PdfDocumentWriter([page], new Dictionary<string, byte[]>());
        using var ms = new MemoryStream();

        // Act
        writer.WriteTo(ms);
        byte[] pdf = ms.ToArray();

        // Assert
        pdf.Length.ShouldBeGreaterThan(100);
        string content = System.Text.Encoding.ASCII.GetString(pdf);
        content.ShouldContain("/Type /Page");
        content.ShouldContain("/Type /Catalog");
    }

    [Fact]
    public void PdfDocumentWriter_MultiplePages_HasCorrectPageCount()
    {
        // Arrange
        var pages = new List<LayoutPage>
        {
            new() { Width = 612f, Height = 792f },
            new() { Width = 612f, Height = 792f },
            new() { Width = 612f, Height = 792f }
        };
        var writer = new PdfDocumentWriter(pages, new Dictionary<string, byte[]>());
        using var ms = new MemoryStream();

        // Act
        writer.WriteTo(ms);
        string content = System.Text.Encoding.ASCII.GetString(ms.ToArray());

        // Assert
        content.ShouldContain("/Count 3");
    }

    [Fact]
    public void FontEmbedder_CreateToUnicodeCMap_ProducesValidCMap()
    {
        // Arrange
        var mapping = new Dictionary<ushort, char>
        {
            { 1, 'A' },
            { 2, 'B' },
            { 3, 'C' }
        };

        // Act
        string cmap = FontEmbedder.CreateToUnicodeCMap(mapping);

        // Assert
        cmap.ShouldContain("begincodespacerange");
        cmap.ShouldContain("endcodespacerange");
        cmap.ShouldContain("beginbfchar");
        cmap.ShouldContain("<0001> <0041>");
        cmap.ShouldContain("<0002> <0042>");
    }
}
