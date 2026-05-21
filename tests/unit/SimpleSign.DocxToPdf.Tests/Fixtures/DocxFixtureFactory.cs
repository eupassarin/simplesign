using DocumentFormat.OpenXml;
using DocumentFormat.OpenXml.Packaging;
using DocumentFormat.OpenXml.Wordprocessing;

namespace SimpleSign.DocxToPdf.Tests.Fixtures;

/// <summary>Creates DOCX test fixtures programmatically.</summary>
internal static class DocxFixtureFactory
{
    public static byte[] CreateSimpleParagraph(string text = "Hello World")
    {
        using var ms = new MemoryStream();
        using (var doc = WordprocessingDocument.Create(ms, WordprocessingDocumentType.Document))
        {
            var mainPart = doc.AddMainDocumentPart();
            mainPart.Document = new Document(
                new Body(
                    new Paragraph(
                        new Run(new Text(text)))));
        }

        return ms.ToArray();
    }

    public static byte[] CreateMultipleParagraphs(params string[] texts)
    {
        using var ms = new MemoryStream();
        using (var doc = WordprocessingDocument.Create(ms, WordprocessingDocumentType.Document))
        {
            var mainPart = doc.AddMainDocumentPart();
            var body = new Body();

            foreach (string text in texts)
            {
                body.Append(new Paragraph(new Run(new Text(text))));
            }

            mainPart.Document = new Document(body);
        }

        return ms.ToArray();
    }

    public static byte[] CreateFormattedDocument()
    {
        using var ms = new MemoryStream();
        using (var doc = WordprocessingDocument.Create(ms, WordprocessingDocumentType.Document))
        {
            var mainPart = doc.AddMainDocumentPart();
            var body = new Body();

            // Bold paragraph
            body.Append(new Paragraph(
                new Run(
                    new RunProperties(new Bold()),
                    new Text("Bold text"))));

            // Italic paragraph
            body.Append(new Paragraph(
                new Run(
                    new RunProperties(new Italic()),
                    new Text("Italic text"))));

            // Colored paragraph
            body.Append(new Paragraph(
                new Run(
                    new RunProperties(new Color { Val = "FF0000" }),
                    new Text("Red text"))));

            // Large font
            body.Append(new Paragraph(
                new Run(
                    new RunProperties(new FontSize { Val = "48" }),
                    new Text("Large text"))));

            mainPart.Document = new Document(body);
        }

        return ms.ToArray();
    }

    public static byte[] CreateSimpleTable(int rows, int cols)
    {
        using var ms = new MemoryStream();
        using (var doc = WordprocessingDocument.Create(ms, WordprocessingDocumentType.Document))
        {
            var mainPart = doc.AddMainDocumentPart();
            var body = new Body();
            var table = new Table();

            var tblPr = new TableProperties(
                new TableWidth { Width = "5000", Type = TableWidthUnitValues.Dxa });
            table.Append(tblPr);

            for (int r = 0; r < rows; r++)
            {
                var row = new TableRow();
                for (int c = 0; c < cols; c++)
                {
                    var cell = new TableCell(
                        new TableCellProperties(
                            new TableCellWidth { Width = $"{5000 / cols}", Type = TableWidthUnitValues.Dxa }),
                        new Paragraph(new Run(new Text($"R{r}C{c}"))));
                    row.Append(cell);
                }

                table.Append(row);
            }

            body.Append(table);
            mainPart.Document = new Document(body);
        }

        return ms.ToArray();
    }

    public static byte[] CreateWithAlignment()
    {
        using var ms = new MemoryStream();
        using (var doc = WordprocessingDocument.Create(ms, WordprocessingDocumentType.Document))
        {
            var mainPart = doc.AddMainDocumentPart();
            var body = new Body();

            body.Append(new Paragraph(
                new ParagraphProperties(new Justification { Val = JustificationValues.Center }),
                new Run(new Text("Centered"))));

            body.Append(new Paragraph(
                new ParagraphProperties(new Justification { Val = JustificationValues.Right }),
                new Run(new Text("Right-aligned"))));

            mainPart.Document = new Document(body);
        }

        return ms.ToArray();
    }

    public static byte[] CreateWithSpacing()
    {
        using var ms = new MemoryStream();
        using (var doc = WordprocessingDocument.Create(ms, WordprocessingDocumentType.Document))
        {
            var mainPart = doc.AddMainDocumentPart();
            var body = new Body();

            body.Append(new Paragraph(
                new ParagraphProperties(
                    new SpacingBetweenLines { Before = "240", After = "120" }),
                new Run(new Text("Spaced paragraph"))));

            mainPart.Document = new Document(body);
        }

        return ms.ToArray();
    }

    public static byte[] CreateWithPageBreak()
    {
        using var ms = new MemoryStream();
        using (var doc = WordprocessingDocument.Create(ms, WordprocessingDocumentType.Document))
        {
            var mainPart = doc.AddMainDocumentPart();
            var body = new Body();

            body.Append(new Paragraph(new Run(new Text("Page 1"))));
            body.Append(new Paragraph(
                new ParagraphProperties(new PageBreakBefore()),
                new Run(new Text("Page 2"))));

            mainPart.Document = new Document(body);
        }

        return ms.ToArray();
    }

    public static byte[] CreateWithStyles()
    {
        using var ms = new MemoryStream();
        using (var doc = WordprocessingDocument.Create(ms, WordprocessingDocumentType.Document))
        {
            var mainPart = doc.AddMainDocumentPart();

            // Add styles part
            var stylesPart = mainPart.AddNewPart<StyleDefinitionsPart>();
            stylesPart.Styles = new Styles(
                new DocDefaults(
                    new RunPropertiesDefault(
                        new RunPropertiesBaseStyle(
                            new RunFonts { Ascii = "Times New Roman" },
                            new FontSize { Val = "24" }))),
                new Style(
                    new StyleName { Val = "Heading 1" },
                    new StyleRunProperties(
                        new Bold(),
                        new FontSize { Val = "32" }))
                { Type = StyleValues.Paragraph, StyleId = "Heading1" });

            var body = new Body();
            body.Append(new Paragraph(
                new ParagraphProperties(new ParagraphStyleId { Val = "Heading1" }),
                new Run(new Text("Heading"))));
            body.Append(new Paragraph(new Run(new Text("Body text"))));

            mainPart.Document = new Document(body);
        }

        return ms.ToArray();
    }

    public static byte[] CreateWithNumbering()
    {
        using var ms = new MemoryStream();
        using (var doc = WordprocessingDocument.Create(ms, WordprocessingDocumentType.Document))
        {
            var mainPart = doc.AddMainDocumentPart();

            // Add numbering part
            var numberingPart = mainPart.AddNewPart<NumberingDefinitionsPart>();
            numberingPart.Numbering = new Numbering(
                new AbstractNum(
                    new Level(
                        new NumberingFormat { Val = NumberFormatValues.Decimal },
                        new LevelText { Val = "%1." },
                        new StartNumberingValue { Val = 1 })
                    { LevelIndex = 0 })
                { AbstractNumberId = 1 },
                new NumberingInstance(
                    new AbstractNumId { Val = 1 })
                { NumberID = 1 });

            var body = new Body();
            body.Append(new Paragraph(
                new ParagraphProperties(
                    new NumberingProperties(
                        new NumberingLevelReference { Val = 0 },
                        new NumberingId { Val = 1 })),
                new Run(new Text("First item"))));
            body.Append(new Paragraph(
                new ParagraphProperties(
                    new NumberingProperties(
                        new NumberingLevelReference { Val = 0 },
                        new NumberingId { Val = 1 })),
                new Run(new Text("Second item"))));

            mainPart.Document = new Document(body);
        }

        return ms.ToArray();
    }

    public static byte[] CreateWithSectionProperties()
    {
        using var ms = new MemoryStream();
        using (var doc = WordprocessingDocument.Create(ms, WordprocessingDocumentType.Document))
        {
            var mainPart = doc.AddMainDocumentPart();
            var body = new Body();

            body.Append(new Paragraph(new Run(new Text("Content"))));

            body.Append(new SectionProperties(
                new PageSize { Width = 12240, Height = 15840 },
                new PageMargin { Top = 1440, Bottom = 1440, Left = 1440, Right = 1440 }));

            mainPart.Document = new Document(body);
        }

        return ms.ToArray();
    }

    public static byte[] CreateEmpty()
    {
        using var ms = new MemoryStream();
        using (var doc = WordprocessingDocument.Create(ms, WordprocessingDocumentType.Document))
        {
            var mainPart = doc.AddMainDocumentPart();
            mainPart.Document = new Document(new Body());
        }

        return ms.ToArray();
    }
}
