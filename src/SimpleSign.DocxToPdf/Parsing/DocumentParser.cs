using System.Globalization;
using DocumentFormat.OpenXml;
using DocumentFormat.OpenXml.Packaging;
using DocumentFormat.OpenXml.Wordprocessing;
using SimpleSign.DocxToPdf.Model;
using ParagraphAlignment = SimpleSign.DocxToPdf.Model.ParagraphAlignment;

namespace SimpleSign.DocxToPdf.Parsing;

/// <summary>Parses the document.xml body elements into the document model.</summary>
internal sealed class DocumentParser
{
    private const float TwipsPerPoint = 20f;

    /// <summary>Parses the main document part into sections.</summary>
    /// <param name="mainPart">The main document part.</param>
    /// <returns>A list of document sections.</returns>
    public static List<DocSection> Parse(MainDocumentPart mainPart)
    {
        ArgumentNullException.ThrowIfNull(mainPart);

        var sections = new List<DocSection>();
        var currentSection = new DocSection();
        Body? body = mainPart.Document?.Body;

        if (body is null)
        {
            sections.Add(currentSection);
            return sections;
        }

        foreach (OpenXmlElement element in body.Elements())
        {
            if (element is Paragraph para)
            {
                DocParagraph docPara = ParseParagraph(para);
                currentSection.Content.Add(docPara);
                currentSection.Paragraphs.Add(docPara);

                // Check for section break in paragraph properties
                SectionProperties? sectPr = para.ParagraphProperties?.SectionProperties;
                if (sectPr is not null)
                {
                    ApplySectionProperties(currentSection, sectPr);
                    sections.Add(currentSection);
                    currentSection = new DocSection();
                }
            }
            else if (element is Table table)
            {
                DocTable docTable = ParseTable(table);
                currentSection.Content.Add(docTable);
                currentSection.Tables.Add(docTable);
            }
            else if (element is SectionProperties finalSectPr)
            {
                ApplySectionProperties(currentSection, finalSectPr);
            }
        }

        sections.Add(currentSection);
        return sections;
    }

    private static DocParagraph ParseParagraph(Paragraph para)
    {
        var docPara = new DocParagraph();
        ParagraphProperties? pPr = para.ParagraphProperties;

        if (pPr is not null)
        {
            ApplyParagraphProperties(docPara, pPr);
        }

        foreach (Run run in para.Elements<Run>())
        {
            DocRun docRun = ParseRun(run);
            if (!string.IsNullOrEmpty(docRun.Text))
            {
                docPara.Runs.Add(docRun);
            }

            // Check for inline images
            foreach (DocumentFormat.OpenXml.Wordprocessing.Drawing drawing in run.Elements<DocumentFormat.OpenXml.Wordprocessing.Drawing>())
            {
                DocImage? image = ParseDrawing(drawing);
                if (image is not null)
                {
                    docPara.Images.Add(image);
                }
            }
        }

        return docPara;
    }

    private static void ApplyParagraphProperties(DocParagraph docPara, ParagraphProperties pPr)
    {
        if (pPr.Justification?.Val?.Value is not null)
        {
            docPara.Alignment = MapJustification(pPr.Justification.Val.Value);
        }

        if (pPr.SpacingBetweenLines is not null)
        {
            SpacingBetweenLines spacing = pPr.SpacingBetweenLines;
            docPara.Spacing = new DocSpacing
            {
                BeforePt = ParseTwips(spacing.Before?.Value),
                AfterPt = ParseTwips(spacing.After?.Value),
                LinePt = ParseTwips(spacing.Line?.Value),
                LineRule = spacing.LineRule?.Value.ToString() ?? "auto"
            };
        }

        if (pPr.Indentation is not null)
        {
            Indentation ind = pPr.Indentation;
            docPara.IndentLeftPt = ParseTwips(ind.Left?.Value);
            docPara.IndentRightPt = ParseTwips(ind.Right?.Value);
            docPara.IndentFirstLinePt = ParseTwips(ind.FirstLine?.Value);
            if (ind.Hanging?.Value is not null)
            {
                docPara.IndentFirstLinePt = -ParseTwips(ind.Hanging.Value);
            }
        }

        if (pPr.NumberingProperties is not null)
        {
            NumberingProperties numPr = pPr.NumberingProperties;
            if (numPr.NumberingLevelReference?.Val?.Value is not null)
            {
                docPara.NumberingLevel = numPr.NumberingLevelReference.Val.Value;
            }

            if (numPr.NumberingId?.Val?.Value is not null)
            {
                docPara.NumberingId = numPr.NumberingId.Val.Value;
            }
        }

        docPara.KeepTogether = pPr.KeepLines is not null;
        docPara.KeepWithNext = pPr.KeepNext is not null;
        docPara.PageBreakBefore = pPr.PageBreakBefore is not null;
        docPara.StyleId = pPr.ParagraphStyleId?.Val?.Value;
    }

    private static DocRun ParseRun(Run run)
    {
        string textContent = string.Concat(run.Elements<Text>().Select(t => t.Text));

        // Also include tab and break elements
        foreach (OpenXmlElement child in run.ChildElements)
        {
            if (child is TabChar)
            {
                textContent += "\t";
            }
            else if (child is Break)
            {
                textContent += "\n";
            }
        }

        var docRun = new DocRun { Text = textContent };

        RunProperties? rPr = run.RunProperties;
        if (rPr is null)
        {
            return docRun;
        }

        docRun.FontName = rPr.RunFonts?.Ascii?.Value;
        if (rPr.FontSize?.Val?.Value is not null &&
            int.TryParse(rPr.FontSize.Val.Value, CultureInfo.InvariantCulture, out int size))
        {
            docRun.SizeHalfPoints = size;
        }

        docRun.Bold = rPr.Bold is not null && rPr.Bold.Val?.Value != false;
        docRun.Italic = rPr.Italic is not null && rPr.Italic.Val?.Value != false;
        docRun.Strikethrough = rPr.Strike is not null && rPr.Strike.Val?.Value != false;
        docRun.Color = rPr.Color?.Val?.Value;
        docRun.Highlight = rPr.Highlight?.Val?.Value.ToString();
        docRun.AllCaps = rPr.Caps is not null && rPr.Caps.Val?.Value != false;

        if (rPr.Underline?.Val?.Value is not null)
        {
            docRun.Underline = MapUnderline(rPr.Underline.Val.Value);
        }

        if (rPr.VerticalTextAlignment?.Val?.Value is not null)
        {
            docRun.Superscript = rPr.VerticalTextAlignment.Val.Value == VerticalPositionValues.Superscript;
            docRun.Subscript = rPr.VerticalTextAlignment.Val.Value == VerticalPositionValues.Subscript;
        }

        return docRun;
    }

    private static DocImage? ParseDrawing(DocumentFormat.OpenXml.Wordprocessing.Drawing drawing)
    {
        var inline = drawing.Inline;
        if (inline is null)
        {
            return null;
        }

        string? blipRelId = inline.Graphic?.GraphicData?
            .Descendants<DocumentFormat.OpenXml.Drawing.Blip>()
            .FirstOrDefault()?.Embed?.Value;

        if (blipRelId is null)
        {
            return null;
        }

        return new DocImage
        {
            RelationshipId = blipRelId,
            WidthEmu = inline.Extent?.Cx?.Value ?? 0,
            HeightEmu = inline.Extent?.Cy?.Value ?? 0,
            IsInline = true
        };
    }

    private static DocTable ParseTable(Table table)
    {
        var docTable = new DocTable();
        TableProperties? tblPr = table.Elements<TableProperties>().FirstOrDefault();

        if (tblPr is not null)
        {
            if (tblPr.TableWidth?.Width?.Value is not null &&
                int.TryParse(tblPr.TableWidth.Width.Value, CultureInfo.InvariantCulture, out int w))
            {
                docTable.WidthPt = w / TwipsPerPoint;
            }

            if (tblPr.TableJustification?.Val?.Value is not null)
            {
                docTable.Alignment = MapTableAlignment(tblPr.TableJustification.Val.Value);
            }
        }

        foreach (TableRow row in table.Elements<TableRow>())
        {
            docTable.Rows.Add(ParseTableRow(row));
        }

        return docTable;
    }

    private static DocTableRow ParseTableRow(TableRow row)
    {
        var docRow = new DocTableRow();
        TableRowProperties? trPr = row.TableRowProperties;

        if (trPr is not null)
        {
            TableRowHeight? rowHeight = trPr.Elements<TableRowHeight>().FirstOrDefault();
            if (rowHeight?.Val?.Value is not null)
            {
                docRow.HeightPt = rowHeight.Val.Value / TwipsPerPoint;
            }
        }

        foreach (TableCell cell in row.Elements<TableCell>())
        {
            docRow.Cells.Add(ParseTableCell(cell));
        }

        return docRow;
    }

    private static DocTableCell ParseTableCell(TableCell cell)
    {
        var docCell = new DocTableCell();
        TableCellProperties? tcPr = cell.TableCellProperties;

        if (tcPr is not null)
        {
            if (tcPr.TableCellWidth?.Width?.Value is not null &&
                int.TryParse(tcPr.TableCellWidth.Width.Value, CultureInfo.InvariantCulture, out int w))
            {
                docCell.WidthPt = w / TwipsPerPoint;
            }

            if (tcPr.GridSpan?.Val?.Value is not null)
            {
                docCell.GridSpan = tcPr.GridSpan.Val.Value;
            }

            if (tcPr.VerticalMerge is not null)
            {
                docCell.VerticalMerge = tcPr.VerticalMerge.Val?.Value == MergedCellValues.Restart
                    ? "restart"
                    : "continue";
            }

            if (tcPr.Shading?.Fill?.Value is not null)
            {
                docCell.ShadingColor = tcPr.Shading.Fill.Value;
            }

            if (tcPr.TableCellVerticalAlignment?.Val?.Value is not null)
            {
                docCell.VerticalAlignment = MapCellVerticalAlignment(tcPr.TableCellVerticalAlignment.Val.Value);
            }
        }

        foreach (Paragraph para in cell.Elements<Paragraph>())
        {
            docCell.Paragraphs.Add(ParseParagraph(para));
        }

        return docCell;
    }

    private static void ApplySectionProperties(DocSection section, SectionProperties sectPr)
    {
        PageSize? pageSize = sectPr.Elements<PageSize>().FirstOrDefault();
        if (pageSize is not null)
        {
            if (pageSize.Width?.Value is not null)
            {
                section.PageWidthPt = pageSize.Width.Value / TwipsPerPoint;
            }

            if (pageSize.Height?.Value is not null)
            {
                section.PageHeightPt = pageSize.Height.Value / TwipsPerPoint;
            }

            if (pageSize.Orient?.Value == PageOrientationValues.Landscape)
            {
                section.Orientation = Model.PageOrientation.Landscape;
            }
        }

        PageMargin? margin = sectPr.Elements<PageMargin>().FirstOrDefault();
        if (margin is not null)
        {
            if (margin.Top?.Value is not null)
            {
                section.MarginTopPt = margin.Top.Value / TwipsPerPoint;
            }

            if (margin.Bottom?.Value is not null)
            {
                section.MarginBottomPt = margin.Bottom.Value / TwipsPerPoint;
            }

            if (margin.Left?.Value is not null)
            {
                section.MarginLeftPt = margin.Left.Value / TwipsPerPoint;
            }

            if (margin.Right?.Value is not null)
            {
                section.MarginRightPt = margin.Right.Value / TwipsPerPoint;
            }
        }
    }

    private static ParagraphAlignment MapJustification(JustificationValues val)
    {
        if (val == JustificationValues.Center)
        {
            return ParagraphAlignment.Center;
        }

        if (val == JustificationValues.Right)
        {
            return ParagraphAlignment.Right;
        }

        if (val == JustificationValues.Both)
        {
            return ParagraphAlignment.Justify;
        }

        return ParagraphAlignment.Left;
    }

    private static Model.UnderlineType MapUnderline(UnderlineValues val)
    {
        if (val == UnderlineValues.Single)
        {
            return Model.UnderlineType.Single;
        }

        if (val == UnderlineValues.Double)
        {
            return Model.UnderlineType.Double;
        }

        if (val == UnderlineValues.Wave)
        {
            return Model.UnderlineType.Wave;
        }

        if (val == UnderlineValues.Dotted)
        {
            return Model.UnderlineType.Dotted;
        }

        if (val == UnderlineValues.Dash)
        {
            return Model.UnderlineType.Dash;
        }

        return Model.UnderlineType.None;
    }

    private static ParagraphAlignment MapTableAlignment(TableRowAlignmentValues val)
    {
        if (val == TableRowAlignmentValues.Center)
        {
            return ParagraphAlignment.Center;
        }

        if (val == TableRowAlignmentValues.Right)
        {
            return ParagraphAlignment.Right;
        }

        return ParagraphAlignment.Left;
    }

    private static Model.VerticalAlignment MapCellVerticalAlignment(TableVerticalAlignmentValues val)
    {
        if (val == TableVerticalAlignmentValues.Center)
        {
            return Model.VerticalAlignment.Center;
        }

        if (val == TableVerticalAlignmentValues.Bottom)
        {
            return Model.VerticalAlignment.Bottom;
        }

        return Model.VerticalAlignment.Top;
    }

    private static float ParseTwips(string? value)
    {
        if (value is null || !int.TryParse(value, CultureInfo.InvariantCulture, out int twips))
        {
            return 0f;
        }

        return twips / TwipsPerPoint;
    }
}
