using SimpleSign.DocxToPdf.Fonts;
using SimpleSign.DocxToPdf.Model;

namespace SimpleSign.DocxToPdf.Layout;

/// <summary>Lays out a complete document model into pages of positioned elements.</summary>
internal sealed class DocumentLayoutEngine
{
    private readonly FontResolver _fontResolver;

    /// <summary>Initializes a new instance of the <see cref="DocumentLayoutEngine"/> class.</summary>
    /// <param name="fontResolver">The font resolver to use.</param>
    public DocumentLayoutEngine(FontResolver fontResolver)
    {
        _fontResolver = fontResolver;
    }

    /// <summary>Lays out the document model into pages.</summary>
    /// <param name="model">The document model.</param>
    /// <returns>A list of layout pages.</returns>
    public List<LayoutPage> Layout(DocumentModel model)
    {
        ArgumentNullException.ThrowIfNull(model);

        var pages = new List<LayoutPage>();
        var paragraphLayouter = new ParagraphLayouter(_fontResolver, model.Styles);
        var tableLayouter = new TableLayouter(paragraphLayouter);

        foreach (DocSection section in model.Sections)
        {
            LayoutSection(section, pages, paragraphLayouter, tableLayouter, model);
        }

        if (pages.Count == 0)
        {
            pages.Add(new LayoutPage
            {
                Width = 612f,
                Height = 792f
            });
        }

        return pages;
    }

    private static void LayoutSection(
        DocSection section,
        List<LayoutPage> pages,
        ParagraphLayouter paragraphLayouter,
        TableLayouter tableLayouter,
        DocumentModel model)
    {
        var pageBreaker = new PageBreaker(section.PageHeightPt, section.MarginTopPt, section.MarginBottomPt);
        float contentWidth = section.PageWidthPt - section.MarginLeftPt - section.MarginRightPt;
        float marginLeft = section.MarginLeftPt;

        var currentPage = new LayoutPage
        {
            Width = section.PageWidthPt,
            Height = section.PageHeightPt
        };
        pages.Add(currentPage);

        float currentY = pageBreaker.ContentStartY;

        foreach (object content in section.Content)
        {
            if (content is DocParagraph paragraph)
            {
                // Handle explicit page break
                if (paragraph.PageBreakBefore && currentY > pageBreaker.ContentStartY)
                {
                    currentPage = new LayoutPage
                    {
                        Width = section.PageWidthPt,
                        Height = section.PageHeightPt
                    };
                    pages.Add(currentPage);
                    currentY = pageBreaker.ContentStartY;
                }

                (List<LayoutElement> elements, float height) = paragraphLayouter.Layout(
                    paragraph, marginLeft, currentY, contentWidth);

                // Check if we need a page break
                if (!pageBreaker.FitsOnPage(currentY, height) && currentY > pageBreaker.ContentStartY)
                {
                    currentPage = new LayoutPage
                    {
                        Width = section.PageWidthPt,
                        Height = section.PageHeightPt
                    };
                    pages.Add(currentPage);
                    currentY = pageBreaker.ContentStartY;

                    // Re-layout on new page
                    (elements, height) = paragraphLayouter.Layout(
                        paragraph, marginLeft, currentY, contentWidth);
                }

                // Resolve image data
                foreach (LayoutElement elem in elements)
                {
                    if (elem is LayoutImage layoutImage && paragraph.Images.Count > 0)
                    {
                        DocImage? docImage = paragraph.Images.FirstOrDefault();
                        if (docImage is not null && model.Images.TryGetValue(docImage.RelationshipId, out byte[]? imgData))
                        {
                            layoutImage.Data = imgData;
                            layoutImage.Format = DetectImageFormat(imgData);
                        }
                    }
                }

                currentPage.Elements.AddRange(elements);
                currentY += height;
            }
            else if (content is DocTable table)
            {
                (List<LayoutElement> tableElements, float tableHeight) = tableLayouter.Layout(
                    table, marginLeft, currentY, contentWidth);

                if (!pageBreaker.FitsOnPage(currentY, tableHeight) && currentY > pageBreaker.ContentStartY)
                {
                    currentPage = new LayoutPage
                    {
                        Width = section.PageWidthPt,
                        Height = section.PageHeightPt
                    };
                    pages.Add(currentPage);
                    currentY = pageBreaker.ContentStartY;

                    (tableElements, tableHeight) = tableLayouter.Layout(
                        table, marginLeft, currentY, contentWidth);
                }

                currentPage.Elements.AddRange(tableElements);
                currentY += tableHeight;
            }
        }
    }

    private static string DetectImageFormat(byte[] data)
    {
        if (data.Length >= 2 && data[0] == 0xFF && data[1] == 0xD8)
        {
            return "jpeg";
        }

        if (data.Length >= 8 && data[0] == 0x89 && data[1] == 0x50)
        {
            return "png";
        }

        return "jpeg";
    }
}
