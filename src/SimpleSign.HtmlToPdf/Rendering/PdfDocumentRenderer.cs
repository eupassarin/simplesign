// Licensed to SimpleSign under the MIT License.

using System.Globalization;
using SimpleSign.HtmlToPdf.Fonts;
using SimpleSign.HtmlToPdf.Layout;
using SimpleSign.HtmlToPdf.Parsing;

namespace SimpleSign.HtmlToPdf.Rendering;

/// <summary>
/// Renders a <see cref="LayoutResult"/> into a complete PDF document.
/// Converts layout boxes into PDF content streams, page objects, and a valid PDF structure.
/// </summary>
public sealed class PdfDocumentRenderer
{
    /// <summary>
    /// Renders the layout result into PDF bytes.
    /// </summary>
    /// <param name="layout">The layout result from the layout engine.</param>
    /// <returns>Complete PDF document bytes.</returns>
    public static byte[] Render(LayoutResult layout)
    {
        var writer = new PdfObjectWriter();
        var imageCache = new ImageObjectCache(writer);

        // Reserve object 1 for catalog
        int catalogObj = writer.AllocateObject();

        // Reserve object 2 for pages dictionary
        int pagesObj = writer.AllocateObject();

        // Render each page
        var pageObjNums = new List<int>();

        int pageNumber = 0;
        foreach (PageBox page in layout.Pages)
        {
            pageNumber++;
            int pageObj = RenderPage(writer, page, pagesObj, imageCache, layout.Metadata, pageNumber, layout.Pages.Count);
            pageObjNums.Add(pageObj);
        }

        // Write pages dictionary
        string pageRefs = string.Join(" ", pageObjNums.Select(n => $"{n} 0 R"));
        writer.WriteObject(pagesObj,
            $"<< /Type /Pages /Kids [{pageRefs}] /Count {pageObjNums.Count} >>");

        // Write outlines if headings were found
        int outlinesObj = 0;
        if (layout.Bookmarks.Count > 0)
        {
            outlinesObj = WriteOutlines(writer, layout, pageObjNums);
        }

        // Write catalog
        if (outlinesObj > 0)
        {
            writer.WriteObject(catalogObj,
                $"<< /Type /Catalog /Pages {pagesObj} 0 R /Outlines {outlinesObj} 0 R /PageMode /UseOutlines >>");
        }
        else
        {
            writer.WriteObject(catalogObj,
                $"<< /Type /Catalog /Pages {pagesObj} 0 R >>");
        }

        // Write /Info dictionary if metadata is present
        WriteInfoDictionary(writer, layout.Metadata);

        return writer.Assemble();
    }

    private static void WriteInfoDictionary(PdfObjectWriter writer, PdfMetadata? metadata)
    {
        int infoObj = writer.AllocateObject();
        string now = DateTime.UtcNow.ToString("'D:'yyyyMMddHHmmss'Z'", CultureInfo.InvariantCulture);

        var parts = new List<string>
        {
            $"/Creator (SimpleSign.HtmlToPdf)",
            $"/Producer (SimpleSign.HtmlToPdf)",
            $"/CreationDate ({now})",
            $"/ModDate ({now})",
        };

        if (metadata?.Title is { Length: > 0 } title)
        {
            parts.Add($"/Title {FormatPdfString(title)}");
        }

        if (metadata?.Author is { Length: > 0 } author)
        {
            parts.Add($"/Author {FormatPdfString(author)}");
        }

        writer.WriteObject(infoObj, $"<< {string.Join(" ", parts)} >>");
        writer.InfoObjectNum = infoObj;
    }

    private static int WriteOutlines(PdfObjectWriter writer, LayoutResult layout, List<int> pageObjNums)
    {
        int outlinesObj = writer.AllocateObject();
        var itemObjNums = new List<int>();

        foreach (BookmarkEntry _ in layout.Bookmarks)
        {
            itemObjNums.Add(writer.AllocateObject());
        }

        // Write each outline item
        for (int i = 0; i < layout.Bookmarks.Count; i++)
        {
            BookmarkEntry bm = layout.Bookmarks[i];
            int pageObjNum = pageObjNums[bm.PageIndex];
            float pdfY = layout.Settings.PageHeight - layout.Settings.Margins.Top - bm.Y;

            string prev = i > 0 ? $"/Prev {itemObjNums[i - 1]} 0 R " : string.Empty;
            string next = i < layout.Bookmarks.Count - 1 ? $"/Next {itemObjNums[i + 1]} 0 R " : string.Empty;

            writer.WriteObject(itemObjNums[i],
                $"<< /Title {FormatPdfString(bm.Title)} /Parent {outlinesObj} 0 R /Dest [{pageObjNum} 0 R /XYZ 0 {F(pdfY)} null] {prev}{next}>>");
        }

        // Write outlines root
        writer.WriteObject(outlinesObj,
            $"<< /Type /Outlines /First {itemObjNums[0]} 0 R /Last {itemObjNums[^1]} 0 R /Count {itemObjNums.Count} >>");

        return outlinesObj;
    }

    private static int RenderPage(PdfObjectWriter writer, PageBox page, int pagesObj, ImageObjectCache imageCache,
        PdfMetadata? metadata, int pageNumber, int totalPages)
    {
        PageSettings settings = page.Settings;
        var cs = new PdfContentStream();
        var linkAnnotations = new List<LinkAnnotation>();
        var pageImages = new HashSet<string>();

        foreach (LayoutBox box in page.Boxes)
        {
            RenderBox(cs, box, settings, linkAnnotations, imageCache, pageImages);
        }

        RenderHeaderFooter(cs, settings, metadata, pageNumber, totalPages);

        // Write content stream
        int contentObj = writer.AllocateObject();
        writer.WriteStreamObject(contentObj, string.Empty, cs.ToBytes());

        // Write link annotation objects
        var annotObjNums = new List<int>();
        foreach (LinkAnnotation link in linkAnnotations)
        {
            int annotObj = writer.AllocateObject();
            string escapedUri = EscapePdfString(link.Url);
            string rect = string.Create(CultureInfo.InvariantCulture,
                $"[{F(link.X1)} {F(link.Y1)} {F(link.X2)} {F(link.Y2)}]");
            writer.WriteObject(annotObj,
                $"<< /Type /Annot /Subtype /Link /Rect {rect} /Border [0 0 0] /A << /Type /Action /S /URI /URI ({escapedUri}) >> >>");
            annotObjNums.Add(annotObj);
        }

        // Build resources
        string fontResources = cs.BuildFontResources();
        string xObjectResources = BuildXObjectResources(pageImages, imageCache);
        string resourceDict = BuildResourceDict(fontResources, xObjectResources);
        string resources = resourceDict.Length > 0 ? $"/Resources {resourceDict}" : string.Empty;

        // Build annotations reference
        string annots = annotObjNums.Count > 0
            ? $"/Annots [{string.Join(" ", annotObjNums.Select(n => $"{n} 0 R"))}]"
            : string.Empty;

        // Write page object
        int pageObj = writer.AllocateObject();
        string mediaBox = string.Create(CultureInfo.InvariantCulture,
            $"/MediaBox [0 0 {F(settings.PageWidth)} {F(settings.PageHeight)}]");
        writer.WriteObject(pageObj,
            $"<< /Type /Page /Parent {pagesObj} 0 R {mediaBox} {resources} /Contents {contentObj} 0 R {annots} >>");

        return pageObj;
    }

    private static void RenderBox(PdfContentStream cs, LayoutBox box, PageSettings settings,
        List<LinkAnnotation> links, ImageObjectCache imageCache, HashSet<string> pageImages)
    {
        switch (box.Type)
        {
            case LayoutBoxType.Block:
                RenderBlockBox(cs, box, settings, links, imageCache, pageImages);
                break;
            case LayoutBoxType.InlineText:
                RenderTextBox(cs, box, settings, links);
                break;
            case LayoutBoxType.ListMarker:
                RenderMarkerBox(cs, box, settings);
                break;
            case LayoutBoxType.HorizontalRule:
                RenderHrBox(cs, box, settings);
                break;
            case LayoutBoxType.Image:
                RenderImageBox(cs, box, settings, imageCache, pageImages);
                break;
            case LayoutBoxType.LineBreak:
            case LayoutBoxType.PageBreak:
                break;
        }
    }

    private static void RenderBlockBox(PdfContentStream cs, LayoutBox box, PageSettings settings,
        List<LinkAnnotation> links, ImageObjectCache imageCache, HashSet<string> pageImages)
    {
        ComputedStyle style = box.Style;
        float pageHeight = settings.PageHeight;
        float mt = settings.Margins.Top;

        // box.X already includes all horizontal offsets (margins, padding) from the layout engine
        float pdfX = box.X;
        float pdfY = pageHeight - mt - box.Y;

        float borderBoxWidth = style.Border.LeftWidth + style.Padding.Left + box.Width
            + style.Padding.Right + style.Border.RightWidth;
        float borderBoxHeight = style.Border.TopWidth + style.Padding.Top + box.Height
            + style.Padding.Bottom + style.Border.BottomWidth;

        // Background
        if (style.BackgroundColor is PdfColor bg && !bg.IsTransparent)
        {
            cs.SetFillColor(bg);
            cs.FillRect(pdfX, pdfY - borderBoxHeight, borderBoxWidth, borderBoxHeight);
        }

        // Borders
        if (style.Border.HasBorder)
        {
            RenderBorders(cs, pdfX, pdfY, borderBoxWidth, borderBoxHeight, style.Border);
        }
    }

    private static void RenderTextBox(PdfContentStream cs, LayoutBox box, PageSettings settings, List<LinkAnnotation> links)
    {
        if (box.Text is null || box.Text.Length == 0)
        {
            return;
        }

        ComputedStyle style = box.Style;
        float pageHeight = settings.PageHeight;
        float mt = settings.Margins.Top;

        string pdfFont = StandardFonts.Resolve(style.FontFamily, style.IsBold, style.IsItalic);

        // box.X already includes all horizontal offsets from the layout engine
        float pdfX = box.X;
        float pdfY = pageHeight - mt - box.Y - style.FontSize * 0.8f;

        // Sub/superscript vertical offset
        if (style.FontPosition == FontPosition.Subscript)
        {
            pdfY -= style.FontSize * 0.3f;
        }
        else if (style.FontPosition == FontPosition.Superscript)
        {
            pdfY += style.FontSize * 0.4f;
        }

        cs.DrawText(box.Text, pdfX, pdfY, pdfFont, style.FontSize, style.Color);

        if (style.IsUnderline)
        {
            cs.DrawUnderline(pdfX, pdfY, box.Width, style.FontSize, style.Color);
        }

        if (style.IsStrikethrough)
        {
            cs.DrawStrikethrough(pdfX, pdfY, box.Width, style.FontSize, style.Color);
        }

        // Collect link annotation
        if (box.LinkUrl is { Length: > 0 })
        {
            float linkY1 = pdfY - style.FontSize * 0.2f;
            float linkY2 = pdfY + style.FontSize * 0.8f;
            links.Add(new LinkAnnotation(box.LinkUrl, pdfX, linkY1, pdfX + box.Width, linkY2));
        }
    }

    private static void RenderMarkerBox(PdfContentStream cs, LayoutBox box, PageSettings settings)
    {
        if (box.Marker is null)
        {
            return;
        }

        ComputedStyle style = box.Style;
        string pdfFont = StandardFonts.Resolve(style.FontFamily, style.IsBold, style.IsItalic);

        float pdfX = box.X;
        float pdfY = settings.PageHeight - settings.Margins.Top - box.Y - style.FontSize * 0.8f;

        cs.DrawText(box.Marker, pdfX, pdfY, pdfFont, style.FontSize, style.Color);
    }

    private static void RenderHrBox(PdfContentStream cs, LayoutBox box, PageSettings settings)
    {
        ComputedStyle style = box.Style;
        float lineWidth = style.Border.TopWidth > 0 ? style.Border.TopWidth : 0.5f;
        PdfColor color = style.Border.TopColor;

        float pdfX = box.X;
        float pdfY = settings.PageHeight - settings.Margins.Top - box.Y - lineWidth / 2;

        cs.SetStrokeColor(color);
        cs.SetLineWidth(lineWidth);
        cs.HorizontalLine(pdfX, pdfY, pdfX + box.Width);
    }

    private static void RenderImageBox(PdfContentStream cs, LayoutBox box, PageSettings settings,
        ImageObjectCache imageCache, HashSet<string> pageImages)
    {
        string? src = box.ImageSource;
        if (src is null)
        {
            return;
        }

        string? imgName = imageCache.GetOrAdd(src);
        if (imgName is null)
        {
            return;
        }

        pageImages.Add(imgName);

        float pdfX = box.X;
        float pdfY = settings.PageHeight - settings.Margins.Top - box.Y - box.Height;

        // q (save) → cm (transform matrix) → Do (paint XObject) → Q (restore)
        cs.AppendRaw($"q {F(box.Width)} 0 0 {F(box.Height)} {F(pdfX)} {F(pdfY)} cm /{imgName} Do Q\n");
    }

    private static void RenderHeaderFooter(PdfContentStream cs, PageSettings settings, PdfMetadata? metadata,
        int pageNumber, int totalPages)
    {
        if (metadata is null)
        {
            return;
        }

        if (metadata.HeaderTemplate is { Length: > 0 } header)
        {
            string text = ResolveTemplate(header, pageNumber, totalPages, metadata.Title);
            float y = settings.PageHeight - settings.Margins.Top / 2;
            float x = settings.Margins.Left;
            float maxWidth = settings.PageWidth - settings.Margins.Left - settings.Margins.Right;
            RenderTemplateText(cs, text, x, y, maxWidth, 9f);
        }

        if (metadata.FooterTemplate is { Length: > 0 } footer)
        {
            string text = ResolveTemplate(footer, pageNumber, totalPages, metadata.Title);
            float y = settings.Margins.Bottom / 2;
            float x = settings.Margins.Left;
            float maxWidth = settings.PageWidth - settings.Margins.Left - settings.Margins.Right;
            RenderTemplateText(cs, text, x, y, maxWidth, 9f);
        }
    }

    private static string ResolveTemplate(string template, int pageNumber, int totalPages, string? title)
    {
        return template
            .Replace("{page}", pageNumber.ToString(CultureInfo.InvariantCulture), StringComparison.OrdinalIgnoreCase)
            .Replace("{pages}", totalPages.ToString(CultureInfo.InvariantCulture), StringComparison.OrdinalIgnoreCase)
            .Replace("{title}", title ?? string.Empty, StringComparison.OrdinalIgnoreCase)
            .Replace("{date}", DateTime.Now.ToString("dd/MM/yyyy", CultureInfo.InvariantCulture), StringComparison.OrdinalIgnoreCase);
    }

    private static void RenderTemplateText(PdfContentStream cs, string text, float x, float y, float maxWidth, float fontSize)
    {
        const string pdfFontName = "Helvetica";
        float textWidth = TextMeasurer.MeasureWidth(text, pdfFontName, fontSize);
        float centerX = x + (maxWidth - textWidth) / 2;
        cs.DrawText(text, centerX, y, pdfFontName, fontSize, new PdfColor(0.5f, 0.5f, 0.5f));
    }

    private static void RenderBorders(PdfContentStream cs, float x, float y, float width, float height, BorderStyle border)
    {
        if (border.TopWidth > 0)
        {
            cs.SetStrokeColor(border.TopColor);
            cs.SetLineWidth(border.TopWidth);
            cs.HorizontalLine(x, y, x + width);
        }

        if (border.BottomWidth > 0)
        {
            cs.SetStrokeColor(border.BottomColor);
            cs.SetLineWidth(border.BottomWidth);
            cs.HorizontalLine(x, y - height, x + width);
        }

        if (border.LeftWidth > 0)
        {
            cs.SetStrokeColor(border.LeftColor);
            cs.SetLineWidth(border.LeftWidth);
            cs.VerticalLine(x, y, y - height);
        }

        if (border.RightWidth > 0)
        {
            cs.SetStrokeColor(border.RightColor);
            cs.SetLineWidth(border.RightWidth);
            cs.VerticalLine(x + width, y, y - height);
        }
    }

    private static string F(float value)
    {
        return value.ToString("F2", CultureInfo.InvariantCulture);
    }

    private static string FormatPdfString(string value)
    {
        // Check if string contains non-ASCII characters
        bool hasNonAscii = false;
        foreach (char c in value)
        {
            if (c > 127)
            {
                hasNonAscii = true;
                break;
            }
        }

        if (!hasNonAscii)
        {
            string escaped = value.Replace("\\", "\\\\").Replace("(", "\\(").Replace(")", "\\)");
            return $"({escaped})";
        }

        // Encode as hex string with UTF-16BE BOM for proper Unicode support in PDF
        byte[] utf16Bytes = System.Text.Encoding.BigEndianUnicode.GetBytes(value);
        var sb = new System.Text.StringBuilder(4 + (utf16Bytes.Length * 2) + 2);
        sb.Append("<FEFF");
        foreach (byte b in utf16Bytes)
        {
            sb.Append(b.ToString("X2"));
        }

        sb.Append('>');
        return sb.ToString();
    }

    private static string EscapePdfString(string value)
    {
        return value.Replace("\\", "\\\\").Replace("(", "\\(").Replace(")", "\\)");
    }

    private static string BuildXObjectResources(HashSet<string> pageImages, ImageObjectCache cache)
    {
        if (pageImages.Count == 0)
        {
            return string.Empty;
        }

        var entries = new List<string>();
        foreach (string name in pageImages)
        {
            if (cache.TryGetObjectNum(name, out int objNum))
            {
                entries.Add($"/{name} {objNum} 0 R");
            }
        }

        return entries.Count > 0 ? $"/XObject << {string.Join(" ", entries)} >>" : string.Empty;
    }

    private static string BuildResourceDict(string fontResources, string xObjectResources)
    {
        if (fontResources.Length == 0 && xObjectResources.Length == 0)
        {
            return string.Empty;
        }

        return $"<< {fontResources} {xObjectResources} >>";
    }
}

/// <summary>Tracks a link annotation region for a page.</summary>
/// <param name="Url">The link URL.</param>
/// <param name="X1">Left edge in PDF coordinates.</param>
/// <param name="Y1">Bottom edge in PDF coordinates.</param>
/// <param name="X2">Right edge in PDF coordinates.</param>
/// <param name="Y2">Top edge in PDF coordinates.</param>
internal readonly record struct LinkAnnotation(string Url, float X1, float Y1, float X2, float Y2);
