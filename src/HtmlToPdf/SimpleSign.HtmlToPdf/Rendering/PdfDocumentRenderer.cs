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
        => Render(layout, layout.Fonts);

    internal static byte[] Render(LayoutResult layout, FontCollection? fonts)
    {
        var writer = new PdfObjectWriter();
        var imageCache = new ImageObjectCache(writer, layout.Resources);

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
            int pageObj = RenderPage(writer, page, pagesObj, imageCache, layout, pageNumber, fonts);
            pageObjNums.Add(pageObj);
        }

        // Embedded fonts are written once, after every page has registered the glyphs it uses.
        fonts?.WriteUsedFonts(writer);

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

        // Write /Info dictionary (and XMP metadata mirroring it for PDF/A)
        DateTime now = DateTime.UtcNow;
        WriteInfoDictionary(writer, layout.Metadata, now);
        writer.FileId = Guid.NewGuid().ToByteArray();

        var catalog = new System.Text.StringBuilder($"<< /Type /Catalog /Pages {pagesObj} 0 R");
        if (outlinesObj > 0)
        {
            catalog.Append(CultureInfo.InvariantCulture, $" /Outlines {outlinesObj} 0 R /PageMode /UseOutlines");
        }

        if (layout.Language is { Length: > 0 } language)
        {
            catalog.Append(CultureInfo.InvariantCulture, $" /Lang {FormatPdfString(language)}");
        }

        if (layout.PdfA)
        {
            int iccObj = writer.AllocateObject();
            writer.WriteStreamObject(iccObj, "/N 3", SrgbProfile.Bytes);
            int metadataObj = writer.AllocateObject();
            writer.WriteStreamObject(metadataObj, "/Type /Metadata /Subtype /XML", BuildXmp(layout.Metadata, now), compress: false);
            catalog.Append(CultureInfo.InvariantCulture, $" /Metadata {metadataObj} 0 R");
            catalog.Append(CultureInfo.InvariantCulture,
                $" /OutputIntents [<< /Type /OutputIntent /S /GTS_PDFA1 /OutputConditionIdentifier (sRGB IEC61966-2.1) /Info (sRGB IEC61966-2.1) /DestOutputProfile {iccObj} 0 R >>]");
        }

        catalog.Append(" >>");
        writer.WriteObject(catalogObj, catalog.ToString());

        return writer.Assemble();
    }

    private const string ProducerName = "SimpleSign.HtmlToPdf";

    private static byte[] BuildXmp(PdfMetadata? metadata, DateTime timestamp)
    {
        static string Escape(string value) => System.Security.SecurityElement.Escape(value) ?? string.Empty;
        string date = timestamp.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture);
        var sb = new System.Text.StringBuilder();
        sb.Append("<?xpacket begin=\"\uFEFF\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?>\n");
        sb.Append("<x:xmpmeta xmlns:x=\"adobe:ns:meta/\">\n<rdf:RDF xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\">\n");
        sb.Append("<rdf:Description rdf:about=\"\" xmlns:pdfaid=\"http://www.aiim.org/pdfa/ns/id/\" xmlns:dc=\"http://purl.org/dc/elements/1.1/\" ");
        sb.Append("xmlns:xmp=\"http://ns.adobe.com/xap/1.0/\" xmlns:pdf=\"http://ns.adobe.com/pdf/1.3/\">\n");
        sb.Append("<pdfaid:part>2</pdfaid:part>\n<pdfaid:conformance>B</pdfaid:conformance>\n");
        sb.Append("<dc:format>application/pdf</dc:format>\n");
        if (metadata?.Title is { Length: > 0 } title)
        {
            sb.Append(CultureInfo.InvariantCulture, $"<dc:title><rdf:Alt><rdf:li xml:lang=\"x-default\">{Escape(title)}</rdf:li></rdf:Alt></dc:title>\n");
        }

        if (metadata?.Author is { Length: > 0 } author)
        {
            sb.Append(CultureInfo.InvariantCulture, $"<dc:creator><rdf:Seq><rdf:li>{Escape(author)}</rdf:li></rdf:Seq></dc:creator>\n");
        }

        sb.Append(CultureInfo.InvariantCulture, $"<xmp:CreatorTool>{ProducerName}</xmp:CreatorTool>\n");
        sb.Append(CultureInfo.InvariantCulture, $"<xmp:CreateDate>{date}</xmp:CreateDate>\n<xmp:ModifyDate>{date}</xmp:ModifyDate>\n");
        sb.Append(CultureInfo.InvariantCulture, $"<pdf:Producer>{ProducerName}</pdf:Producer>\n");
        sb.Append("</rdf:Description>\n</rdf:RDF>\n</x:xmpmeta>\n<?xpacket end=\"w\"?>");
        return System.Text.Encoding.UTF8.GetBytes(sb.ToString());
    }

    private static void WriteInfoDictionary(PdfObjectWriter writer, PdfMetadata? metadata, DateTime timestamp)
    {
        int infoObj = writer.AllocateObject();
        string now = timestamp.ToString("'D:'yyyyMMddHHmmss'Z'", CultureInfo.InvariantCulture);

        var parts = new List<string>
        {
            $"/Creator ({ProducerName})",
            $"/Producer ({ProducerName})",
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
        LayoutResult layout, int pageNumber, FontCollection? fonts)
    {
        PdfMetadata? metadata = layout.Metadata;
        int totalPages = layout.Pages.Count;
        PageSettings settings = page.Settings;
        var resources = new PageResources(writer);
        var cs = new PdfContentStream(fonts, resources);
        var linkAnnotations = new List<LinkAnnotation>();
        var pageImages = new HashSet<string>();
        var effects = new BoxEffects(page, settings);
        var context = new RenderContext(settings, linkAnnotations, imageCache, pageImages, layout.CanvasNode);

        // The root element's background covers the whole page (CSS canvas).
        if (layout.CanvasStyle is { } canvas)
        {
            PaintCanvas(cs, canvas, settings, imageCache, pageImages);
        }

        foreach (LayoutBox box in page.Boxes)
        {
            BoxEffects.Effect effect = effects.For(box.Node);
            if (effect.IsTrivial)
            {
                RenderBox(cs, box, context);
                continue;
            }

            if (effect.Alpha <= 0.0005f)
            {
                continue;
            }

            int firstLink = linkAnnotations.Count;
            cs.SaveState();
            BoxEffects.Apply(cs, effect);
            RenderBox(cs, box, context);
            cs.RestoreState();
            cs.GroupAlpha = 1f;
            for (int i = firstLink; i < linkAnnotations.Count; i++)
            {
                LinkAnnotation link = linkAnnotations[i];
                var (x1, y1, x2, y2) = BoxEffects.TransformBounds(effect, link.X1, link.Y1, link.X2, link.Y2);
                linkAnnotations[i] = link with { X1 = x1, Y1 = y1, X2 = x2, Y2 = y2 };
            }
        }

        RenderHeaderFooter(cs, settings, metadata, pageNumber, totalPages);
        RenderMarginBoxes(cs, settings, layout.MarginBoxes, pageNumber, totalPages);

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
                $"<< /Type /Annot /Subtype /Link /F 4 /Rect {rect} /Border [0 0 0] /A << /Type /Action /S /URI /URI ({escapedUri}) >> >>");
            annotObjNums.Add(annotObj);
        }

        // Build resources
        string customFontEntries = fonts is not null
            ? FontCollection.BuildFontResources(writer, cs.UsedEmbeddedFonts)
            : string.Empty;
        string fontResources = cs.BuildFontResources(customFontEntries);
        foreach (string name in pageImages)
        {
            if (imageCache.TryGetObjectNum(name, out int objNum))
            {
                resources.AddXObject(name, objNum);
            }
        }

        string resourceDict = BuildResourceDict(fontResources, resources.BuildEntries());
        string resourcesEntry = resourceDict.Length > 0 ? $"/Resources {resourceDict} " : string.Empty;

        // Build annotations reference
        string annots = annotObjNums.Count > 0
            ? $"/Annots [{string.Join(" ", annotObjNums.Select(n => $"{n} 0 R"))}]"
            : string.Empty;

        // Write page object
        int pageObj = writer.AllocateObject();
        string mediaBox = string.Create(CultureInfo.InvariantCulture,
            $"/MediaBox [0 0 {F(settings.PageWidth)} {F(settings.PageHeight)}]");
        // Pages using transparency get an explicit RGB blending space (required for PDF/A-2).
        string group = resources.UsesTransparency ? "/Group << /Type /Group /S /Transparency /CS /DeviceRGB >> " : string.Empty;
        writer.WriteObject(pageObj,
            $"<< /Type /Page /Parent {pagesObj} 0 R {mediaBox} {resourcesEntry}{group}/Contents {contentObj} 0 R {annots} >>");

        return pageObj;
    }

    /// <summary>Per-page state shared by the box renderers.</summary>
    private sealed record RenderContext(PageSettings Settings, List<LinkAnnotation> Links, ImageObjectCache Images,
        HashSet<string> PageImages, HtmlNode? CanvasNode);

    private static void RenderBox(PdfContentStream cs, LayoutBox box, RenderContext context)
    {
        PageSettings settings = context.Settings;
        List<LinkAnnotation> links = context.Links;
        switch (box.Type)
        {
            case LayoutBoxType.Block:
                RenderBlockBox(cs, box, context);
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
                RenderImageBox(cs, box, settings, context.Images, context.PageImages, links);
                break;
            case LayoutBoxType.LineBreak:
            case LayoutBoxType.PageBreak:
                break;
        }
    }

    /// <summary>Gets the border box of a block or image box in PDF coordinates.</summary>
    internal static PdfRect BorderBoxOf(LayoutBox box, PageSettings settings)
    {
        ComputedStyle style = box.Style;
        BorderStyle border = style.Border;
        float width, height;
        if (box.BorderCentered || box.Type != LayoutBoxType.Block)
        {
            width = box.Width;
            height = box.Height;
        }
        else
        {
            float topExtras = box.SuppressTopBorder ? 0 : border.TopWidth + Math.Max(0, style.Padding.Top);
            float bottomExtras = box.SuppressBottomBorder ? 0 : border.BottomWidth + Math.Max(0, style.Padding.Bottom);
            width = border.LeftWidth + Math.Max(0, style.Padding.Left) + box.Width + Math.Max(0, style.Padding.Right) + border.RightWidth;
            height = topExtras + box.Height + bottomExtras;
        }

        float pdfTop = settings.PageHeight - settings.Margins.Top - box.Y;
        bool rounded = style.BorderRadius > 0 && !box.SuppressTopBorder && !box.SuppressBottomBorder;
        return new PdfRect(box.X, pdfTop - height, Math.Max(0, width), Math.Max(0, height), rounded ? style.BorderRadius : 0);
    }

    private static void RenderBlockBox(PdfContentStream cs, LayoutBox box, RenderContext context)
    {
        ComputedStyle style = box.Style;
        if (style.IsHidden)
        {
            return;
        }

        PageSettings settings = context.Settings;
        BorderStyle border = style.Border;
        PdfRect rect = BorderBoxOf(box, settings);
        if (rect.Width <= 0 || rect.Height < 0)
        {
            return;
        }

        if (style.BoxShadows is { Count: > 0 } shadows)
        {
            BackgroundPainter.PaintOuterShadows(cs, shadows, rect, new PdfRect(0, 0, settings.PageWidth, settings.PageHeight));
        }

        // Fragments of a box split across pages do not paint the suppressed edge's border/padding.
        ComputedStyle paintStyle = style;
        if (box.BorderCentered || box.SuppressTopBorder || box.SuppressBottomBorder)
        {
            paintStyle = style.Clone();
            if (box.BorderCentered)
            {
                paintStyle.Border = BorderStyle.None;
                paintStyle.Padding = Thickness.Zero;
            }
            else
            {
                paintStyle.Padding = paintStyle.Padding with
                {
                    Top = box.SuppressTopBorder ? 0 : paintStyle.Padding.Top,
                    Bottom = box.SuppressBottomBorder ? 0 : paintStyle.Padding.Bottom,
                };
            }
        }

        if (!ReferenceEquals(box.Node, context.CanvasNode) || box.Node is null)
        {
            BackgroundPainter.Paint(cs, paintStyle, rect, context.Images, context.PageImages);
        }

        if (style.BoxShadows is { Count: > 0 } insetShadows && insetShadows.Any(s => s.Inset))
        {
            BorderStyle b = box.BorderCentered ? BorderStyle.None : border;
            BackgroundPainter.PaintInsetShadows(cs, insetShadows, rect.Inset(
                box.SuppressTopBorder ? 0 : b.TopWidth, b.RightWidth, box.SuppressBottomBorder ? 0 : b.BottomWidth, b.LeftWidth));
        }

        if (border.HasBorder)
        {
            RenderBorders(cs, rect.X, rect.Top, rect.Width, rect.Height, border, box.BorderCentered, box.SuppressTopBorder, box.SuppressBottomBorder, rect.Radius);
        }
    }

    private static void PaintCanvas(PdfContentStream cs, ComputedStyle style, PageSettings settings, ImageObjectCache images, HashSet<string> pageImages)
    {
        ComputedStyle canvas = style.Clone();
        canvas.Border = BorderStyle.None;
        canvas.Padding = Thickness.Zero;
        canvas.BackgroundClips = null;
        canvas.BackgroundOrigins = null;
        BackgroundPainter.Paint(cs, canvas, new PdfRect(0, 0, settings.PageWidth, settings.PageHeight), images, pageImages);
    }

    private static void RenderTextBox(PdfContentStream cs, LayoutBox box, PageSettings settings, List<LinkAnnotation> links)
    {
        if (box.Text is null || box.Text.Length == 0)
        {
            return;
        }

        ComputedStyle style = box.Style;
        if (style.IsHidden)
        {
            return;
        }

        float pageHeight = settings.PageHeight;
        float mt = settings.Margins.Top;
        float fontSize = style.FontSize;

        // box.X already includes all horizontal offsets from the layout engine
        float pdfX = box.X;
        float pdfY = pageHeight - mt - box.Y - fontSize * 0.8f;

        if (box.InlineBackground is PdfColor inlineBg && !inlineBg.IsTransparent)
        {
            float extend = box.SpaceBefore ? fontSize * 0.28f : 0;
            cs.SetFillColor(inlineBg);
            cs.FillRect(pdfX - extend, pdfY - (fontSize * 0.25f), box.Width + extend, fontSize * 1.2f);
        }

        // Sub/superscript vertical offset
        if (style.FontPosition == FontPosition.Subscript)
        {
            pdfY -= fontSize * 0.3f;
        }
        else if (style.FontPosition == FontPosition.Superscript)
        {
            pdfY += fontSize * 0.4f;
        }

        if (box.Text.Trim().Length > 0)
        {
            ResolvedFont pdfFont = TextMeasurer.ResolveFont(style, cs.Fonts);
            if (style.TextShadows is { Count: > 0 } shadows)
            {
                for (int i = shadows.Count - 1; i >= 0; i--)
                {
                    CssShadow shadow = shadows[i];
                    if (shadow.Color.IsTransparent)
                    {
                        continue;
                    }

                    // Blur is approximated by a few faint copies around the offset.
                    (float Dx, float Dy)[] offsets = shadow.Blur > 0.5f
                        ? [(0, 0), (-shadow.Blur / 3, 0), (shadow.Blur / 3, 0), (0, -shadow.Blur / 3), (0, shadow.Blur / 3)]
                        : [(0, 0)];
                    PdfColor color = shadow.Color with { Alpha = shadow.Color.Alpha / (offsets.Length > 1 ? 2.5f : 1f) };
                    foreach (var (dx, dy) in offsets)
                    {
                        cs.DrawText(DrawnText(box), pdfX + shadow.OffsetX + dx, pdfY - shadow.OffsetY + dy, pdfFont, fontSize, color, style.LetterSpacing, style.WordSpacing, box.Rtl);
                    }
                }
            }

            cs.DrawText(DrawnText(box), pdfX, pdfY, pdfFont, fontSize, style.Color, style.LetterSpacing, style.WordSpacing, box.Rtl);
        }

        if (style.IsUnderline)
        {
            cs.DrawUnderline(pdfX, pdfY, box.Width, fontSize, style.Color);
        }

        if (style.IsStrikethrough)
        {
            cs.DrawStrikethrough(pdfX, pdfY, box.Width, fontSize, style.Color);
        }

        // Collect link annotation
        if (box.LinkUrl is { Length: > 0 })
        {
            float linkY1 = pdfY - fontSize * 0.2f;
            float linkY2 = pdfY + fontSize * 0.8f;
            links.Add(new LinkAnnotation(box.LinkUrl, pdfX, linkY1, pdfX + box.Width, linkY2));
        }
    }

    private static string DrawnText(LayoutBox box) => box.Rtl ? Bidi.Mirror(box.Text!) : box.Text!;

    private static void RenderMarkerBox(PdfContentStream cs, LayoutBox box, PageSettings settings)
    {
        ComputedStyle style = box.Style;
        if (style.IsHidden)
        {
            return;
        }

        float pdfTop = settings.PageHeight - settings.Margins.Top - box.Y;
        switch (box.MarkerShape)
        {
            case MarkerShape.Disc:
                cs.SetFillColor(style.Color);
                cs.Circle(box.X + (box.Width / 2), pdfTop - (box.Height / 2), box.Width / 2, fill: true);
                return;
            case MarkerShape.Circle:
                cs.SetStrokeColor(style.Color);
                cs.SetLineWidth(Math.Max(0.4f, style.FontSize * 0.05f));
                cs.Circle(box.X + (box.Width / 2), pdfTop - (box.Height / 2), (box.Width / 2) * 0.9f, fill: false);
                return;
            case MarkerShape.Square:
                cs.SetFillColor(style.Color);
                cs.FillRect(box.X, pdfTop - box.Height, box.Width, box.Height);
                return;
        }

        if (box.Marker is null)
        {
            return;
        }

        ResolvedFont pdfFont = TextMeasurer.ResolveFont(style, cs.Fonts);
        float pdfY = pdfTop - style.FontSize * 0.8f;
        cs.DrawText(box.Marker, box.X, pdfY, pdfFont, style.FontSize, style.Color);
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
        ImageObjectCache imageCache, HashSet<string> pageImages, List<LinkAnnotation> links)
    {
        if (box.Style.IsHidden)
        {
            return;
        }

        if (box.Svg is { } svg)
        {
            float top = settings.PageHeight - settings.Margins.Top - box.Y;
            new Svg.SvgRenderer(imageCache, pageImages).Draw(cs, svg, new PdfRect(box.X, top - box.Height, box.Width, box.Height));
            if (box.LinkUrl is { Length: > 0 })
            {
                links.Add(new LinkAnnotation(box.LinkUrl, box.X, top - box.Height, box.X + box.Width, top));
            }

            return;
        }

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
        cs.DrawImage(imgName, pdfX, pdfY, box.Width, box.Height);

        if (box.LinkUrl is { Length: > 0 })
        {
            links.Add(new LinkAnnotation(box.LinkUrl, pdfX, pdfY, pdfX + box.Width, pdfY + box.Height));
        }
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

    /// <summary>Draws the <c>@page</c> margin boxes for one page, vertically centered in the margins.</summary>
    private static void RenderMarginBoxes(PdfContentStream cs, PageSettings settings, IReadOnlyList<PageMarginBox> boxes, int pageNumber, int totalPages)
    {
        if (boxes.Count == 0)
        {
            return;
        }

        float left = settings.Margins.Left;
        float contentWidth = settings.ContentWidth;
        float third = contentWidth / 3;
        foreach (PageMarginBox box in PageMarginBox.ForPage(boxes, pageNumber))
        {
            if (box.Evaluate(pageNumber, totalPages) is not { Length: > 0 } text)
            {
                continue;
            }

            ComputedStyle style = box.Style;
            bool top = box.Position.StartsWith("top", StringComparison.Ordinal);
            (float x, float width, TextAlign defaultAlign) = box.Position[(top ? 4 : 7)..] switch
            {
                "left-corner" => (0f, left, TextAlign.Right),
                "left" => (left, third, TextAlign.Left),
                "center" => (left + third, third, TextAlign.Center),
                "right" => (left + (2 * third), third, TextAlign.Right),
                _ => (left + contentWidth, settings.Margins.Right, TextAlign.Left),
            };

            ResolvedFont font = TextMeasurer.ResolveFont(style, cs.Fonts);
            float fontSize = style.FontSize;
            float textWidth = TextMeasurer.MeasureResolved(text, font, cs.Fonts, fontSize, style.LetterSpacing, style.WordSpacing);
            TextAlign align = style.TextAlign is TextAlign.Center or TextAlign.Right ? style.TextAlign : defaultAlign;
            float textX = align switch
            {
                TextAlign.Center => x + ((width - textWidth) / 2),
                TextAlign.Right => x + width - textWidth,
                _ => x,
            };

            // Center the cap height in the margin band.
            float band = top ? settings.Margins.Top : settings.Margins.Bottom;
            float baseline = (top ? settings.PageHeight - band : 0) + (band / 2) - (fontSize * 0.35f);
            cs.DrawText(text, textX, baseline, font, fontSize, style.Color, style.LetterSpacing, style.WordSpacing);
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
        ResolvedFont font = FontCollection.Resolve(cs.Fonts, ["Helvetica"], false, false);
        float textWidth = TextMeasurer.MeasureResolved(text, font, cs.Fonts, fontSize, 0, 0);
        float centerX = x + (maxWidth - textWidth) / 2;
        cs.DrawText(text, centerX, y, font, fontSize, new PdfColor(0.5f, 0.5f, 0.5f));
    }

    private static void RenderBorders(PdfContentStream cs, float x, float top, float width, float height, BorderStyle border,
        bool centered, bool suppressTop, bool suppressBottom, float radius)
    {
        float bottom = top - height;
        if (radius > 0 && border.IsUniform && border.TopWidth > 0 && border.TopStyle != BorderLineStyle.None)
        {
            float w = border.TopWidth;
            float inset = centered ? 0 : w / 2;
            cs.SaveState();
            cs.SetStrokeColor(border.TopColor);
            cs.SetLineWidth(w);
            ApplyDash(cs, border.TopStyle, w);
            cs.RoundedRectPath(x + inset, bottom + inset, width - (2 * inset), height - (2 * inset), Math.Max(0, radius - inset));
            cs.Stroke();
            cs.RestoreState();
            return;
        }

        // Each side is stroked along the middle of its border band (inside the border box),
        // or exactly on the edge for collapsed table borders.
        float tInset = centered ? 0 : border.TopWidth / 2;
        float bInset = centered ? 0 : border.BottomWidth / 2;
        float lInset = centered ? 0 : border.LeftWidth / 2;
        float rInset = centered ? 0 : border.RightWidth / 2;

        if (border.TopWidth > 0 && !suppressTop)
        {
            DrawSide(cs, border.TopStyle, border.TopColor, border.TopWidth, x, top - tInset, x + width, top - tInset, horizontal: true);
        }

        if (border.BottomWidth > 0 && !suppressBottom)
        {
            DrawSide(cs, border.BottomStyle, border.BottomColor, border.BottomWidth, x, bottom + bInset, x + width, bottom + bInset, horizontal: true);
        }

        if (border.LeftWidth > 0)
        {
            DrawSide(cs, border.LeftStyle, border.LeftColor, border.LeftWidth, x + lInset, top, x + lInset, bottom, horizontal: false);
        }

        if (border.RightWidth > 0)
        {
            DrawSide(cs, border.RightStyle, border.RightColor, border.RightWidth, x + width - rInset, top, x + width - rInset, bottom, horizontal: false);
        }
    }

    private static void DrawSide(PdfContentStream cs, BorderLineStyle style, PdfColor color, float width,
        float x1, float y1, float x2, float y2, bool horizontal)
    {
        if (style == BorderLineStyle.None || width <= 0)
        {
            return;
        }

        cs.SaveState();
        cs.SetStrokeColor(color);
        if (style == BorderLineStyle.Double && width >= 2.25f)
        {
            float line = width / 3;
            float offset = width / 3;
            cs.SetLineWidth(line);
            if (horizontal)
            {
                cs.Line(x1, y1 + offset, x2, y2 + offset);
                cs.Line(x1, y1 - offset, x2, y2 - offset);
            }
            else
            {
                cs.Line(x1 - offset, y1, x2 - offset, y2);
                cs.Line(x1 + offset, y1, x2 + offset, y2);
            }

            cs.RestoreState();
            return;
        }

        cs.SetLineWidth(width);
        ApplyDash(cs, style, width);
        cs.Line(x1, y1, x2, y2);
        cs.RestoreState();
    }

    private static void ApplyDash(PdfContentStream cs, BorderLineStyle style, float width)
    {
        switch (style)
        {
            case BorderLineStyle.Dashed:
                cs.SetDash(Math.Max(3 * width, 2f), Math.Max(3 * width, 2f));
                break;
            case BorderLineStyle.Dotted:
                cs.SetLineCap(1);
                cs.SetDash(0, Math.Max(2 * width, 1.5f));
                break;
        }
    }

    private static string F(float value) => value.ToString("F2", CultureInfo.InvariantCulture);

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

    private static string EscapePdfString(string value) => value.Replace("\\", "\\\\").Replace("(", "\\(").Replace(")", "\\)");

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
