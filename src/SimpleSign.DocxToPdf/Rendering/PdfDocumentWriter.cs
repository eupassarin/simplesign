using System.Globalization;
using System.IO.Compression;
using System.Text;
using SimpleSign.DocxToPdf.Layout;

namespace SimpleSign.DocxToPdf.Rendering;

/// <summary>Writes a complete PDF 1.7 document from layout pages.</summary>
internal sealed class PdfDocumentWriter
{
    private readonly List<LayoutPage> _pages;
    private int _nextObjectId = 1;

    /// <summary>Initializes a new instance of the <see cref="PdfDocumentWriter"/> class.</summary>
    /// <param name="pages">The layout pages to render.</param>
    /// <param name="images">The image data dictionary (reserved for future use).</param>
    public PdfDocumentWriter(List<LayoutPage> pages, Dictionary<string, byte[]> images)
    {
        ArgumentNullException.ThrowIfNull(pages);
        ArgumentNullException.ThrowIfNull(images);
        _pages = pages;
    }

    /// <summary>Writes the PDF to a stream.</summary>
    /// <param name="output">The output stream.</param>
    public void WriteTo(Stream output)
    {
        ArgumentNullException.ThrowIfNull(output);

        using var writer = new StreamWriter(output, Encoding.ASCII, leaveOpen: true);
        writer.NewLine = "\n";
        var offsets = new List<long>();

        // Header
        writer.Write("%PDF-1.7\n");
        writer.Write("%\xe2\xe3\xcf\xd3\n");
        writer.Flush();

        // Build objects
        int catalogId = _nextObjectId++;
        int pagesId = _nextObjectId++;
        int fontId = _nextObjectId++;

        // Build page objects
        var pageObjectIds = new List<int>();
        var contentObjectIds = new List<int>();
        var imageObjectData = new Dictionary<int, List<(string Name, int ObjId)>>();

        foreach (LayoutPage page in _pages)
        {
            int pageId = _nextObjectId++;
            int contentId = _nextObjectId++;
            pageObjectIds.Add(pageId);
            contentObjectIds.Add(contentId);

            var pageImages = new List<(string Name, int ObjId)>();
            int imageIdx = 0;
            foreach (LayoutElement elem in page.Elements)
            {
                if (elem is LayoutImage { Data.Length: > 0 })
                {
                    int imgObjId = _nextObjectId++;
                    string imgName = $"Im{imageIdx}";
                    pageImages.Add((imgName, imgObjId));
                    imageIdx++;
                }
            }

            imageObjectData[pageId] = pageImages;
        }

        // Write catalog
        offsets.Add(output.Position);
        WriteObject(writer, catalogId, $"<< /Type /Catalog /Pages {pagesId} 0 R >>");
        writer.Flush();

        // Write pages object
        offsets.Add(output.Position);
        string kids = string.Join(" ", pageObjectIds.Select(id => $"{id} 0 R"));
        WriteObject(writer, pagesId, $"<< /Type /Pages /Kids [{kids}] /Count {pageObjectIds.Count} >>");
        writer.Flush();

        // Write font object (simple Type1 Helvetica for fallback)
        offsets.Add(output.Position);
        WriteObject(writer, fontId,
            "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>");
        writer.Flush();

        // Write page and content objects
        for (int i = 0; i < _pages.Count; i++)
        {
            LayoutPage page = _pages[i];
            int pageId = pageObjectIds[i];
            int contentId = contentObjectIds[i];
            List<(string Name, int ObjId)> pageImgs = imageObjectData[pageId];

            // Build resource dictionary
            var resources = new StringBuilder();
            resources.Append("<< /Font << /F1 ");
            resources.Append(fontId);
            resources.Append(" 0 R >>");

            if (pageImgs.Count > 0)
            {
                resources.Append(" /XObject << ");
                foreach ((string name, int objId) in pageImgs)
                {
                    resources.Append(CultureInfo.InvariantCulture, $"/{name} {objId} 0 R ");
                }

                resources.Append(">>");
            }

            resources.Append(" >>");

            // Write page object
            offsets.Add(output.Position);
            string pageDict = string.Create(CultureInfo.InvariantCulture,
                $"<< /Type /Page /Parent {pagesId} 0 R /MediaBox [0 0 {page.Width:F2} {page.Height:F2}] /Contents {contentId} 0 R /Resources {resources} >>");
            WriteObject(writer, pageId, pageDict);
            writer.Flush();

            // Build content stream
            byte[] contentBytes = BuildContentStream(page, pageImgs);
            byte[] compressed = Compress(contentBytes);

            // Write content stream object
            offsets.Add(output.Position);
            writer.Write($"{contentId} 0 obj\n");
            writer.Write($"<< /Length {compressed.Length} /Filter /FlateDecode >>\n");
            writer.Write("stream\n");
            writer.Flush();
            output.Write(compressed);
            output.Flush();
            writer.Write("\nendstream\n");
            writer.Write("endobj\n");
            writer.Flush();

            // Write image objects
            int imgIdx = 0;
            foreach (LayoutElement elem in page.Elements)
            {
                if (elem is LayoutImage { Data.Length: > 0 } img && imgIdx < pageImgs.Count)
                {
                    int imgObjId = pageImgs[imgIdx].ObjId;
                    offsets.Add(output.Position);
                    WriteImageObject(writer, output, imgObjId, img);
                    writer.Flush();
                    imgIdx++;
                }
            }
        }

        // Cross-reference table
        long xrefOffset = output.Position;
        writer.Write("xref\n");
        writer.Write($"0 {_nextObjectId}\n");
        writer.Write("0000000000 65535 f \n");

        foreach (long offset in offsets)
        {
            writer.Write($"{offset:D10} 00000 n \n");
        }

        // Trailer
        writer.Write("trailer\n");
        writer.Write($"<< /Size {_nextObjectId} /Root {catalogId} 0 R >>\n");
        writer.Write("startxref\n");
        writer.Write($"{xrefOffset}\n");
        writer.Write("%%EOF\n");
        writer.Flush();
    }

    private static byte[] BuildContentStream(LayoutPage page, List<(string Name, int ObjId)> images)
    {
        var builder = new PdfContentStreamBuilder();
        float pageHeight = page.Height;
        int imageIdx = 0;

        // Draw rectangles first (backgrounds)
        foreach (LayoutElement elem in page.Elements)
        {
            if (elem is LayoutRect rect)
            {
                (float r, float g, float b) = ParseHexColor(rect.FillColor);
                builder.SetFillColor(r, g, b);
                float pdfY = pageHeight - elem.Y - elem.Height;
                builder.Rectangle(elem.X, pdfY, elem.Width, elem.Height);
                builder.Fill();
            }
        }

        // Draw lines (borders)
        foreach (LayoutElement elem in page.Elements)
        {
            if (elem is LayoutLine line)
            {
                (float r, float g, float b) = ParseHexColor(line.Color);
                builder.SetStrokeColor(r, g, b);
                builder.SetLineWidth(line.LineWidth);
                float pdfY1 = pageHeight - line.Y;
                float pdfY2 = pageHeight - line.EndY;
                builder.MoveTo(line.X, pdfY1);
                builder.LineTo(line.EndX, pdfY2);
                builder.Stroke();
            }
        }

        // Draw text
        builder.BeginText();
        builder.SetFont("F1", 12);

        foreach (LayoutElement elem in page.Elements)
        {
            if (elem is LayoutText text)
            {
                (float r, float g, float b) = ParseHexColor(text.Color);
                builder.SetFillColor(r, g, b);
                builder.SetFont("F1", text.FontSizePt);
                float pdfY = pageHeight - text.Y - text.FontSizePt;
                builder.SetTextMatrix(1, 0, 0, 1, text.X, pdfY);
                builder.ShowText(text.Text);
            }
        }

        builder.EndText();

        // Draw images
        foreach (LayoutElement elem in page.Elements)
        {
            if (elem is LayoutImage { Data.Length: > 0 } img && imageIdx < images.Count)
            {
                builder.SaveState();
                float pdfY = pageHeight - img.Y - img.Height;
                builder.ConcatMatrix(img.Width, 0, 0, img.Height, img.X, pdfY);
                builder.PaintXObject(images[imageIdx].Name);
                builder.RestoreState();
                imageIdx++;
            }
        }

        return builder.ToBytes();
    }

    private static void WriteObject(StreamWriter writer, int id, string content)
    {
        writer.Write($"{id} 0 obj\n");
        writer.Write(content);
        writer.Write("\nendobj\n");
    }

    private static void WriteImageObject(StreamWriter writer, Stream output, int id, LayoutImage img)
    {
        byte[] pixelData;
        int width;
        int height;
        string filter;

        if (img.Format == "jpeg")
        {
            // JPEG can be embedded directly with DCTDecode
            pixelData = img.Data;
            width = Math.Max((int)img.Width, 1);
            height = Math.Max((int)img.Height, 1);
            filter = "/DCTDecode";
        }
        else
        {
            // PNG: decode to raw RGB pixels, then FlateDecode
            byte[]? decoded = PngDecoder.Decode(img.Data, out int pngWidth, out int pngHeight);
            if (decoded is not null)
            {
                pixelData = Compress(decoded);
                width = pngWidth;
                height = pngHeight;
            }
            else
            {
                // Fallback: treat as raw pixel data (best effort)
                pixelData = Compress(img.Data);
                width = Math.Max((int)img.Width, 1);
                height = Math.Max((int)img.Height, 1);
            }

            filter = "/FlateDecode";
        }

        writer.Write($"{id} 0 obj\n");
        writer.Write(string.Create(CultureInfo.InvariantCulture,
            $"<< /Type /XObject /Subtype /Image /Width {width} /Height {height} /ColorSpace /DeviceRGB /BitsPerComponent 8 /Length {pixelData.Length} /Filter {filter} >>\n"));
        writer.Write("stream\n");
        writer.Flush();
        output.Write(pixelData);
        output.Flush();
        writer.Write("\nendstream\n");
        writer.Write("endobj\n");
    }

    private static byte[] Compress(byte[] data)
    {
        using var ms = new MemoryStream();
        using (var deflate = new DeflateStream(ms, CompressionLevel.Fastest, leaveOpen: true))
        {
            deflate.Write(data);
        }

        byte[] deflated = ms.ToArray();
        var result = new byte[deflated.Length + 6];
        result[0] = 0x78;
        result[1] = 0x01;
        Array.Copy(deflated, 0, result, 2, deflated.Length);
        uint adler = Adler32(data);
        result[^4] = (byte)(adler >> 24);
        result[^3] = (byte)(adler >> 16);
        result[^2] = (byte)(adler >> 8);
        result[^1] = (byte)adler;
        return result;
    }

    private static uint Adler32(byte[] data)
    {
        uint a = 1;
        uint b = 0;
        foreach (byte d in data)
        {
            a = (a + d) % 65521;
            b = (b + a) % 65521;
        }

        return (b << 16) | a;
    }

    private static (float R, float G, float B) ParseHexColor(string hex)
    {
        if (hex.Length < 6)
        {
            return (0f, 0f, 0f);
        }

        if (hex.StartsWith('#'))
        {
            hex = hex[1..];
        }

        if (!int.TryParse(hex[..2], NumberStyles.HexNumber, CultureInfo.InvariantCulture, out int r))
        {
            r = 0;
        }

        if (!int.TryParse(hex[2..4], NumberStyles.HexNumber, CultureInfo.InvariantCulture, out int g))
        {
            g = 0;
        }

        if (!int.TryParse(hex[4..6], NumberStyles.HexNumber, CultureInfo.InvariantCulture, out int b))
        {
            b = 0;
        }

        return (r / 255f, g / 255f, b / 255f);
    }
}
