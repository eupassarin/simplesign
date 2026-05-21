using SimpleSign.DocxToPdf.Layout;

namespace SimpleSign.DocxToPdf.Rendering;

/// <summary>Renders table borders and backgrounds into PDF content streams.</summary>
internal static class TableRenderer
{
    /// <summary>Renders a table border line.</summary>
    /// <param name="builder">The content stream builder.</param>
    /// <param name="line">The layout line element.</param>
    /// <param name="pageHeight">The page height for Y coordinate flipping.</param>
    public static void RenderBorder(PdfContentStreamBuilder builder, LayoutLine line, float pageHeight)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(line);

        (float r, float g, float b) = ParseColor(line.Color);
        builder.SetStrokeColor(r, g, b);
        builder.SetLineWidth(line.LineWidth);

        float pdfY1 = pageHeight - line.Y;
        float pdfY2 = pageHeight - line.EndY;
        builder.MoveTo(line.X, pdfY1);
        builder.LineTo(line.EndX, pdfY2);
        builder.Stroke();
    }

    /// <summary>Renders a cell background.</summary>
    /// <param name="builder">The content stream builder.</param>
    /// <param name="rect">The layout rect element.</param>
    /// <param name="pageHeight">The page height for Y coordinate flipping.</param>
    public static void RenderCellBackground(PdfContentStreamBuilder builder, LayoutRect rect, float pageHeight)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(rect);

        (float r, float g, float b) = ParseColor(rect.FillColor);
        builder.SetFillColor(r, g, b);
        float pdfY = pageHeight - rect.Y - rect.Height;
        builder.Rectangle(rect.X, pdfY, rect.Width, rect.Height);
        builder.Fill();
    }

    private static (float R, float G, float B) ParseColor(string hex)
    {
        if (string.IsNullOrEmpty(hex) || hex.Length < 6)
        {
            return (0f, 0f, 0f);
        }

        int r = Convert.ToInt32(hex[..2], 16);
        int g = Convert.ToInt32(hex[2..4], 16);
        int b = Convert.ToInt32(hex[4..6], 16);
        return (r / 255f, g / 255f, b / 255f);
    }
}
