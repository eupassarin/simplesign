using SimpleSign.DocxToPdf.Layout;

namespace SimpleSign.DocxToPdf.Rendering;

/// <summary>Renders text runs into PDF content stream operations.</summary>
internal static class TextRenderer
{
    /// <summary>Renders a text element to the content stream builder.</summary>
    /// <param name="builder">The content stream builder.</param>
    /// <param name="text">The layout text element.</param>
    /// <param name="pageHeight">The page height for Y coordinate flipping.</param>
    public static void Render(PdfContentStreamBuilder builder, LayoutText text, float pageHeight)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(text);

        (float r, float g, float b) = ParseColor(text.Color);
        builder.SetFillColor(r, g, b);
        builder.SetFont("F1", text.FontSizePt);

        float pdfY = pageHeight - text.Y - text.FontSizePt;
        builder.SetTextMatrix(1, 0, 0, 1, text.X, pdfY);
        builder.ShowText(text.Text);
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
