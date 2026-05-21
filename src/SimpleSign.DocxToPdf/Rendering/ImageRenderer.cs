using SimpleSign.DocxToPdf.Layout;

namespace SimpleSign.DocxToPdf.Rendering;

/// <summary>Renders images into PDF content streams.</summary>
internal static class ImageRenderer
{
    /// <summary>Renders an image XObject reference in the content stream.</summary>
    /// <param name="builder">The content stream builder.</param>
    /// <param name="image">The layout image element.</param>
    /// <param name="xObjectName">The XObject resource name.</param>
    /// <param name="pageHeight">The page height for Y coordinate flipping.</param>
    public static void Render(PdfContentStreamBuilder builder, LayoutImage image, string xObjectName, float pageHeight)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(image);
        ArgumentNullException.ThrowIfNull(xObjectName);

        builder.SaveState();
        float pdfY = pageHeight - image.Y - image.Height;
        builder.ConcatMatrix(image.Width, 0, 0, image.Height, image.X, pdfY);
        builder.PaintXObject(xObjectName);
        builder.RestoreState();
    }

    /// <summary>Detects the image format from the data header bytes.</summary>
    /// <param name="data">The image data.</param>
    /// <returns>The format string ("jpeg" or "png").</returns>
    public static string DetectFormat(byte[] data)
    {
        ArgumentNullException.ThrowIfNull(data);

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
