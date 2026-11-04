using System.Text;
using QRCoder;

namespace SimpleSign.PAdES.Signing;

/// <summary>
/// Renders the visual appearance of a PDF signature stamp as a Form XObject stream.
/// Responsible for text layout, font embedding, and PDF content stream generation.
/// </summary>
internal static class SignatureAppearanceRenderer
{
    /// <summary>
    /// Builds a Form XObject that renders the visible signature appearance,
    /// including optional background color and image, QR code, text lines and border.
    /// </summary>
    /// <param name="objNum">Object number for the Form XObject.</param>
    /// <param name="options">Signature field options.</param>
    /// <param name="sigTime">Signing time (UTC).</param>
    /// <param name="width">Computed stamp width.</param>
    /// <param name="height">Computed stamp height.</param>
    /// <param name="imageObjNum">Object number for the image XObject (0 if no image).</param>
    /// <param name="fontFileObjNum">Object number for the /FontFile2 stream (0 to skip embedding).</param>
    /// <param name="fontDescriptorObjNum">Object number for the /FontDescriptor (0 to skip embedding).</param>
    /// <param name="softMaskObjNum">Object number for the image soft mask (0 drops image transparency).</param>
    /// <returns>Bytes for the Form XObject, followed by the image XObject and its soft mask when present.</returns>
    public static byte[] BuildAppearanceXObject(int objNum, SignatureFieldOptions options, DateTime sigTime, float width, float height, int imageObjNum = 0, int fontFileObjNum = 0, int fontDescriptorObjNum = 0, int softMaskObjNum = 0)
    {
        var appearance = options.Appearance!;
        AppearanceImage? image = imageObjNum > 0 ? AppearanceImage.FromAppearance(appearance) : null;
        string baseFontName = appearance.GetBaseFontName();

        var stream = new StringBuilder();
        Line(stream, "q");

        if (appearance.BackgroundColor is { } fill)
        {
            Line(stream, $"{F(fill.R)} {F(fill.G)} {F(fill.B)} rg");
            Line(stream, $"0 0 {F(width)} {F(height)} re f");
        }

        if (image is not null)
        {
            AppendImage(stream, image, appearance.BackgroundImageFit, width, height);
        }

        // QR code (rendered as filled rectangles on the left side)
        if (!string.IsNullOrEmpty(appearance.VerificationUrl))
        {
            using var qrGenerator = new QRCodeGenerator();
            var qrCodeData = qrGenerator.CreateQrCode(appearance.VerificationUrl, QRCodeGenerator.ECCLevel.M);
            int modules = qrCodeData.ModuleMatrix.Count;
            float qrSize = SignatureAppearance.QrSize(height);
            float moduleSize = qrSize / modules;

            // White background for QR code (ensures quiet zone contrast)
            Line(stream, "1 1 1 rg");
            Line(stream, $"{F(2)} {F(2)} {F(qrSize)} {F(qrSize)} re f");

            // Dark modules
            Line(stream, "0 0 0 rg");
            for (int r = 0; r < modules; r++)
            {
                for (int c = 0; c < modules; c++)
                {
                    if (qrCodeData.ModuleMatrix[r][c])
                    {
                        float x = 2 + (c * moduleSize);
                        float y = height - 2 - ((r + 1) * moduleSize);
                        Line(stream, $"{F(x)} {F(y)} {F(moduleSize)} {F(moduleSize)} re f");
                    }
                }
            }
        }

        stream.Append(BuildTextLines(options, appearance, sigTime, width, height));

        // Border last, so the background image and QR code do not cover it.
        if (appearance.BorderColor is { } border)
        {
            Line(stream, $"{F(border.R)} {F(border.G)} {F(border.B)} RG");
            Line(stream, $"{F(appearance.BorderWidth)} w");
            float bw = appearance.BorderWidth / 2;
            Line(stream, $"{F(bw)} {F(bw)} {F(width - appearance.BorderWidth)} {F(height - appearance.BorderWidth)} re S");
        }

        Line(stream, "Q");

        byte[] streamBytes = Encoding.Latin1.GetBytes(stream.ToString());
        byte[] form = WrapInFormXObject(objNum, width, height, streamBytes, baseFontName, fontFileObjNum, fontDescriptorObjNum, image is not null ? imageObjNum : 0);
        if (image is null)
        {
            return form;
        }

        byte[] imageObjects = image.BuildObjects(imageObjNum, softMaskObjNum);
        byte[] result = new byte[form.Length + imageObjects.Length];
        form.CopyTo(result, 0);
        imageObjects.CopyTo(result, form.Length);
        return result;
    }

    /// <summary>Draws the background image with the requested fit mode.</summary>
    private static void AppendImage(StringBuilder stream, AppearanceImage image, SignatureImageFit fit, float width, float height)
    {
        float drawW = width;
        float drawH = height;
        float tx = 0;
        float ty = 0;
        bool clip = false;

        if (fit is SignatureImageFit.Contain or SignatureImageFit.Cover && image.PixelWidth > 0 && image.PixelHeight > 0)
        {
            float sx = width / image.PixelWidth;
            float sy = height / image.PixelHeight;
            float scale = fit == SignatureImageFit.Contain ? Math.Min(sx, sy) : Math.Max(sx, sy);
            drawW = image.PixelWidth * scale;
            drawH = image.PixelHeight * scale;
            tx = (width - drawW) / 2;
            ty = (height - drawH) / 2;
            clip = fit == SignatureImageFit.Cover;
        }

        Line(stream, "q");
        if (clip)
        {
            Line(stream, $"0 0 {F(width)} {F(height)} re W n");
        }

        Line(stream, $"{F(drawW)} 0 0 {F(drawH)} {F(tx)} {F(ty)} cm");
        Line(stream, "/Img0 Do");
        Line(stream, "Q");
    }

    /// <summary>
    /// Generates the BT/ET text block for the visual signature stamp.
    /// </summary>
    private static string BuildTextLines(SignatureFieldOptions options, SignatureAppearance appearance, DateTime sigTime, float width, float height)
    {
        var sb = new StringBuilder();

        // Text color (default: black)
        if (appearance.TextColor is { } tc)
        {
            Line(sb, $"{F(tc.R)} {F(tc.G)} {F(tc.B)} rg");
        }
        else
        {
            Line(sb, "0 0 0 rg");
        }

        Line(sb, "BT");

        float? currentSize = null;
        foreach (var line in appearance.Layout(options.SignerName, options.Reason, options.Location, sigTime, width, height))
        {
            if (currentSize != line.FontSize)
            {
                Line(sb, $"/F1 {F(line.FontSize)} Tf");
                currentSize = line.FontSize;
            }

            Line(sb, $"1 0 0 1 {F(line.X)} {F(line.Y)} Tm");
            Line(sb, $"({EscapePdfString(line.Text)}) Tj");
        }

        Line(sb, "ET");
        return sb.ToString();
    }

    /// <summary>
    /// Wraps content stream bytes in a PDF Form XObject with <c>/BBox</c> and <c>/Resources</c>
    /// (the stamp font with WinAnsiEncoding, plus the background image when present).
    /// </summary>
    private static byte[] WrapInFormXObject(int objNum, float width, float height, byte[] streamBytes, string baseFontName, int fontFileObjNum, int fontDescriptorObjNum, int imageObjNum)
    {
        bool embedFont = fontFileObjNum > 0 && fontDescriptorObjNum > 0;
        bool isHelvetica = string.Equals(baseFontName, "Helvetica", StringComparison.OrdinalIgnoreCase);

        var xObjDict = new StringBuilder();
        xObjDict.Append($"{objNum} 0 obj\n");
        xObjDict.Append("<< /Type /XObject\n");
        xObjDict.Append("   /Subtype /Form\n");
        xObjDict.Append($"   /BBox [0 0 {F(width)} {F(height)}]\n");
        xObjDict.Append("   /Resources <<\n");
        xObjDict.Append("      /Font << /F1 <<\n");

        if (embedFont && isHelvetica)
        {
            xObjDict.Append("         /Type /Font /Subtype /TrueType /BaseFont /LiberationSans\n");
            xObjDict.Append($"         /FirstChar {FontResources.FirstChar} /LastChar {FontResources.LastChar}\n");
            xObjDict.Append($"         {PdfFontWriter.BuildWidthsArray()}\n");
            xObjDict.Append($"         /FontDescriptor {fontDescriptorObjNum} 0 R\n");
            xObjDict.Append("         /Encoding /WinAnsiEncoding\n");
        }
        else
        {
            xObjDict.Append($"         /Type /Font /Subtype /Type1 /BaseFont /{baseFontName} /Encoding /WinAnsiEncoding\n");
        }

        xObjDict.Append("      >> >>\n");
        if (imageObjNum > 0)
        {
            xObjDict.Append($"      /XObject << /Img0 {imageObjNum} 0 R >>\n");
        }

        xObjDict.Append("   >>\n");
        xObjDict.Append($"   /Length {streamBytes.Length}\n");
        xObjDict.Append(">>\n");
        xObjDict.Append("stream\n");

        byte[] headerBytes = Encoding.Latin1.GetBytes(xObjDict.ToString());
        byte[] trailerBytes = Encoding.Latin1.GetBytes("\nendstream\nendobj\n");

        byte[] result = new byte[headerBytes.Length + streamBytes.Length + trailerBytes.Length];
        headerBytes.CopyTo(result, 0);
        streamBytes.CopyTo(result, headerBytes.Length);
        trailerBytes.CopyTo(result, headerBytes.Length + streamBytes.Length);
        return result;
    }

    /// <summary>
    /// Escapes special characters in a PDF literal string per ISO 32000 §7.3.4.2 Table 3.
    /// </summary>
    internal static string EscapePdfString(string s)
    {
        return s.Replace("\\", "\\\\")
                .Replace("(", "\\(")
                .Replace(")", "\\)")
                .Replace("\n", "\\n")
                .Replace("\r", "\\r")
                .Replace("\t", "\\t")
                .Replace("\b", "\\b")
                .Replace("\f", "\\f");
    }

    /// <summary>
    /// Appends one content-stream line ending in LF. <see cref="StringBuilder.AppendLine()"/>
    /// would use the platform newline, making the stamp bytes differ between Windows and Unix.
    /// </summary>
    private static void Line(StringBuilder sb, string text) => sb.Append(text).Append('\n');

    /// <summary>Formats a float with '.' decimal separator regardless of system locale.</summary>
    internal static string F(float value) => PdfFormatting.F(value);
}
