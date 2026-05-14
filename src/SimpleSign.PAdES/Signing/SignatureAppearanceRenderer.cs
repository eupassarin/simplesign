using System.Globalization;
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
    /// including optional background image, border, signer name, date, reason, and location.
    /// </summary>
    /// <param name="objNum">Object number for the Form XObject.</param>
    /// <param name="options">Signature field options.</param>
    /// <param name="sigTime">Signing time.</param>
    /// <param name="width">Computed stamp width.</param>
    /// <param name="height">Computed stamp height.</param>
    /// <param name="imageObjNum">Object number for the image XObject (0 if no image).</param>
    /// <returns>Bytes for the Form XObject (and image XObject if present).</returns>
    public static byte[] BuildAppearanceXObject(int objNum, SignatureFieldOptions options, DateTime sigTime, float width, float height, int imageObjNum = 0)
    {
        var appearance = options.Appearance!;
        bool hasPng = appearance.BackgroundImagePng is { Length: > 0 } && imageObjNum > 0;
        bool hasJpeg = appearance.BackgroundImageJpeg is { Length: > 0 } && imageObjNum > 0;
        bool hasImage = hasPng || hasJpeg;
        string baseFontName = appearance.GetBaseFontName();

        var stream = new StringBuilder();
        stream.AppendLine("q");

        // Border
        if (appearance.BorderColor is { } border)
        {
            stream.AppendLine($"{F(border.R)} {F(border.G)} {F(border.B)} RG");
            stream.AppendLine($"{F(appearance.BorderWidth)} w");
            float bw = appearance.BorderWidth / 2;
            stream.AppendLine($"{F(bw)} {F(bw)} {F(width - appearance.BorderWidth)} {F(height - appearance.BorderWidth)} re S");
        }

        // Background image (scaled to fill)
        if (hasImage)
        {
            stream.AppendLine($"{F(width)} 0 0 {F(height)} 0 0 cm");
            stream.AppendLine("/Img0 Do");
            // Reset transform for text
            stream.AppendLine("Q");
            stream.AppendLine("q");
        }

        // QR code (rendered as filled rectangles on the left side)
        float qrOffset = 0;
        if (!string.IsNullOrEmpty(appearance.VerificationUrl))
        {
            using var qrGenerator = new QRCodeGenerator();
            var qrCodeData = qrGenerator.CreateQrCode(appearance.VerificationUrl, QRCodeGenerator.ECCLevel.M);
            int modules = qrCodeData.ModuleMatrix.Count;
            float qrSize = height - 4; // 2pt margin each side
            float moduleSize = qrSize / modules;
            qrOffset = qrSize + 6; // QR width + gap

            // White background for QR code (ensures quiet zone contrast)
            stream.AppendLine("1 1 1 rg");
            stream.AppendLine($"{F(2)} {F(2)} {F(qrSize)} {F(qrSize)} re f");

            // Dark modules
            stream.AppendLine("0 0 0 rg");
            for (int r = 0; r < modules; r++)
            {
                for (int c = 0; c < modules; c++)
                {
                    if (qrCodeData.ModuleMatrix[r][c])
                    {
                        float x = 2 + (c * moduleSize);
                        float y = height - 2 - ((r + 1) * moduleSize);
                        stream.AppendLine($"{F(x)} {F(y)} {F(moduleSize)} {F(moduleSize)} re f");
                    }
                }
            }
        }

        stream.Append(BuildTextLines(options, appearance, sigTime, height, baseFontName, qrOffset));
        stream.AppendLine("Q");

        byte[] streamBytes = Encoding.Latin1.GetBytes(stream.ToString());

        if (hasImage)
        {
            if (hasPng)
            {
                return WrapInFormXObjectWithPngImage(objNum, width, height, streamBytes, appearance.BackgroundImagePng!.Value.ToArray(), imageObjNum, baseFontName);
            }

            return WrapInFormXObjectWithJpegImage(objNum, width, height, streamBytes, appearance.BackgroundImageJpeg!.Value.ToArray(), imageObjNum, baseFontName);
        }

        return WrapInFormXObject(objNum, width, height, streamBytes, baseFontName);
    }

    /// <summary>
    /// Generates the BT/ET text block for the visual signature stamp.
    /// </summary>
    private static string BuildTextLines(SignatureFieldOptions options, SignatureAppearance appearance, DateTime sigTime, float height, string baseFontName, float xOffset = 0)
    {
        float fontSize = appearance.GetFontSizeValue();
        float labelFontSize = appearance.GetLabelFontSizeValue();
        float lineHeight = SignatureAppearance.GetLineHeight();

        var sb = new StringBuilder();

        // Text color (default: black)
        if (appearance.TextColor is { } tc)
        {
            sb.AppendLine($"{F(tc.R)} {F(tc.G)} {F(tc.B)} rg");
        }
        else
        {
            sb.AppendLine("0 0 0 rg");
        }

        sb.AppendLine("BT");

        // Line 1: "Signed by" label.
        string signerDisplayName = SignatureAppearance.Truncate(options.SignerName ?? "Signer");
        sb.AppendLine($"/F1 {F(labelFontSize)} Tf");
        sb.AppendLine($"{F(3 + xOffset)} {F(height - lineHeight)} Td");
        sb.AppendLine("(Signed by) Tj");

        // Line 2: Signer name.
        sb.AppendLine($"/F1 {F(fontSize)} Tf");
        sb.AppendLine($"0 -{F(lineHeight)} Td");
        sb.AppendLine($"({EscapePdfString(signerDisplayName)}) Tj");

        if (appearance.ShowDate)
        {
            sb.AppendLine($"/F1 {F(labelFontSize)} Tf");
            sb.AppendLine($"0 -{F(lineHeight)} Td");
            sb.AppendLine($"({sigTime:dd/MM/yyyy HH:mm} UTC) Tj");
        }

        if (appearance.ShowReason && !string.IsNullOrEmpty(options.Reason))
        {
            sb.AppendLine($"0 -{F(lineHeight)} Td");
            sb.AppendLine($"(Reason: {EscapePdfString(SignatureAppearance.Truncate(options.Reason))}) Tj");
        }

        if (appearance.ShowLocation && !string.IsNullOrEmpty(options.Location))
        {
            sb.AppendLine($"0 -{F(lineHeight)} Td");
            sb.AppendLine($"(Location: {EscapePdfString(SignatureAppearance.Truncate(options.Location))}) Tj");
        }

        if (appearance.ExtraLines is { Count: > 0 })
        {
            foreach (string line in appearance.ExtraLines)
            {
                sb.AppendLine($"0 -{F(lineHeight)} Td");
                sb.AppendLine($"({EscapePdfString(SignatureAppearance.Truncate(line))}) Tj");
            }
        }

        sb.AppendLine("ET");
        return sb.ToString();
    }

    /// <summary>
    /// Wraps content stream bytes in a PDF Form XObject with
    /// <c>/BBox</c>, <c>/Resources</c> (Helvetica with WinAnsiEncoding), and <c>/Matrix</c>.
    /// </summary>
    private static byte[] WrapInFormXObject(int objNum, float width, float height, byte[] streamBytes, string baseFontName)
    {
        StringBuilder xObjDict = new StringBuilder();
        xObjDict.Append($"{objNum} 0 obj\n");
        xObjDict.Append("<< /Type /XObject\n");
        xObjDict.Append("   /Subtype /Form\n");
        xObjDict.Append($"   /BBox [0 0 {F(width)} {F(height)}]\n");
        xObjDict.Append("   /Resources << /Font << /F1 <<\n");
        xObjDict.Append($"      /Type /Font /Subtype /Type1 /BaseFont /{baseFontName} /Encoding /WinAnsiEncoding\n");
        xObjDict.Append("   >> >> >>\n");
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
    /// Wraps content stream in a Form XObject with both font and image resources.
    /// The JPEG image is embedded as a separate inline XObject (DCTDecode).
    /// </summary>
    private static byte[] WrapInFormXObjectWithJpegImage(int objNum, float width, float height, byte[] streamBytes, byte[] jpegBytes, int imageObjNum, string baseFontName)
    {
        // Build the image XObject first
        var (imgWidth, imgHeight) = DetectJpegDimensions(jpegBytes);

        var imgObj = new StringBuilder();
        imgObj.Append($"{imageObjNum} 0 obj\n");
        imgObj.Append("<< /Type /XObject\n");
        imgObj.Append("   /Subtype /Image\n");
        imgObj.Append($"   /Width {imgWidth}\n");
        imgObj.Append($"   /Height {imgHeight}\n");
        imgObj.Append("   /ColorSpace /DeviceRGB\n");
        imgObj.Append("   /BitsPerComponent 8\n");
        imgObj.Append("   /Filter /DCTDecode\n");
        imgObj.Append($"   /Length {jpegBytes.Length}\n");
        imgObj.Append(">>\n");
        imgObj.Append("stream\n");
        byte[] imgHeader = Encoding.Latin1.GetBytes(imgObj.ToString());
        byte[] imgTrailer = Encoding.Latin1.GetBytes("\nendstream\nendobj\n");

        // Build the form XObject with image reference in resources
        var xObjDict = new StringBuilder();
        xObjDict.Append($"{objNum} 0 obj\n");
        xObjDict.Append("<< /Type /XObject\n");
        xObjDict.Append("   /Subtype /Form\n");
        xObjDict.Append($"   /BBox [0 0 {F(width)} {F(height)}]\n");
        xObjDict.Append("   /Resources <<\n");
        xObjDict.Append($"      /Font << /F1 << /Type /Font /Subtype /Type1 /BaseFont /{baseFontName} /Encoding /WinAnsiEncoding >> >>\n");
        xObjDict.Append($"      /XObject << /Img0 {imageObjNum} 0 R >>\n");
        xObjDict.Append("   >>\n");
        xObjDict.Append($"   /Length {streamBytes.Length}\n");
        xObjDict.Append(">>\n");
        xObjDict.Append("stream\n");
        byte[] formHeader = Encoding.Latin1.GetBytes(xObjDict.ToString());
        byte[] formTrailer = Encoding.Latin1.GetBytes("\nendstream\nendobj\n");

        // Concatenate: form XObject + image XObject
        int totalLen = formHeader.Length + streamBytes.Length + formTrailer.Length +
                       imgHeader.Length + jpegBytes.Length + imgTrailer.Length;
        byte[] result = new byte[totalLen];
        int offset = 0;

        formHeader.CopyTo(result, offset);
        offset += formHeader.Length;
        streamBytes.CopyTo(result, offset);
        offset += streamBytes.Length;
        formTrailer.CopyTo(result, offset);
        offset += formTrailer.Length;
        imgHeader.CopyTo(result, offset);
        offset += imgHeader.Length;
        jpegBytes.CopyTo(result, offset);
        offset += jpegBytes.Length;
        imgTrailer.CopyTo(result, offset);

        return result;
    }

    /// <summary>
    /// Wraps content stream in a Form XObject with PNG image support (FlateDecode + predictors).
    /// Supports RGB/Gray 8-bit PNG without interlace.
    /// </summary>
    private static byte[] WrapInFormXObjectWithPngImage(int objNum, float width, float height, byte[] streamBytes, byte[] pngBytes, int imageObjNum, string baseFontName)
    {
        var png = ParsePng(pngBytes);

        var imgObj = new StringBuilder();
        imgObj.Append($"{imageObjNum} 0 obj\n");
        imgObj.Append("<< /Type /XObject\n");
        imgObj.Append("   /Subtype /Image\n");
        imgObj.Append($"   /Width {png.Width}\n");
        imgObj.Append($"   /Height {png.Height}\n");
        imgObj.Append($"   /ColorSpace /{png.ColorSpace}\n");
        imgObj.Append("   /BitsPerComponent 8\n");
        imgObj.Append("   /Filter /FlateDecode\n");
        imgObj.Append("   /DecodeParms << /Predictor 15 /Colors ");
        imgObj.Append(png.Colors);
        imgObj.Append(" /BitsPerComponent 8 /Columns ");
        imgObj.Append(png.Width);
        imgObj.Append(" >>\n");
        imgObj.Append($"   /Length {png.CompressedData.Length}\n");
        imgObj.Append(">>\n");
        imgObj.Append("stream\n");
        byte[] imgHeader = Encoding.Latin1.GetBytes(imgObj.ToString());
        byte[] imgTrailer = Encoding.Latin1.GetBytes("\nendstream\nendobj\n");

        var xObjDict = new StringBuilder();
        xObjDict.Append($"{objNum} 0 obj\n");
        xObjDict.Append("<< /Type /XObject\n");
        xObjDict.Append("   /Subtype /Form\n");
        xObjDict.Append($"   /BBox [0 0 {F(width)} {F(height)}]\n");
        xObjDict.Append("   /Resources <<\n");
        xObjDict.Append($"      /Font << /F1 << /Type /Font /Subtype /Type1 /BaseFont /{baseFontName} /Encoding /WinAnsiEncoding >> >>\n");
        xObjDict.Append($"      /XObject << /Img0 {imageObjNum} 0 R >>\n");
        xObjDict.Append("   >>\n");
        xObjDict.Append($"   /Length {streamBytes.Length}\n");
        xObjDict.Append(">>\n");
        xObjDict.Append("stream\n");
        byte[] formHeader = Encoding.Latin1.GetBytes(xObjDict.ToString());
        byte[] formTrailer = Encoding.Latin1.GetBytes("\nendstream\nendobj\n");

        int totalLen = formHeader.Length + streamBytes.Length + formTrailer.Length +
                       imgHeader.Length + png.CompressedData.Length + imgTrailer.Length;
        byte[] result = new byte[totalLen];
        int offset = 0;

        formHeader.CopyTo(result, offset);
        offset += formHeader.Length;
        streamBytes.CopyTo(result, offset);
        offset += streamBytes.Length;
        formTrailer.CopyTo(result, offset);
        offset += formTrailer.Length;
        imgHeader.CopyTo(result, offset);
        offset += imgHeader.Length;
        png.CompressedData.CopyTo(result, offset);
        offset += png.CompressedData.Length;
        imgTrailer.CopyTo(result, offset);

        return result;
    }

    private static ParsedPng ParsePng(byte[] pngBytes)
    {
        ReadOnlySpan<byte> signature = [137, 80, 78, 71, 13, 10, 26, 10];
        if (pngBytes.Length < 8 || !pngBytes.AsSpan(0, 8).SequenceEqual(signature))
        {
            throw new ArgumentException("BackgroundImagePng is not a valid PNG file.", nameof(pngBytes));
        }

        int offset = 8;
        int width = 0;
        int height = 0;
        byte bitDepth = 0;
        byte colorType = 0;
        byte interlace = 0;
        var idatParts = new List<byte[]>();

        while (offset + 12 <= pngBytes.Length)
        {
            int length = ReadInt32BigEndian(pngBytes, offset);
            offset += 4;
            if (offset + 4 > pngBytes.Length)
            {
                break;
            }

            string chunkType = Encoding.ASCII.GetString(pngBytes, offset, 4);
            offset += 4;
            if (offset + length + 4 > pngBytes.Length)
            {
                break;
            }

            ReadOnlySpan<byte> chunkData = pngBytes.AsSpan(offset, length);
            offset += length;
            offset += 4; // CRC

            if (chunkType == "IHDR")
            {
                if (length < 13)
                {
                    throw new ArgumentException("PNG IHDR chunk is invalid.", nameof(pngBytes));
                }

                width = ReadInt32BigEndian(chunkData, 0);
                height = ReadInt32BigEndian(chunkData, 4);
                bitDepth = chunkData[8];
                colorType = chunkData[9];
                interlace = chunkData[12];
            }
            else if (chunkType == "IDAT")
            {
                idatParts.Add(chunkData.ToArray());
            }
            else if (chunkType == "IEND")
            {
                break;
            }
        }

        if (width <= 0 || height <= 0 || idatParts.Count == 0)
        {
            throw new ArgumentException("PNG is missing required chunks (IHDR/IDAT).", nameof(pngBytes));
        }

        if (bitDepth != 8)
        {
            throw new NotSupportedException("Only 8-bit PNG is supported for signature appearance.");
        }

        if (interlace != 0)
        {
            throw new NotSupportedException("Interlaced PNG is not supported for signature appearance.");
        }

        string colorSpace;
        int colors;
        if (colorType == 2) // RGB
        {
            colorSpace = "DeviceRGB";
            colors = 3;
        }
        else if (colorType == 0) // Grayscale
        {
            colorSpace = "DeviceGray";
            colors = 1;
        }
        else
        {
            throw new NotSupportedException("Only PNG color types 0 (grayscale) and 2 (RGB) are supported.");
        }

        int len = idatParts.Sum(p => p.Length);
        byte[] data = new byte[len];
        int pOffset = 0;
        foreach (var p in idatParts)
        {
            Buffer.BlockCopy(p, 0, data, pOffset, p.Length);
            pOffset += p.Length;
        }

        return new ParsedPng(width, height, colorSpace, colors, data);
    }

    private static int ReadInt32BigEndian(ReadOnlySpan<byte> data, int offset)
    {
        return (data[offset] << 24) |
               (data[offset + 1] << 16) |
               (data[offset + 2] << 8) |
               data[offset + 3];
    }

    private sealed record ParsedPng(int Width, int Height, string ColorSpace, int Colors, byte[] CompressedData);

    /// <summary>
    /// Detects JPEG image dimensions by parsing SOF0/SOF2 markers.
    /// Returns (width, height) or (1, 1) if detection fails.
    /// </summary>
    private static (int Width, int Height) DetectJpegDimensions(byte[] jpeg)
    {
        // JPEG markers: SOF0 = 0xFFC0, SOF2 = 0xFFC2
        for (int i = 0; i < jpeg.Length - 9; i++)
        {
            if (jpeg[i] == 0xFF && (jpeg[i + 1] == 0xC0 || jpeg[i + 1] == 0xC2))
            {
                int h = (jpeg[i + 5] << 8) | jpeg[i + 6];
                int w = (jpeg[i + 7] << 8) | jpeg[i + 8];
                if (w > 0 && h > 0)
                {
                    return (w, h);
                }
            }
        }

        return (1, 1);
    }

    /// <summary>
    /// Escapes special characters in a PDF string literal: backslash, open paren, close paren.
    /// </summary>
    internal static string EscapePdfString(string s)
    {
        return s.Replace("\\", "\\\\").Replace("(", "\\(").Replace(")", "\\)");
    }

    /// <summary>Formats a float with '.' decimal separator regardless of system locale.</summary>
    internal static string F(float value) => value.ToString("F2", CultureInfo.InvariantCulture);
}
