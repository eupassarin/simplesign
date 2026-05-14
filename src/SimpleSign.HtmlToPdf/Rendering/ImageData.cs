// Licensed to SimpleSign under the MIT License.

namespace SimpleSign.HtmlToPdf.Rendering;

/// <summary>Image format.</summary>
internal enum ImageFormat
{
    Jpeg,
    Png,
    Unknown,
}

/// <summary>Parsed image data with dimensions and raw bytes.</summary>
internal sealed class ImageData
{
    public byte[] Data { get; init; } = [];
    public ImageFormat Format { get; init; }
    public int Width { get; init; }
    public int Height { get; init; }
    public int BitsPerComponent { get; init; } = 8;
    public int Components { get; init; } = 3; // RGB

    /// <summary>Parse image from data URI (data:image/...) or file path.</summary>
    public static ImageData? Parse(string? src)
    {
        if (string.IsNullOrWhiteSpace(src))
        {
            return null;
        }

        byte[]? bytes = null;
        ImageFormat format = ImageFormat.Unknown;

        if (src.StartsWith("data:", StringComparison.OrdinalIgnoreCase))
        {
            (bytes, format) = ParseDataUri(src);
        }
        else if (File.Exists(src))
        {
            bytes = File.ReadAllBytes(src);
            format = DetectFormat(bytes);
        }

        if (bytes is null || bytes.Length == 0)
        {
            return null;
        }

        if (format == ImageFormat.Unknown)
        {
            format = DetectFormat(bytes);
        }

        return format switch
        {
            ImageFormat.Jpeg => ParseJpeg(bytes),
            ImageFormat.Png => ParsePng(bytes),
            _ => null,
        };
    }

    private static (byte[]? Data, ImageFormat Format) ParseDataUri(string uri)
    {
        // data:image/png;base64,iVBOR...
        int commaIdx = uri.IndexOf(',');
        if (commaIdx < 0)
        {
            return (null, ImageFormat.Unknown);
        }

        ReadOnlySpan<char> header = uri.AsSpan(0, commaIdx);
        string base64 = uri[(commaIdx + 1)..];

        ImageFormat format = ImageFormat.Unknown;
        if (header.Contains("image/jpeg", StringComparison.OrdinalIgnoreCase) ||
            header.Contains("image/jpg", StringComparison.OrdinalIgnoreCase))
        {
            format = ImageFormat.Jpeg;
        }
        else if (header.Contains("image/png", StringComparison.OrdinalIgnoreCase))
        {
            format = ImageFormat.Png;
        }

        try
        {
            byte[] bytes = Convert.FromBase64String(base64);
            return (bytes, format);
        }
        catch (FormatException)
        {
            return (null, ImageFormat.Unknown);
        }
    }

    private static ImageFormat DetectFormat(byte[] data)
    {
        if (data.Length >= 3 && data[0] == 0xFF && data[1] == 0xD8 && data[2] == 0xFF)
        {
            return ImageFormat.Jpeg;
        }

        if (data.Length >= 8 &&
            data[0] == 0x89 && data[1] == 0x50 && data[2] == 0x4E && data[3] == 0x47 &&
            data[4] == 0x0D && data[5] == 0x0A && data[6] == 0x1A && data[7] == 0x0A)
        {
            return ImageFormat.Png;
        }

        return ImageFormat.Unknown;
    }

    /// <summary>Parse JPEG: find SOF0/SOF2 marker to get dimensions.</summary>
    private static ImageData? ParseJpeg(byte[] data)
    {
        int i = 2; // skip FF D8
        while (i + 1 < data.Length)
        {
            if (data[i] != 0xFF)
            {
                i++;
                continue;
            }

            byte marker = data[i + 1];
            i += 2;

            // SOF0 (baseline), SOF1 (extended), SOF2 (progressive)
            if (marker is 0xC0 or 0xC1 or 0xC2)
            {
                if (i + 7 > data.Length)
                {
                    break;
                }

                int bpc = data[i + 2];
                int height = (data[i + 3] << 8) | data[i + 4];
                int width = (data[i + 5] << 8) | data[i + 6];
                int components = data[i + 7];

                if (width <= 0 || height <= 0)
                {
                    return null;
                }

                return new ImageData
                {
                    Data = data,
                    Format = ImageFormat.Jpeg,
                    Width = width,
                    Height = height,
                    BitsPerComponent = bpc,
                    Components = components,
                };
            }

            // Skip other markers
            if (i + 1 < data.Length)
            {
                int len = (data[i] << 8) | data[i + 1];
                i += len;
            }
        }

        return null;
    }

    /// <summary>Parse PNG: read IHDR chunk for dimensions and color type.</summary>
    private static ImageData? ParsePng(byte[] data)
    {
        // PNG: 8-byte signature + IHDR chunk (length[4] + "IHDR"[4] + data[13])
        if (data.Length < 24)
        {
            return null;
        }

        int offset = 8; // skip signature

        // IHDR chunk: 4 bytes length, 4 bytes "IHDR"
        if (data[offset + 4] != 'I' || data[offset + 5] != 'H' ||
            data[offset + 6] != 'D' || data[offset + 7] != 'R')
        {
            return null;
        }

        offset += 8; // skip length + type

        int width = (data[offset] << 24) | (data[offset + 1] << 16) |
                    (data[offset + 2] << 8) | data[offset + 3];
        int height = (data[offset + 4] << 24) | (data[offset + 5] << 16) |
                     (data[offset + 6] << 8) | data[offset + 7];
        int bitDepth = data[offset + 8];
        int colorType = data[offset + 9];

        // Color type: 0=Grayscale, 2=RGB, 3=Indexed, 4=Grayscale+Alpha, 6=RGBA
        int components = colorType switch
        {
            0 => 1,
            2 => 3,
            4 => 2,
            6 => 4,
            _ => 3,
        };

        if (width <= 0 || height <= 0)
        {
            return null;
        }

        return new ImageData
        {
            Data = data,
            Format = ImageFormat.Png,
            Width = width,
            Height = height,
            BitsPerComponent = bitDepth,
            Components = components,
        };
    }
}
