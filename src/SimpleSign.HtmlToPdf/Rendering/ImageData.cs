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

    /// <summary>Gets a value indicating whether a CMYK JPEG stores inverted samples (Adobe APP14).</summary>
    public bool AdobeInverted { get; init; }

    /// <summary>Parse image from a data URI.</summary>
    public static ImageData? Parse(string? src) => Parse(src, ResourceLoader.DataUriOnly);

    /// <summary>Parse image from a data URI, local file, or custom-loaded reference.</summary>
    public static ImageData? Parse(string? src, ResourceLoader loader)
    {
        byte[]? bytes = loader.Load(src);
        if (bytes is null || bytes.Length == 0)
        {
            return null;
        }

        return DetectFormat(bytes) switch
        {
            ImageFormat.Jpeg => ParseJpeg(bytes),
            ImageFormat.Png => ParsePng(bytes),
            _ => null,
        };
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
        bool adobe = false;
        while (i + 1 < data.Length)
        {
            if (data[i] != 0xFF)
            {
                i++;
                continue;
            }

            byte marker = data[i + 1];
            i += 2;

            // APP14 "Adobe": CMYK/YCCK samples are stored inverted.
            if (marker == 0xEE && i + 7 < data.Length && data[i + 2] == 'A' && data[i + 3] == 'd' && data[i + 4] == 'o' && data[i + 5] == 'b' && data[i + 6] == 'e')
            {
                adobe = true;
            }

            // Standalone markers without a length.
            if (marker is 0xD8 or 0x01 or (>= 0xD0 and <= 0xD7))
            {
                continue;
            }

            // Any start-of-frame marker (baseline, extended, progressive, lossless) except DHT/JPG/DAC.
            if (marker is >= 0xC0 and <= 0xCF and not 0xC4 and not 0xC8 and not 0xCC)
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
                    AdobeInverted = adobe && components == 4,
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
