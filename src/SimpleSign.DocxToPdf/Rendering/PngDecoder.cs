using System.IO.Compression;

namespace SimpleSign.DocxToPdf.Rendering;

/// <summary>Decodes PNG files to raw RGB pixel data for PDF image embedding.</summary>
internal static class PngDecoder
{
    private static readonly byte[] PngSignature = [137, 80, 78, 71, 13, 10, 26, 10];

    /// <summary>Decodes a PNG file into raw RGB pixel data.</summary>
    /// <param name="pngData">The raw PNG file bytes.</param>
    /// <param name="width">The image width in pixels.</param>
    /// <param name="height">The image height in pixels.</param>
    /// <returns>Raw RGB pixel data (3 bytes per pixel, row-major), or null if decoding fails.</returns>
    public static byte[]? Decode(byte[] pngData, out int width, out int height)
    {
        width = 0;
        height = 0;

        if (pngData.Length < 8 || !pngData.AsSpan(0, 8).SequenceEqual(PngSignature))
        {
            return null;
        }

        int bitDepth = 0;
        int colorType = 0;
        byte[]? palette = null;
        using var idatStream = new MemoryStream();
        int offset = 8;

        // Parse chunks
        while (offset + 12 <= pngData.Length)
        {
            uint chunkLength = ReadUInt32(pngData, offset);
            string chunkType = System.Text.Encoding.ASCII.GetString(pngData, offset + 4, 4);
            int dataStart = offset + 8;

            if (dataStart + (int)chunkLength > pngData.Length)
            {
                break;
            }

            switch (chunkType)
            {
                case "IHDR":
                    if (chunkLength < 13)
                    {
                        return null;
                    }

                    width = (int)ReadUInt32(pngData, dataStart);
                    height = (int)ReadUInt32(pngData, dataStart + 4);
                    bitDepth = pngData[dataStart + 8];
                    colorType = pngData[dataStart + 9];
                    // Interlacing not supported for simplicity
                    if (pngData[dataStart + 12] != 0)
                    {
                        return null;
                    }

                    break;

                case "PLTE":
                    palette = new byte[chunkLength];
                    Array.Copy(pngData, dataStart, palette, 0, (int)chunkLength);
                    break;

                case "IDAT":
                    idatStream.Write(pngData, dataStart, (int)chunkLength);
                    break;

                case "IEND":
                    break;
            }

            offset = dataStart + (int)chunkLength + 4; // +4 for CRC
        }

        if (width == 0 || height == 0 || idatStream.Length == 0)
        {
            return null;
        }

        // Only support 8-bit depth for now
        if (bitDepth != 8)
        {
            return null;
        }

        // Decompress IDAT data (zlib format: 2-byte header + deflate + 4-byte checksum)
        byte[] compressedData = idatStream.ToArray();
        byte[]? rawScanlines = DecompressZlib(compressedData);
        if (rawScanlines is null)
        {
            return null;
        }

        // Calculate bytes per pixel based on color type
        int bytesPerPixel = colorType switch
        {
            0 => 1, // Grayscale
            2 => 3, // RGB
            3 => 1, // Indexed (palette)
            4 => 2, // Grayscale + Alpha
            6 => 4, // RGBA
            _ => 0
        };

        if (bytesPerPixel == 0)
        {
            return null;
        }

        int stride = width * bytesPerPixel;
        int expectedLength = height * (stride + 1); // +1 for filter byte per row

        if (rawScanlines.Length < expectedLength)
        {
            return null;
        }

        // Unfilter scanlines
        byte[] unfiltered = new byte[height * stride];
        for (int row = 0; row < height; row++)
        {
            int srcRowStart = row * (stride + 1);
            byte filterType = rawScanlines[srcRowStart];
            int srcDataStart = srcRowStart + 1;
            int dstRowStart = row * stride;

            for (int col = 0; col < stride; col++)
            {
                byte raw = rawScanlines[srcDataStart + col];
                byte a = col >= bytesPerPixel ? unfiltered[dstRowStart + col - bytesPerPixel] : (byte)0;
                byte b = row > 0 ? unfiltered[dstRowStart - stride + col] : (byte)0;
                byte c = (row > 0 && col >= bytesPerPixel) ? unfiltered[dstRowStart - stride + col - bytesPerPixel] : (byte)0;

                unfiltered[dstRowStart + col] = filterType switch
                {
                    0 => raw,                                   // None
                    1 => (byte)(raw + a),                       // Sub
                    2 => (byte)(raw + b),                       // Up
                    3 => (byte)(raw + ((a + b) / 2)),           // Average
                    4 => (byte)(raw + PaethPredictor(a, b, c)), // Paeth
                    _ => raw
                };
            }
        }

        // Convert to RGB
        return colorType switch
        {
            0 => GrayscaleToRgb(unfiltered, width, height),
            2 => unfiltered, // Already RGB
            3 => IndexedToRgb(unfiltered, width, height, palette),
            4 => GrayscaleAlphaToRgb(unfiltered, width, height),
            6 => RgbaToRgb(unfiltered, width, height),
            _ => null
        };
    }

    private static byte[] GrayscaleToRgb(byte[] data, int width, int height)
    {
        byte[] rgb = new byte[width * height * 3];
        for (int i = 0; i < width * height; i++)
        {
            rgb[i * 3] = data[i];
            rgb[i * 3 + 1] = data[i];
            rgb[i * 3 + 2] = data[i];
        }

        return rgb;
    }

    private static byte[]? IndexedToRgb(byte[] data, int width, int height, byte[]? palette)
    {
        if (palette is null || palette.Length < 3)
        {
            return null;
        }

        byte[] rgb = new byte[width * height * 3];
        for (int i = 0; i < width * height; i++)
        {
            int paletteIdx = data[i] * 3;
            if (paletteIdx + 2 >= palette.Length)
            {
                continue;
            }

            rgb[i * 3] = palette[paletteIdx];
            rgb[i * 3 + 1] = palette[paletteIdx + 1];
            rgb[i * 3 + 2] = palette[paletteIdx + 2];
        }

        return rgb;
    }

    private static byte[] GrayscaleAlphaToRgb(byte[] data, int width, int height)
    {
        byte[] rgb = new byte[width * height * 3];
        for (int i = 0; i < width * height; i++)
        {
            byte gray = data[i * 2];
            rgb[i * 3] = gray;
            rgb[i * 3 + 1] = gray;
            rgb[i * 3 + 2] = gray;
        }

        return rgb;
    }

    private static byte[] RgbaToRgb(byte[] data, int width, int height)
    {
        byte[] rgb = new byte[width * height * 3];
        for (int i = 0; i < width * height; i++)
        {
            rgb[i * 3] = data[i * 4];
            rgb[i * 3 + 1] = data[i * 4 + 1];
            rgb[i * 3 + 2] = data[i * 4 + 2];
        }

        return rgb;
    }

    private static byte PaethPredictor(byte a, byte b, byte c)
    {
        int p = a + b - c;
        int pa = Math.Abs(p - a);
        int pb = Math.Abs(p - b);
        int pc = Math.Abs(p - c);

        if (pa <= pb && pa <= pc)
        {
            return a;
        }

        return pb <= pc ? b : c;
    }

    private static byte[]? DecompressZlib(byte[] data)
    {
        if (data.Length < 2)
        {
            return null;
        }

        try
        {
            // Skip 2-byte zlib header
            using var input = new MemoryStream(data, 2, data.Length - 2);
            using var deflate = new DeflateStream(input, CompressionMode.Decompress);
            using var output = new MemoryStream();
            deflate.CopyTo(output);
            return output.ToArray();
        }
        catch (Exception)
        {
            return null;
        }
    }

    private static uint ReadUInt32(byte[] data, int offset) =>
        ((uint)data[offset] << 24) | ((uint)data[offset + 1] << 16) |
        ((uint)data[offset + 2] << 8) | data[offset + 3];
}
