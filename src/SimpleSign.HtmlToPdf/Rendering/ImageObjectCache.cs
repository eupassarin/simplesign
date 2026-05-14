// Licensed to SimpleSign under the MIT License.

using System.IO.Compression;

namespace SimpleSign.HtmlToPdf.Rendering;

/// <summary>
/// Caches image data as PDF XObject indirect objects.
/// Deduplicates images by source URI and writes them once per document.
/// </summary>
internal sealed class ImageObjectCache
{
    private readonly PdfObjectWriter _writer;
    private readonly Dictionary<string, string> _sourceToName = new(StringComparer.Ordinal);
    private readonly Dictionary<string, int> _nameToObjNum = [];
    private int _counter;

    public ImageObjectCache(PdfObjectWriter writer)
    {
        _writer = writer;
    }

    /// <summary>Gets or creates a PDF image XObject for the given source.</summary>
    /// <returns>Image resource name (e.g., "Img1"), or null if image is invalid.</returns>
    public string? GetOrAdd(string source)
    {
        if (_sourceToName.TryGetValue(source, out string? existing))
        {
            return existing;
        }

        ImageData? img = ImageData.Parse(source);
        if (img is null)
        {
            return null;
        }

        _counter++;
        string name = $"Img{_counter}";
        int objNum = _writer.AllocateObject();

        WriteImageXObject(objNum, img);

        _sourceToName[source] = name;
        _nameToObjNum[name] = objNum;
        return name;
    }

    /// <summary>Gets the PDF object number for a named image.</summary>
    public bool TryGetObjectNum(string name, out int objNum)
    {
        return _nameToObjNum.TryGetValue(name, out objNum);
    }

    private void WriteImageXObject(int objNum, ImageData img)
    {
        if (img.Format == ImageFormat.Jpeg)
        {
            WriteJpegXObject(objNum, img);
        }
        else if (img.Format == ImageFormat.Png)
        {
            WritePngXObject(objNum, img);
        }
    }

    private void WriteJpegXObject(int objNum, ImageData img)
    {
        // JPEG: embed raw bytes with DCTDecode
        string colorSpace = img.Components switch
        {
            1 => "/DeviceGray",
            4 => "/DeviceCMYK",
            _ => "/DeviceRGB",
        };

        string dict = $"/Type /XObject /Subtype /Image /Width {img.Width} /Height {img.Height} " +
                       $"/ColorSpace {colorSpace} /BitsPerComponent {img.BitsPerComponent} /Filter /DCTDecode";

        _writer.WriteStreamObject(objNum, dict, img.Data);
    }

    private void WritePngXObject(int objNum, ImageData img)
    {
        // PNG: decompress IDAT chunks, strip alpha, re-compress as raw RGB with FlateDecode
        byte[] rawPixels = DecodePngPixels(img);
        if (rawPixels.Length == 0)
        {
            return;
        }

        // Strip alpha channel if present (RGBA → RGB, Gray+Alpha → Gray)
        byte[] rgbData;
        int pdfComponents;

        if (img.Components == 4) // RGBA
        {
            pdfComponents = 3;
            rgbData = StripAlpha(rawPixels, img.Width, img.Height, 4, 3);
        }
        else if (img.Components == 2) // Grayscale+Alpha
        {
            pdfComponents = 1;
            rgbData = StripAlpha(rawPixels, img.Width, img.Height, 2, 1);
        }
        else
        {
            pdfComponents = img.Components;
            rgbData = rawPixels;
        }

        // Re-compress with deflate
        byte[] compressed = Deflate(rgbData);

        string colorSpace = pdfComponents switch
        {
            1 => "/DeviceGray",
            _ => "/DeviceRGB",
        };

        string dict = $"/Type /XObject /Subtype /Image /Width {img.Width} /Height {img.Height} " +
                       $"/ColorSpace {colorSpace} /BitsPerComponent 8 /Filter /FlateDecode";

        _writer.WriteStreamObject(objNum, dict, compressed);
    }

    private static byte[] DecodePngPixels(ImageData img)
    {
        // Guard against integer overflow on large images (max ~100 MP)
        const long MaxPixelBytes = 100_000_000L;
        long totalPixelBytes = (long)img.Width * img.Height * img.Components * (img.BitsPerComponent / 8);
        if (totalPixelBytes > MaxPixelBytes || totalPixelBytes <= 0)
        {
            return [];
        }

        // Concatenate all IDAT chunk data
        byte[] idatData = ExtractIdatData(img.Data);
        if (idatData.Length == 0)
        {
            return [];
        }

        // Decompress (zlib: 2-byte header + deflate data)
        byte[] decompressed;
        try
        {
            using var input = new MemoryStream(idatData);
            // Skip zlib header (2 bytes)
            input.ReadByte();
            input.ReadByte();
            using var deflate = new DeflateStream(input, CompressionMode.Decompress);
            using var output = new MemoryStream();
            deflate.CopyTo(output);
            decompressed = output.ToArray();
        }
        catch
        {
            return [];
        }

        // Remove PNG row filters (filter byte at start of each row)
        int bytesPerPixel = img.Components * (img.BitsPerComponent / 8);
        int stride = img.Width * bytesPerPixel;
        int filteredStride = stride + 1; // +1 for filter byte

        if (decompressed.Length < filteredStride * img.Height)
        {
            return [];
        }

        byte[] pixels = new byte[stride * img.Height];
        byte[] prevRow = new byte[stride];

        for (int row = 0; row < img.Height; row++)
        {
            int srcOffset = row * filteredStride;
            int dstOffset = row * stride;
            byte filterType = decompressed[srcOffset];
            srcOffset++; // skip filter byte

            for (int x = 0; x < stride; x++)
            {
                byte raw = decompressed[srcOffset + x];
                byte a = x >= bytesPerPixel ? pixels[dstOffset + x - bytesPerPixel] : (byte)0;
                byte b = prevRow[x];
                byte c = x >= bytesPerPixel ? prevRow[x - bytesPerPixel] : (byte)0;

                pixels[dstOffset + x] = filterType switch
                {
                    0 => raw,                    // None
                    1 => (byte)(raw + a),        // Sub
                    2 => (byte)(raw + b),        // Up
                    3 => (byte)(raw + (a + b) / 2), // Average
                    4 => (byte)(raw + PaethPredictor(a, b, c)), // Paeth
                    _ => raw,
                };
            }

            // Save current row as previous for next iteration
            Array.Copy(pixels, dstOffset, prevRow, 0, stride);
        }

        return pixels;
    }

    private static byte[] ExtractIdatData(byte[] png)
    {
        using var ms = new MemoryStream();
        int offset = 8; // skip PNG signature

        while (offset + 8 <= png.Length)
        {
            int chunkLen = (png[offset] << 24) | (png[offset + 1] << 16) |
                           (png[offset + 2] << 8) | png[offset + 3];
            if (chunkLen < 0)
            {
                break;
            }

            string chunkType = System.Text.Encoding.ASCII.GetString(png, offset + 4, 4);

            offset += 8; // past length + type

            if (offset + chunkLen > png.Length)
            {
                break;
            }

            if (chunkType == "IDAT")
            {
                ms.Write(png, offset, chunkLen);
            }
            else if (chunkType == "IEND")
            {
                break;
            }

            offset += chunkLen + 4; // data + CRC
        }

        return ms.ToArray();
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

    private static byte[] StripAlpha(byte[] data, int width, int height, int srcComponents, int dstComponents)
    {
        byte[] result = new byte[width * height * dstComponents];
        int srcStride = width * srcComponents;
        int dstStride = width * dstComponents;

        for (int row = 0; row < height; row++)
        {
            for (int col = 0; col < width; col++)
            {
                int srcIdx = row * srcStride + col * srcComponents;
                int dstIdx = row * dstStride + col * dstComponents;

                for (int ch = 0; ch < dstComponents; ch++)
                {
                    result[dstIdx + ch] = data[srcIdx + ch];
                }
            }
        }

        return result;
    }

    private static byte[] Deflate(byte[] data)
    {
        using var output = new MemoryStream();
        using (var deflate = new DeflateStream(output, CompressionLevel.Optimal, leaveOpen: true))
        {
            deflate.Write(data, 0, data.Length);
        }

        return output.ToArray();
    }
}
