using System.Buffers.Binary;
using System.IO.Compression;
using System.Text;

namespace SimpleSign.PAdES.Signing;

/// <summary>
/// Background image of a signature stamp, converted to PDF image XObjects.
/// JPEG data is embedded as-is (DCTDecode). PNG data is embedded as-is (FlateDecode with PNG
/// predictors) when it has no transparency; images with an alpha channel or a palette
/// transparency chunk are decoded, and the alpha values go to a separate soft mask image.
/// </summary>
internal sealed class AppearanceImage
{
    private const int MaxDimension = 10_000;
    private const long MaxPixels = 25_000_000;

    private readonly string _imageDict;
    private readonly byte[] _imageData;
    private readonly byte[]? _softMaskData;

    private AppearanceImage(int width, int height, string imageDict, byte[] imageData, byte[]? softMaskData)
    {
        PixelWidth = width;
        PixelHeight = height;
        _imageDict = imageDict;
        _imageData = imageData;
        _softMaskData = softMaskData;
    }

    /// <summary>Image width in pixels.</summary>
    public int PixelWidth { get; }

    /// <summary>Image height in pixels.</summary>
    public int PixelHeight { get; }

    /// <summary>True when the image needs a soft mask object for its transparency.</summary>
    public bool HasSoftMask => _softMaskData is not null;

    /// <summary>Creates the image for an appearance, or returns null when it has no background image.</summary>
    /// <exception cref="ArgumentException">The PNG data is malformed.</exception>
    /// <exception cref="NotSupportedException">The PNG uses a format the stamp does not support.</exception>
    public static AppearanceImage? FromAppearance(SignatureAppearance appearance)
    {
        if (appearance.BackgroundImagePng is { Length: > 0 } png)
        {
            return FromPng(png.ToArray());
        }

        return appearance.BackgroundImageJpeg is { Length: > 0 } jpeg ? FromJpeg(jpeg.ToArray()) : null;
    }

    /// <summary>
    /// Returns true when PNG data has an alpha channel or a transparency chunk.
    /// Malformed data returns true, so callers treat it conservatively.
    /// </summary>
    public static bool PngHasTransparency(ReadOnlySpan<byte> png)
    {
        try
        {
            var chunks = ReadPngChunks(png.ToArray());
            return chunks.ColorType is 4 or 6 || chunks.Transparency is not null;
        }
        catch (ArgumentException)
        {
            return true;
        }
    }

    /// <summary>
    /// Writes the image object (and its soft mask object, when present) as indirect objects.
    /// The soft mask is omitted when <paramref name="softMaskObjNum"/> is 0.
    /// </summary>
    public byte[] BuildObjects(int imageObjNum, int softMaskObjNum)
    {
        bool withMask = _softMaskData is not null && softMaskObjNum > 0;
        using var ms = new MemoryStream();

        var dict = new StringBuilder();
        dict.Append($"{imageObjNum} 0 obj\n<< /Type /XObject\n   /Subtype /Image\n");
        dict.Append($"   /Width {PixelWidth}\n   /Height {PixelHeight}\n");
        dict.Append(_imageDict);
        if (withMask)
        {
            dict.Append($"   /SMask {softMaskObjNum} 0 R\n");
        }

        dict.Append($"   /Length {_imageData.Length}\n>>\nstream\n");
        WriteObject(ms, dict.ToString(), _imageData);

        if (withMask)
        {
            string maskDict =
                $"{softMaskObjNum} 0 obj\n<< /Type /XObject\n   /Subtype /Image\n" +
                $"   /Width {PixelWidth}\n   /Height {PixelHeight}\n" +
                "   /ColorSpace /DeviceGray\n   /BitsPerComponent 8\n   /Filter /FlateDecode\n" +
                $"   /Length {_softMaskData!.Length}\n>>\nstream\n";
            WriteObject(ms, maskDict, _softMaskData);
        }

        return ms.ToArray();
    }

    private static void WriteObject(MemoryStream ms, string header, byte[] data)
    {
        ms.Write(Encoding.Latin1.GetBytes(header));
        ms.Write(data);
        ms.Write("\nendstream\nendobj\n"u8);
    }

    // ── JPEG ────────────────────────────────────────────────────────────

    private static AppearanceImage FromJpeg(byte[] jpeg)
    {
        var info = ReadJpegInfo(jpeg);
        string colorSpace = info.Components switch
        {
            1 => "/DeviceGray",
            4 => "/DeviceCMYK",
            _ => "/DeviceRGB",
        };

        var dict = new StringBuilder();
        dict.Append($"   /ColorSpace {colorSpace}\n   /BitsPerComponent 8\n");

        // Adobe CMYK JPEGs store inverted values (APP14 "Adobe" marker).
        if (info.Components == 4 && info.Adobe)
        {
            dict.Append("   /Decode [1 0 1 0 1 0 1 0]\n");
        }

        dict.Append("   /Filter /DCTDecode\n");
        return new AppearanceImage(info.Width, info.Height, dict.ToString(), jpeg, null);
    }

    /// <summary>
    /// Reads dimensions and component count by walking the JPEG marker segments.
    /// Returns a 1×1 RGB image description when the data cannot be parsed.
    /// </summary>
    internal static (int Width, int Height, int Components, bool Adobe) ReadJpegInfo(ReadOnlySpan<byte> jpeg)
    {
        (int, int, int, bool) fallback = (1, 1, 3, false);
        if (jpeg.Length < 4 || jpeg[0] != 0xFF || jpeg[1] != 0xD8)
        {
            return fallback;
        }

        bool adobe = false;
        int pos = 2;
        while (pos + 4 <= jpeg.Length)
        {
            if (jpeg[pos] != 0xFF)
            {
                return fallback;
            }

            byte marker = jpeg[pos + 1];
            if (marker == 0xFF)
            {
                pos++; // fill byte
                continue;
            }

            pos += 2;
            if (marker is 0x01 or (>= 0xD0 and <= 0xD7))
            {
                continue; // markers without a length
            }

            if (marker is 0xD9 or 0xDA)
            {
                break; // end of image / start of scan: no frame header found before it
            }

            int length = BinaryPrimitives.ReadUInt16BigEndian(jpeg[pos..]);
            if (length < 2 || pos + length > jpeg.Length)
            {
                return fallback;
            }

            var segment = jpeg.Slice(pos + 2, length - 2);
            if (marker == 0xEE && segment.Length >= 5 && segment[..5].SequenceEqual("Adobe"u8))
            {
                adobe = true;
            }
            else if (marker is >= 0xC0 and <= 0xCF and not 0xC4 and not 0xC8 and not 0xCC && segment.Length >= 6)
            {
                int height = BinaryPrimitives.ReadUInt16BigEndian(segment[1..]);
                int width = BinaryPrimitives.ReadUInt16BigEndian(segment[3..]);
                int components = segment[5];
                return width > 0 && height > 0 ? (width, height, components, adobe) : fallback;
            }

            pos += length;
        }

        return fallback;
    }

    // ── PNG ─────────────────────────────────────────────────────────────

    private sealed record PngChunks(
        int Width, int Height, byte BitDepth, byte ColorType, byte Interlace,
        byte[]? Palette, byte[]? Transparency, byte[] Data);

    private static AppearanceImage FromPng(byte[] pngBytes)
    {
        var png = ReadPngChunks(pngBytes);

        if (png.Interlace != 0)
        {
            throw new NotSupportedException("Interlaced PNG is not supported for signature appearance.");
        }

        if (png.Width > MaxDimension || png.Height > MaxDimension || (long)png.Width * png.Height > MaxPixels)
        {
            throw new NotSupportedException($"PNG images larger than {MaxDimension}x{MaxDimension} or {MaxPixels} pixels are not supported for signature appearance.");
        }

        return png.ColorType switch
        {
            0 or 2 => FromOpaquePng(png),
            3 => FromPalettePng(png),
            4 or 6 => FromAlphaPng(png),
            _ => throw new NotSupportedException($"PNG color type {png.ColorType} is not supported for signature appearance."),
        };
    }

    private static AppearanceImage FromOpaquePng(PngChunks png)
    {
        RequireBitDepth8(png);
        int colors = png.ColorType == 2 ? 3 : 1;
        string colorSpace = png.ColorType == 2 ? "/DeviceRGB" : "/DeviceGray";
        string dict =
            $"   /ColorSpace {colorSpace}\n   /BitsPerComponent 8\n   /Filter /FlateDecode\n" +
            $"   /DecodeParms << /Predictor 15 /Colors {colors} /BitsPerComponent 8 /Columns {png.Width} >>\n";
        return new AppearanceImage(png.Width, png.Height, dict, png.Data, null);
    }

    private static AppearanceImage FromPalettePng(PngChunks png)
    {
        if (png.BitDepth is not (1 or 2 or 4 or 8))
        {
            throw new ArgumentException("PNG palette image has an invalid bit depth.");
        }

        if (png.Palette is not { Length: >= 3 } palette || palette.Length % 3 != 0)
        {
            throw new ArgumentException("PNG palette image is missing its PLTE chunk.");
        }

        int entries = palette.Length / 3;
        string dict =
            $"   /ColorSpace [/Indexed /DeviceRGB {entries - 1} <{Convert.ToHexString(palette)}>]\n" +
            $"   /BitsPerComponent {png.BitDepth}\n   /Filter /FlateDecode\n" +
            $"   /DecodeParms << /Predictor 15 /Colors 1 /BitsPerComponent {png.BitDepth} /Columns {png.Width} >>\n";

        byte[]? mask = null;
        if (png.Transparency is { Length: > 0 } trns)
        {
            byte[] raw = Unfilter(png, bitsPerPixel: png.BitDepth);
            int rowBytes = RowBytes(png.Width, png.BitDepth);
            byte[] alpha = new byte[png.Width * png.Height];
            int mask8 = (1 << png.BitDepth) - 1;
            for (int y = 0; y < png.Height; y++)
            {
                int row = y * rowBytes;
                for (int x = 0; x < png.Width; x++)
                {
                    int bit = x * png.BitDepth;
                    int index = (raw[row + (bit >> 3)] >> (8 - png.BitDepth - (bit & 7))) & mask8;
                    alpha[(y * png.Width) + x] = index < trns.Length ? trns[index] : (byte)255;
                }
            }

            mask = Deflate(alpha);
        }

        return new AppearanceImage(png.Width, png.Height, dict, png.Data, mask);
    }

    private static AppearanceImage FromAlphaPng(PngChunks png)
    {
        RequireBitDepth8(png);
        int colors = png.ColorType == 6 ? 3 : 1;
        int channels = colors + 1;
        byte[] raw = Unfilter(png, bitsPerPixel: 8 * channels);
        int pixels = png.Width * png.Height;
        byte[] color = new byte[pixels * colors];
        byte[] alpha = new byte[pixels];
        for (int p = 0, src = 0; p < pixels; p++)
        {
            for (int c = 0; c < colors; c++)
            {
                color[(p * colors) + c] = raw[src++];
            }

            alpha[p] = raw[src++];
        }

        string colorSpace = colors == 3 ? "/DeviceRGB" : "/DeviceGray";
        string dict = $"   /ColorSpace {colorSpace}\n   /BitsPerComponent 8\n   /Filter /FlateDecode\n";
        return new AppearanceImage(png.Width, png.Height, dict, Deflate(color), Deflate(alpha));
    }

    private static void RequireBitDepth8(PngChunks png)
    {
        if (png.BitDepth != 8)
        {
            throw new NotSupportedException("Only 8-bit PNG is supported for signature appearance (palette images may use 1, 2, 4 or 8 bits).");
        }
    }

    private static PngChunks ReadPngChunks(byte[] pngBytes)
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
        byte[]? palette = null;
        byte[]? transparency = null;
        using var idat = new MemoryStream();

        while (offset + 12 <= pngBytes.Length)
        {
            int length = BinaryPrimitives.ReadInt32BigEndian(pngBytes.AsSpan(offset));
            offset += 4;
            string chunkType = Encoding.ASCII.GetString(pngBytes, offset, 4);
            offset += 4;
            if (length < 0 || offset + (long)length + 4 > pngBytes.Length)
            {
                break;
            }

            ReadOnlySpan<byte> chunkData = pngBytes.AsSpan(offset, length);
            offset += length + 4; // data + CRC

            switch (chunkType)
            {
                case "IHDR":
                    if (length < 13)
                    {
                        throw new ArgumentException("PNG IHDR chunk is invalid.", nameof(pngBytes));
                    }

                    width = BinaryPrimitives.ReadInt32BigEndian(chunkData);
                    height = BinaryPrimitives.ReadInt32BigEndian(chunkData[4..]);
                    bitDepth = chunkData[8];
                    colorType = chunkData[9];
                    interlace = chunkData[12];
                    break;
                case "PLTE":
                    palette = chunkData.ToArray();
                    break;
                case "tRNS":
                    transparency = chunkData.ToArray();
                    break;
                case "IDAT":
                    idat.Write(chunkData);
                    break;
                default:
                    break;
            }

            if (chunkType == "IEND")
            {
                break;
            }
        }

        if (width <= 0 || height <= 0 || idat.Length == 0)
        {
            throw new ArgumentException("PNG is missing required chunks (IHDR/IDAT).", nameof(pngBytes));
        }

        // A tRNS chunk on grayscale/RGB images is a color key; it is ignored (image stays opaque).
        if (colorType is 0 or 2)
        {
            transparency = null;
        }

        return new PngChunks(width, height, bitDepth, colorType, interlace, palette, transparency, idat.ToArray());
    }

    private static int RowBytes(int width, int bitsPerPixel) => (int)(((long)width * bitsPerPixel + 7) / 8);

    /// <summary>Inflates the IDAT data and reverses the PNG row filters (ISO/IEC 15948 §9).</summary>
    private static byte[] Unfilter(PngChunks png, int bitsPerPixel)
    {
        int rowBytes = RowBytes(png.Width, bitsPerPixel);
        int bpp = Math.Max(1, bitsPerPixel / 8);
        byte[] filtered = new byte[(long)png.Height * (rowBytes + 1)];

        using (var input = new MemoryStream(png.Data))
        using (var zlib = new ZLibStream(input, CompressionMode.Decompress))
        {
            int read;
            try
            {
                read = zlib.ReadAtLeast(filtered, filtered.Length, throwOnEndOfStream: false);
            }
            catch (InvalidDataException ex)
            {
                throw new ArgumentException("PNG image data is corrupt.", nameof(png), ex);
            }

            if (read < filtered.Length)
            {
                throw new ArgumentException("PNG image data is truncated.", nameof(png));
            }
        }

        byte[] raw = new byte[(long)png.Height * rowBytes];
        for (int y = 0; y < png.Height; y++)
        {
            int filter = filtered[y * (rowBytes + 1)];
            int src = (y * (rowBytes + 1)) + 1;
            int dst = y * rowBytes;
            int prev = dst - rowBytes;
            for (int i = 0; i < rowBytes; i++)
            {
                int a = i >= bpp ? raw[dst + i - bpp] : 0;
                int b = y > 0 ? raw[prev + i] : 0;
                int c = i >= bpp && y > 0 ? raw[prev + i - bpp] : 0;
                int x = filtered[src + i];
                raw[dst + i] = filter switch
                {
                    0 => (byte)x,
                    1 => (byte)(x + a),
                    2 => (byte)(x + b),
                    3 => (byte)(x + ((a + b) >> 1)),
                    4 => (byte)(x + Paeth(a, b, c)),
                    _ => throw new ArgumentException($"PNG row filter {filter} is invalid.", nameof(png)),
                };
            }
        }

        return raw;
    }

    private static int Paeth(int a, int b, int c)
    {
        int p = a + b - c;
        int pa = Math.Abs(p - a);
        int pb = Math.Abs(p - b);
        int pc = Math.Abs(p - c);
        return pa <= pb && pa <= pc ? a : pb <= pc ? b : c;
    }

    private static byte[] Deflate(byte[] data)
    {
        using var ms = new MemoryStream();
        using (var zlib = new ZLibStream(ms, CompressionLevel.Optimal))
        {
            zlib.Write(data);
        }

        return ms.ToArray();
    }
}
