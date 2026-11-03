// Licensed to SimpleSign under the MIT License.

using System.Buffers.Binary;
using System.IO.Compression;

namespace SimpleSign.HtmlToPdf.Rendering;

/// <summary>Decoded PNG pixels as 8-bit color samples plus an optional 8-bit alpha plane.</summary>
/// <param name="Width">Width in pixels.</param>
/// <param name="Height">Height in pixels.</param>
/// <param name="Color">Color samples (1 component for gray, 3 for RGB) per pixel.</param>
/// <param name="ColorComponents">1 for grayscale, 3 for RGB.</param>
/// <param name="Alpha">Alpha samples per pixel, or null when the image is fully opaque.</param>
internal sealed record DecodedPng(int Width, int Height, byte[] Color, int ColorComponents, byte[]? Alpha);

/// <summary>
/// Minimal, dependency-free PNG decoder: all color types (gray, RGB, palette, gray+alpha, RGBA),
/// bit depths 1–16, tRNS transparency, and Adam7 interlacing.
/// </summary>
internal static class PngDecoder
{
    private const long MaxPixels = 50_000_000L;

    private static readonly (int X0, int Y0, int Dx, int Dy)[] Adam7 =
    [
        (0, 0, 8, 8), (4, 0, 8, 8), (0, 4, 4, 8), (2, 0, 4, 4), (0, 2, 2, 4), (1, 0, 2, 2), (0, 1, 1, 2),
    ];

    /// <summary>Decodes a PNG file. Returns null for malformed or unsupported data.</summary>
    internal static DecodedPng? Decode(byte[] png)
    {
        try
        {
            return DecodeCore(png);
        }
        catch (Exception ex) when (ex is InvalidDataException or IndexOutOfRangeException or ArgumentException or OverflowException)
        {
            return null;
        }
    }

    private static DecodedPng? DecodeCore(byte[] png)
    {
        if (png.Length < 33)
        {
            return null;
        }

        int width = 0, height = 0, bitDepth = 0, colorType = 0, interlace = 0;
        byte[]? palette = null;
        byte[]? transparency = null;
        using var idat = new MemoryStream();

        int offset = 8;
        while (offset + 12 <= png.Length)
        {
            int length = BinaryPrimitives.ReadInt32BigEndian(png.AsSpan(offset));
            if (length < 0 || offset + 12 + length > png.Length)
            {
                break;
            }

            string type = System.Text.Encoding.ASCII.GetString(png, offset + 4, 4);
            ReadOnlySpan<byte> data = png.AsSpan(offset + 8, length);
            switch (type)
            {
                case "IHDR":
                    width = BinaryPrimitives.ReadInt32BigEndian(data);
                    height = BinaryPrimitives.ReadInt32BigEndian(data[4..]);
                    bitDepth = data[8];
                    colorType = data[9];
                    interlace = data[12];
                    break;
                case "PLTE":
                    palette = data.ToArray();
                    break;
                case "tRNS":
                    transparency = data.ToArray();
                    break;
                case "IDAT":
                    idat.Write(data);
                    break;
            }

            if (type == "IEND")
            {
                break;
            }

            offset += 12 + length;
        }

        if (width <= 0 || height <= 0 || (long)width * height > MaxPixels || bitDepth is not (1 or 2 or 4 or 8 or 16))
        {
            return null;
        }

        int channels = colorType switch
        {
            0 => 1,
            2 => 3,
            3 => 1,
            4 => 2,
            6 => 4,
            _ => 0,
        };
        if (channels == 0 || (colorType == 3 && palette is null))
        {
            return null;
        }

        byte[] raw;
        idat.Position = 0;
        using (var zlib = new ZLibStream(idat, CompressionMode.Decompress))
        using (var output = new MemoryStream())
        {
            zlib.CopyTo(output);
            raw = output.ToArray();
        }

        int bitsPerPixel = channels * bitDepth;
        int bytesPerPixel = Math.Max(1, bitsPerPixel / 8);

        // Samples normalized to 8 bits per channel, in source channel layout.
        byte[] samples = new byte[width * height * channels];
        int position = 0;
        if (interlace == 0)
        {
            position = DecodePass(raw, position, width, height, channels, bitDepth, bytesPerPixel, samples, width, 0, 0, 1, 1);
        }
        else
        {
            foreach (var (x0, y0, dx, dy) in Adam7)
            {
                int passWidth = (width - x0 + dx - 1) / dx;
                int passHeight = (height - y0 + dy - 1) / dy;
                if (passWidth <= 0 || passHeight <= 0)
                {
                    continue;
                }

                position = DecodePass(raw, position, passWidth, passHeight, channels, bitDepth, bytesPerPixel, samples, width, x0, y0, dx, dy);
            }
        }

        return Convert(samples, width, height, colorType, bitDepth, palette, transparency);
    }

    private static int DecodePass(byte[] raw, int position, int width, int height, int channels, int bitDepth,
        int bytesPerPixel, byte[] samples, int imageWidth, int x0, int y0, int dx, int dy)
    {
        int stride = ((width * channels * bitDepth) + 7) / 8;
        byte[] previous = new byte[stride];
        byte[] current = new byte[stride];
        for (int row = 0; row < height; row++)
        {
            if (position + 1 + stride > raw.Length)
            {
                throw new InvalidDataException("Truncated PNG image data.");
            }

            byte filter = raw[position++];
            for (int i = 0; i < stride; i++)
            {
                byte x = raw[position + i];
                byte a = i >= bytesPerPixel ? current[i - bytesPerPixel] : (byte)0;
                byte b = previous[i];
                byte c = i >= bytesPerPixel ? previous[i - bytesPerPixel] : (byte)0;
                current[i] = filter switch
                {
                    1 => (byte)(x + a),
                    2 => (byte)(x + b),
                    3 => (byte)(x + ((a + b) >> 1)),
                    4 => (byte)(x + Paeth(a, b, c)),
                    _ => x,
                };
            }

            position += stride;
            int y = y0 + (row * dy);
            for (int col = 0; col < width; col++)
            {
                int x = x0 + (col * dx);
                int target = ((y * imageWidth) + x) * channels;
                for (int ch = 0; ch < channels; ch++)
                {
                    samples[target + ch] = ReadSample(current, (col * channels) + ch, bitDepth);
                }
            }

            (previous, current) = (current, previous);
        }

        return position;
    }

    /// <summary>Reads one sample; values below 8 bits are returned unscaled (palette indexes) and scaled later.</summary>
    private static byte ReadSample(byte[] row, int index, int bitDepth)
    {
        switch (bitDepth)
        {
            case 8:
                return row[index];
            case 16:
                return row[index * 2];
            default:
                int bitOffset = index * bitDepth;
                int shift = 8 - bitDepth - (bitOffset % 8);
                return (byte)((row[bitOffset / 8] >> shift) & ((1 << bitDepth) - 1));
        }
    }

    private static DecodedPng Convert(byte[] samples, int width, int height, int colorType, int bitDepth, byte[]? palette, byte[]? trns)
    {
        int pixels = width * height;
        int maxLow = (1 << bitDepth) - 1;
        byte Scale(byte v) => bitDepth < 8 ? (byte)(v * 255 / maxLow) : v;

        switch (colorType)
        {
            case 0:
                {
                    byte[] gray = new byte[pixels];
                    byte[]? alpha = null;
                    int transparentGray = trns is { Length: >= 2 } ? BinaryPrimitives.ReadUInt16BigEndian(trns) : -1;
                    if (bitDepth == 16 && transparentGray >= 0)
                    {
                        transparentGray >>= 8;
                    }

                    for (int i = 0; i < pixels; i++)
                    {
                        gray[i] = Scale(samples[i]);
                        if (transparentGray >= 0 && samples[i] == transparentGray)
                        {
                            alpha ??= Filled(pixels);
                            alpha[i] = 0;
                        }
                    }

                    return new DecodedPng(width, height, gray, 1, alpha);
                }

            case 2:
                {
                    byte[]? alpha = null;
                    if (trns is { Length: >= 6 })
                    {
                        int shift = bitDepth == 16 ? 8 : 0;
                        int tr = BinaryPrimitives.ReadUInt16BigEndian(trns) >> shift;
                        int tg = BinaryPrimitives.ReadUInt16BigEndian(trns.AsSpan(2)) >> shift;
                        int tb = BinaryPrimitives.ReadUInt16BigEndian(trns.AsSpan(4)) >> shift;
                        for (int i = 0; i < pixels; i++)
                        {
                            if (samples[i * 3] == tr && samples[(i * 3) + 1] == tg && samples[(i * 3) + 2] == tb)
                            {
                                alpha ??= Filled(pixels);
                                alpha[i] = 0;
                            }
                        }
                    }

                    return new DecodedPng(width, height, samples, 3, alpha);
                }

            case 3:
                {
                    byte[] rgb = new byte[pixels * 3];
                    byte[]? alpha = null;
                    int entries = palette!.Length / 3;
                    for (int i = 0; i < pixels; i++)
                    {
                        int index = samples[i];
                        if (index < entries)
                        {
                            rgb[i * 3] = palette[index * 3];
                            rgb[(i * 3) + 1] = palette[(index * 3) + 1];
                            rgb[(i * 3) + 2] = palette[(index * 3) + 2];
                        }

                        if (trns is not null && index < trns.Length && trns[index] != 255)
                        {
                            alpha ??= Filled(pixels);
                            alpha[i] = trns[index];
                        }
                    }

                    return new DecodedPng(width, height, rgb, 3, alpha);
                }

            case 4:
                {
                    byte[] gray = new byte[pixels];
                    byte[] alpha = new byte[pixels];
                    bool translucent = false;
                    for (int i = 0; i < pixels; i++)
                    {
                        gray[i] = samples[i * 2];
                        alpha[i] = samples[(i * 2) + 1];
                        translucent |= alpha[i] != 255;
                    }

                    return new DecodedPng(width, height, gray, 1, translucent ? alpha : null);
                }

            default:
                {
                    byte[] rgb = new byte[pixels * 3];
                    byte[] alpha = new byte[pixels];
                    bool translucent = false;
                    for (int i = 0; i < pixels; i++)
                    {
                        rgb[i * 3] = samples[i * 4];
                        rgb[(i * 3) + 1] = samples[(i * 4) + 1];
                        rgb[(i * 3) + 2] = samples[(i * 4) + 2];
                        alpha[i] = samples[(i * 4) + 3];
                        translucent |= alpha[i] != 255;
                    }

                    return new DecodedPng(width, height, rgb, 3, translucent ? alpha : null);
                }
        }
    }

    private static byte[] Filled(int length)
    {
        byte[] alpha = new byte[length];
        Array.Fill(alpha, (byte)255);
        return alpha;
    }

    private static byte Paeth(byte a, byte b, byte c)
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
}
