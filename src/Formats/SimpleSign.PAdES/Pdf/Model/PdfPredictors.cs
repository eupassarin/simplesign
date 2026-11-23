namespace SimpleSign.PAdES.Pdf.Model;

/// <summary>
/// The predictors of <c>FlateDecode</c> and <c>LZWDecode</c> (ISO 32000-1 §7.4.4.4): TIFF predictor 2 and the
/// PNG predictors (10–15, every row tagged with its own PNG filter type: None, Sub, Up, Average, Paeth;
/// ISO/IEC 15948 §9).
/// </summary>
/// <remarks>
/// A row is <c>ceil(Colors × BitsPerComponent × Columns / 8)</c> bytes. A last row shorter than that (data cut
/// short) is decoded as far as it goes rather than dropped.
/// </remarks>
internal static class PdfPredictors
{
    /// <summary>Reverses the predictor <paramref name="decodeParams"/> names.</summary>
    /// <param name="data">The data the filter decoded (inflated); not changed.</param>
    /// <param name="decodeParams">The filter's decode parameters.</param>
    /// <param name="filterName">The filter the predictor belongs to, for the errors.</param>
    /// <returns>
    /// The samples: <paramref name="data"/> itself for predictor 1, a new array otherwise (for the PNG predictors,
    /// without the tag byte of each row).
    /// </returns>
    /// <exception cref="PdfFilterException">
    /// An unknown predictor, parameters out of range (Colors &lt; 1, BitsPerComponent not 1, 2, 4, 8 or 16,
    /// Columns &lt; 1, a row too long), or a PNG row tag other than 0–4.
    /// </exception>
    internal static byte[] Decode(byte[] data, PdfDecodeParams decodeParams, string filterName = PdfFilters.FlateDecode)
    {
        ArgumentNullException.ThrowIfNull(data);
        ArgumentNullException.ThrowIfNull(decodeParams);

        int predictor = decodeParams.Predictor;
        if (predictor == 1)
        {
            return data;
        }

        if (predictor != 2 && predictor is < 10 or > 15)
        {
            throw new PdfFilterException(filterName, $"/Predictor {predictor} is not defined.");
        }

        RowLayout layout = Layout(decodeParams, filterName);
        return predictor == 2
            ? DecodeTiff(data, decodeParams, layout)
            : DecodePng(data, layout, filterName);
    }

    /// <summary>
    /// PNG predictors: each row is one tag byte (the PNG filter type) and the row's bytes, each predicted from the
    /// byte one pixel to the left (<c>a</c>), the byte above (<c>b</c>) and the one above-left (<c>c</c>), all 0
    /// outside the image.
    /// </summary>
    private static byte[] DecodePng(byte[] data, RowLayout layout, string filterName)
    {
        int rowBytes = layout.RowBytes;
        int bpp = layout.BytesPerPixel;
        int stride = rowBytes + 1;
        int fullRows = data.Length / stride;
        int tail = data.Length % stride;
        byte[] output = new byte[(fullRows * rowBytes) + Math.Max(0, tail - 1)];

        int src = 0;
        int dst = 0;
        while (src < data.Length)
        {
            byte tag = data[src];
            int n = Math.Min(rowBytes, data.Length - src - 1);
            ReadOnlySpan<byte> raw = data.AsSpan(src + 1, n);
            Span<byte> row = output.AsSpan(dst, n);
            ReadOnlySpan<byte> up = dst == 0 ? default : output.AsSpan(dst - rowBytes, n);

            switch (tag)
            {
                case 0: // None
                    raw.CopyTo(row);
                    break;
                case 1: // Sub: + a
                    for (int i = 0; i < n; i++)
                    {
                        row[i] = (byte)(raw[i] + (i >= bpp ? row[i - bpp] : 0));
                    }

                    break;
                case 2: // Up: + b
                    for (int i = 0; i < n; i++)
                    {
                        row[i] = (byte)(raw[i] + (up.IsEmpty ? 0 : up[i]));
                    }

                    break;
                case 3: // Average: + floor((a + b) / 2)
                    for (int i = 0; i < n; i++)
                    {
                        int a = i >= bpp ? row[i - bpp] : 0;
                        int b = up.IsEmpty ? 0 : up[i];
                        row[i] = (byte)(raw[i] + ((a + b) >> 1));
                    }

                    break;
                case 4: // Paeth: + whichever of a, b, c is nearest to a + b − c
                    for (int i = 0; i < n; i++)
                    {
                        int a = i >= bpp ? row[i - bpp] : 0;
                        int b = up.IsEmpty ? 0 : up[i];
                        int c = i >= bpp && !up.IsEmpty ? up[i - bpp] : 0;
                        row[i] = (byte)(raw[i] + Paeth(a, b, c));
                    }

                    break;
                default:
                    throw new PdfFilterException(filterName, $"PNG row tag {tag} at offset {src} is not a PNG filter type (0-4).");
            }

            src += stride;
            dst += n;
        }

        return output;
    }

    /// <summary>The Paeth predictor of ISO/IEC 15948 §9.4, ties broken in the order a, b, c.</summary>
    private static int Paeth(int a, int b, int c)
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

    /// <summary>
    /// TIFF predictor 2 (TIFF 6.0 §14): every component of a pixel is the difference from the same component of
    /// the pixel to its left, modulo 2^BitsPerComponent; rows are independent.
    /// </summary>
    private static byte[] DecodeTiff(byte[] data, PdfDecodeParams decodeParams, RowLayout layout)
    {
        byte[] output = (byte[])data.Clone();
        int colors = decodeParams.Colors;
        int bpc = decodeParams.BitsPerComponent;
        long samplesPerRow = (long)colors * decodeParams.Columns;

        for (int start = 0; start < output.Length; start += layout.RowBytes)
        {
            Span<byte> row = output.AsSpan(start, Math.Min(layout.RowBytes, output.Length - start));
            switch (bpc)
            {
                case 8:
                    for (int i = colors; i < row.Length; i++)
                    {
                        row[i] += row[i - colors];
                    }

                    break;
                case 16:
                    for (int s = colors; s < row.Length / 2; s++)
                    {
                        int value = ((row[2 * s] << 8) | row[(2 * s) + 1]) + ((row[2 * (s - colors)] << 8) | row[(2 * (s - colors)) + 1]);
                        row[2 * s] = (byte)(value >> 8);
                        row[(2 * s) + 1] = (byte)value;
                    }

                    break;
                default: // 1, 2, 4: samples packed from the most significant bit
                    int samples = (int)Math.Min(samplesPerRow, row.Length * 8L / bpc);
                    int mask = (1 << bpc) - 1;
                    for (int s = colors; s < samples; s++)
                    {
                        WriteSample(row, s, bpc, (ReadSample(row, s, bpc) + ReadSample(row, s - colors, bpc)) & mask);
                    }

                    break;
            }
        }

        return output;
    }

    private static int ReadSample(ReadOnlySpan<byte> row, int index, int bpc)
    {
        int bit = index * bpc;
        int shift = 8 - bpc - (bit % 8);
        return (row[bit / 8] >> shift) & ((1 << bpc) - 1);
    }

    private static void WriteSample(Span<byte> row, int index, int bpc, int value)
    {
        int bit = index * bpc;
        int shift = 8 - bpc - (bit % 8);
        int mask = ((1 << bpc) - 1) << shift;
        row[bit / 8] = (byte)((row[bit / 8] & ~mask) | (value << shift));
    }

    private static RowLayout Layout(PdfDecodeParams p, string filterName)
    {
        if (p.Colors < 1)
        {
            throw new PdfFilterException(filterName, $"/Colors {p.Colors} is less than 1.");
        }

        if (p.BitsPerComponent is not (1 or 2 or 4 or 8 or 16))
        {
            throw new PdfFilterException(filterName, $"/BitsPerComponent {p.BitsPerComponent} is not 1, 2, 4, 8 or 16.");
        }

        if (p.Columns < 1)
        {
            throw new PdfFilterException(filterName, $"/Columns {p.Columns} is less than 1.");
        }

        long bitsPerPixel = (long)p.Colors * p.BitsPerComponent;
        if (bitsPerPixel > (int.MaxValue - 1L) * 8 / p.Columns)
        {
            throw new PdfFilterException(filterName, $"a row of {p.Columns} columns × {p.Colors} colours × {p.BitsPerComponent} bits is too long.");
        }

        long rowBytes = ((bitsPerPixel * p.Columns) + 7) / 8;
        return new RowLayout((int)rowBytes, (int)Math.Max(1, (bitsPerPixel + 7) / 8));
    }

    /// <summary>The bytes of a row, and of a pixel (at least 1: what the PNG filters step back by).</summary>
    private readonly record struct RowLayout(int RowBytes, int BytesPerPixel);
}
