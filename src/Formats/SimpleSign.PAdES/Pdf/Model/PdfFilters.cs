using System.IO.Compression;
using SimpleSign.Core.Constants;

namespace SimpleSign.PAdES.Pdf.Model;

/// <summary>
/// The decode parameters of one filter (ISO 32000-1 §7.4.4.4, Table 8 and §7.4.4.3, Table 9), as plain
/// values: a stream's <c>/DecodeParms</c> dictionary read by the object model, or the defaults when it has none.
/// </summary>
/// <remarks>
/// Only <c>FlateDecode</c> uses them here (<see cref="Predictor"/> and what describes a row);
/// <see cref="EarlyChange"/> belongs to <c>LZWDecode</c>, kept so the model can hand over every entry it knows.
/// </remarks>
internal sealed record PdfDecodeParams
{
    /// <summary>The parameters a filter has without <c>/DecodeParms</c>: no predictor.</summary>
    public static PdfDecodeParams Default { get; } = new();

    /// <summary><c>/Predictor</c>: 1 none, 2 TIFF predictor 2, 10–15 PNG predictors. Default 1.</summary>
    public int Predictor { get; init; } = 1;

    /// <summary><c>/Colors</c>: interleaved colour components per sample. Default 1.</summary>
    public int Colors { get; init; } = 1;

    /// <summary><c>/BitsPerComponent</c>: 1, 2, 4, 8 or 16. Default 8.</summary>
    public int BitsPerComponent { get; init; } = 8;

    /// <summary><c>/Columns</c>: samples in each row. Default 1.</summary>
    public int Columns { get; init; } = 1;

    /// <summary><c>/EarlyChange</c> (<c>LZWDecode</c> only): when the code length grows. Default 1.</summary>
    public int EarlyChange { get; init; } = 1;
}

/// <summary>
/// The standard stream filters of ISO 32000-1 §7.4 that carry the structure of a PDF (cross-reference and
/// object streams, metadata, embedded files, content): <c>FlateDecode</c> with its predictors,
/// <c>ASCII85Decode</c> and <c>ASCIIHexDecode</c>. Every other filter is refused with
/// <see cref="PdfUnsupportedFilterException"/>, before anything is decoded.
/// </summary>
/// <remarks>
/// <para>
/// Plain values in, bytes out: the filter names and their decode parameters as the object model reads them
/// (ADR 0032), with no dependency on the model's own types.
/// </para>
/// <para>
/// Every filter's output is held to <c>maxDecodedBytes</c> (<see cref="DefaultMaxDecodedBytes"/>, the limit
/// the old reader has always had), and inflating stops as soon as it is passed: a decompression bomb costs
/// at most that much memory. Corrupt data throws <see cref="PdfFilterException"/>; data that simply ends
/// early (a truncated deflate stream, an <c>ASCII85Decode</c> stream without its <c>~&gt;</c>) gives what was
/// decoded, as viewers do.
/// </para>
/// </remarks>
internal static class PdfFilters
{
    /// <summary>The most bytes one filter may produce unless the caller says otherwise: 50 MB.</summary>
    internal const int DefaultMaxDecodedBytes = 50 * 1024 * 1024;

    /// <summary><c>FlateDecode</c>: zlib/deflate (RFC 1950, RFC 1951), §7.4.4.</summary>
    internal const string FlateDecode = "FlateDecode";

    /// <summary><c>ASCII85Decode</c>: base-85, §7.4.3.</summary>
    internal const string Ascii85Decode = "ASCII85Decode";

    /// <summary><c>ASCIIHexDecode</c>: hexadecimal, §7.4.2.</summary>
    internal const string AsciiHexDecode = "ASCIIHexDecode";

    /// <summary><c>LZWDecode</c>, §7.4.4: not supported.</summary>
    internal const string LzwDecode = "LZWDecode";

    /// <summary><c>RunLengthDecode</c>, §7.4.5: not supported.</summary>
    internal const string RunLengthDecode = "RunLengthDecode";

    private const int CopyBufferSize = 16 * 1024;

    /// <summary>
    /// Decodes a stream's data through its filters, in order (the first filter of <c>/Filter</c> is applied first).
    /// </summary>
    /// <param name="data">The stream's encoded bytes.</param>
    /// <param name="filters">
    /// The filter names, without the leading slash (<c>FlateDecode</c>; the inline-image abbreviations <c>Fl</c>,
    /// <c>A85</c>, <c>AHx</c>… are accepted too). Empty: the data is returned as it is.
    /// </param>
    /// <param name="decodeParams">
    /// The decode parameters of each filter, by position; a missing or <see langword="null"/> entry means the defaults.
    /// </param>
    /// <param name="maxDecodedBytes">The most bytes any one filter may produce.</param>
    /// <returns>The decoded bytes (a new array).</returns>
    /// <exception cref="PdfUnsupportedFilterException">One of the filters is not supported; nothing was decoded.</exception>
    /// <exception cref="PdfDecodedSizeLimitException">A filter's output went over <paramref name="maxDecodedBytes"/>.</exception>
    /// <exception cref="PdfFilterException">The data is corrupt for one of the filters.</exception>
    internal static byte[] Decode(
        ReadOnlySpan<byte> data,
        IReadOnlyList<string> filters,
        IReadOnlyList<PdfDecodeParams?>? decodeParams = null,
        int maxDecodedBytes = DefaultMaxDecodedBytes)
    {
        ArgumentNullException.ThrowIfNull(filters);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maxDecodedBytes);

        var canonical = new string[filters.Count];
        for (int i = 0; i < filters.Count; i++)
        {
            string name = filters[i];
            canonical[i] = CanonicalName(name) ?? throw new PdfUnsupportedFilterException(name);
        }

        if (canonical.Length == 0)
        {
            return data.ToArray();
        }

        byte[] current = [];
        ReadOnlySpan<byte> input = data;
        for (int i = 0; i < canonical.Length; i++)
        {
            PdfDecodeParams? parms = decodeParams is not null && i < decodeParams.Count ? decodeParams[i] : null;
            current = canonical[i] switch
            {
                FlateDecode => DecodeFlate(input, parms, maxDecodedBytes),
                Ascii85Decode => DecodeAscii85(input, maxDecodedBytes),
                _ => DecodeAsciiHex(input, maxDecodedBytes),
            };
            input = current;
        }

        return current;
    }

    /// <summary>
    /// Whether <see cref="Decode"/> can decode a filter of this name (abbreviations accepted).
    /// </summary>
    /// <param name="filterName">The filter name, without the leading slash.</param>
    internal static bool IsSupported(string filterName) => CanonicalName(filterName) is not null;

    /// <summary>
    /// <c>FlateDecode</c> followed by the predictor its parameters name (<see cref="PdfPredictors"/>).
    /// </summary>
    /// <param name="data">The compressed bytes.</param>
    /// <param name="decodeParams">The filter's decode parameters, or <see langword="null"/> for none.</param>
    /// <param name="maxDecodedBytes">The most bytes inflating may produce.</param>
    /// <returns>The decoded bytes.</returns>
    internal static byte[] DecodeFlate(ReadOnlySpan<byte> data, PdfDecodeParams? decodeParams, int maxDecodedBytes = DefaultMaxDecodedBytes)
    {
        byte[] inflated = Inflate(data, maxDecodedBytes);
        return decodeParams is null || decodeParams.Predictor == 1
            ? inflated
            : PdfPredictors.Decode(inflated, decodeParams, FlateDecode);
    }

    /// <summary>
    /// Inflates zlib data (RFC 1950): the two-byte header (six with a preset dictionary) is checked and skipped and the
    /// deflate data after it inflated; the Adler-32 checksum is not checked, as by viewers.
    /// </summary>
    /// <param name="data">The zlib bytes.</param>
    /// <param name="maxDecodedBytes">The most bytes inflating may produce; it stops as soon as it would pass them.</param>
    /// <returns>The inflated bytes; empty for empty input or a header alone. A truncated stream gives what was inflated.</returns>
    /// <exception cref="PdfDecodedSizeLimitException">The output would go over <paramref name="maxDecodedBytes"/>.</exception>
    /// <exception cref="PdfFilterException">A lone header byte, a header that is not zlib's, or corrupt deflate data.</exception>
    internal static byte[] Inflate(ReadOnlySpan<byte> data, int maxDecodedBytes = DefaultMaxDecodedBytes)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maxDecodedBytes);
        if (data.IsEmpty)
        {
            return [];
        }

        if (data.Length < 2)
        {
            throw new PdfFilterException(FlateDecode, "the zlib header is truncated.");
        }

        // RFC 1950 §2.2: compression method 8 (deflate), and CMF·256 + FLG a multiple of 31.
        if ((data[0] & 0x0F) != 8 || ((data[0] << 8) | data[1]) % 31 != 0)
        {
            throw new PdfFilterException(FlateDecode, $"0x{data[0]:X2}{data[1]:X2} is not a zlib header.");
        }

        int headerSize = (data[1] & Asn1Tags.ZlibFdictMask) != 0 ? 6 : 2;
        if (data.Length <= headerSize)
        {
            return [];
        }

        using var input = new MemoryStream(data[headerSize..].ToArray(), writable: false);
        using var deflate = new DeflateStream(input, CompressionMode.Decompress);
        using var output = new MemoryStream();
        byte[] buffer = new byte[CopyBufferSize];
        try
        {
            int read;
            while ((read = deflate.Read(buffer, 0, buffer.Length)) > 0)
            {
                if (output.Length + read > maxDecodedBytes)
                {
                    throw new PdfDecodedSizeLimitException(FlateDecode, maxDecodedBytes);
                }

                output.Write(buffer, 0, read);
            }
        }
        catch (InvalidDataException ex)
        {
            throw new PdfFilterException(FlateDecode, "the deflate data is corrupt.", ex);
        }

        return output.ToArray();
    }

    /// <summary>
    /// <c>ASCII85Decode</c> (§7.4.3): white-space ignored, <c>z</c> for four zero bytes, a final partial group of
    /// 2–4 characters for 1–3 bytes, <c>~&gt;</c> the end of data (anything after it ignored; its absence tolerated).
    /// A leading <c>&lt;~</c>, which PostScript writes and some producers copy, is skipped.
    /// </summary>
    /// <param name="data">The encoded bytes.</param>
    /// <param name="maxDecodedBytes">The most bytes the output may have.</param>
    /// <returns>The decoded bytes.</returns>
    /// <exception cref="PdfFilterException">
    /// A character outside <c>!</c>–<c>u</c>, a <c>z</c> inside a group, a <c>~</c> not followed by <c>&gt;</c>,
    /// a group worth more than 2³²−1, or a single character left at the end.
    /// </exception>
    internal static byte[] DecodeAscii85(ReadOnlySpan<byte> data, int maxDecodedBytes = DefaultMaxDecodedBytes)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maxDecodedBytes);

        int pos = 0;
        while (pos < data.Length && IsWhiteSpace(data[pos]))
        {
            pos++;
        }

        if (pos + 1 < data.Length && data[pos] == '<' && data[pos + 1] == '~')
        {
            pos += 2;
        }

        using var output = new MemoryStream(data.Length / 5 * 4 + 4);
        Span<byte> word = stackalloc byte[4];
        ulong value = 0;
        int groupLength = 0;

        for (; pos < data.Length; pos++)
        {
            byte b = data[pos];
            if (IsWhiteSpace(b))
            {
                continue;
            }

            if (b == '~')
            {
                if (pos + 1 >= data.Length || data[pos + 1] != '>')
                {
                    throw new PdfFilterException(Ascii85Decode, $"'~' at offset {pos} is not followed by '>'.");
                }

                break;
            }

            if (b == 'z')
            {
                if (groupLength != 0)
                {
                    throw new PdfFilterException(Ascii85Decode, $"'z' at offset {pos} is inside a group.");
                }

                word.Clear();
                WriteChecked(output, word, Ascii85Decode, maxDecodedBytes);
                continue;
            }

            if (b < '!' || b > 'u')
            {
                throw new PdfFilterException(Ascii85Decode, $"byte 0x{b:X2} at offset {pos} is not a base-85 digit.");
            }

            value = value * 85 + (ulong)(b - '!');
            if (++groupLength == 5)
            {
                WriteGroup(output, word, value, 4, pos, maxDecodedBytes);
                value = 0;
                groupLength = 0;
            }
        }

        if (groupLength == 1)
        {
            throw new PdfFilterException(Ascii85Decode, "a single character is left in the final group.");
        }

        if (groupLength > 1)
        {
            // Pad with 'u' (84) to a full group, keep groupLength − 1 bytes (§7.4.3).
            for (int i = groupLength; i < 5; i++)
            {
                value = value * 85 + 84;
            }

            WriteGroup(output, word, value, groupLength - 1, pos, maxDecodedBytes);
        }

        return output.ToArray();
    }

    /// <summary>
    /// <c>ASCIIHexDecode</c> (§7.4.2): pairs of hexadecimal digits (either case), white-space ignored, <c>&gt;</c>
    /// the end of data (its absence tolerated); an odd final digit is followed by an implied 0.
    /// </summary>
    /// <param name="data">The encoded bytes.</param>
    /// <param name="maxDecodedBytes">The most bytes the output may have.</param>
    /// <returns>The decoded bytes.</returns>
    /// <exception cref="PdfFilterException">A character that is neither a hexadecimal digit, white-space nor <c>&gt;</c>.</exception>
    internal static byte[] DecodeAsciiHex(ReadOnlySpan<byte> data, int maxDecodedBytes = DefaultMaxDecodedBytes)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maxDecodedBytes);

        byte[] output = new byte[(data.Length + 1) / 2];
        int count = 0;
        int high = -1;
        for (int pos = 0; pos < data.Length; pos++)
        {
            byte b = data[pos];
            if (b == '>')
            {
                break;
            }

            if (IsWhiteSpace(b))
            {
                continue;
            }

            int digit = HexValue(b);
            if (digit < 0)
            {
                throw new PdfFilterException(AsciiHexDecode, $"byte 0x{b:X2} at offset {pos} is not a hexadecimal digit.");
            }

            if (high < 0)
            {
                high = digit;
                continue;
            }

            output[count++] = (byte)((high << 4) | digit);
            high = -1;
        }

        if (high >= 0)
        {
            output[count++] = (byte)(high << 4);
        }

        if (count > maxDecodedBytes)
        {
            throw new PdfDecodedSizeLimitException(AsciiHexDecode, maxDecodedBytes);
        }

        return output.AsSpan(0, count).ToArray();
    }

    /// <summary>
    /// The full name of a filter (Table 6), mapping the inline-image abbreviations (Table 94); <see langword="null"/>
    /// when it is not one this class decodes.
    /// </summary>
    private static string? CanonicalName(string? name) =>
        (name is ['/', .. var rest] ? rest : name) switch
        {
            FlateDecode or "Fl" => FlateDecode,
            Ascii85Decode or "A85" => Ascii85Decode,
            AsciiHexDecode or "AHx" => AsciiHexDecode,
            _ => null,
        };

    private static void WriteGroup(MemoryStream output, Span<byte> word, ulong value, int bytes, int pos, int maxDecodedBytes)
    {
        if (value > uint.MaxValue)
        {
            throw new PdfFilterException(Ascii85Decode, $"the group ending at offset {pos} is worth more than 2^32 - 1.");
        }

        word[0] = (byte)(value >> 24);
        word[1] = (byte)(value >> 16);
        word[2] = (byte)(value >> 8);
        word[3] = (byte)value;
        WriteChecked(output, word[..bytes], Ascii85Decode, maxDecodedBytes);
    }

    private static void WriteChecked(MemoryStream output, ReadOnlySpan<byte> bytes, string filterName, int maxDecodedBytes)
    {
        if (output.Length + bytes.Length > maxDecodedBytes)
        {
            throw new PdfDecodedSizeLimitException(filterName, maxDecodedBytes);
        }

        output.Write(bytes);
    }

    /// <summary>The white-space characters of §7.2.3 (NUL, HT, LF, FF, CR, SP).</summary>
    private static bool IsWhiteSpace(byte b) => b is 0 or 9 or 10 or 12 or 13 or 32;

    private static int HexValue(byte b) => b switch
    {
        >= (byte)'0' and <= (byte)'9' => b - '0',
        >= (byte)'a' and <= (byte)'f' => b - 'a' + 10,
        >= (byte)'A' and <= (byte)'F' => b - 'A' + 10,
        _ => -1,
    };
}
