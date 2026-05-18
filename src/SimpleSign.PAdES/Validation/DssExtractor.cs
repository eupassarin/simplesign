using System.IO.Compression;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Logging;
using SimpleSign.Pdf;

namespace SimpleSign.PAdES.Validation;

/// <summary>
/// Extracts embedded revocation data (CRLs, OCSPs) from the PDF DSS dictionary.
/// Used for offline/archival validation (PAdES-B-LT/LTA).
/// </summary>
internal static partial class DssExtractor
{
    /// <summary>
    /// Attempts to extract embedded CRLs from the PDF DSS (Document Security Store) dictionary.
    /// Returns a list of DER-encoded CRLs; empty list if no DSS is found or on error.
    /// </summary>
    internal static async Task<IReadOnlyList<byte[]>> TryReadDssDataAsync(
        Stream pdfStream,
        CancellationToken ct,
        ILogger? logger = null)
    {
        try
        {
            pdfStream.Seek(0, SeekOrigin.Begin);
            int length = (int)Math.Min(pdfStream.Length, PdfStructureReader.MaxPdfSize);
            var pdfBytes = new byte[length];
            int read = 0;
            while (read < length)
            {
                int n = await pdfStream.ReadAsync(pdfBytes.AsMemory(read, length - read), ct).ConfigureAwait(false);
                if (n == 0)
                {
                    break;
                }
                read += n;
            }
            var data = pdfBytes.AsSpan(0, read);

            var dssDictSlice = FindDssDictionary(data);
            if (dssDictSlice == null)
            {
                return [];
            }

            return ExtractCrlsFromDss(dssDictSlice.Value.Span, data);
        }
        // S2221: intentional broad catch — data extraction from untrusted PDF
        catch (Exception ex)
        {
            logger?.CrlExtractionFromPdfFailed(ex.Message);
            return [];
        }
    }

    /// <summary>
    /// Locates the DSS dictionary in the PDF bytes by finding <c>/DSS N 0 R</c> in the catalog.
    /// </summary>
    internal static ReadOnlyMemory<byte>? FindDssDictionary(ReadOnlySpan<byte> data)
    {
        var dssKey = "/DSS "u8;
        int dssIdx = IndexOfBytes(data, dssKey);
        if (dssIdx < 0)
        {
            return null;
        }

        int numStart = dssIdx + dssKey.Length;
        int numEnd = numStart;
        while (numEnd < data.Length && data[numEnd] >= '0' && data[numEnd] <= '9')
        {
            numEnd++;
        }
        if (numEnd == numStart)
        {
            return null;
        }
        if (!int.TryParse(data[numStart..numEnd], out int dssObjNum))
        {
            return null;
        }

        var objMarker = Encoding.ASCII.GetBytes($"{dssObjNum} 0 obj");
        int objIdx = IndexOfBytes(data, objMarker);
        if (objIdx < 0)
        {
            return null;
        }

        int dictStart = IndexOfBytesFrom(data, "<<"u8, objIdx);
        if (dictStart < 0)
        {
            return null;
        }

        // Count bracket depth to handle nested dictionaries
        int depth = 0;
        int dictEnd = -1;
        for (int i = dictStart; i < data.Length - 1; i++)
        {
            if (data[i] == '<' && data[i + 1] == '<')
            {
                depth++;
                i++; // skip second '<'
            }
            else if (data[i] == '>' && data[i + 1] == '>')
            {
                depth--;
                i++; // skip second '>'
                if (depth == 0)
                {
                    dictEnd = i - 1; // points to first '>'
                    break;
                }
            }
        }

        if (dictEnd < 0)
        {
            return null;
        }

        return data[dictStart..(dictEnd + 2)].ToArray();
    }

    /// <summary>
    /// Extracts DER-encoded CRLs from the <c>/CRLs [...]</c> array in a DSS dictionary.
    /// </summary>
    internal static List<byte[]> ExtractCrlsFromDss(ReadOnlySpan<byte> dssDictSlice, ReadOnlySpan<byte> data)
    {
        var crls = new List<byte[]>();

        var crlsKey = "/CRLs ["u8;
        int crlsIdx = IndexOfBytes(dssDictSlice, crlsKey);
        if (crlsIdx >= 0)
        {
            int arrayStart = crlsIdx + crlsKey.Length;
            int arrayEnd = IndexOfBytesFrom(dssDictSlice, "]"u8, arrayStart);
            if (arrayEnd > arrayStart)
            {
                var arraySlice = dssDictSlice[arrayStart..arrayEnd];
                foreach (var objRef in ParseObjRefs(arraySlice))
                {
                    var crlObjMarker = Encoding.ASCII.GetBytes($"{objRef} 0 obj");
                    int crlObjIdx = IndexOfBytes(data, crlObjMarker);
                    if (crlObjIdx < 0)
                    {
                        continue;
                    }

                    // Check if stream uses FlateDecode compression
                    int streamStart = IndexOfBytesFrom(data, "stream"u8, crlObjIdx);
                    if (streamStart < 0)
                    {
                        continue;
                    }

                    bool isFlateEncoded = IndexOfBytesFrom(data, "FlateDecode"u8, crlObjIdx) is int flateIdx
                        && flateIdx >= 0 && flateIdx < streamStart;

                    streamStart += 6; // skip "stream"
                    // PDF spec: "stream" followed by \r\n or \n
                    if (streamStart < data.Length && data[streamStart] == '\r' && streamStart + 1 < data.Length && data[streamStart + 1] == '\n')
                    {
                        streamStart += 2;
                    }
                    else if (streamStart < data.Length && data[streamStart] == '\n')
                    {
                        streamStart += 1;
                    }

                    int streamEnd = IndexOfBytesFrom(data, "\nendstream"u8, streamStart);
                    if (streamEnd < 0)
                    {
                        continue;
                    }

                    byte[] streamBytes = data[streamStart..streamEnd].ToArray();

                    if (isFlateEncoded)
                    {
                        streamBytes = DecompressZlib(streamBytes);
                    }

                    crls.Add(streamBytes);
                }
            }
        }

        return crls;
    }

    internal static int IndexOfBytes(ReadOnlySpan<byte> haystack, ReadOnlySpan<byte> needle)
    {
        for (int i = 0; i <= haystack.Length - needle.Length; i++)
        {
            if (haystack[i..].StartsWith(needle))
            {
                return i;
            }
        }
        return -1;
    }

    internal static int IndexOfBytesFrom(ReadOnlySpan<byte> haystack, ReadOnlySpan<byte> needle, int from)
    {
        if (from < 0 || from >= haystack.Length)
        {
            return -1;
        }
        int idx = IndexOfBytes(haystack[from..], needle);
        return idx < 0 ? -1 : from + idx;
    }

    internal static IEnumerable<int> ParseObjRefs(ReadOnlySpan<byte> arrayContent)
    {
        var text = Encoding.ASCII.GetString(arrayContent.ToArray());
        var matches = ObjRefRegex().Matches(text);
        var result = new List<int>(matches.Count);
        foreach (Match m in matches)
        {
            if (int.TryParse(m.Groups[1].Value, out int n))
            {
                result.Add(n);
            }
        }
        return result;
    }

    [GeneratedRegex(@"(\d+)\s+0\s+R")]
    internal static partial Regex ObjRefRegex();

    private static byte[] DecompressZlib(byte[] compressed)
    {
        using var input = new MemoryStream(compressed);
        using var zlib = new ZLibStream(input, CompressionMode.Decompress);
        using var output = new MemoryStream();
        zlib.CopyTo(output);
        return output.ToArray();
    }
}
