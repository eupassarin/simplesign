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
        var fullData = await TryReadFullDssDataAsync(pdfStream, ct, logger).ConfigureAwait(false);
        return fullData.GlobalCrls;
    }

    /// <summary>
    /// Extracts full DSS validation data including global CRLs/OCSPs/Certs and per-signature VRI entries.
    /// Used for VRI-aware validation in multi-signature PDFs.
    /// </summary>
    internal static async Task<DssValidationData> TryReadFullDssDataAsync(
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
                return DssValidationData.Empty;
            }

            var dssSpan = dssDictSlice.Value.Span;
            var globalCrls = ExtractCrlsFromDss(dssSpan, data);
            var globalOcsps = ExtractStreamsFromArray(dssSpan, "/OCSPs ["u8, data);
            var globalCerts = ExtractStreamsFromArray(dssSpan, "/Certs ["u8, data);
            var vriEntries = ExtractVriData(dssSpan, data);

            return new DssValidationData(globalCrls, globalOcsps, globalCerts, vriEntries);
        }
        // S2221: intentional broad catch — data extraction from untrusted PDF
        catch (Exception ex)
        {
            logger?.CrlExtractionFromPdfFailed(ex.Message);
            return DssValidationData.Empty;
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
        // Incremental updates append revisions; the latest definition of an object
        // number wins (xref chain semantics), so resolve the LAST occurrence.
        int objIdx = LastIndexOfBytes(data, objMarker);
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
                    // Resolve the latest definition of the object (incremental update semantics).
                    int crlObjIdx = LastIndexOfBytes(data, crlObjMarker);
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

                    int streamEnd = IndexOfBytesFrom(data, "endstream"u8, streamStart);
                    if (streamEnd < 0)
                    {
                        continue;
                    }
                    // PDF spec: stream data ends before EOL + "endstream". Trim trailing \r\n or \n.
                    if (streamEnd >= 2 && data[streamEnd - 2] == '\r' && data[streamEnd - 1] == '\n')
                    {
                        streamEnd -= 2;
                    }
                    else if (streamEnd >= 1 && data[streamEnd - 1] == '\n')
                    {
                        streamEnd -= 1;
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

    /// <summary>
    /// Finds the LAST occurrence of <paramref name="needle"/> in <paramref name="haystack"/>.
    /// Used to resolve object definitions in incremental PDF updates, where the latest
    /// revision's definition of an object number wins.
    /// </summary>
    internal static int LastIndexOfBytes(ReadOnlySpan<byte> haystack, ReadOnlySpan<byte> needle)
    {
        for (int i = haystack.Length - needle.Length; i >= 0; i--)
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

    /// <summary>
    /// Extracts stream data from a named array in the DSS dictionary (generalized version of ExtractCrlsFromDss).
    /// Works for /OCSPs and /Certs arrays.
    /// </summary>
    internal static List<byte[]> ExtractStreamsFromArray(ReadOnlySpan<byte> dssDictSlice, ReadOnlySpan<byte> arrayKey, ReadOnlySpan<byte> pdfData)
    {
        int idx = IndexOfBytes(dssDictSlice, arrayKey);
        if (idx < 0)
        {
            return [];
        }

        int arrayStart = idx + arrayKey.Length;
        int arrayEnd = IndexOfBytesFrom(dssDictSlice, "]"u8, arrayStart);
        if (arrayEnd <= arrayStart)
        {
            return [];
        }

        var results = new List<byte[]>();
        foreach (int objRef in ParseObjRefs(dssDictSlice[arrayStart..arrayEnd]))
        {
            byte[]? streamData = ExtractStreamByObjNum(pdfData, objRef);
            if (streamData is not null)
            {
                results.Add(streamData);
            }
        }

        return results;
    }

    /// <summary>
    /// Extracts VRI data (per-signature revocation data) from the DSS dictionary.
    /// Returns a dictionary keyed by uppercase hex SHA-1 hash of each signature's CMS bytes.
    /// </summary>
    private static Dictionary<string, VriData> ExtractVriData(ReadOnlySpan<byte> dssDictSlice, ReadOnlySpan<byte> pdfData)
    {
        var result = new Dictionary<string, VriData>(StringComparer.OrdinalIgnoreCase);

        int vriIdx = IndexOfBytes(dssDictSlice, "/VRI "u8);
        if (vriIdx < 0)
        {
            vriIdx = IndexOfBytes(dssDictSlice, "/VRI<<"u8);
        }

        if (vriIdx < 0)
        {
            return result;
        }

        int outerDictStart = IndexOfBytesFrom(dssDictSlice, "<<"u8, vriIdx + 4);
        if (outerDictStart < 0)
        {
            return result;
        }

        // Find outer VRI dict bounds
        int depth = 0;
        int outerDictEnd = -1;
        for (int i = outerDictStart; i < dssDictSlice.Length - 1; i++)
        {
            if (dssDictSlice[i] == '<' && dssDictSlice[i + 1] == '<')
            {
                depth++;
                i++;
            }
            else if (dssDictSlice[i] == '>' && dssDictSlice[i + 1] == '>')
            {
                depth--;
                i++;
                if (depth == 0)
                {
                    outerDictEnd = i + 1;
                    break;
                }
            }
        }

        if (outerDictEnd < 0)
        {
            return result;
        }

        var vriContent = dssDictSlice[(outerDictStart + 2)..outerDictEnd];
        var vriText = Encoding.Latin1.GetString(vriContent.ToArray());

        // Find VRI keys that point to object references (indirect VRI entries)
        var indirectMatches = VriEntryRegex().Matches(vriText);
        foreach (Match m in indirectMatches)
        {
            string hash = m.Groups[1].Value.ToUpperInvariant();
            if (int.TryParse(m.Groups[2].Value, out int vriObjNum))
            {
                var vriData = ExtractVriEntryData(pdfData, vriObjNum);
                if (vriData is not null)
                {
                    result[hash] = vriData;
                }
            }
        }

        return result;
    }

    /// <summary>
    /// Extracts VRI entry data (CRLs, OCSPs, Certs) from a VRI object by object number.
    /// </summary>
    private static VriData? ExtractVriEntryData(ReadOnlySpan<byte> pdfData, int vriObjNum)
    {
        var objMarker = Encoding.ASCII.GetBytes($"{vriObjNum} 0 obj");
        // Resolve the latest definition of the object (incremental update semantics).
        int objIdx = LastIndexOfBytes(pdfData, objMarker);
        if (objIdx < 0)
        {
            return null;
        }

        int dictStart = IndexOfBytesFrom(pdfData, "<<"u8, objIdx);
        if (dictStart < 0)
        {
            return null;
        }

        // Find dict end
        int ddepth = 0;
        int dictEnd = -1;
        for (int i = dictStart; i < pdfData.Length - 1; i++)
        {
            if (pdfData[i] == '<' && pdfData[i + 1] == '<')
            {
                ddepth++;
                i++;
            }
            else if (pdfData[i] == '>' && pdfData[i + 1] == '>')
            {
                ddepth--;
                i++;
                if (ddepth == 0)
                {
                    dictEnd = i + 1;
                    break;
                }
            }
        }

        if (dictEnd < 0)
        {
            return null;
        }

        var vriDictSpan = pdfData[dictStart..dictEnd];

        var crls = ExtractStreamsFromVriArray(vriDictSpan, "/CRL ["u8, pdfData);
        if (crls.Count == 0)
        {
            crls = ExtractStreamsFromVriArray(vriDictSpan, "/CRL["u8, pdfData);
        }

        var ocsps = ExtractStreamsFromVriArray(vriDictSpan, "/OCSP ["u8, pdfData);
        if (ocsps.Count == 0)
        {
            ocsps = ExtractStreamsFromVriArray(vriDictSpan, "/OCSP["u8, pdfData);
        }

        var certs = ExtractStreamsFromVriArray(vriDictSpan, "/Cert ["u8, pdfData);
        if (certs.Count == 0)
        {
            certs = ExtractStreamsFromVriArray(vriDictSpan, "/Cert["u8, pdfData);
        }

        return new VriData(crls, ocsps, certs);
    }

    /// <summary>
    /// Extracts streams from an array within a VRI entry dictionary.
    /// </summary>
    private static List<byte[]> ExtractStreamsFromVriArray(ReadOnlySpan<byte> dictSpan, ReadOnlySpan<byte> arrayKey, ReadOnlySpan<byte> pdfData)
    {
        int idx = IndexOfBytes(dictSpan, arrayKey);
        if (idx < 0)
        {
            return [];
        }

        int arrayStart = idx + arrayKey.Length;
        int arrayEnd = IndexOfBytesFrom(dictSpan, "]"u8, arrayStart);
        if (arrayEnd <= arrayStart)
        {
            return [];
        }

        var results = new List<byte[]>();
        foreach (int objRef in ParseObjRefs(dictSpan[arrayStart..arrayEnd]))
        {
            byte[]? streamData = ExtractStreamByObjNum(pdfData, objRef);
            if (streamData is not null)
            {
                results.Add(streamData);
            }
        }

        return results;
    }

    /// <summary>
    /// Extracts raw stream data from a PDF object by object number.
    /// Handles FlateDecode decompression.
    /// </summary>
    private static byte[]? ExtractStreamByObjNum(ReadOnlySpan<byte> pdfData, int objNum)
    {
        var objMarker = Encoding.ASCII.GetBytes($"{objNum} 0 obj");
        // Resolve the latest definition of the object (incremental update semantics).
        int objIdx = LastIndexOfBytes(pdfData, objMarker);
        if (objIdx < 0)
        {
            return null;
        }

        int streamStart = IndexOfBytesFrom(pdfData, "stream"u8, objIdx);
        if (streamStart < 0)
        {
            return null;
        }

        bool isFlateEncoded = IndexOfBytesFrom(pdfData, "FlateDecode"u8, objIdx) is int flateIdx
            && flateIdx >= 0 && flateIdx < streamStart;

        streamStart += 6; // skip "stream"
        if (streamStart < pdfData.Length && pdfData[streamStart] == '\r' && streamStart + 1 < pdfData.Length && pdfData[streamStart + 1] == '\n')
        {
            streamStart += 2;
        }
        else if (streamStart < pdfData.Length && pdfData[streamStart] == '\n')
        {
            streamStart += 1;
        }

        int streamEnd = IndexOfBytesFrom(pdfData, "endstream"u8, streamStart);
        if (streamEnd < 0)
        {
            return null;
        }

        if (streamEnd >= 2 && pdfData[streamEnd - 2] == '\r' && pdfData[streamEnd - 1] == '\n')
        {
            streamEnd -= 2;
        }
        else if (streamEnd >= 1 && pdfData[streamEnd - 1] == '\n')
        {
            streamEnd -= 1;
        }

        byte[] streamBytes = pdfData[streamStart..streamEnd].ToArray();

        if (isFlateEncoded)
        {
            streamBytes = DecompressZlib(streamBytes);
        }

        return streamBytes;
    }

    /// <summary>
    /// Parses the existing DSS dictionary from PDF bytes and returns the object references
    /// for CRLs, OCSPs, Certs, and VRI entries. Used for DSS merge during multi-signature LTV embedding.
    /// </summary>
    internal static Signing.ExistingDssData ParseExistingDss(ReadOnlySpan<byte> pdfData)
    {
        var dssDictSlice = FindDssDictionary(pdfData);
        if (dssDictSlice == null)
        {
            return Signing.ExistingDssData.Empty;
        }

        var dssSpan = dssDictSlice.Value.Span;

        var crlRefs = ParseArrayRefs(dssSpan, "/CRLs ["u8);
        var ocspRefs = ParseArrayRefs(dssSpan, "/OCSPs ["u8);
        var certRefs = ParseArrayRefs(dssSpan, "/Certs ["u8);
        var vriEntries = ParseVriEntries(dssSpan);

        return new Signing.ExistingDssData(crlRefs, ocspRefs, certRefs, vriEntries);
    }

    /// <summary>
    /// Parses object references from a named array (e.g. "/CRLs [10 0 R 20 0 R]") in the DSS dictionary.
    /// </summary>
    private static List<int> ParseArrayRefs(ReadOnlySpan<byte> dssDictSlice, ReadOnlySpan<byte> arrayKey)
    {
        int idx = IndexOfBytes(dssDictSlice, arrayKey);
        if (idx < 0)
        {
            return [];
        }

        int arrayStart = idx + arrayKey.Length;
        int arrayEnd = IndexOfBytesFrom(dssDictSlice, "]"u8, arrayStart);
        if (arrayEnd <= arrayStart)
        {
            return [];
        }

        return [.. ParseObjRefs(dssDictSlice[arrayStart..arrayEnd])];
    }

    /// <summary>
    /// Parses VRI dictionary entries from the DSS. Returns hash → object number mapping.
    /// VRI format: /VRI &lt;&lt; /HASH1 N 0 R /HASH2 M 0 R ... &gt;&gt;
    /// </summary>
    private static Dictionary<string, int> ParseVriEntries(ReadOnlySpan<byte> dssDictSlice)
    {
        var result = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);

        int vriIdx = IndexOfBytes(dssDictSlice, "/VRI "u8);
        if (vriIdx < 0)
        {
            vriIdx = IndexOfBytes(dssDictSlice, "/VRI<<"u8);
        }

        if (vriIdx < 0)
        {
            return result;
        }

        int dictStart = IndexOfBytesFrom(dssDictSlice, "<<"u8, vriIdx + 4);
        if (dictStart < 0)
        {
            return result;
        }

        // Find matching >> (accounting for nested dicts inside VRI entries)
        int depth = 0;
        int dictEnd = -1;
        for (int i = dictStart; i < dssDictSlice.Length - 1; i++)
        {
            if (dssDictSlice[i] == '<' && dssDictSlice[i + 1] == '<')
            {
                depth++;
                i++;
            }
            else if (dssDictSlice[i] == '>' && dssDictSlice[i + 1] == '>')
            {
                depth--;
                i++;
                if (depth == 0)
                {
                    dictEnd = i + 1;
                    break;
                }
            }
        }

        if (dictEnd < 0)
        {
            return result;
        }

        var vriContent = dssDictSlice[(dictStart + 2)..dictEnd];
        var vriText = Encoding.Latin1.GetString(vriContent.ToArray());

        // Match VRI keys: /HEXHASH followed by object reference (N 0 R) or nested dict
        var matches = VriEntryRegex().Matches(vriText);
        foreach (Match m in matches)
        {
            string hash = m.Groups[1].Value.ToUpperInvariant();
            if (int.TryParse(m.Groups[2].Value, out int objNum))
            {
                result[hash] = objNum;
            }
        }

        return result;
    }

    [GeneratedRegex(@"/([0-9A-Fa-f]{10,40})\s+(\d+)\s+0\s+R")]
    private static partial Regex VriEntryRegex();

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
