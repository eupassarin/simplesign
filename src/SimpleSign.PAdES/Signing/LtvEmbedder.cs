using System.IO.Compression;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using SimpleSign.Core.Http;
using SimpleSign.Core.Revocation;
using SimpleSign.Pdf;

namespace SimpleSign.PAdES.Signing;

/// <summary>
/// Embeds revocation data (CRL + OCSP) and VRI (Validation Related Information)
/// in the PDF DSS (Document Security Store) for LTV (Long Term Validation).
/// The resulting PDF can be validated offline even after certificate expiration.
/// Conforms to PAdES Part 4 (ETSI EN 319 142-1), Annex A.
/// </summary>
public sealed class LtvEmbedder
{
    private readonly HttpClient _httpClient;
    private readonly ILogger _logger;

    /// <param name="httpClient">
    /// <see cref="HttpClient"/> instance for downloading CRL/OCSP.
    /// In ASP.NET Core, inject via <c>IHttpClientFactory.CreateClient()</c> to avoid socket exhaustion.
    /// If null, uses the shared instance from <see cref="DefaultHttpClientProvider"/>.
    /// </param>
    /// <param name="logger">Optional logger for structured diagnostics.</param>
    public LtvEmbedder(HttpClient? httpClient = null, ILogger? logger = null)
    {
        _httpClient = httpClient ?? DefaultHttpClientProvider.Instance.GetClient();
        _logger = logger ?? NullLogger.Instance;
    }

    /// <summary>
    /// Creates an embedder using a custom <see cref="IHttpClientProvider"/>.
    /// Use this in ASP.NET Core to integrate with <c>IHttpClientFactory</c>.
    /// </summary>
    public LtvEmbedder(IHttpClientProvider httpClientProvider, ILogger? logger = null)
    {
        ArgumentNullException.ThrowIfNull(httpClientProvider);
        _httpClient = httpClientProvider.GetClient();
        _logger = logger ?? NullLogger.Instance;
    }

    /// <summary>
    /// Collects revocation data (CRL + OCSP) from all certificates in the chain
    /// and embeds them in the PDF as an incremental update (DSS dictionary with VRI).
    /// </summary>
    /// <param name="signedPdf">The signed PDF bytes.</param>
    /// <param name="certificateChain">Full certificate chain (signer + intermediates + root).</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The PDF bytes with embedded LTV data.</returns>
    public async Task<byte[]> EmbedLtvDataAsync(
        byte[] signedPdf,
        IReadOnlyList<X509Certificate2> certificateChain,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(signedPdf);
        ArgumentNullException.ThrowIfNull(certificateChain);

        var crlData = new List<byte[]>();
        var ocspData = new List<byte[]>();
        var ocspClient = new OcspClient(_httpClient, _logger);

        foreach (var cert in certificateChain)
        {
            _logger.LtvProcessingCert(cert.Subject);
            // Try OCSP first (smaller, faster, more current)
            var ocspUrl = OcspClient.GetOcspUrl(cert);
            if (ocspUrl is not null)
            {
                try
                {
                    var issuerCert = certificateChain.FirstOrDefault(c => c.SubjectName.RawData.AsSpan().SequenceEqual(cert.IssuerName.RawData));
                    var (_, responseBytes) = await ocspClient.FetchOcspResponseAsync(cert, issuerCert, ocspUrl, cancellationToken).ConfigureAwait(false);
                    ocspData.Add(responseBytes);
                    continue; // OCSP succeeded, skip CRL for this cert
                }
                catch (Exception ex) when (ex is HttpRequestException or InvalidOperationException or InvalidDataException)
                {
                    _logger.OcspFailedFallingBackToCrl(cert.Subject, ex.Message);
                }
            }

            // Fallback to CRL
            var crlUrl = CrlClient.GetCrlUrl(cert, _logger);
            if (crlUrl is not null)
            {
                try
                {
                    var crl = await ResilientHttp.GetBytesAsync(_httpClient, crlUrl, logger: _logger, ct: cancellationToken).ConfigureAwait(false);
                    if (crl is not null)
                    {
                        crlData.Add(crl);
                    }
                }
                catch (HttpRequestException ex)
                {
                    _logger.CrlDownloadFailed(ex.Message);
                }
            }
        }

        if (crlData is [] && ocspData is [])
        {
            return signedPdf;
        }

        _logger.LtvDataCollected(crlData.Count, ocspData.Count, certificateChain.Count);

        // Extract signature /Contents hashes for VRI
        var signatureHashes = ExtractSignatureContentHashes(signedPdf);

        return AppendDssDictionary(signedPdf, crlData, ocspData, certificateChain, signatureHashes);
    }

    /// <summary>
    /// Computes the SHA-1 hash of each signature's /Contents value for VRI dictionary keys.
    /// Per PAdES Part 4, VRI keys are uppercase hex SHA-1 of the DER-encoded signature value.
    /// </summary>
    internal static List<string> ExtractSignatureContentHashes(byte[] pdf)
    {
        var hashes = new List<string>();
        var span = pdf.AsSpan();
        ReadOnlySpan<byte> contentsToken = "/Contents <"u8;
        int searchPos = 0;

        while (searchPos < span.Length)
        {
            int matchPos = span[searchPos..].IndexOf(contentsToken);
            if (matchPos < 0)
            {
                break;
            }

            matchPos += searchPos;
            int hexStart = matchPos + contentsToken.Length;

            // Find closing '>'
            int hexEnd = span[hexStart..].IndexOf((byte)'>');
            if (hexEnd < 0)
            {
                break;
            }

            hexEnd += hexStart;

            // Check this looks like a signature /Contents (long hex string, >1000 chars)
            int hexLen = hexEnd - hexStart;
            if (hexLen > 1000)
            {
                // Decode the hex to bytes and compute SHA-1
                try
                {
                    string hexString = System.Text.Encoding.Latin1.GetString(span.Slice(hexStart, hexLen));
                    // Pad with leading zero if odd length (hex encoding requires even length)
                    if (hexString.Length % 2 != 0)
                    {
                        hexString = "0" + hexString;
                    }

                    if (hexString.Length > 0)
                    {
                        byte[] sigBytes = Convert.FromHexString(hexString);
#pragma warning disable CA5350 // VRI key is defined as SHA-1 by PAdES spec
                        byte[] hash = SHA1.HashData(sigBytes);
#pragma warning restore CA5350
                        hashes.Add(Convert.ToHexString(hash));
                    }
                }
                catch (FormatException)
                {
                    // Not valid hex — skip
                }
            }

            searchPos = hexEnd + 1;
        }

        return hashes;
    }

    private static byte[] AppendDssDictionary(
        byte[] signedPdf,
        List<byte[]> crls,
        List<byte[]> ocsps,
        IReadOnlyList<X509Certificate2> certs,
        List<string> signatureHashes)
    {
        int nextObj = FindNextObjectNumber(signedPdf);
        int dssObjNum = nextObj;
        int catalogObjNum = FindRootObjectNumber(signedPdf);

        var result = new MemoryStream();
        result.Write(signedPdf);

        var xrefMap = new SortedDictionary<int, long>();
        int nextObjNum = dssObjNum + 1;

        // Write CRL stream objects
        var crlRefs = WriteStreamObjects(result, crls, ref nextObjNum, xrefMap);

        // Write OCSP response stream objects
        var ocspRefs = WriteStreamObjects(result, ocsps, ref nextObjNum, xrefMap);

        // Write certificate stream objects
        var certDataList = certs.Select(c => c.RawData).ToList();
        var certRefs = WriteStreamObjects(result, certDataList, ref nextObjNum, xrefMap);

        // Build VRI dictionaries (one per signature)
        var vriEntries = new List<(string Hash, int ObjNum)>();
        foreach (var sigHash in signatureHashes)
        {
            int vriObjNum = nextObjNum++;
            long vriOffset = result.Position;
            xrefMap[vriObjNum] = vriOffset;

            var vriSb = new System.Text.StringBuilder();
            vriSb.Append($"{vriObjNum} 0 obj\n");
            vriSb.Append("<<\n");
            if (crlRefs is not [])
            {
                vriSb.Append($"   /CRL [{string.Join(" ", crlRefs)}]\n");
            }

            if (ocspRefs is not [])
            {
                vriSb.Append($"   /OCSP [{string.Join(" ", ocspRefs)}]\n");
            }

            if (certRefs is not [])
            {
                vriSb.Append($"   /Cert [{string.Join(" ", certRefs)}]\n");
            }

            // ISO 32000-2 §12.8.4.4: /TU is the time at which the VRI was created
            vriSb.Append($"   /TU (D:{DateTime.UtcNow:yyyyMMddHHmmss}+00'00')\n");

            vriSb.Append(">>\nendobj\n");
            result.Write(System.Text.Encoding.Latin1.GetBytes(vriSb.ToString()));

            vriEntries.Add((sigHash, vriObjNum));
        }

        // Write DSS dictionary
        long dssOffset = result.Position;
        xrefMap[dssObjNum] = dssOffset;

        var dssSb = new System.Text.StringBuilder();
        dssSb.Append($"{dssObjNum} 0 obj\n");
        dssSb.Append("<< /Type /DSS\n");
        if (crlRefs is not [])
        {
            dssSb.Append($"   /CRLs [{string.Join(" ", crlRefs)}]\n");
        }

        if (ocspRefs is not [])
        {
            dssSb.Append($"   /OCSPs [{string.Join(" ", ocspRefs)}]\n");
        }

        if (certRefs is not [])
        {
            dssSb.Append($"   /Certs [{string.Join(" ", certRefs)}]\n");
        }

        if (vriEntries is not [])
        {
            dssSb.Append("   /VRI <<\n");
            foreach (var (hash, objNum) in vriEntries)
            {
                dssSb.Append($"      /{hash} {objNum} 0 R\n");
            }

            dssSb.Append("   >>\n");
        }

        dssSb.Append(">>\nendobj\n");
        result.Write(System.Text.Encoding.Latin1.GetBytes(dssSb.ToString()));

        // Write updated catalog with /DSS reference
        long catOffset = result.Position;
        xrefMap[catalogObjNum] = catOffset;

        byte[] updCatalog = BuildUpdatedCatalogDss(catalogObjNum, signedPdf, dssObjNum);
        result.Write(updCatalog);

        int trailerSize = Math.Max(dssObjNum + 1, xrefMap.Keys.Max() + 1);

        long prevXRef = FindLastStartXRef(signedPdf);
        string? trailerId = PdfStructureParser.FindTrailerId(signedPdf);
        string? trailerInfo = PdfStructureParser.FindTrailerInfo(signedPdf);

        bool useXRefStream = PdfStructureParser.UsesXRefStreams(signedPdf);
        long xrefOffset = result.Position;

        if (useXRefStream)
        {
            int xrefObjNum = xrefMap.Keys.Max() + 1;
            trailerSize = Math.Max(trailerSize, xrefObjNum + 1);
            var (xrefBytes, _) = PdfSignatureWriter.BuildXrefStream(
                xrefMap, xrefObjNum, trailerSize, catalogObjNum, prevXRef, xrefOffset, trailerId, trailerInfo);
            result.Write(xrefBytes);
        }
        else
        {
            string xrefTrailer = BuildDssXrefAndTrailer(xrefMap, trailerSize, catalogObjNum, prevXRef, trailerId, trailerInfo, xrefOffset);
            result.Write(System.Text.Encoding.Latin1.GetBytes(xrefTrailer));
        }

        return result.ToArray();
    }

    /// <summary>
    /// Writes a list of byte arrays as PDF stream objects to the output stream.
    /// Returns indirect reference strings (e.g. "N 0 R") for each written object.
    /// </summary>
    private static List<string> WriteStreamObjects(
        MemoryStream output,
        List<byte[]> dataList,
        ref int nextObjNum,
        SortedDictionary<int, long> offsets)
    {
        var refs = new List<string>();
        foreach (var data in dataList)
        {
            int objNum = nextObjNum++;
            refs.Add($"{objNum} 0 R");

            offsets[objNum] = output.Position;

            // Compress with zlib (FlateDecode) — CRLs can be 1MB+ uncompressed
            byte[] compressed = CompressWithZlib(data);

            var sb = new System.Text.StringBuilder();
            sb.Append($"{objNum} 0 obj\n");
            sb.Append($"<< /Filter /FlateDecode /Length {compressed.Length} >>\n");
            sb.Append("stream\n");
            byte[] header = System.Text.Encoding.Latin1.GetBytes(sb.ToString());
            byte[] footer = System.Text.Encoding.Latin1.GetBytes("\nendstream\nendobj\n");
            output.Write(header);
            output.Write(compressed);
            output.Write(footer);
        }

        return refs;
    }

    private static byte[] CompressWithZlib(byte[] data)
    {
        using var ms = new MemoryStream();
        using (var zlib = new ZLibStream(ms, CompressionLevel.Optimal, leaveOpen: true))
        {
            zlib.Write(data);
        }

        return ms.ToArray();
    }

    private static string BuildDssXrefAndTrailer(
        SortedDictionary<int, long> xrefMap,
        int trailerSize,
        int catalogObjNum,
        long prevXRef,
        string? trailerId,
        string? trailerInfo,
        long xrefOffset)
    {
        var xref = new System.Text.StringBuilder();
        xref.Append("xref\n");

        var sortedKeys = xrefMap.Keys.ToList();
        int idx = 0;
        while (idx < sortedKeys.Count)
        {
            int groupStart = sortedKeys[idx];
            int j = idx;
            while (j + 1 < sortedKeys.Count && sortedKeys[j + 1] == sortedKeys[j] + 1)
            {
                j++;
            }

            int count = j - idx + 1;
            xref.Append($"{groupStart} {count}\n");
            for (int k = idx; k <= j; k++)
            {
                xref.Append($"{xrefMap[sortedKeys[k]]:D10} 00000 n\r\n");
            }

            idx = j + 1;
        }

        xref.Append("trailer\n");
        xref.Append($"<< /Size {Math.Max(trailerSize, xrefMap.Keys.Max() + 1)}\n");
        xref.Append($"   /Root {catalogObjNum} 0 R\n");
        xref.Append($"   /Prev {prevXRef}\n");
        if (trailerId != null)
        {
            xref.Append($"   {trailerId}\n");
        }
        if (trailerInfo != null)
        {
            xref.Append($"   {trailerInfo}\n");
        }
        xref.Append(">>\n");
        xref.Append($"startxref\n{xrefOffset}\n%%EOF\n");

        return xref.ToString();
    }

    private static int FindRootObjectNumber(byte[] pdf)
    {
        ReadOnlySpan<byte> rootKey = "/Root "u8;
        var span = pdf.AsSpan();
        int idx = span.LastIndexOf(rootKey);
        if (idx < 0)
        {
            return 1;
        }

        int pos = idx + rootKey.Length;
        int num = 0;
        while (pos < pdf.Length && pdf[pos] >= '0' && pdf[pos] <= '9')
        {
            num = num * 10 + (pdf[pos++] - '0');
        }

        return num > 0 ? num : 1;
    }

    private static byte[] BuildUpdatedCatalogDss(int catalogObjNum, byte[] pdf, int dssObjNum)
    {
        string marker = $"{catalogObjNum} 0 obj";
        byte[] markerBytes = System.Text.Encoding.Latin1.GetBytes(marker);
        int start = -1;
        for (int i = pdf.Length - markerBytes.Length; i >= 0; i--)
        {
            if (pdf.AsSpan(i, markerBytes.Length).SequenceEqual(markerBytes))
            {
                start = i;
                break;
            }
        }
        if (start < 0)
        {
            return System.Text.Encoding.Latin1.GetBytes(
                $"{catalogObjNum} 0 obj\n<< /Type /Catalog /DSS {dssObjNum} 0 R >>\nendobj\n");
        }

        ReadOnlySpan<byte> endobjMarker = "endobj"u8;
        int endobjIdx = pdf.AsSpan(start).IndexOf(endobjMarker);
        int end = endobjIdx >= 0 ? start + endobjIdx + 6 : pdf.Length;

        string original = System.Text.Encoding.Latin1.GetString(pdf, start, end - start);

        // Remove existing /DSS if present
        int dssIdx = original.IndexOf("/DSS ", StringComparison.Ordinal);
        if (dssIdx >= 0)
        {
            int lineEnd = original.IndexOf('\n', dssIdx);
            if (lineEnd >= 0)
            {
                original = original[..dssIdx] + original[(lineEnd + 1)..];
            }
        }

        int insertIdx = original.LastIndexOf(">>\nendobj", StringComparison.Ordinal);
        if (insertIdx < 0)
        {
            insertIdx = original.LastIndexOf(">>", StringComparison.Ordinal);
        }

        if (insertIdx < 0)
        {
            return System.Text.Encoding.Latin1.GetBytes(original);
        }

        string updated = original[..insertIdx] + $"   /DSS {dssObjNum} 0 R\n" + original[insertIdx..];
        return System.Text.Encoding.Latin1.GetBytes(updated);
    }

    private static int FindNextObjectNumber(byte[] pdf)
    {
        ReadOnlySpan<byte> sizeKey = "/Size "u8;
        var span = pdf.AsSpan();
        int idx = span.LastIndexOf(sizeKey);
        if (idx < 0)
        {
            return 10;
        }

        int pos = idx + sizeKey.Length;
        int size = 0;
        while (pos < pdf.Length && pdf[pos] >= '0' && pdf[pos] <= '9')
        {
            size = size * 10 + (pdf[pos++] - '0');
        }

        // Also check highest object number to avoid collisions
        ReadOnlySpan<byte> objMarker = " 0 obj"u8;
        int highest = 0;
        int searchPos = 0;
        while (searchPos < pdf.Length)
        {
            int objIdx = pdf.AsSpan(searchPos).IndexOf(objMarker);
            if (objIdx < 0)
            {
                break;
            }

            int absPos = searchPos + objIdx;
            int numEnd = absPos;
            int numStart = numEnd - 1;
            while (numStart >= 0 && pdf[numStart] >= '0' && pdf[numStart] <= '9')
            {
                numStart--;
            }

            numStart++;
            if (numStart < numEnd)
            {
                int objNum = 0;
                for (int i = numStart; i < numEnd; i++)
                {
                    objNum = objNum * 10 + (pdf[i] - '0');
                }

                if (objNum > highest)
                {
                    highest = objNum;
                }
            }

            searchPos = absPos + objMarker.Length;
        }

        return Math.Max(size, highest + 1);
    }

    private static long FindLastStartXRef(byte[] pdf)
    {
        ReadOnlySpan<byte> marker = "startxref"u8;
        var span = pdf.AsSpan();
        int idx = span.LastIndexOf(marker);
        if (idx < 0)
        {
            return 0;
        }

        int pos = idx + marker.Length;
        while (pos < pdf.Length && (pdf[pos] == ' ' || pdf[pos] == '\n' || pdf[pos] == '\r'))
        {
            pos++;
        }

        long val = 0;
        while (pos < pdf.Length && pdf[pos] >= '0' && pdf[pos] <= '9')
        {
            val = val * 10 + (pdf[pos++] - '0');
        }

        return val;
    }
}
