using System.Collections.Concurrent;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using SimpleSign.Core.Constants;
using SimpleSign.Core.Crypto;
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
    /// <param name="timestampTokenBytes">Optional raw DER bytes of the signature timestamp token (for VRI /TS).</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The PDF bytes with embedded LTV data.</returns>
    public async Task<byte[]> EmbedLtvDataAsync(
        byte[] signedPdf,
        IReadOnlyList<X509Certificate2> certificateChain,
        byte[]? timestampTokenBytes = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(signedPdf);
        ArgumentNullException.ThrowIfNull(certificateChain);

        const int MaxIterations = 10;
        var crlData = new List<byte[]>();
        var ocspData = new List<byte[]>();
        var allCerts = new List<X509Certificate2>(certificateChain);
        var ocspClient = new OcspClient(_httpClient, _logger);

        if (timestampTokenBytes is { Length: > 0 })
        {
            var tsaCerts = TsaCertificateExtractor.ExtractCertificates(timestampTokenBytes);
            var certThumbprints = new HashSet<string>(allCerts.Count, StringComparer.OrdinalIgnoreCase);
            foreach (var c in allCerts)
            {
                certThumbprints.Add(c.Thumbprint);
            }

            foreach (var tsaCert in tsaCerts)
            {
                if (certThumbprints.Add(tsaCert.Thumbprint))
                {
                    allCerts.Add(tsaCert);
                }
                else
                {
                    tsaCert.Dispose();
                }
            }
        }

        // Iterative stabilisation loop: process certificates in parallel until no new ones are discovered.
        // Each iteration snapshots the current cert list for issuer lookups and runs all
        // OCSP/CRL/AIA fetches concurrently. Newly discovered certs are merged after the
        // iteration completes so reads within the iteration are lock-free.
        var processedThumbprints = new ConcurrentDictionary<string, byte>(StringComparer.OrdinalIgnoreCase);
        var workingSet = new Queue<X509Certificate2>(allCerts);
        var parallelOptions = new ParallelOptions
        {
            MaxDegreeOfParallelism = Environment.ProcessorCount * 2,
            CancellationToken = cancellationToken,
        };
        int iteration = 0;

        while (workingSet.Count > 0 && iteration < MaxIterations)
        {
            iteration++;

            var allCertsSnapshot = allCerts.ToList();

            var certs = new List<X509Certificate2>(workingSet.Count);
            while (workingSet.Count > 0)
            {
                certs.Add(workingSet.Dequeue());
            }

            var ocspBag = new ConcurrentBag<byte[]>();
            var crlBag = new ConcurrentBag<byte[]>();
            var nextRoundCerts = new ConcurrentDictionary<string, X509Certificate2>(StringComparer.OrdinalIgnoreCase);

            await Parallel.ForEachAsync(certs, parallelOptions, async (cert, ct) =>
            {
                if (!processedThumbprints.TryAdd(cert.Thumbprint, 0))
                {
                    return;
                }

                if (HasOcspNoCheckExtension(cert))
                {
                    _logger.LtvProcessingCert($"{cert.Subject} (OcspNoCheck — skipping revocation)");
                    return;
                }

                _logger.LtvProcessingCert(cert.Subject);

                var ocspUrl = OcspClient.GetOcspUrl(cert);
                if (ocspUrl is not null)
                {
                    try
                    {
                        var issuerCert = allCertsSnapshot.FirstOrDefault(c => c.SubjectName.RawData.AsSpan().SequenceEqual(cert.IssuerName.RawData));
                        var ocspResult = await ocspClient.FetchOcspResponseAsync(cert, issuerCert, ocspUrl, ct).ConfigureAwait(false);
                        ocspBag.Add(ocspResult.ResponseBytes);

                        foreach (var respCert in ocspResult.ResponderCertificates)
                        {
                            if (processedThumbprints.ContainsKey(respCert.Thumbprint) ||
                                !nextRoundCerts.TryAdd(respCert.Thumbprint, respCert))
                            {
                                respCert.Dispose();
                            }
                        }

                        return;
                    }
                    catch (Exception ex) when (ex is HttpRequestException or InvalidOperationException or InvalidDataException)
                    {
                        _logger.OcspFailedFallingBackToCrl(cert.Subject, ex.Message);
                    }
                }

                var crlUrl = CrlClient.GetCrlUrl(cert, _logger);
                if (crlUrl is not null)
                {
                    try
                    {
                        var crl = await ResilientHttp.GetBytesAsync(_httpClient, crlUrl, logger: _logger, ct: ct).ConfigureAwait(false);
                        if (crl is not null)
                        {
                            crlBag.Add(crl);

                            var crlIssuerDn = CrlClient.ExtractCrlIssuerDn(crl, _logger);
                            if (crlIssuerDn is not null)
                            {
                                bool crlIssuerFound = allCertsSnapshot.Any(c =>
                                    c.SubjectName.RawData.AsSpan().SequenceEqual(crlIssuerDn));

                                if (!crlIssuerFound)
                                {
                                    var crlIssuerCert = await TryFetchCrlIssuerCertAsync(crlIssuerDn, cert, ct).ConfigureAwait(false);
                                    if (crlIssuerCert is not null)
                                    {
                                        if (processedThumbprints.ContainsKey(crlIssuerCert.Thumbprint) ||
                                            !nextRoundCerts.TryAdd(crlIssuerCert.Thumbprint, crlIssuerCert))
                                        {
                                            crlIssuerCert.Dispose();
                                        }
                                        else
                                        {
                                            _logger.LtvProcessingCert($"CRL issuer discovered: {crlIssuerCert.Subject}");
                                        }
                                    }
                                }
                            }
                        }
                    }
                    catch (HttpRequestException ex)
                    {
                        _logger.CrlDownloadFailed(ex.Message);
                    }
                }
            });

            foreach (var ocsp in ocspBag)
            {
                ocspData.Add(ocsp);
            }

            foreach (var crl in crlBag)
            {
                crlData.Add(crl);
            }

            var allCertsThumbprints = new HashSet<string>(allCerts.Count + nextRoundCerts.Count, StringComparer.OrdinalIgnoreCase);
            foreach (var c in allCerts)
            {
                allCertsThumbprints.Add(c.Thumbprint);
            }

            foreach (var (thumbprint, cert) in nextRoundCerts)
            {
                if (allCertsThumbprints.Add(thumbprint))
                {
                    allCerts.Add(cert);
                    workingSet.Enqueue(cert);
                }
            }
        }

        // If no revocation data found AND no certificates to embed, return early
        // (but still append EOL if needed for proper incremental update chaining)
        if (crlData is [] && ocspData is [] && allCerts is [])
        {
            _logger.LtvNoRevocationDataCollected();
            // v0.4.0: even when no LTV data is embedded, the source PDF must end
            // with an EOL marker so any downstream incremental update is LF-preceded.
            // Avoid a full double-copy: check the last byte and only allocate when
            // the trailing EOL is actually missing.
            signedPdf = EnsureTrailingEol(signedPdf);
            return signedPdf;
        }

        _logger.LtvDataCollected(crlData.Count, ocspData.Count, allCerts.Count);

        // Extract signature /Contents hashes for VRI (SHA-1 per ISO 32000-2 §12.8.4.4)
        var signatureHashes = ExtractSignatureContentHashes(signedPdf);

        if (crlData is [] && ocspData is [])
        {
            _logger.LtvNoRevocationDataCollected();
            // Only certificates are available — only worth embedding a DSS if there are
            // actual signatures to key VRI entries against (e.g. self-signed cert scenario).
            // Without signatures there is nothing to reference; return early and preserve
            // the EOL invariant the same way the "no data at all" path does.
            if (signatureHashes.Count == 0)
            {
                signedPdf = EnsureTrailingEol(signedPdf);
                return signedPdf;
            }
        }

        // Parse existing DSS for merge (multi-signature support)
        var existingDss = Validation.DssExtractor.ParseExistingDss(signedPdf);

        return AppendDssDictionary(signedPdf, crlData, ocspData, allCerts, signatureHashes, existingDss, timestampTokenBytes);
    }

    private static byte[] EnsureTrailingEol(byte[] data)
    {
        if (data.Length > 0 && data[^1] != (byte)'\n' && data[^1] != (byte)'\r')
        {
            byte[] result = new byte[data.Length + 1];
            data.CopyTo(result, 0);
            result[^1] = (byte)'\n';
            return result;
        }
        return data;
    }

    /// <summary>
    /// Computes the SHA-1 hash of each signature's /Contents value for VRI dictionary keys.
    /// Per ISO 32000-2 §12.8.4.4, the VRI key is the uppercase hex SHA-1 of the raw byte string
    /// value of the /Contents entry — i.e. the full decoded bytes including any trailing zero
    /// padding used to reserve space for the signature. Validators such as the ETSI Signature
    /// Conformance Checker compute SHA-1 over the complete /Contents bytes and look for a
    /// matching VRI key; stripping the padding would produce a different hash and break matching.
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

            int hexEnd = span[hexStart..].IndexOf((byte)'>');
            if (hexEnd < 0)
            {
                break;
            }

            hexEnd += hexStart;

            int hexLen = hexEnd - hexStart;
            if (hexLen > 1000)
            {
                try
                {
                    string hexString = System.Text.Encoding.Latin1.GetString(span.Slice(hexStart, hexLen));
                    if (hexString.Length % 2 != 0)
                    {
                        hexString = "0" + hexString;
                    }

                    if (hexString.Length > 0)
                    {
                        byte[] sigBytes = Convert.FromHexString(hexString);
#pragma warning disable CA5350 // VRI key is defined as SHA-1 by PAdES spec
                        byte[] sha1 = SHA1.HashData(sigBytes);
#pragma warning restore CA5350
                        hashes.Add(Convert.ToHexString(sha1));
                    }
                }
                catch (FormatException)
                {
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
        List<string> signatureHashes,
        ExistingDssData existingDss,
        byte[]? timestampTokenBytes = null)
    {
        int nextObj = FindNextObjectNumber(signedPdf);
        int dssObjNum = nextObj;
        int catalogObjNum = FindRootObjectNumber(signedPdf);

        var result = new MemoryStream();
        result.Write(signedPdf);
        IncrementalUpdateUtility.EnsureTrailingEol(result);

        var xrefMap = new SortedDictionary<int, long>();
        int nextObjNum = dssObjNum + 1;

        // Write CRL stream objects
        var crlRefs = WriteStreamObjects(result, crls, ref nextObjNum, xrefMap);

        // Write OCSP response stream objects
        var ocspRefs = WriteStreamObjects(result, ocsps, ref nextObjNum, xrefMap);

        // Write certificate stream objects (deduplicated by thumbprint)
        var certThumbprintMap = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var certRefs = new List<string>();
        var certRefSet = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var cert in certs)
        {
            string thumbprint = cert.Thumbprint;
            if (certThumbprintMap.TryGetValue(thumbprint, out var existingRef))
            {
                if (certRefSet.Add(existingRef))
                {
                    certRefs.Add(existingRef);
                }
                continue;
            }

            int objNum = nextObjNum++;
            string objRef = $"{objNum} 0 R";
            certRefSet.Add(objRef);
            certRefs.Add(objRef);
            certThumbprintMap[thumbprint] = objRef;

            xrefMap[objNum] = result.Position;
            byte[] compressed = CompressWithZlib(cert.RawData);
            var sb = new System.Text.StringBuilder();
            sb.Append($"{objNum} 0 obj\n");
            sb.Append($"<< /Filter /FlateDecode /Length {compressed.Length} >>\n");
            sb.Append("stream\n");
            byte[] header = System.Text.Encoding.Latin1.GetBytes(sb.ToString());
            byte[] footer = System.Text.Encoding.Latin1.GetBytes("\nendstream\nendobj\n");
            result.Write(header);
            result.Write(compressed);
            result.Write(footer);
        }

        // Write /TS stream object for timestamp token if provided
        string? tsRef = null;
        if (timestampTokenBytes is { Length: > 0 })
        {
            int tsObjNum = nextObjNum++;
            xrefMap[tsObjNum] = result.Position;
            byte[] tsCompressed = CompressWithZlib(timestampTokenBytes);
            var tsSb = new System.Text.StringBuilder();
            tsSb.Append($"{tsObjNum} 0 obj\n");
            tsSb.Append($"<< /Filter /FlateDecode /Length {tsCompressed.Length} >>\n");
            tsSb.Append("stream\n");
            result.Write(System.Text.Encoding.Latin1.GetBytes(tsSb.ToString()));
            result.Write(tsCompressed);
            result.Write(System.Text.Encoding.Latin1.GetBytes("\nendstream\nendobj\n"));
            tsRef = $"{tsObjNum} 0 R";
        }

        // Build VRI dictionaries (one per signature)
        var vriEntries = new List<(string Hash, int ObjNum)>();
        foreach (var sha1Hash in signatureHashes)
        {
            int vriObjNum = nextObjNum++;
            long vriOffset = result.Position;
            xrefMap[vriObjNum] = vriOffset;

            var vriSb = new System.Text.StringBuilder();
            vriSb.Append($"{vriObjNum} 0 obj\n");
            vriSb.Append("<< /Type /VRI\n");
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

            if (tsRef is not null)
            {
                vriSb.Append($"   /TS {tsRef}\n");
            }

            // ISO 32000-2 §12.8.4.4: /TU is the time at which the VRI was created
            vriSb.Append($"   /TU (D:{DateTime.UtcNow:yyyyMMddHHmmss}+00'00')\n");

            vriSb.Append(">>\nendobj\n");
            result.Write(System.Text.Encoding.Latin1.GetBytes(vriSb.ToString()));

            vriEntries.Add((sha1Hash, vriObjNum));
        }

        // Write DSS dictionary — merge existing refs with new refs
        long dssOffset = result.Position;
        xrefMap[dssObjNum] = dssOffset;

        // Merge existing object refs with newly written refs
        var allCrlRefs = MergeRefs(existingDss.CrlObjRefs, crlRefs);
        var allOcspRefs = MergeRefs(existingDss.OcspObjRefs, ocspRefs);
        var allCertRefs = MergeRefs(existingDss.CertObjRefs, certRefs);

        var allVriEntries = new List<(string Hash, int ObjNum)>(existingDss.VriEntries.Count + vriEntries.Count);
        var newVriHashes = new HashSet<string>(vriEntries.Count, StringComparer.OrdinalIgnoreCase);
        foreach (var (hash, _) in vriEntries)
        {
            newVriHashes.Add(hash);
        }

        foreach (var (hash, objNum) in existingDss.VriEntries)
        {
            if (!newVriHashes.Contains(hash))
            {
                allVriEntries.Add((hash, objNum));
            }
        }

        allVriEntries.AddRange(vriEntries);

        var dssSb = new System.Text.StringBuilder();
        dssSb.Append($"{dssObjNum} 0 obj\n");
        dssSb.Append("<< /Type /DSS\n");
        if (allCrlRefs is not [])
        {
            dssSb.Append($"   /CRLs [{string.Join(" ", allCrlRefs)}]\n");
        }

        if (allOcspRefs is not [])
        {
            dssSb.Append($"   /OCSPs [{string.Join(" ", allOcspRefs)}]\n");
        }

        if (allCertRefs is not [])
        {
            dssSb.Append($"   /Certs [{string.Join(" ", allCertRefs)}]\n");
        }

        if (allVriEntries is not [])
        {
            dssSb.Append("   /VRI <<\n");
            foreach (var (hash, objNum) in allVriEntries)
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
            byte[] xrefTrailer = PdfSignatureWriter.BuildXrefTableAndTrailer(xrefMap, trailerSize, catalogObjNum, prevXRef, xrefOffset, trailerId, trailerInfo);
            result.Write(xrefTrailer);
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

    /// <summary>
    /// Merges existing object references (from prior DSS) with newly written references.
    /// Existing refs are formatted as "N 0 R" strings. Deduplication is by object number.
    /// </summary>
    private static List<string> MergeRefs(IReadOnlyList<int> existingObjNums, List<string> newRefs)
    {
        var merged = new List<string>();
        var seen = new HashSet<int>();

        // Add existing references first (preserves prior data)
        foreach (int objNum in existingObjNums)
        {
            if (seen.Add(objNum))
            {
                merged.Add($"{objNum} 0 R");
            }
        }

        // Add new references, skipping duplicates
        foreach (string r in newRefs)
        {
            // Extract obj number from "N 0 R" string
            int spaceIdx = r.IndexOf(' ');
            if (spaceIdx > 0 && int.TryParse(r.AsSpan(0, spaceIdx), out int num) && seen.Add(num))
            {
                merged.Add(r);
            }
        }

        return merged;
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

        // Find the position to insert /DSS — just before the closing >> of the top-level dict.
        // Normalise CRLF → LF so Windows / iText / Adobe source PDFs match the sentinel;
        // fall back to a depth-aware search for the top-level dict close when the
        // sentinel is not found (e.g. unusual line endings or nested dicts).
        string normalised = original.Replace("\r\n", "\n", StringComparison.Ordinal);
        int insertIdx = normalised.LastIndexOf(">>\nendobj", StringComparison.Ordinal);
        if (insertIdx < 0)
        {
            insertIdx = PdfStructureParser.FindOutermostDictClose(normalised);
        }

        if (insertIdx < 0)
        {
            return System.Text.Encoding.Latin1.GetBytes(normalised);
        }

        // Splice against normalised (not original) so the index is correct even when
        // the source catalog contained CRLF line endings.
        string updated = normalised[..insertIdx] + $"   /DSS {dssObjNum} 0 R\n" + normalised[insertIdx..];

        // ISO 32000 §7.3.10: endobj shall be followed by an EOL marker. The next
        // object (XRef stream, written immediately after by the caller) would
        // otherwise start with no EOL predecessor and fail spacingCompliesPDFA.
        if (!updated.EndsWith('\n'))
        {
            updated += "\n";
        }

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

    /// <summary>
    /// Checks whether a certificate carries the id-pkix-ocsp-nocheck extension (RFC 6960 §4.2.2.2.1).
    /// Certificates with this extension are exempt from revocation checking.
    /// </summary>
    private static bool HasOcspNoCheckExtension(X509Certificate2 cert) =>
        cert.Extensions[Oids.OcspNoCheck] is not null;

    /// <summary>
    /// Attempts to fetch the CRL issuer certificate via the cert's AIA caIssuers URL.
    /// Returns the certificate if found and its subject matches the expected CRL issuer DN.
    /// Returns null if the certificate cannot be fetched or doesn't match.
    /// </summary>
    private async Task<X509Certificate2?> TryFetchCrlIssuerCertAsync(
        byte[] expectedIssuerDn,
        X509Certificate2 currentCert,
        CancellationToken ct)
    {
        // Try caIssuers from the current cert's AIA extension
        var caIssuersUrl = OcspClient.GetCaIssuersUrl(currentCert);
        if (caIssuersUrl is null)
        {
            return null;
        }

        try
        {
            var certBytes = await ResilientHttp.GetBytesAsync(_httpClient, caIssuersUrl, logger: _logger, ct: ct).ConfigureAwait(false);
            if (certBytes is null)
            {
                return null;
            }

            var fetchedCert = CertificateLoader.LoadCertificate(certBytes);
            if (fetchedCert.SubjectName.RawData.AsSpan().SequenceEqual(expectedIssuerDn))
            {
                return fetchedCert;
            }

            fetchedCert.Dispose();
            return null;
        }
        catch (Exception ex) when (ex is HttpRequestException or CryptographicException)
        {
            return null;
        }
    }
}
