using System.IO.Compression;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using SimpleSign.PAdES.Pdf;

namespace SimpleSign.PAdES.Signing;

/// <summary>
/// How <see cref="LtvEmbedder"/> wrote the DSS before the PDF object model (ADR 0032): the signatures, the next object
/// number and the catalog found by searching the file's text. Kept, internal, for the golden tests of the embedder
/// until the old code is removed.
/// </summary>
internal static class LtvEmbedderLegacy
{
    /// <summary>
    /// Computes the SHA-1 hash of each signature's /Contents value for VRI dictionary keys.
    /// Per ISO 32000-2 §12.8.4.4, the VRI key is the uppercase hex SHA-1 of the raw byte string
    /// value of the /Contents entry — i.e. the full decoded bytes including any trailing zero
    /// padding used to reserve space for the signature. Validators such as the ETSI Signature
    /// Conformance Checker compute SHA-1 over the complete /Contents bytes and look for a
    /// matching VRI key; stripping the padding would produce a different hash and break matching.
    /// </summary>
    internal static List<string> ExtractSignatureContentHashes(byte[] pdf, ILogger? logger = null)
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
                catch (FormatException ex)
                {
                    (logger ?? NullLogger.Instance).LogWarning("Failed to decode hex string for VRI key: {Message}", ex.Message);
                }
            }

            searchPos = hexEnd + 1;
        }

        return hashes;
    }

    internal static byte[] AppendDssDictionary(
        byte[] signedPdf,
        List<byte[]> crls,
        List<byte[]> ocsps,
        IReadOnlyList<X509Certificate2> certs,
        List<string> signatureHashes,
        ExistingDssData existingDss,
        byte[]? timestampTokenBytes,
        IReadOnlyList<PdfDssArtifact> artifacts,
        TimeProvider? timeProvider = null)
    {
        int nextObj = FindNextObjectNumber(signedPdf);
        int dssObjNum = nextObj;
        int catalogObjNum = PdfStructureParser.FindRootObjectNumber(signedPdf);

        using var result = new MemoryStream();
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

        // The validation material and timestamp supplied to this invocation belong to the
        // signature that was just added, which is the last signature in the incremental PDF.
        // Historical VRI mappings are immutable: replacing them would discard their original
        // per-signature /TS and validation-data associations.
        string? currentSignatureHash = signatureHashes.Count > 0 ? signatureHashes[^1] : null;
        bool createCurrentVri = currentSignatureHash is not null
            && !existingDss.VriEntries.ContainsKey(currentSignatureHash);

        // Write /TS only when a new current-signature VRI will reference it. If the current
        // signature already has a VRI, preserve that mapping instead of creating an orphaned
        // timestamp stream or destructively rebuilding the VRI.
        string? tsRef = null;
        if (createCurrentVri && timestampTokenBytes is { Length: > 0 })
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

        // Extra artifacts: one stream per distinct content, listed under their DSS key and
        // referenced from the new signature's VRI under their VRI key.
        var artifactRefs = new Dictionary<string, List<string>>(StringComparer.Ordinal);
        var vriArtifactRefs = new Dictionary<string, List<string>>(StringComparer.Ordinal);
        var written = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var artifact in artifacts)
        {
            string digest = Convert.ToHexString(SHA256.HashData(artifact.Content.Span));
            if (!written.TryGetValue(digest, out var objRef))
            {
                objRef = WriteStreamObjects(result, [artifact.Content.ToArray()], ref nextObjNum, xrefMap)[0];
                written[digest] = objRef;
            }

            Add(artifactRefs, artifact.DssKey, objRef);
            Add(vriArtifactRefs, artifact.VriKey, objRef);
        }

        static void Add(Dictionary<string, List<string>> map, string key, string objRef)
        {
            if (!map.TryGetValue(key, out var list))
            {
                map[key] = list = [];
            }

            if (!list.Contains(objRef))
            {
                list.Add(objRef);
            }
        }

        // Build a VRI only for the newly added signature. Existing mappings remain active and
        // continue to reference the validation material and timestamp collected for their own
        // signatures. Validation material collected in this pass cannot safely be attributed to
        // historical signatures merely because their hashes are present in the document.
        var vriEntries = new List<(string Hash, int ObjNum)>();
        if (createCurrentVri)
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

            foreach (var (key, refs) in vriArtifactRefs)
            {
                vriSb.Append(refs.Count == 1 ? $"   /{key} {refs[0]}\n" : $"   /{key} [{string.Join(" ", refs)}]\n");
            }

            // ISO 32000-2 §12.8.4.4: /TU is the time at which the VRI was created
            vriSb.Append($"   /TU (D:{(timeProvider ?? TimeProvider.System).GetUtcNow().UtcDateTime:yyyyMMddHHmmss}+00'00')\n");

            vriSb.Append(">>\nendobj\n");
            result.Write(System.Text.Encoding.Latin1.GetBytes(vriSb.ToString()));

            vriEntries.Add((currentSignatureHash!, vriObjNum));
        }

        // Write DSS dictionary — merge existing refs with new refs
        long dssOffset = result.Position;
        xrefMap[dssObjNum] = dssOffset;

        // Merge existing object refs with newly written refs
        var allCrlRefs = MergeRefs(existingDss.CrlObjRefs, crlRefs);
        var allOcspRefs = MergeRefs(existingDss.OcspObjRefs, ocspRefs);
        var allCertRefs = MergeRefs(existingDss.CertObjRefs, certRefs);

        var allVriEntries = new List<(string Hash, int ObjNum)>(existingDss.VriEntries.Count + vriEntries.Count);
        allVriEntries.AddRange(existingDss.VriEntries.Select(entry => (entry.Key, entry.Value)));
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

        foreach (string key in existingDss.ExtraArrays.Keys.Union(artifactRefs.Keys, StringComparer.Ordinal))
        {
            var merged = MergeRefs(
                existingDss.ExtraArrays.TryGetValue(key, out var old) ? old : [],
                artifactRefs.TryGetValue(key, out var added) ? added : []);
            dssSb.Append($"   /{key} [{string.Join(" ", merged)}]\n");
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

    private static byte[] BuildUpdatedCatalogDss(int catalogObjNum, byte[] pdf, int dssObjNum)
    {
        // The last "N 0 obj" that is not the tail of a larger number: a plain search for "1 0 obj"
        // also matches "21 0 obj" (a stamp's font descriptor, say) and would rewrite that object as
        // the catalog, dropping the AcroForm and the signature field with it.
        var (start, end) = PdfStructureParser.FindObjectBytes(pdf, catalogObjNum);
        if (start < 0)
        {
            return System.Text.Encoding.Latin1.GetBytes(
                $"{catalogObjNum} 0 obj\n<< /Type /Catalog /DSS {dssObjNum} 0 R >>\nendobj\n");
        }

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

    internal static int FindNextObjectNumber(byte[] pdf)
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
