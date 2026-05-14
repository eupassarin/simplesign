using System.Security.Cryptography;
using System.Text;
using SimpleSign.Core.Crypto;
using SimpleSign.Pdf;

namespace SimpleSign.PAdES.Signing;

/// <summary>
/// Writes a document-level timestamp (DocTimeStamp) as an incremental PDF update.
/// The DocTimeStamp is a signature field with <c>/SubFilter /ETSI.RFC3161</c> whose
/// <c>/Contents</c> is an RFC 3161 TimeStampToken covering the entire document.
/// This is the final step for PAdES-B-LTA (archival) compliance.
/// </summary>
public static class DocTimeStampWriter
{
    /// <summary>
    /// Default bytes reserved for the timestamp token hex in /Contents (32 KB).
    /// Timestamp tokens are typically 4–8 KB; 32 KB provides ample margin.
    /// </summary>
    public const int DefaultTimestampReservedBytes = 32768;

    /// <summary>
    /// Appends a document-level timestamp to a signed PDF with embedded DSS/LTV data.
    /// The timestamp covers the entire document up to the /Contents placeholder,
    /// providing archival-grade proof that the DSS data existed at timestamp time.
    /// </summary>
    /// <param name="signedPdf">The signed PDF bytes (with DSS already embedded).</param>
    /// <param name="tsaUrl">The TSA (Timestamp Authority) URL.</param>
    /// <param name="httpClient">HttpClient for TSA communication.</param>
    /// <param name="hashAlgorithm">Hash algorithm (default: SHA-256).</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The PDF bytes with the DocTimeStamp appended.</returns>
    public static async Task<byte[]> AppendDocTimeStampAsync(
        byte[] signedPdf,
        string tsaUrl,
        HttpClient httpClient,
        HashAlgorithmName? hashAlgorithm = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(signedPdf);
        ArgumentException.ThrowIfNullOrWhiteSpace(tsaUrl);
        ArgumentNullException.ThrowIfNull(httpClient);

        var hashAlg = hashAlgorithm ?? HashAlgorithmName.SHA256;
        int contentsReservedBytes = DefaultTimestampReservedBytes;
        int contentsHexLength = contentsReservedBytes * 2;
        DateTime sigNow = DateTime.UtcNow;

        // Determine object numbers
        int nextObjNum = PdfStructureParser.DetermineNextObjectNumber(signedPdf);
        int sigObjNum = nextObjNum;
        int fieldObjNum = nextObjNum + 1;
        int catalogObjNum = PdfStructureParser.FindRootObjectNumber(signedPdf);
        int existingAcroFormObjNum = PdfStructureParser.FindAcroFormObjNum(signedPdf, catalogObjNum);
        bool reuseAcroForm = existingAcroFormObjNum > 0;
        int acroFormObjNum = reuseAcroForm ? existingAcroFormObjNum : (nextObjNum + 2);

        // Build the timestamp signature dictionary (/SubFilter /ETSI.RFC3161)
        string contentsPlaceholder = new string('0', contentsHexLength);
        string fieldName = $"DocTimeStamp_{sigNow:yyyyMMddHHmmss}";

        var sigDict = new StringBuilder();
        sigDict.Append($"{sigObjNum} 0 obj\n");
        sigDict.Append("<< /Type /Sig\n");
        sigDict.Append("   /Filter /Adobe.PPKLite\n");
        sigDict.Append("   /SubFilter /ETSI.RFC3161\n");
        sigDict.Append("   /ByteRange [0000000000 0000000000 0000000000 0000000000]\n");
        sigDict.Append($"   /Contents <{contentsPlaceholder}>\n");
        sigDict.Append($"   /M (D:{sigNow:yyyyMMddHHmmss}+00'00')\n");
        sigDict.Append(">>\nendobj\n");
        string sigDictText = sigDict.ToString();

        // Locate first page for /P reference and /Annots update
        var (pageObjNum, pageObjDictStart, pageObjDictEnd) = PdfStructureParser.FindFirstPageObject(signedPdf);

        // Build the field annotation (invisible — no /Rect)
        var fieldDict = new StringBuilder();
        fieldDict.Append($"{fieldObjNum} 0 obj\n");
        fieldDict.Append("<< /Type /Annot\n");
        fieldDict.Append("   /Subtype /Widget\n");
        fieldDict.Append("   /FT /Sig\n");
        fieldDict.Append($"   /T ({fieldName})\n");
        fieldDict.Append($"   /V {sigObjNum} 0 R\n");
        if (pageObjNum > 0)
        {
            fieldDict.Append($"   /P {pageObjNum} 0 R\n");
        }
        fieldDict.Append("   /F 0\n");
        fieldDict.Append("   /Rect [0 0 0 0]\n");
        fieldDict.Append(">>\nendobj\n");

        // Build AcroForm — delegate to shared builder to preserve all existing keys
        byte[] acroFormBytes = PdfSignatureWriter.BuildAcroFormDictionary(acroFormObjNum, signedPdf, existingAcroFormObjNum, fieldObjNum, catalogObjNum);

        // Only rewrite the Catalog when the AcroForm reference changes.
        // Rewriting the Catalog unnecessarily causes Adobe diff analysis
        // to flag earlier signatures as modified.
        bool needCatalogUpdate = !reuseAcroForm;
        byte[]? catalogBytes = null;
        if (needCatalogUpdate)
        {
            var (catStart, catEnd) = PdfStructureParser.FindObjectBytes(signedPdf, catalogObjNum);
            string catalogText;
            if (catStart >= 0)
            {
                string origCatalog = Encoding.Latin1.GetString(signedPdf.AsSpan().Slice(catStart, catEnd - catStart));
                string updCatalog = PdfStructureParser.RemoveKeyFromDict(origCatalog, "/AcroForm");
                catalogText = PdfStructureParser.InsertIntoDict(updCatalog, $"   /AcroForm {acroFormObjNum} 0 R\n");
            }
            else
            {
                // Catalog may be in a compressed Object Stream
                string? compressedCatalog = PdfStructureParser.ExtractObjectFromObjStm(signedPdf, catalogObjNum);
                if (compressedCatalog != null)
                {
                    string fullObj = $"{catalogObjNum} 0 obj\n{compressedCatalog.Trim()}\nendobj\n";
                    string updCatalog = PdfStructureParser.RemoveKeyFromDict(fullObj, "/AcroForm");
                    catalogText = PdfStructureParser.InsertIntoDict(updCatalog, $"   /AcroForm {acroFormObjNum} 0 R\n");
                }
                else
                {
                    catalogText = $"{catalogObjNum} 0 obj\n<< /Type /Catalog /AcroForm {acroFormObjNum} 0 R >>\nendobj\n";
                }
            }
            catalogBytes = Encoding.Latin1.GetBytes(catalogText);
        }

        // Write all objects to output
        var output = new MemoryStream();
        output.Write(signedPdf);

        byte[] sigDictBytes = Encoding.Latin1.GetBytes(sigDictText);
        byte[] fieldDictBytes = Encoding.Latin1.GetBytes(fieldDict.ToString());

        long sigObjOffset = output.Position;
        output.Write(sigDictBytes);
        long fieldObjOffset = output.Position;
        output.Write(fieldDictBytes);
        long acroFormObjOffset = output.Position;
        output.Write(acroFormBytes);

        long catalogObjOffset = 0L;
        if (catalogBytes != null)
        {
            catalogObjOffset = output.Position;
            output.Write(catalogBytes);
        }

        // Update page /Annots to include the timestamp field
        long updPageObjOffset = 0L;
        if (pageObjNum > 0)
        {
            byte[] updatedPageBytes;
            if (pageObjDictStart >= 0)
            {
                updatedPageBytes = PdfSignatureWriter.BuildUpdatedPageObject(pageObjNum, signedPdf, pageObjDictStart, pageObjDictEnd, fieldObjNum);
            }
            else
            {
                updatedPageBytes = PdfSignatureWriter.BuildUpdatedPageObjectFromObjStm(pageObjNum, signedPdf, fieldObjNum);
            }

            if (updatedPageBytes.Length > 0)
            {
                updPageObjOffset = output.Position;
                output.Write(updatedPageBytes);
            }
            else
            {
                pageObjNum = -1;
            }
        }

        // Build xref and trailer
        var objectOffsets = new SortedDictionary<int, long>
        {
            [sigObjNum] = sigObjOffset,
            [fieldObjNum] = fieldObjOffset,
            [acroFormObjNum] = acroFormObjOffset
        };
        if (needCatalogUpdate)
        {
            objectOffsets[catalogObjNum] = catalogObjOffset;
        }
        if (pageObjNum > 0)
        {
            objectOffsets[pageObjNum] = updPageObjOffset;
        }

        long prevXRef = FindLastStartXRef(signedPdf);
        int trailerSize = Math.Max(acroFormObjNum + 1, objectOffsets.Keys.Max() + 1);
        long xrefOffset = output.Position;

        string? trailerId = PdfStructureParser.FindTrailerId(signedPdf);
        string? trailerInfo = PdfStructureParser.FindTrailerInfo(signedPdf);

        bool useXRefStream = PdfStructureParser.UsesXRefStreams(signedPdf);
        if (useXRefStream)
        {
            int xrefObjNum = objectOffsets.Keys.Max() + 1;
            trailerSize = Math.Max(trailerSize, xrefObjNum + 1);
            var (xrefBytes, _) = PdfSignatureWriter.BuildXrefStream(objectOffsets, xrefObjNum, trailerSize, catalogObjNum, prevXRef, xrefOffset, trailerId, trailerInfo);
            output.Write(xrefBytes);
        }
        else
        {
            var xref = new StringBuilder();
            xref.Append("xref\n");
            var sortedKeys = objectOffsets.Keys.ToList();
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
                    xref.Append($"{objectOffsets[sortedKeys[k]]:D10} 00000 n\r\n");
                }

                idx = j + 1;
            }

            xref.Append("trailer\n");
            xref.Append($"<< /Size {trailerSize}\n");
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

            output.Write(Encoding.Latin1.GetBytes(xref.ToString()));
        }

        // Back-fill ByteRange
        long totalFileLength = output.Position;
        int contentsHexLocalOffset = sigDictText.IndexOf("/Contents <", StringComparison.Ordinal) + "/Contents <".Length;
        long byteRange1Length = sigObjOffset + contentsHexLocalOffset - 1;
        long byteRange2Offset = sigObjOffset + contentsHexLocalOffset + contentsHexLength + 1;
        long byteRange2Length = totalFileLength - byteRange2Offset;

        string byteRangeValue = $"[0 {byteRange1Length} {byteRange2Offset} {byteRange2Length}]"
            .PadRight("[0000000000 0000000000 0000000000 0000000000]".Length);

        int byteRangeLocalOffset = sigDictText.IndexOf("/ByteRange ", StringComparison.Ordinal);
        long byteRangeWriteOffset = sigObjOffset + byteRangeLocalOffset + "/ByteRange ".Length;

        output.Seek(byteRangeWriteOffset, SeekOrigin.Begin);
        output.Write(Encoding.Latin1.GetBytes(byteRangeValue));
        output.Seek(0, SeekOrigin.End);

        // Read the signed bytes (ByteRange 1 + ByteRange 2)
        byte[] pdfBytes = output.ToArray();
        byte[] signedBytes = new byte[byteRange1Length + byteRange2Length];
        Array.Copy(pdfBytes, 0, signedBytes, 0, (int)byteRange1Length);
        Array.Copy(pdfBytes, (int)byteRange2Offset, signedBytes, (int)byteRange1Length, (int)byteRange2Length);

        // Request timestamp from TSA
        var tsaClient = new TimestampClient(httpClient, tsaUrl);
        byte[] timestampToken = await tsaClient.GetTimestampAsync(signedBytes, hashAlg, cancellationToken).ConfigureAwait(false);

        if (timestampToken.Length > contentsReservedBytes)
        {
            throw new InvalidOperationException(
                $"Timestamp token ({timestampToken.Length} bytes) exceeds reserved space ({contentsReservedBytes} bytes).");
        }

        // Write timestamp token as hex into /Contents
        string hexTimestamp = Convert.ToHexString(timestampToken)
            .PadRight(contentsHexLength, '0');

        long contentsWriteOffset = sigObjOffset + contentsHexLocalOffset;
        Array.Copy(Encoding.Latin1.GetBytes(hexTimestamp), 0, pdfBytes, (int)contentsWriteOffset, contentsHexLength);

        return pdfBytes;
    }

    private static long FindLastStartXRef(byte[] pdf)
    {
        ReadOnlySpan<byte> marker = "startxref"u8;
        int idx = pdf.AsSpan().LastIndexOf(marker);
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
