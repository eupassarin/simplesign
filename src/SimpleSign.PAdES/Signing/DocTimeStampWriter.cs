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
        string fieldName = $"DocTimeStamp_{DateTime.UtcNow:yyyyMMddHHmmss}";

        var sigDict = new StringBuilder();
        sigDict.Append($"{sigObjNum} 0 obj\n");
        sigDict.Append("<< /Type /Sig\n");
        sigDict.Append("   /Filter /Adobe.PPKLite\n");
        sigDict.Append("   /SubFilter /ETSI.RFC3161\n");
        sigDict.Append("   /ByteRange [0000000000 0000000000 0000000000 0000000000]\n");
        sigDict.Append($"   /Contents <{contentsPlaceholder}>\n");
        sigDict.Append(">>\nendobj\n");
        string sigDictText = sigDict.ToString();

        // Build the field annotation (invisible — no /Rect)
        var fieldDict = new StringBuilder();
        fieldDict.Append($"{fieldObjNum} 0 obj\n");
        fieldDict.Append("<< /Type /Annot\n");
        fieldDict.Append("   /Subtype /Widget\n");
        fieldDict.Append("   /FT /Sig\n");
        fieldDict.Append($"   /T ({fieldName})\n");
        fieldDict.Append($"   /V {sigObjNum} 0 R\n");
        fieldDict.Append("   /Rect [0 0 0 0]\n");
        fieldDict.Append(">>\nendobj\n");

        // Build AcroForm with merged fields
        var existingFields = new List<string>();
        int sourceObjNum = existingAcroFormObjNum > 0 ? existingAcroFormObjNum : acroFormObjNum;
        if (sourceObjNum > 0)
        {
            var (objStart, objEnd) = PdfStructureParser.FindObjectBytes(signedPdf, sourceObjNum);
            if (objStart >= 0)
            {
                existingFields = PdfStructureParser.ParseFieldsArray(
                    Encoding.Latin1.GetString(signedPdf.AsSpan().Slice(objStart, objEnd - objStart)));
            }
        }

        existingFields.Add($"{fieldObjNum} 0 R");
        string acroFormText = $"{acroFormObjNum} 0 obj\n<< /Type /AcroForm\n   /Fields [{string.Join(" ", existingFields)}]\n   /SigFlags 3\n>>\nendobj\n";

        // Build updated catalog
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
            catalogText = $"{catalogObjNum} 0 obj\n<< /Type /Catalog /AcroForm {acroFormObjNum} 0 R >>\nendobj\n";
        }

        // Write all objects to output
        var output = new MemoryStream();
        output.Write(signedPdf);

        byte[] sigDictBytes = Encoding.Latin1.GetBytes(sigDictText);
        byte[] fieldDictBytes = Encoding.Latin1.GetBytes(fieldDict.ToString());
        byte[] acroFormBytes = Encoding.Latin1.GetBytes(acroFormText);
        byte[] catalogBytes = Encoding.Latin1.GetBytes(catalogText);

        long sigObjOffset = output.Position;
        output.Write(sigDictBytes);
        long fieldObjOffset = output.Position;
        output.Write(fieldDictBytes);
        long acroFormObjOffset = output.Position;
        output.Write(acroFormBytes);
        long catalogObjOffset = output.Position;
        output.Write(catalogBytes);

        // Build xref and trailer
        var objectOffsets = new SortedDictionary<int, long>
        {
            [sigObjNum] = sigObjOffset,
            [fieldObjNum] = fieldObjOffset,
            [acroFormObjNum] = acroFormObjOffset,
            [catalogObjNum] = catalogObjOffset
        };

        long prevXRef = FindLastStartXRef(signedPdf);
        int trailerSize = Math.Max(acroFormObjNum + 1, objectOffsets.Keys.Max() + 1);
        long xrefOffset = output.Position;

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
        xref.Append(">>\n");
        xref.Append($"startxref\n{xrefOffset}\n%%EOF\n");

        output.Write(Encoding.Latin1.GetBytes(xref.ToString()));

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
        string hexTimestamp = Convert.ToHexString(timestampToken).ToLowerInvariant()
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
