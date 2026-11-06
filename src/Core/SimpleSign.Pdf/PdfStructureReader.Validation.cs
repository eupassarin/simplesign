using SimpleSign.Pdf.Enums;
using SimpleSign.Pdf.Exceptions;

namespace SimpleSign.Pdf;

public sealed partial class PdfStructureReader
{
    #region PDF Header Validation

    private static void ValidatePdfHeader(ReadOnlySpan<byte> data)
    {
        if (!data.StartsWith(PdfHeaderMarker))
        {
            throw new PdfStructureException("Not a valid PDF file (missing %PDF- header).");
        }
    }

    /// <summary>
    /// Throws <see cref="EncryptedPdfException"/> if the PDF trailer contains an /Encrypt entry.
    /// </summary>
    private static void ThrowIfEncrypted(ReadOnlySpan<byte> data)
    {
        if (DetectEncryption(data))
        {
            throw new EncryptedPdfException(
                "This PDF is encrypted. SimpleSign cannot sign or validate encrypted PDFs. " +
                "Decrypt the PDF first using a tool like Adobe Acrobat or qpdf.");
        }
    }

    /// <summary>
    /// Core logic for DocMDP permission level detection on an already-buffered PDF span.
    /// Returns 0 if no DocMDP, or the permission level (1, 2, or 3).
    ///
    /// Per ITI VALIDAR developer guide, /Perms is NOT added to the catalog.
    /// Detection is based solely on /TransformMethod /DocMDP in signature objects.
    /// </summary>
    private static int GetDocMdpPermissionLevel(ReadOnlySpan<byte> data)
    {
        // Find /TransformMethod /DocMDP in any signature object
        int tmPos = IndexOf(data, TransformMethodDocMdp, 0);
        if (tmPos < 0)
        {
            return 0;
        }

        // Search for /P within a bounded window after /TransformMethod /DocMDP
        int permSearchEnd = Math.Min(tmPos + PermissionSearchWindow, data.Length);
        int permKeyPos = IndexOf(data[tmPos..permSearchEnd], PermissionKey, 0);
        if (permKeyPos < 0)
        {
            return 1; // DocMDP exists but no explicit /P — most restrictive
        }

        // Skip whitespace after "/P "
        int valuePos = permKeyPos + PermissionKey.Length;
        while (valuePos < permSearchEnd - tmPos && data[tmPos + valuePos] == ' ')
        {
            valuePos++;
        }

        if (valuePos >= permSearchEnd - tmPos)
        {
            return 1;
        }

        // Parse integer (handles optional negative sign)
        int startPos = valuePos;
        if (data[tmPos + valuePos] == '-')
        {
            valuePos++;
        }

        while (valuePos < permSearchEnd - tmPos &&
               data[tmPos + valuePos] >= (byte)'0' &&
               data[tmPos + valuePos] <= (byte)'9')
        {
            valuePos++;
        }

        if (valuePos <= startPos)
        {
            return 1;
        }

        int permissionLevel = 0;
        for (int i = startPos; i < valuePos; i++)
        {
            byte b = data[tmPos + i];
            if (b == (byte)'-')
            {
                continue;
            }

            permissionLevel = permissionLevel * 10 + (b - '0');
        }

        return permissionLevel is >= 1 and <= 3 ? permissionLevel : 1;
    }

    /// <summary>
    /// Detects whether a PDF contains an /Encrypt dictionary in the trailer.
    /// </summary>
    private static bool DetectEncryption(ReadOnlySpan<byte> data)
    {
        // Search for /Encrypt in the trailer region (last 4KB typically)
        int searchStart = Math.Max(0, data.Length - 4096);
        if (IsEncryptReference(data, searchStart))
        {
            return true;
        }

        // Also check from the start (for linearized PDFs where trailer is near the beginning)
        return IsEncryptReference(data, 0, Math.Min(data.Length, 4096));
    }

    /// <summary>
    /// Checks whether /Encrypt is followed by whitespace and a digit or inline dict,
    /// to avoid false positives on content streams containing the literal string.
    /// </summary>
    private static bool IsEncryptReference(ReadOnlySpan<byte> data, int regionStart, int regionLength = -1)
    {
        var region = regionLength >= 0 ? data.Slice(regionStart, regionLength) : data[regionStart..];
        int idx = IndexOf(region, EncryptKey, 0);
        while (idx >= 0)
        {
            int afterKey = idx + EncryptKey.Length;
            if (afterKey < region.Length)
            {
                byte next = region[afterKey];
                if (next == (byte)' ' || next == (byte)'\n' || next == (byte)'\r' || next == (byte)'\t')
                {
                    return true;
                }
                if (next == (byte)'<')
                {
                    return true;
                }
            }
            // Not a valid reference, keep searching
            idx = afterKey < region.Length ? IndexOf(region, EncryptKey, afterKey) : -1;
        }
        return false;
    }

    /// <summary>
    /// Scans XMP metadata for pdfaid:part and pdfaid:conformance to determine PDF/A level.
    /// XMP metadata in PDFs is stored as XML inside a stream object.
    /// Handles compress ObjStm by first decompressing all ObjStms and scanning the decompressed data.
    /// </summary>
    internal static PdfALevel DetectPdfALevel(ReadOnlySpan<byte> data)
    {
        PdfALevel level = ScanForPdfAIdTags(data);
        if (level != PdfALevel.None)
        {
            return level;
        }

        return ScanCompressedObjStmsForPdfAIdTags(data);
    }

    private static PdfALevel ScanForPdfAIdTags(ReadOnlySpan<byte> span)
    {
        var partTag = "pdfaid:part>"u8;
        int partIdx = IndexOf(span, partTag, 0);
        if (partIdx < 0)
        {
            return PdfALevel.None;
        }

        return ParsePdfALevelFromSpan(span, partIdx, partTag);
    }

    private static PdfALevel ScanCompressedObjStmsForPdfAIdTags(ReadOnlySpan<byte> data)
    {
        ReadOnlySpan<byte> objStmMarker1 = "/Type /ObjStm"u8;
        ReadOnlySpan<byte> objStmMarker2 = "/Type/ObjStm"u8;
        ReadOnlySpan<byte> streamMarker = "stream"u8;
        var partTag = "pdfaid:part>"u8;

        int searchPos = 0;
        while (searchPos < data.Length)
        {
            int p1 = data[searchPos..].IndexOf(objStmMarker1);
            int p2 = data[searchPos..].IndexOf(objStmMarker2);
            int matchOffset;
            if (p1 >= 0 && p2 >= 0)
            { matchOffset = Math.Min(p1, p2); }
            else if (p1 >= 0)
            { matchOffset = p1; }
            else if (p2 >= 0)
            { matchOffset = p2; }
            else
            { break; }

            int absolutePos = searchPos + matchOffset;
            searchPos = absolutePos + 1;

            int objStart = ScanBackwardsForObjId(data, absolutePos);
            if (objStart < 0)
            {
                continue;
            }

            int streamKeyPos = IndexOf(data[objStart..], streamMarker, 0);
            if (streamKeyPos < 0)
            {
                continue;
            }

            int streamContentStart = objStart + streamKeyPos + streamMarker.Length;
            if (streamContentStart + 1 >= data.Length)
            {
                continue;
            }

            if (data[streamContentStart] == (byte)'\r')
            {
                streamContentStart++;
            }

            if (streamContentStart < data.Length && data[streamContentStart] == (byte)'\n')
            {
                streamContentStart++;
            }

            int endstreamPos = data[streamContentStart..].IndexOf("\nendstream"u8);
            if (endstreamPos < 0)
            {
                continue;
            }

            int streamContentEnd = streamContentStart + endstreamPos;
            var compressed = data.Slice(streamContentStart, streamContentEnd - streamContentStart);

            try
            {
                byte[] decompressed = InflateZlib(compressed);
                if (decompressed.Length == 0)
                {
                    continue;
                }

                int partIdx = new ReadOnlySpan<byte>(decompressed).IndexOf(partTag);
                if (partIdx >= 0)
                {
                    return ParsePdfALevelFromSpan(new ReadOnlySpan<byte>(decompressed), partIdx, partTag);
                }
            }
            catch
            {
            }
        }

        return PdfALevel.None;
    }

    private static int ScanBackwardsForObjId(ReadOnlySpan<byte> data, int fromPos)
    {
        int searchStart = Math.Max(0, fromPos - 512);
        ReadOnlySpan<byte> region = data[searchStart..fromPos];
        var objMarker = " obj"u8;
        int objIdx = -1;
        for (int i = region.Length - objMarker.Length; i >= 0; i--)
        {
            bool match = true;
            for (int j = 0; j < objMarker.Length; j++)
            {
                if (region[i + j] != objMarker[j])
                {
                    match = false;
                    break;
                }
            }
            if (match)
            {
                objIdx = i;
                break;
            }
        }

        if (objIdx < 0)
        {
            return -1;
        }

        int numEnd = searchStart + objIdx;
        int numStart = numEnd;
        while (numStart > searchStart && data[numStart - 1] >= (byte)'0' && data[numStart - 1] <= (byte)'9')
        {
            numStart--;
        }

        return numStart < numEnd ? numStart : -1;
    }

    private static PdfALevel ParsePdfALevelFromSpan(ReadOnlySpan<byte> span, int partIdx, ReadOnlySpan<byte> partTag)
    {
        int partStart = partIdx + partTag.Length;
        if (partStart >= span.Length)
        {
            return PdfALevel.Unknown;
        }
        int part = span[partStart] - '0';

        var confTag = "pdfaid:conformance>"u8;
        int confIdx = IndexOf(span, confTag, partIdx);
        char conformance = 'B';
        if (confIdx >= 0)
        {
            int confStart = confIdx + confTag.Length;
            if (confStart < span.Length)
            {
                conformance = char.ToUpperInvariant((char)span[confStart]);
            }
        }

        return (part, conformance) switch
        {
            (1, 'A') => PdfALevel.A1a,
            (1, 'B') => PdfALevel.A1b,
            (2, 'A') => PdfALevel.A2a,
            (2, 'B') => PdfALevel.A2b,
            (2, 'U') => PdfALevel.A2u,
            (3, 'A') => PdfALevel.A3a,
            (3, 'B') => PdfALevel.A3b,
            (3, 'U') => PdfALevel.A3u,
            (4, 'A') => PdfALevel.A4a,
            (4, 'B') => PdfALevel.A4b,
            (4, 'U') => PdfALevel.A4u,
            (4, 'E') => PdfALevel.A4e,
            _ => PdfALevel.Unknown
        };
    }
    #endregion
}
