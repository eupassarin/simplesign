using System.Buffers;
using System.IO.Compression;
using System.Text;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using SimpleSign.Core.Constants;
using SimpleSign.Pdf.Enums;
using SimpleSign.Pdf.Exceptions;

namespace SimpleSign.Pdf;

/// <summary>
/// Reads PDF structure to extract digital signature fields and their metadata.
/// Supports classic xref tables, xref streams (PDF 1.5+), and FlateDecode compression.
/// </summary>
public sealed class PdfStructureReader
{
    /// <summary>Maximum PDF file size supported (200 MB).</summary>
    public const int MaxPdfSize = 200 * 1024 * 1024;

    /// <summary>Maximum number of xref revisions to follow via /Prev chain.</summary>
    private const int MaxXrefRevisions = 100;

    /// <summary>Search window for /P permission level after /TransformMethod /DocMDP (bytes).</summary>
    private const int PermissionSearchWindow = 2048;

    /// <summary>Maximum stream scan size when /Length is missing (10 MB).</summary>
    private const int MaxStreamScanBytes = 10 * 1024 * 1024;

    #region PDF byte markers

    private static ReadOnlySpan<byte> PdfHeaderMarker => "%PDF-"u8;
    private static ReadOnlySpan<byte> StartXrefMarker => "startxref"u8;
    private static ReadOnlySpan<byte> XrefMarker => "xref"u8;
    private static ReadOnlySpan<byte> TrailerMarker => "trailer"u8;
    private static ReadOnlySpan<byte> ObjMarker => " obj"u8;
    private static ReadOnlySpan<byte> StreamMarker => "stream"u8;
    private static ReadOnlySpan<byte> EndStreamMarker => "endstream"u8;
    private static ReadOnlySpan<byte> ByteRangeKey => "/ByteRange"u8;
    private static ReadOnlySpan<byte> PrevKey => "/Prev "u8;
    private static ReadOnlySpan<byte> TransformMethodDocMdp => "/TransformMethod /DocMDP"u8;
    private static ReadOnlySpan<byte> PermissionKey => "/P "u8;
    private static ReadOnlySpan<byte> EncryptKey => "/Encrypt"u8;
    #endregion

    #region Public API

    /// <summary>
    /// Reads all digital signature fields from a PDF stream.
    /// Parses the cross-reference table (classic or stream) and scans for /ByteRange dictionaries.
    /// </summary>
    public static async Task<IReadOnlyList<PdfSignatureField>> ReadSignatureFieldsAsync(
        Stream pdfStream, ILogger? logger = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(pdfStream);
        if (!pdfStream.CanSeek)
        {
            throw new ArgumentException("Stream must be seekable to parse PDF structure.", nameof(pdfStream));
        }

        (logger ?? NullLogger.Instance).PdfReadingSignatureFields(pdfStream.Length);

        byte[] buffer = ArrayPool<byte>.Shared.Rent((int)Math.Min(pdfStream.Length, MaxPdfSize));
        try
        {
            pdfStream.Seek(0, SeekOrigin.Begin);
            int bytesRead = await ReadFullyAsync(pdfStream, buffer, cancellationToken).ConfigureAwait(false);
            Span<byte> data = buffer.AsSpan(0, bytesRead);

            ValidatePdfHeader(data);
            ThrowIfEncrypted(data);
            var crossRefs = ParseCrossReferenceTable(data);
            var fields = ExtractSignatureFields(data, crossRefs);

            (logger ?? NullLogger.Instance).PdfSignatureFieldsFound(fields.Count);

            return fields;
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    /// <summary>
    /// Checks if the PDF has a DocMDP certification signature that prohibits further modifications.
    /// Returns true if the document is locked (permission level &lt; 3).
    /// </summary>
    public static async Task<bool> IsDocMdpLockedAsync(
        Stream pdfStream, ILogger? logger = null, CancellationToken cancellationToken = default)
    {
        int level = await GetDocMdpPermissionLevelAsync(pdfStream, logger, cancellationToken).ConfigureAwait(false);
        return level > 0 && level < 3;
    }

    /// <summary>
    /// Detects if the PDF is linearized (§9.9). Linearized PDFs have a Linearized dictionary
    /// in the first object. This is informational — linearized PDFs are fully supported for
    /// signature operations since we always follow the startxref chain from the end of the file.
    /// </summary>
    public static bool IsLinearized(ReadOnlySpan<byte> data)
    {
        // The Linearized dictionary must be in the first 1024 bytes
        int searchLen = Math.Min(data.Length, 1024);
        return IndexOf(data[..searchLen], "/Linearized"u8, 0) >= 0;
    }

    /// <summary>
    /// Returns the DocMDP permission level from the PDF.
    /// 0 = no DocMDP, 1 = no changes allowed, 2 = form filling only, 3 = form filling and annotations.
    /// </summary>
    public static async Task<int> GetDocMdpPermissionLevelAsync(
        Stream pdfStream, ILogger? logger = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(pdfStream);
        byte[] buffer = ArrayPool<byte>.Shared.Rent((int)Math.Min(pdfStream.Length, MaxPdfSize));
        try
        {
            pdfStream.Seek(0, SeekOrigin.Begin);
            int bytesRead = await ReadFullyAsync(pdfStream, buffer, cancellationToken).ConfigureAwait(false);
            Span<byte> data = buffer.AsSpan(0, bytesRead);

            int level = GetDocMdpPermissionLevel(data);
            (logger ?? NullLogger.Instance).PdfDocMdpChecked(level > 0 && level < 3);
            return level;
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    /// <summary>
    /// Checks if the PDF is encrypted. Encrypted PDFs cannot be signed or validated by SimpleSign.
    /// </summary>
    public static async Task<bool> IsEncryptedAsync(
        Stream pdfStream, ILogger? logger = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(pdfStream);
        byte[] buffer = ArrayPool<byte>.Shared.Rent((int)Math.Min(pdfStream.Length, MaxPdfSize));
        try
        {
            pdfStream.Seek(0, SeekOrigin.Begin);
            int bytesRead = await ReadFullyAsync(pdfStream, buffer, cancellationToken).ConfigureAwait(false);
            bool encrypted = DetectEncryption(buffer.AsSpan(0, bytesRead));
            (logger ?? NullLogger.Instance).PdfEncryptionChecked(encrypted);
            return encrypted;
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    /// <summary>
    /// Detects the PDF/A conformance level by scanning XMP metadata for <c>pdfaid:part</c>
    /// and <c>pdfaid:conformance</c> elements.
    /// </summary>
    public static async Task<PdfALevel> DetectPdfALevelAsync(
        Stream pdfStream, ILogger? logger = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(pdfStream);
        byte[] buffer = ArrayPool<byte>.Shared.Rent((int)Math.Min(pdfStream.Length, MaxPdfSize));
        try
        {
            pdfStream.Seek(0, SeekOrigin.Begin);
            int bytesRead = await ReadFullyAsync(pdfStream, buffer, cancellationToken).ConfigureAwait(false);
            PdfALevel level = DetectPdfALevel(buffer.AsSpan(0, bytesRead));
            (logger ?? NullLogger.Instance).PdfADetected(level.ToString());
            return level;
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    /// <summary>
    /// Reads the signed byte ranges from a PDF stream, concatenating both segments.
    /// Used to compute the hash for signature verification.
    /// </summary>
    public static async Task<byte[]> ReadSignedBytesAsync(
        Stream pdfStream, PdfByteRange byteRange, ILogger? logger = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(pdfStream);
        ArgumentNullException.ThrowIfNull(byteRange);
        if (!byteRange.IsValid)
        {
            throw new ArgumentException("Invalid ByteRange.", nameof(byteRange));
        }

        (logger ?? NullLogger.Instance).PdfReadingSignedBytes(byteRange.Offset1, byteRange.Length1, byteRange.Offset2, byteRange.Length2);

        byte[] result = new byte[byteRange.Length1 + byteRange.Length2];

        // Read first segment (before /Contents)
        pdfStream.Seek(byteRange.Offset1, SeekOrigin.Begin);
        await ReadExactAsync(pdfStream, result.AsMemory(0, (int)byteRange.Length1), cancellationToken).ConfigureAwait(false);

        // Read second segment (after /Contents)
        pdfStream.Seek(byteRange.Offset2, SeekOrigin.Begin);
        await ReadExactAsync(pdfStream, result.AsMemory((int)byteRange.Length1, (int)byteRange.Length2), cancellationToken).ConfigureAwait(false);

        (logger ?? NullLogger.Instance).PdfSignedBytesRead(byteRange.Length1 + byteRange.Length2);

        return result;
    }
    /// <summary>
    /// Detects the PDF version from the header of a PDF stream.
    /// Returns <see cref="PdfVersion.Unknown"/> if the header cannot be parsed.
    /// </summary>
    public static async Task<PdfVersion> DetectPdfVersionAsync(
        Stream pdfStream, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(pdfStream);
        byte[] buffer = ArrayPool<byte>.Shared.Rent((int)Math.Min(pdfStream.Length, MaxPdfSize));
        try
        {
            pdfStream.Seek(0, SeekOrigin.Begin);
            int bytesRead = await ReadFullyAsync(pdfStream, buffer, cancellationToken).ConfigureAwait(false);
            return DetectPdfVersion(buffer.AsSpan(0, bytesRead));
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    /// <summary>
    /// Detects the PDF version from the header bytes (%PDF-X.Y).
    /// Returns <see cref="PdfVersion.Unknown"/> if the header cannot be parsed.
    /// </summary>
    public static PdfVersion DetectPdfVersion(ReadOnlySpan<byte> data)
    {
        // Header must start with %PDF- and have at least 8 bytes: %PDF-X.Y
        if (data.Length < 8 || !data.StartsWith(PdfHeaderMarker))
        {
            return PdfVersion.Unknown;
        }

        byte major = data[5];
        byte dot = data[6];
        byte minor = data[7];

        if (dot != (byte)'.' || major < (byte)'0' || major > (byte)'9' || minor < (byte)'0' || minor > (byte)'9')
        {
            return PdfVersion.Unknown;
        }

        int version = (major - '0') * 10 + (minor - '0');
        return Enum.IsDefined((PdfVersion)version) ? (PdfVersion)version : PdfVersion.Unknown;
    }

    /// <summary>
    /// Detects the PDF version from a byte array.
    /// </summary>
    public static PdfVersion DetectPdfVersion(byte[] data)
    {
        ArgumentNullException.ThrowIfNull(data);
        return DetectPdfVersion(data.AsSpan());
    }

    #endregion

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

    #region Cross-Reference Table Parsing

    /// <summary>
    /// Parses the complete cross-reference chain, following /Prev pointers through all revisions.
    /// Supports both classic xref tables and xref streams (PDF 1.5+).
    /// </summary>
    private static List<PdfCrossRef> ParseCrossReferenceTable(ReadOnlySpan<byte> data)
    {
        var crossRefs = new List<PdfCrossRef>();
        var seenObjects = new HashSet<int>();
        // Collect Type 2 xref entries: objects compressed inside Object Streams (ObjStm)
        var compressedEntries = new List<PdfCompressedObjectRef>();

        long startXrefPos = FindStartXRef(data);
        if (startXrefPos < 0)
        {
            throw new PdfStructureException("PDF is missing 'startxref' marker.");
        }

        long xrefOffset = ReadLongAfterMarker(data, (int)(startXrefPos + StartXrefMarker.Length));
        if (xrefOffset < 0)
        {
            throw new PdfStructureException("Invalid startxref offset.", xrefOffset);
        }

        // Follow /Prev chain through all revisions (with cycle detection)
        var visitedOffsets = new HashSet<long>();
        int remainingRevisions = MaxXrefRevisions;

        while (xrefOffset > 0 && remainingRevisions-- > 0 && visitedOffsets.Add(xrefOffset))
        {
            int offset = (int)xrefOffset;
            if (offset < 0 || offset >= data.Length)
            {
                break;
            }

            // Determine if this is a classic xref table or an xref stream
            long prevOffset = data[offset..].StartsWith(XrefMarker)
                ? ParseClassicXrefRevision(data, offset, crossRefs, seenObjects)
                : ParseXrefStreamRevision(data, offset, crossRefs, seenObjects, compressedEntries);

            if (prevOffset <= 0)
            {
                break;
            }

            xrefOffset = prevOffset;
        }

        // Resolve Object Streams: decompress ObjStm objects to find byte offsets of compressed objects
        if (compressedEntries.Count > 0)
        {
            ResolveObjectStreams(data, crossRefs, seenObjects, compressedEntries);
        }

        return crossRefs;
    }

    /// <summary>Entry for a Type 2 xref record: an object compressed inside an Object Stream.</summary>
    private readonly record struct PdfCompressedObjectRef(int ObjectNumber, int ObjStmNumber, int IndexInStream);

    /// <summary>
    /// Parses a classic xref table revision (text format).
    /// Format: "xref\n0 6\n0000000000 65535 f \n0000000009 00000 n \n..."
    /// Returns the /Prev offset from the trailer, or -1 if no more revisions.
    /// </summary>
    private static long ParseClassicXrefRevision(
        ReadOnlySpan<byte> data, int startPos, List<PdfCrossRef> crossRefs, HashSet<int> seenObjects)
    {
        int pos = SkipToNextLine(data, startPos + XrefMarker.Length);

        while (pos < data.Length)
        {
            // Check if we've reached the trailer
            if (data[pos..].StartsWith(TrailerMarker))
            {
                return FindPrevInTrailer(data, pos);
            }

            // Read subsection header: "firstObjNum count"
            if (!TryReadTwoIntegers(data, pos, out int firstObjNum, out int entryCount, out int afterPos))
            {
                break;
            }

            pos = SkipToNextLine(data, afterPos);

            // Read each 20-byte xref entry
            for (int i = 0; i < entryCount; i++)
            {
                if (pos + 20 > data.Length)
                {
                    break;
                }

                ReadOnlySpan<byte> entry = data.Slice(pos, Math.Min(20, data.Length - pos));
                if (entry.Length >= 18)
                {
                    long byteOffset = ParseFixedInt(entry, 0, 10);
                    byte statusFlag = entry[17]; // 'n' (110) = in-use, 'f' (102) = free
                    int objectNumber = firstObjNum + i;

                    if (statusFlag == (byte)'n' && byteOffset > 0 && seenObjects.Add(objectNumber))
                    {
                        crossRefs.Add(new PdfCrossRef(objectNumber, byteOffset));
                    }
                }
                pos += 20;
            }
        }

        return -1;
    }

    /// <summary>
    /// Finds the /Prev offset value in a trailer dictionary.
    /// Searches only within the trailer's dictionary (&lt;&lt;...&gt;&gt;), not beyond it.
    /// </summary>
    private static long FindPrevInTrailer(ReadOnlySpan<byte> data, int trailerPos)
    {
        // Find the dictionary start (<<) after "trailer"
        int dictStart = IndexOf(data[trailerPos..Math.Min(trailerPos + 64, data.Length)], "<<"u8, 0);
        if (dictStart < 0)
        {
            return -1;
        }

        int absDictStart = trailerPos + dictStart;
        int dictEnd = FindMatchingDictEnd(data, absDictStart);
        int searchEnd = dictEnd > absDictStart ? dictEnd + 2 : Math.Min(trailerPos + 512, data.Length);

        int prevKeyPos = IndexOf(data[trailerPos..searchEnd], PrevKey, 0);
        if (prevKeyPos < 0)
        {
            return -1;
        }

        int valuePos = trailerPos + prevKeyPos + PrevKey.Length;
        return ParseDecimalLong(data, valuePos);
    }

    /// <summary>
    /// Parses a cross-reference stream revision (PDF 1.5+ binary format).
    /// The xref data is stored as a stream object with /W [w1 w2 w3] field widths.
    /// Returns the /Prev offset, or -1 if no more revisions.
    /// </summary>
    private static long ParseXrefStreamRevision(
        ReadOnlySpan<byte> data, int pos, List<PdfCrossRef> crossRefs, HashSet<int> seenObjects,
        List<PdfCompressedObjectRef>? compressedEntries = null, ILogger? logger = null)
    {
        // Find the stream keyword to delimit the dictionary region
        int streamKeywordOffset = IndexOf(data[pos..], StreamMarker, 0);
        if (streamKeywordOffset < 0)
        {
            return -1;
        }

        ReadOnlySpan<byte> dictRegion = data.Slice(pos, streamKeywordOffset);

        // Extract /Prev value for chain traversal
        long prevOffset = -1;
        int prevKeyPos = IndexOf(dictRegion, PrevKey, 0);
        if (prevKeyPos >= 0)
        {
            long parsedPrev = ParseDecimalLong(dictRegion, prevKeyPos + PrevKey.Length);
            if (parsedPrev > 0)
            {
                prevOffset = parsedPrev;
            }
        }

        try
        {
            DecodeXrefStream(data, pos, dictRegion, crossRefs, seenObjects, compressedEntries);
        }
        catch (Exception ex) when (ex is InvalidDataException or ArgumentOutOfRangeException or OverflowException)
        {
            logger?.XrefStreamDecodingFailed(ex.Message);
        }

        return prevOffset;
    }

    /// <summary>
    /// Decodes the binary content of an xref stream object.
    /// Reads /W (field widths), /Index (subsection ranges), /Filter, then decompresses and parses entries.
    /// </summary>
    private static void DecodeXrefStream(
        ReadOnlySpan<byte> data, int objPos, ReadOnlySpan<byte> dictRegion,
        List<PdfCrossRef> crossRefs, HashSet<int> seenObjects,
        List<PdfCompressedObjectRef>? compressedEntries = null)
    {
        if (!ParseXrefFieldWidths(dictRegion, out int w1, out int w2, out int w3, out int entrySize))
        {
            return;
        }

        var subsections = ParseXrefSubsections(dictRegion);
        if (subsections.Count == 0)
        {
            return;
        }

        // Extract raw stream bytes using /Length or endstream fallback
        ReadOnlySpan<byte> rawStreamData = ExtractStreamBytes(data, objPos, dictRegion);
        if (rawStreamData.IsEmpty)
        {
            return;
        }

        // Decode stream filters (ASCII85Decode, FlateDecode, or both)
        byte[] decodedData = ApplyStreamFilters(rawStreamData, dictRegion);
        if (decodedData.Length == 0)
        {
            return;
        }

        // Apply PNG predictor if DecodeParms specifies one (Predictor >= 10)
        int predictor = ParseDecodeParmInt(dictRegion, "/Predictor "u8);
        if (predictor >= 10)
        {
            int columns = ParseDecodeParmInt(dictRegion, "/Columns "u8);
            if (columns <= 0)
            {
                columns = entrySize;
            }

            decodedData = ApplyPngPredictor(decodedData, columns);
            if (decodedData.Length == 0)
            {
                return;
            }
        }

        DecompressAndClassifyXrefEntries(decodedData, subsections, w1, w2, w3, entrySize, crossRefs, seenObjects, compressedEntries);
    }

    /// <summary>
    /// Parses the /W array from an xref stream dictionary and validates field widths.
    /// Returns the three field widths (type, value, generation/index) and the total entry size.
    /// </summary>
    private static bool ParseXrefFieldWidths(
        ReadOnlySpan<byte> dictRegion, out int w1, out int w2, out int w3, out int entrySize)
    {
        w1 = w2 = w3 = entrySize = 0;

        int wKeyPos = IndexOf(dictRegion, "/W"u8, 0);
        if (wKeyPos < 0)
        {
            return false;
        }

        int arrayStart = wKeyPos + 2;
        while (arrayStart < dictRegion.Length && dictRegion[arrayStart] != '[')
        {
            arrayStart++;
        }

        if (arrayStart >= dictRegion.Length)
        {
            return false;
        }

        arrayStart++; // skip '['

        if (!TryParseDecimalLong(dictRegion, SkipWhitespace(dictRegion, arrayStart), out long typeWidth, out int afterW1)
            || !TryParseDecimalLong(dictRegion, SkipWhitespace(dictRegion, afterW1), out long valueWidth, out int afterW2)
            || !TryParseDecimalLong(dictRegion, SkipWhitespace(dictRegion, afterW2), out long genWidth, out _))
        {
            return false;
        }

        w1 = (int)typeWidth;
        w2 = (int)valueWidth;
        w3 = (int)genWidth;
        entrySize = w1 + w2 + w3;
        return entrySize > 0;
    }

    /// <summary>
    /// Parses the /Index array from an xref stream dictionary, or defaults to [0, /Size].
    /// Returns a list of (startObjNum, count) subsection tuples.
    /// </summary>
    private static List<(int StartObjNum, int Count)> ParseXrefSubsections(ReadOnlySpan<byte> dictRegion)
    {
        // Parse /Size (total object count, used as default /Index)
        long totalSize = 0;
        int sizeKeyPos = IndexOf(dictRegion, "/Size "u8, 0);
        if (sizeKeyPos >= 0)
        {
            TryParseDecimalLong(dictRegion, sizeKeyPos + "/Size "u8.Length, out totalSize, out _);
        }

        // Parse /Index [start1 count1 start2 count2 ...] — subsection ranges
        var subsections = new List<(int StartObjNum, int Count)>();
        int indexKeyPos = IndexOf(dictRegion, "/Index"u8, 0);
        if (indexKeyPos >= 0)
        {
            int idxPos = indexKeyPos + "/Index"u8.Length;
            while (idxPos < dictRegion.Length && dictRegion[idxPos] != '[')
            {
                idxPos++;
            }

            idxPos++; // skip '['

            while (idxPos < dictRegion.Length && dictRegion[idxPos] != ']')
            {
                idxPos = SkipWhitespace(dictRegion, idxPos);
                if (idxPos >= dictRegion.Length || dictRegion[idxPos] == ']'
                    || !TryParseDecimalLong(dictRegion, idxPos, out long startObj, out idxPos))
                {
                    break;
                }

                idxPos = SkipWhitespace(dictRegion, idxPos);
                if (!TryParseDecimalLong(dictRegion, idxPos, out long count, out idxPos))
                {
                    break;
                }

                subsections.Add(((int)startObj, (int)count));
            }
        }

        // Default /Index is [0 Size]
        if (subsections.Count == 0 && totalSize > 0)
        {
            subsections.Add((0, (int)totalSize));
        }

        return subsections;
    }

    /// <summary>
    /// Classifies decoded xref stream entries into cross-references (type 1) and compressed entries (type 2).
    /// </summary>
    private static void DecompressAndClassifyXrefEntries(
        byte[] decodedData, List<(int StartObjNum, int Count)> subsections,
        int w1, int w2, int w3, int entrySize,
        List<PdfCrossRef> crossRefs, HashSet<int> seenObjects,
        List<PdfCompressedObjectRef>? compressedEntries)
    {
        // Parse xref entries: each entry is [type(w1) value(w2) gen(w3)]
        // Type 0 = free, Type 1 = uncompressed object (value = byte offset), Type 2 = compressed in ObjStm
        int dataOffset = 0;
        foreach (var (startObjNum, count) in subsections)
        {
            for (int i = 0; i < count; i++)
            {
                if (dataOffset + entrySize > decodedData.Length)
                {
                    return;
                }

                int entryType = ReadBigEndianInt(decodedData, dataOffset, w1);
                int entryValue = ReadBigEndianInt(decodedData, dataOffset + w1, w2);
                int entryGen = ReadBigEndianInt(decodedData, dataOffset + w1 + w2, w3);
                int objectNumber = startObjNum + i;

                if (entryType == 1 && entryValue > 0 && seenObjects.Add(objectNumber))
                {
                    // Type 1 = uncompressed object at byte offset entryValue
                    crossRefs.Add(new PdfCrossRef(objectNumber, entryValue));
                }
                else if (entryType == 2 && compressedEntries != null && seenObjects.Add(objectNumber))
                {
                    // Type 2 = object compressed in ObjStm (entryValue = ObjStm obj#, entryGen = index)
                    compressedEntries.Add(new PdfCompressedObjectRef(objectNumber, entryValue, entryGen));
                }

                dataOffset += entrySize;
            }
        }
    }

    /// <summary>
    /// Resolves Type 2 xref entries by decompressing their parent Object Streams.
    /// An Object Stream (ObjStm) contains multiple objects packed together with FlateDecode.
    /// The stream header lists N (object_number, byte_offset) pairs, followed by the object data.
    /// </summary>
    private static void ResolveObjectStreams(
        ReadOnlySpan<byte> data, List<PdfCrossRef> crossRefs, HashSet<int> seenObjects,
        List<PdfCompressedObjectRef> compressedEntries, ILogger? logger = null)
    {
        // Group entries by their containing ObjStm
        var byObjStm = new Dictionary<int, List<PdfCompressedObjectRef>>();
        foreach (var entry in compressedEntries)
        {
            if (!byObjStm.TryGetValue(entry.ObjStmNumber, out var list))
            {
                list = [];
                byObjStm[entry.ObjStmNumber] = list;
            }
            list.Add(entry);
        }

        foreach (var (objStmNum, entries) in byObjStm)
        {
            try
            {
                var result = ExtractObjStmContent(data, crossRefs, objStmNum);
                if (result == null)
                {
                    continue;
                }

                var (decompressed, objCount, firstObjDataOffset) = result.Value;

                ParseObjStmOffsets(decompressed, objCount, entries, crossRefs);
            }
            catch (Exception ex) when (ex is InvalidDataException or ArgumentOutOfRangeException or IndexOutOfRangeException)
            {
                logger?.ObjStmResolveFailed(objStmNum, ex.Message);
            }
        }
    }

    /// <summary>
    /// Locates an ObjStm object, parses /N and /First from its dictionary,
    /// and extracts and decompresses the stream content.
    /// Returns the decompressed bytes, object count, and first object data offset, or null on failure.
    /// </summary>
    private static (byte[] Decompressed, long ObjCount, long FirstObjDataOffset)? ExtractObjStmContent(
        ReadOnlySpan<byte> data, List<PdfCrossRef> crossRefs, int objStmNum)
    {
        // Find the ObjStm object's byte offset in crossRefs
        int objStmOffset = -1;
        foreach (var xref in crossRefs)
        {
            if (xref.ObjectNumber == objStmNum)
            {
                objStmOffset = (int)xref.Offset;
                break;
            }
        }
        if (objStmOffset < 0 || objStmOffset >= data.Length)
        {
            return null;
        }

        // Parse ObjStm dictionary to get /N (number of objects) and /First (byte offset of first object)
        int streamKeyPos = IndexOf(data[objStmOffset..], StreamMarker, 0);
        if (streamKeyPos < 0)
        {
            return null;
        }

        ReadOnlySpan<byte> objStmDict = data.Slice(objStmOffset, streamKeyPos);

        int nPos = IndexOf(objStmDict, "/N "u8, 0);
        int firstPos = IndexOf(objStmDict, "/First "u8, 0);
        if (nPos < 0 || firstPos < 0)
        {
            return null;
        }

        if (!TryParseDecimalLong(objStmDict, nPos + "/N "u8.Length, out long objCount, out _))
        {
            return null;
        }
        if (!TryParseDecimalLong(objStmDict, firstPos + "/First "u8.Length, out long firstObjDataOffset, out _))
        {
            return null;
        }

        // Extract and decompress the stream data
        ReadOnlySpan<byte> rawStream = ExtractStreamBytes(data, objStmOffset, objStmDict);
        if (rawStream.IsEmpty)
        {
            return null;
        }

        byte[] decompressed = ApplyStreamFilters(rawStream, objStmDict);
        if (decompressed.Length == 0)
        {
            return null;
        }

        return (decompressed, objCount, firstObjDataOffset);
    }

    /// <summary>
    /// Parses the object number/offset pairs from the decompressed ObjStm header,
    /// and adds matching compressed entries to the cross-references list with sentinel offset -1.
    /// </summary>
    private static void ParseObjStmOffsets(
        byte[] decompressed, long objCount,
        List<PdfCompressedObjectRef> entries, List<PdfCrossRef> crossRefs)
    {
        // Parse the header: N pairs of (objectNumber byteOffset)
        // These offsets are relative to /First
        var objOffsets = new List<(int ObjNum, int Offset)>();
        int headerPos = 0;
        for (int i = 0; i < (int)objCount && headerPos < decompressed.Length; i++)
        {
            headerPos = SkipWhitespace(decompressed, headerPos);
            if (!TryParseDecimalLong(decompressed, headerPos, out long num, out headerPos))
            {
                break;
            }
            headerPos = SkipWhitespace(decompressed, headerPos);
            if (!TryParseDecimalLong(decompressed, headerPos, out long off, out headerPos))
            {
                break;
            }
            objOffsets.Add(((int)num, (int)off));
        }

        // For each compressed entry, add to crossRefs with sentinel offset -1.
        // Signature value dictionaries (with /ByteRange) are never in ObjStm,
        // but catalog/AcroForm objects may be. The brute-force /ByteRange scan
        // in ExtractSignatureFields works on the main buffer regardless.
        foreach (var entry in entries)
        {
            if (entry.IndexInStream >= 0 && entry.IndexInStream < objOffsets.Count)
            {
                crossRefs.Add(new PdfCrossRef(entry.ObjectNumber, -1));
            }
        }
    }

    /// <summary>
    /// Reads a big-endian integer from a byte array with the given field width.
    /// </summary>
    private static int ReadBigEndianInt(byte[] data, int offset, int width)
    {
        if (width == 0)
        {
            return 0;
        }

        int value = 0;
        for (int i = 0; i < width && offset + i < data.Length; i++)
        {
            value = (value << 8) | data[offset + i];
        }
        return value;
    }

    /// <summary>
    /// Extracts raw stream bytes from a PDF stream object.
    /// Uses /Length when available for precise extraction, falling back to endstream marker scan.
    /// </summary>
    internal static ReadOnlySpan<byte> ExtractStreamBytes(
        ReadOnlySpan<byte> data, int objPos, ReadOnlySpan<byte> dictRegion)
    {
        int streamKeyPos = IndexOf(data[objPos..], StreamMarker, 0);
        if (streamKeyPos < 0)
        {
            return [];
        }

        int streamStart = objPos + streamKeyPos + StreamMarker.Length;

        // Skip CR/LF after "stream" keyword
        if (streamStart < data.Length && data[streamStart] == '\r')
        {
            streamStart++;
        }

        if (streamStart < data.Length && data[streamStart] == '\n')
        {
            streamStart++;
        }

        // Try /Length first for precise stream extraction.
        // Supports both direct values (/Length 1234) and indirect references (/Length 5 0 R).
        int lengthKeyPos = IndexOf(dictRegion, "/Length "u8, 0);
        if (lengthKeyPos >= 0)
        {
            int lengthValPos = lengthKeyPos + "/Length "u8.Length;
            if (TryParseDecimalLong(dictRegion, lengthValPos, out long streamLength, out int afterNum))
            {
                // Check if this is an indirect reference: "N 0 R"
                int checkPos = SkipWhitespace(dictRegion, afterNum);
                if (checkPos < dictRegion.Length && dictRegion[checkPos] == (byte)'0')
                {
                    // Looks like "N 0 R" — dereference the object
                    int refObjNum = (int)streamLength;
                    streamLength = ResolveIndirectLength(data, refObjNum);
                }

                if (streamLength > 0 && streamStart + streamLength <= data.Length)
                {
                    return data.Slice(streamStart, (int)streamLength);
                }
            }
        }

        // Fallback: scan for endstream (limited to prevent hanging on malformed PDFs)
        int maxScan = Math.Min(data.Length - streamStart, MaxStreamScanBytes);
        int endstreamOffset = IndexOf(data.Slice(streamStart, maxScan), EndStreamMarker, 0);
        if (endstreamOffset < 0)
        {
            return [];
        }

        int streamEnd = streamStart + endstreamOffset;
        if (streamEnd > streamStart && data[streamEnd - 1] == '\n')
        {
            streamEnd--;
        }

        if (streamEnd > streamStart && data[streamEnd - 1] == '\r')
        {
            streamEnd--;
        }

        return data[streamStart..streamEnd];
    }

    /// <summary>
    /// Resolves an indirect /Length reference (e.g., "5 0 R") by finding the referenced object
    /// and extracting its numeric value. Returns 0 if resolution fails.
    /// ISO 32000-1 §7.5.1: /Length may be an indirect reference.
    /// </summary>
    internal static long ResolveIndirectLength(ReadOnlySpan<byte> data, int objNum)
    {
        // Search for "objNum 0 obj" — the object that holds the length value
        byte[] objHeader = Encoding.Latin1.GetBytes($"{objNum} 0 obj");
        int searchPos = 0;
        int matchPos = -1;

        while (searchPos < data.Length)
        {
            int found = IndexOf(data[searchPos..], objHeader, 0);
            if (found < 0)
            {
                break;
            }

            found += searchPos;

            // Ensure not a suffix match (e.g., "15 0 obj" matching "5 0 obj")
            if (found > 0 && data[found - 1] >= (byte)'0' && data[found - 1] <= (byte)'9')
            {
                searchPos = found + 1;
                continue;
            }

            matchPos = found;
            searchPos = found + objHeader.Length;
        }

        if (matchPos < 0)
        {
            return 0;
        }

        // The object body should contain just a number, e.g.: "5 0 obj\n1234\nendobj"
        int valueStart = matchPos + objHeader.Length;
        valueStart = SkipWhitespace(data, valueStart);

        return TryParseDecimalLong(data, valueStart, out long length, out _) ? length : 0;
    }

    /// <summary>
    /// Applies stream filters (ASCII85Decode, FlateDecode, or a chain of both) to raw stream data.
    /// Handles /Filter as a single name or an array of names (ISO 32000-1 §7.3.4.2).
    /// </summary>
    internal static byte[] ApplyStreamFilters(ReadOnlySpan<byte> rawData, ReadOnlySpan<byte> dictRegion)
    {
        int filterKeyPos = IndexOf(dictRegion, "/Filter"u8, 0);
        if (filterKeyPos < 0)
        {
            return rawData.ToArray();
        }

        var filterSlice = dictRegion[filterKeyPos..];
        bool hasAscii85 = IndexOf(filterSlice, "ASCII85Decode"u8, 0) >= 0;
        bool hasFlate = IndexOf(filterSlice, "FlateDecode"u8, 0) >= 0;

        byte[] result = rawData.ToArray();

        // Determine filter order from the /Filter value.
        // /Filter [/ASCII85Decode /FlateDecode] means: apply ASCII85 first, then Flate.
        // /Filter [/FlateDecode /ASCII85Decode] means: apply Flate first, then ASCII85.
        // For a single filter, just apply it.
        if (hasAscii85 && hasFlate)
        {
            // Check order: which appears first in the array?
            int a85Pos = IndexOf(filterSlice, "ASCII85Decode"u8, 0);
            int flatePos = IndexOf(filterSlice, "FlateDecode"u8, 0);
            if (a85Pos < flatePos)
            {
                result = DecodeAscii85(result);
                result = InflateZlib(result);
            }
            else
            {
                result = InflateZlib(result);
                result = DecodeAscii85(result);
            }
        }
        else if (hasFlate)
        {
            result = InflateZlib(result);
        }
        else if (hasAscii85)
        {
            result = DecodeAscii85(result);
        }

        return result;
    }

    /// <summary>
    /// Decodes ASCII85 (aka base85) encoded data per ISO 32000-1 §7.4.3.
    /// Handles &lt;~ ~&gt; delimiters, 'z' shorthand for four zero bytes,
    /// whitespace in the encoded stream, and final partial groups.
    /// </summary>
    internal static byte[] DecodeAscii85(ReadOnlySpan<byte> encoded)
    {
        // Find <~ and ~> delimiters if present
        int startIdx = 0;
        int endIdx = encoded.Length;

        int delimStart = IndexOf(encoded, "<~"u8, 0);
        if (delimStart >= 0)
        {
            startIdx = delimStart + 2;
        }

        int delimEnd = IndexOf(encoded, "~>"u8, startIdx);
        if (delimEnd >= 0)
        {
            endIdx = delimEnd;
        }

        var output = new MemoryStream(encoded.Length * 4 / 5);
        Span<byte> group = stackalloc byte[5];
        int groupLen = 0;

        for (int i = startIdx; i < endIdx; i++)
        {
            byte b = encoded[i];

            // Skip whitespace (space, tab, CR, LF, FF)
            if (b == ' ' || b == '\t' || b == '\r' || b == '\n' || b == '\f')
            {
                continue;
            }

            // 'z' is shorthand for four zero bytes (only valid outside partial groups)
            if (b == (byte)'z')
            {
                if (groupLen != 0)
                {
                    return []; // 'z' inside a partial group is invalid
                }

                output.WriteByte(0);
                output.WriteByte(0);
                output.WriteByte(0);
                output.WriteByte(0);
                continue;
            }

            // Valid ASCII85 characters are '!' (33) through 'u' (117)
            if (b < 33 || b > 117)
            {
                return []; // Invalid character
            }

            group[groupLen++] = (byte)(b - 33);

            if (groupLen == 5)
            {
                // Decode a full 5-character group into 4 bytes
                uint value = (uint)group[0] * 85 * 85 * 85 * 85
                           + (uint)group[1] * 85 * 85 * 85
                           + (uint)group[2] * 85 * 85
                           + (uint)group[3] * 85
                           + group[4];

                output.WriteByte((byte)(value >> 24));
                output.WriteByte((byte)(value >> 16));
                output.WriteByte((byte)(value >> 8));
                output.WriteByte((byte)value);
                groupLen = 0;
            }
        }

        // Handle final partial group (2-4 chars → 1-3 bytes)
        if (groupLen > 1)
        {
            // Pad with 'u' (value 84) to make a full group
            for (int j = groupLen; j < 5; j++)
            {
                group[j] = 84; // 'u' - 33
            }

            uint value = (uint)group[0] * 85 * 85 * 85 * 85
                       + (uint)group[1] * 85 * 85 * 85
                       + (uint)group[2] * 85 * 85
                       + (uint)group[3] * 85
                       + group[4];

            int bytesToWrite = groupLen - 1;
            if (bytesToWrite >= 1)
            {
                output.WriteByte((byte)(value >> 24));
            }

            if (bytesToWrite >= 2)
            {
                output.WriteByte((byte)(value >> 16));
            }

            if (bytesToWrite >= 3)
            {
                output.WriteByte((byte)(value >> 8));
            }
        }
        else if (groupLen == 1)
        {
            return []; // Single trailing char is invalid per spec
        }

        return output.ToArray();
    }

    /// <summary>
    /// Decompresses zlib-wrapped data (RFC 1950 = 2-byte header + RFC 1951 deflate).
    /// Skips the zlib header (2 bytes, or 6 if FDICT flag is set).
    /// </summary>
    private static byte[] InflateZlib(ReadOnlySpan<byte> compressedData, ILogger? logger = null)
    {
        if (compressedData.Length < 2)
        {
            return [];
        }

        try
        {
            // Skip zlib header: 2 bytes (CMF + FLG), plus 4 bytes if FDICT flag (bit 5 of FLG) is set
            int headerSize = 2;
            if ((compressedData[1] & Asn1Tags.ZlibFdictMask) != 0)
            {
                headerSize += 4; // FDICT present
            }

            if (compressedData.Length <= headerSize)
            {
                return [];
            }

            const int maxDecompressedSize = 50 * 1024 * 1024; // 50MB limit
            using var input = new MemoryStream(compressedData[headerSize..].ToArray());
            using var deflate = new DeflateStream(input, CompressionMode.Decompress);
            using var output = new MemoryStream();

            byte[] buffer = new byte[8192];
            int totalRead = 0;
            int bytesRead;
            while ((bytesRead = deflate.Read(buffer, 0, buffer.Length)) > 0)
            {
                totalRead += bytesRead;
                if (totalRead > maxDecompressedSize)
                {
                    throw new InvalidDataException($"Decompressed stream exceeds {maxDecompressedSize / (1024 * 1024)}MB limit — possible decompression bomb.");
                }
                output.Write(buffer, 0, bytesRead);
            }

            return output.ToArray();
        }
        catch (InvalidDataException)
        {
            throw;
        }
        catch (Exception ex) when (ex is InvalidOperationException or ArgumentException)
        {
            logger?.FlateDecodeDecompressionFailed(ex.Message);
            return [];
        }
    }

    /// <summary>
    /// Applies PNG row predictor (Predictor 10-15) to decoded stream data.
    /// Each row is (1 + columns) bytes: a filter type byte followed by column data bytes.
    /// Filter types: 0=None, 1=Sub, 2=Up.
    /// </summary>
    private static byte[] ApplyPngPredictor(byte[] data, int columns)
    {
        int rowSize = 1 + columns; // filter byte + data bytes
        if (rowSize <= 1 || data.Length < rowSize)
        {
            return data;
        }

        int rowCount = data.Length / rowSize;

        // Guard against multiplication overflow
        if (columns > int.MaxValue / Math.Max(rowCount, 1))
        {
            return data;
        }

        byte[] result = new byte[rowCount * columns];
        byte[] prevRow = new byte[columns];

        for (int row = 0; row < rowCount; row++)
        {
            int srcOffset = row * rowSize;
            int dstOffset = row * columns;
            byte filterType = data[srcOffset];

            switch (filterType)
            {
                case 0: // None
                    Buffer.BlockCopy(data, srcOffset + 1, result, dstOffset, columns);
                    break;
                case 1: // Sub
                    result[dstOffset] = data[srcOffset + 1];
                    for (int i = 1; i < columns; i++)
                    {
                        result[dstOffset + i] = (byte)(data[srcOffset + 1 + i] + result[dstOffset + i - 1]);
                    }
                    break;
                case 2: // Up
                    for (int i = 0; i < columns; i++)
                    {
                        result[dstOffset + i] = (byte)(data[srcOffset + 1 + i] + prevRow[i]);
                    }
                    break;
                default: // Average (3), Paeth (4) — rare in xref streams, treat as raw
                    Buffer.BlockCopy(data, srcOffset + 1, result, dstOffset, columns);
                    break;
            }

            Buffer.BlockCopy(result, dstOffset, prevRow, 0, columns);
        }

        return result;
    }

    /// <summary>
    /// Extracts an integer value from a DecodeParms dictionary entry (e.g., "/Predictor 12").
    /// Searches within the /DecodeParms sub-dictionary.
    /// </summary>
    private static int ParseDecodeParmInt(ReadOnlySpan<byte> dictRegion, ReadOnlySpan<byte> key)
    {
        int dpPos = IndexOf(dictRegion, "/DecodeParms"u8, 0);
        if (dpPos < 0)
        {
            return 0;
        }

        int keyPos = IndexOf(dictRegion[dpPos..], key, 0);
        if (keyPos < 0)
        {
            return 0;
        }

        return TryParseDecimalLong(dictRegion, dpPos + keyPos + key.Length, out long value, out _)
            ? (int)value
            : 0;
    }
    #endregion

    #region Signature Field Extraction

    /// <summary>
    /// Scans the PDF data for /ByteRange markers and extracts signature field metadata.
    /// </summary>
    private static IReadOnlyList<PdfSignatureField> ExtractSignatureFields(
        ReadOnlySpan<byte> data, List<PdfCrossRef> crossRefs)
    {
        var fields = new List<PdfSignatureField>();
        int searchPos = 0;

        while (searchPos < data.Length)
        {
            int byteRangePos = IndexOf(data, ByteRangeKey, searchPos);
            if (byteRangePos < 0)
            {
                break;
            }

            // Find the enclosing dictionary <<...>>
            int dictStart = FindDictStart(data, byteRangePos);
            if (dictStart < 0)
            {
                searchPos = byteRangePos + ByteRangeKey.Length;
                continue;
            }

            int objNumber = FindOwningObject(data, dictStart, crossRefs);
            int dictEnd = FindMatchingDictEnd(data, dictStart);
            if (dictEnd < 0)
            {
                searchPos = byteRangePos + ByteRangeKey.Length;
                continue;
            }

            var field = ParseSignatureDict(data[dictStart..(dictEnd + 2)], dictStart, objNumber, data);
            if (field is not null)
            {
                fields.Add(field);
            }

            // Always advance past the /ByteRange marker to prevent infinite loops
            // when FindDictStart returns a dict that doesn't contain /ByteRange
            searchPos = Math.Max(dictEnd + 2, byteRangePos + ByteRangeKey.Length);
        }

        return fields.AsReadOnly();
    }

    /// <summary>
    /// Parses a signature dictionary to extract ByteRange, Contents, signing time, and SubFilter.
    /// </summary>
    private static PdfSignatureField? ParseSignatureDict(
        ReadOnlySpan<byte> dictSpan, int dictAbsoluteOffset, int objNumber, ReadOnlySpan<byte> fullData)
    {
        var byteRange = ExtractByteRange(dictSpan);
        if (byteRange is null)
        {
            return null;
        }

        // Usage-rights signatures (Adobe Reader Extensions, /TransformMethod /UR3 in
        // the /Reference array) are not document signatures: Acrobat does not show them
        // in the signature panel, and they must not be reported by inspection or
        // validation. Skip them here so every consumer of this reader behaves
        // consistently.
        if (ContainsNameToken(dictSpan, "/UR3"u8))
        {
            return null;
        }

        byte[] contentsBytes = ExtractContents(byteRange, fullData);
        DateTimeOffset? signingTime = ExtractPdfDate(dictSpan);
        string? subFilter = ExtractPdfName(dictSpan, "/SubFilter"u8);
        string? reason = ExtractPdfString(dictSpan, "/Reason"u8);
        string? location = ExtractPdfString(dictSpan, "/Location"u8);
        string? contactInfo = ExtractPdfString(dictSpan, "/ContactInfo"u8);
        string? signerName = ExtractPdfString(dictSpan, "/Name"u8);

        string fieldName = ResolveSignatureFieldName(fullData, objNumber)
            ?? $"Signature_{objNumber}";

        return new PdfSignatureField
        {
            FieldName = fieldName,
            ByteRange = byteRange,
            ContentsBytes = contentsBytes,
            SigDictObjectNumber = objNumber,
            PdfSigningTime = signingTime,
            SubFilter = subFilter,
            Reason = reason,
            Location = location,
            ContactInfo = contactInfo,
            SignerName = signerName,
        };
    }

    /// <summary>
    /// Resolves the AcroForm field dictionary whose /V entry points at the
    /// signature dictionary and returns its /T value.
    /// </summary>
    private static string? ResolveSignatureFieldName(
        ReadOnlySpan<byte> data, int signatureObjectNumber)
    {
        int valuePos = 0;
        while ((valuePos = IndexOf(data, "/V"u8, valuePos)) >= 0)
        {
            int pos = valuePos + 2;
            while (pos < data.Length && IsWhitespace(data[pos]))
            {
                pos++;
            }

            if (TryParseDecimalLong(data, pos, out long referencedObject, out int afterObject)
                && referencedObject == signatureObjectNumber)
            {
                pos = afterObject;
                while (pos < data.Length && IsWhitespace(data[pos]))
                {
                    pos++;
                }

                if (TryParseDecimalLong(data, pos, out _, out int afterGeneration))
                {
                    pos = afterGeneration;
                    while (pos < data.Length && IsWhitespace(data[pos]))
                    {
                        pos++;
                    }

                    if (pos < data.Length && data[pos] == 'R')
                    {
                        int dictStart = FindDictStart(data, valuePos);
                        int dictEnd = dictStart >= 0 ? FindMatchingDictEnd(data, dictStart) : -1;
                        if (dictEnd >= 0)
                        {
                            string? fieldName = ExtractPdfString(
                                data[dictStart..(dictEnd + 2)], "/T"u8);
                            if (!string.IsNullOrEmpty(fieldName))
                            {
                                return fieldName;
                            }
                        }
                    }
                }
            }

            valuePos += 2;
        }

        return null;
    }

    /// <summary>
    /// Determines whether a PDF name token (e.g. "/UR3") appears in the span with a
    /// valid token boundary after it (whitespace, '/', '>', ']', or end of span),
    /// so that longer names such as "/UR3Something" do not match.
    /// </summary>
    private static bool ContainsNameToken(ReadOnlySpan<byte> span, ReadOnlySpan<byte> name)
    {
        int pos = 0;
        while ((pos = IndexOf(span, name, pos)) >= 0)
        {
            int after = pos + name.Length;
            if (after >= span.Length
                || IsWhitespace(span[after])
                || span[after] == (byte)'/'
                || span[after] == (byte)'>'
                || span[after] == (byte)']')
            {
                return true;
            }

            pos = after;
        }

        return false;
    }

    /// <summary>
    /// Extracts a PDF name value (e.g., /SubFilter /adbe.pkcs7.detached) from a dictionary span.
    /// </summary>
    private static string? ExtractPdfName(ReadOnlySpan<byte> dictSpan, ReadOnlySpan<byte> key)
    {
        int keyPos = IndexOf(dictSpan, key, 0);
        if (keyPos < 0)
        {
            return null;
        }

        // Skip whitespace after key
        int pos = keyPos + key.Length;
        while (pos < dictSpan.Length && IsWhitespace(dictSpan[pos]))
        {
            pos++;
        }

        if (pos >= dictSpan.Length)
        {
            return null;
        }

        // Expect '/' (0x2F) starting the name value
        if (dictSpan[pos] != '/')
        {
            return null;
        }
        pos++;

        // Read until delimiter (/, >, newline, space)
        int nameStart = pos;
        while (pos < dictSpan.Length
               && dictSpan[pos] != '/' && dictSpan[pos] != '>'
               && dictSpan[pos] != '\n' && dictSpan[pos] != '\r' && dictSpan[pos] != ' ')
        {
            pos++;
        }

        if (pos <= nameStart)
        {
            return null;
        }

        return Encoding.ASCII.GetString(dictSpan[nameStart..pos]).Trim();
    }

    /// <summary>
    /// Extracts a PDF text string value for a given key (e.g., /Reason (text) or
    /// /Reason &lt;FEFF...&gt;). Supports literal strings (with escape sequences,
    /// nested parentheses and octal escapes) and hexadecimal strings per
    /// ISO 32000-1 §7.3.4.
    /// </summary>
    internal static string? ExtractPdfString(ReadOnlySpan<byte> dictSpan, ReadOnlySpan<byte> key)
    {
        int searchPos = 0;
        int keyPos;
        while ((keyPos = IndexOf(dictSpan, key, searchPos)) >= 0)
        {
            int afterKey = keyPos + key.Length;
            if (afterKey >= dictSpan.Length
                || IsWhitespace(dictSpan[afterKey])
                || dictSpan[afterKey] == '('
                || dictSpan[afterKey] == '<')
            {
                break;
            }

            // A short key such as /T must not match /Type.
            searchPos = afterKey;
        }

        if (keyPos < 0)
        {
            return null;
        }

        // Skip whitespace after key
        int pos = keyPos + key.Length;
        while (pos < dictSpan.Length && IsWhitespace(dictSpan[pos]))
        {
            pos++;
        }

        if (pos >= dictSpan.Length)
        {
            return null;
        }

        if (dictSpan[pos] == '(')
        {
            return ExtractLiteralString(dictSpan, pos);
        }

        if (dictSpan[pos] == '<')
        {
            return ExtractHexString(dictSpan, pos);
        }

        return null;
    }

    /// <summary>
    /// Extracts a literal string starting at the '(' at <paramref name="openParenPos"/>,
    /// honouring escape sequences, nested parentheses and octal escapes
    /// (ISO 32000-1 §7.3.4.2).
    /// </summary>
    private static string? ExtractLiteralString(ReadOnlySpan<byte> dictSpan, int openParenPos)
    {
        int pos = openParenPos + 1;

        // Read until the closing parenthesis, handling escaped chars and nesting.
        int depth = 1;
        int valueStart = pos;
        while (pos < dictSpan.Length && depth > 0)
        {
            if (dictSpan[pos] == '\\')
            {
                pos++; // skip escaped char
            }
            else if (dictSpan[pos] == '(')
            {
                depth++;
            }
            else if (dictSpan[pos] == ')')
            {
                depth--;
            }
            pos++;
        }

        if (depth != 0)
        {
            return null;
        }

        int valueEnd = pos - 1; // exclude closing paren
        if (valueEnd <= valueStart)
        {
            return null;
        }

        byte[] unescaped = UnescapePdfLiteralString(dictSpan[valueStart..valueEnd]);
        return DecodePdfTextString(unescaped);
    }

    /// <summary>
    /// Extracts a hexadecimal string starting at the '&lt;' at <paramref name="openAnglePos"/>
    /// (ISO 32000-1 §7.3.4.3).
    /// </summary>
    private static string? ExtractHexString(ReadOnlySpan<byte> dictSpan, int openAnglePos)
    {
        int pos = openAnglePos + 1;
        int hexStart = pos;
        while (pos < dictSpan.Length && dictSpan[pos] != '>')
        {
            pos++;
        }

        if (pos >= dictSpan.Length)
        {
            return null;
        }

        return DecodePdfTextString(DecodePdfHexString(dictSpan[hexStart..pos]));
    }

    /// <summary>
    /// Unescapes a PDF literal string body per ISO 32000-1 §7.3.4.2 Table 3,
    /// including \n \r \t \b \f \( \) \\, octal escapes (\ddd) and line
    /// continuations (\&lt;EOL&gt;). Unknown escapes drop the backslash.
    /// </summary>
    private static byte[] UnescapePdfLiteralString(ReadOnlySpan<byte> raw)
    {
        var output = new List<byte>(raw.Length);
        for (int i = 0; i < raw.Length; i++)
        {
            byte b = raw[i];
            if (b != (byte)'\\')
            {
                output.Add(b);
                continue;
            }

            if (i + 1 >= raw.Length)
            {
                break; // trailing backslash — ignore
            }

            byte next = raw[i + 1];
            switch (next)
            {
                case (byte)'n':
                    output.Add((byte)'\n');
                    i++;
                    break;
                case (byte)'r':
                    output.Add((byte)'\r');
                    i++;
                    break;
                case (byte)'t':
                    output.Add((byte)'\t');
                    i++;
                    break;
                case (byte)'b':
                    output.Add((byte)'\b');
                    i++;
                    break;
                case (byte)'f':
                    output.Add((byte)'\f');
                    i++;
                    break;
                case (byte)'(':
                case (byte)')':
                case (byte)'\\':
                    output.Add(next);
                    i++;
                    break;
                case (byte)'\r':
                    // Line continuation: \r or \r\n.
                    i++;
                    if (i + 1 < raw.Length && raw[i + 1] == (byte)'\n')
                    {
                        i++;
                    }
                    break;
                case (byte)'\n':
                    // Line continuation: \<LF>.
                    i++;
                    break;
                default:
                    if (next is >= (byte)'0' and <= (byte)'7')
                    {
                        // Octal escape: one to three octal digits.
                        int value = 0;
                        int count = 0;
                        while (count < 3 && i + 1 < raw.Length && raw[i + 1] is >= (byte)'0' and <= (byte)'7')
                        {
                            value = (value * 8) + (raw[i + 1] - (byte)'0');
                            i++;
                            count++;
                        }
                        output.Add((byte)value);
                    }
                    else
                    {
                        // Unknown escape: the backslash is ignored (ISO 32000-1 §7.3.4.2).
                        output.Add(next);
                        i++;
                    }
                    break;
            }
        }

        return [.. output];
    }

    /// <summary>
    /// Decodes the body of a hexadecimal PDF string (between '&lt;' and '&gt;').
    /// Whitespace characters are ignored and an odd final nibble is padded
    /// with a trailing zero nibble (ISO 32000-1 §7.3.4.3).
    /// </summary>
    internal static byte[] DecodePdfHexString(ReadOnlySpan<byte> hex)
    {
        var output = new List<byte>((hex.Length / 2) + 1);
        int highNibble = -1;
        foreach (byte b in hex)
        {
            if (IsHexWhitespace(b))
            {
                continue;
            }

            int nibble = HexNibble(b);
            if (nibble < 0)
            {
                continue;
            }

            if (highNibble < 0)
            {
                highNibble = nibble;
            }
            else
            {
                output.Add((byte)((highNibble << 4) | nibble));
                highNibble = -1;
            }
        }

        if (highNibble >= 0)
        {
            output.Add((byte)(highNibble << 4));
        }

        return [.. output];
    }

    /// <summary>
    /// Determines whether a byte is PDF whitespace inside a hexadecimal string
    /// (NUL, TAB, LF, FF, CR, SP — ISO 32000-1 §7.2.2).
    /// </summary>
    private static bool IsHexWhitespace(byte b) => b is 0 or (byte)' ' or (byte)'\t' or (byte)'\n' or (byte)'\f' or (byte)'\r';

    /// <summary>
    /// Converts one hex digit to its numeric value, or -1 when not a hex digit.
    /// </summary>
    private static int HexNibble(byte b)
    {
        if (b is >= (byte)'0' and <= (byte)'9')
        {
            return b - (byte)'0';
        }
        if (b is >= (byte)'A' and <= (byte)'F')
        {
            return (b - (byte)'A') + 10;
        }
        if (b is >= (byte)'a' and <= (byte)'f')
        {
            return (b - (byte)'a') + 10;
        }

        return -1;
    }

    /// <summary>
    /// Decodes a PDF text string per ISO 32000-1 §7.9.2.2.
    /// UTF-16BE (FE FF) and UTF-16LE (FF FE) byte-order marks are honoured;
    /// strings without a BOM are decoded as PDFDocEncoding (Annex D).
    /// </summary>
    internal static string DecodePdfTextString(ReadOnlySpan<byte> raw)
    {
        if (raw.Length >= 2 && raw[0] == 0xFE && raw[1] == 0xFF)
        {
            return DecodeUtf16(raw[2..], Encoding.BigEndianUnicode);
        }

        if (raw.Length >= 2 && raw[0] == 0xFF && raw[1] == 0xFE)
        {
            return DecodeUtf16(raw[2..], Encoding.Unicode);
        }

        return DecodePdfDocEncoding(raw);
    }

    /// <summary>
    /// Decodes UTF-16 bytes, dropping a trailing odd byte when present.
    /// </summary>
    private static string DecodeUtf16(ReadOnlySpan<byte> payload, Encoding encoding)
    {
        if ((payload.Length & 1) == 1)
        {
            payload = payload[..^1];
        }

        return encoding.GetString(payload);
    }

    /// <summary>
    /// Decodes bytes as PDFDocEncoding per ISO 32000-1 Annex D (Table D.2).
    /// </summary>
    private static string DecodePdfDocEncoding(ReadOnlySpan<byte> raw)
    {
        var sb = new StringBuilder(raw.Length);
        foreach (byte b in raw)
        {
            sb.Append(MapPdfDocByte(b));
        }

        return sb.ToString();
    }

    /// <summary>
    /// Maps one PDFDocEncoding byte to its Unicode code point (ISO 32000-1 Annex D).
    /// </summary>
    private static char MapPdfDocByte(byte b) => b switch
    {
        0x18 => '\u02D8', // breve
        0x19 => '\u02C7', // caron
        0x1A => '\u02C6', // modifier letter circumflex
        0x1B => '\u02D9', // dot above
        0x1C => '\u02DD', // double acute accent
        0x1D => '\u02DB', // ogonek
        0x1E => '\u02DA', // ring above
        0x1F => '\u02DC', // small tilde
        0x7F => '\uFFFD', // undefined in PDFDocEncoding
        0x80 => '\u2022', // bullet
        0x81 => '\u2020', // dagger
        0x82 => '\u2021', // double dagger
        0x83 => '\u2026', // ellipsis
        0x84 => '\u2014', // em dash
        0x85 => '\u2013', // en dash
        0x86 => '\u0192', // florin
        0x87 => '\u2044', // fraction slash
        0x88 => '\u2039', // single left-pointing angle quote
        0x89 => '\u203A', // single right-pointing angle quote
        0x8A => '\u2212', // minus sign
        0x8B => '\u2030', // per mille sign
        0x8C => '\u201E', // double low-9 quotation mark
        0x8D => '\u201C', // left double quotation mark
        0x8E => '\u201D', // right double quotation mark
        0x8F => '\u2018', // left single quotation mark
        0x90 => '\u2019', // right single quotation mark
        0x91 => '\u201A', // single low-9 quotation mark
        0x92 => '\u2122', // trademark
        0x93 => '\uFB01', // fi ligature
        0x94 => '\uFB02', // fl ligature
        0x95 => '\u0141', // L with stroke
        0x96 => '\u0152', // OE ligature
        0x97 => '\u0160', // S with caron
        0x98 => '\u0178', // Y with diaeresis
        0x99 => '\u017D', // Z with caron
        0x9A => '\u0131', // dotless i
        0x9B => '\u0142', // l with stroke
        0x9C => '\u0153', // oe ligature
        0x9D => '\u0161', // s with caron
        0x9E => '\u017E', // z with caron
        0x9F => '\uFFFD', // undefined in PDFDocEncoding
        0xA0 => '\u20AC', // euro sign
        _ => (char)b,
    };

    /// <summary>
    /// Extracts the /M (modification date) from a signature dictionary.
    /// Format: /M (D:YYYYMMDDHHmmss+HH'mm'). Literal, hexadecimal, and UTF-16
    /// text strings are decoded with the shared PDF text-string decoder.
    /// </summary>
    private static DateTimeOffset? ExtractPdfDate(ReadOnlySpan<byte> dictSpan)
    {
        string? dateString = ExtractPdfString(dictSpan, "/M"u8);
        if (string.IsNullOrEmpty(dateString))
        {
            return null;
        }

        return ParsePdfDate(dateString);
    }

    /// <summary>
    /// Parses a PDF date string (D:YYYYMMDDHHmmss±HH'mm') into a DateTimeOffset.
    /// </summary>
    private static DateTimeOffset? ParsePdfDate(string dateStr, ILogger? logger = null)
    {
        // Strip "D:" prefix
        if (dateStr.StartsWith("D:", StringComparison.OrdinalIgnoreCase))
        {
            dateStr = dateStr[2..];
        }

        if (dateStr.Length < 14)
        {
            return null;
        }

        if (!int.TryParse(dateStr[0..4], out int year))
        {
            return null;
        }
        if (!int.TryParse(dateStr[4..6], out int month))
        {
            return null;
        }
        if (!int.TryParse(dateStr[6..8], out int day))
        {
            return null;
        }
        if (!int.TryParse(dateStr[8..10], out int hour))
        {
            return null;
        }
        if (!int.TryParse(dateStr[10..12], out int minute))
        {
            return null;
        }
        if (!int.TryParse(dateStr[12..14], out int second))
        {
            return null;
        }

        // Parse timezone offset (e.g., +03'00', -05'30', Z)
        var tzOffset = TimeSpan.Zero;
        if (dateStr.Length > 14)
        {
            char sign = dateStr[14];
            if ((sign == '+' || sign == '-')
                && dateStr.Length >= 20
                && int.TryParse(dateStr[15..17], out int tzHours)
                && int.TryParse(dateStr[18..20], out int tzMinutes))
            {
                tzOffset = new TimeSpan(tzHours, tzMinutes, 0);
                if (sign == '-')
                {
                    tzOffset = -tzOffset;
                }
            }
        }

        try
        {
            return new DateTimeOffset(year, month, day, hour, minute, second, tzOffset);
        }
        catch (Exception ex) when (ex is ArgumentOutOfRangeException or ArgumentException)
        {
            logger?.PdfDateParsingFailed(ex.Message);
            return null;
        }
    }

    /// <summary>
    /// Extracts the /ByteRange [offset1 length1 offset2 length2] array from a dictionary.
    /// </summary>
    private static PdfByteRange? ExtractByteRange(ReadOnlySpan<byte> dictSpan)
    {
        int keyPos = IndexOf(dictSpan, ByteRangeKey, 0);
        if (keyPos < 0)
        {
            return null;
        }

        // Skip whitespace and find opening bracket '['
        int pos = keyPos + ByteRangeKey.Length;
        while (pos < dictSpan.Length && IsWhitespace(dictSpan[pos]))
        {
            pos++;
        }

        if (pos >= dictSpan.Length || dictSpan[pos] != '[')
        {
            return null;
        }
        pos++; // skip '['

        if (!TryReadFourLongs(dictSpan, pos, out long offset1, out long length1, out long offset2, out long length2))
        {
            return null;
        }

        return new PdfByteRange
        {
            Offset1 = offset1,
            Length1 = length1,
            Offset2 = offset2,
            Length2 = length2
        };
    }

    /// <summary>
    /// Extracts the /Contents hex string between the two ByteRange segments.
    /// The Contents field contains the CMS/PKCS#7 signature in hex encoding.
    /// </summary>
    private static byte[] ExtractContents(PdfByteRange byteRange, ReadOnlySpan<byte> fullData)
    {
        long gapStart = byteRange.Offset1 + byteRange.Length1;
        long gapEnd = byteRange.Offset2;

        if (gapStart >= fullData.Length || gapEnd > fullData.Length || gapStart >= gapEnd
            || gapStart > int.MaxValue || gapEnd > int.MaxValue)
        {
            return [];
        }

        ReadOnlySpan<byte> gapRegion = fullData[(int)gapStart..(int)gapEnd];

        // Find hex string delimiters: <hexdata>, skipping comments (% to end of line)
        // that may appear between the ByteRange segments.
        int hexStart = -1;
        int hexEnd = -1;
        for (int i = 0; i < gapRegion.Length; i++)
        {
            if (gapRegion[i] == (byte)'%')
            {
                while (i < gapRegion.Length && gapRegion[i] != (byte)'\n' && gapRegion[i] != (byte)'\r')
                {
                    i++;
                }
                continue;
            }

            if (gapRegion[i] == '<' && hexStart < 0)
            {
                hexStart = i;
            }
            if (gapRegion[i] == '>')
            {
                hexEnd = i;
                break;
            }
        }

        if (hexStart < 0 || hexEnd <= hexStart)
        {
            return [];
        }

        return HexDecode(gapRegion[(hexStart + 1)..hexEnd]);
    }
    #endregion

    #region PDF Structure Navigation

    /// <summary>
    /// Finds the "startxref" marker by scanning backwards from the end of the file.
    /// Per PDF spec, it must be within the last 1024 bytes.
    /// </summary>
    private static long FindStartXRef(ReadOnlySpan<byte> data)
    {
        int searchStart = Math.Max(0, data.Length - 1024);
        for (int pos = data.Length - StartXrefMarker.Length - 1; pos >= searchStart; pos--)
        {
            if (data[pos..].StartsWith(StartXrefMarker))
            {
                return pos;
            }
        }
        return -1;
    }

    /// <summary>
    /// Reads a decimal long value after skipping whitespace at the given position.
    /// </summary>
    private static long ReadLongAfterMarker(ReadOnlySpan<byte> data, int pos)
    {
        while (pos < data.Length && IsWhitespace(data[pos]))
        {
            pos++;
        }

        if (!TryParseDecimalLong(data, pos, out long value, out _))
        {
            return -1;
        }

        return value;
    }

    /// <summary>
    /// Finds the start of the enclosing dictionary (&lt;&lt;) by scanning backwards from nearPos.
    /// Verifies the found dictionary actually encloses nearPos (handles nested dicts), and
    /// skips literal strings, hexadecimal strings, and comments while scanning backwards.
    /// </summary>
    private static int FindDictStart(ReadOnlySpan<byte> data, int nearPos)
    {
        for (int pos = nearPos; pos >= 1; pos--)
        {
            byte b = data[pos];
            if (b == (byte)')')
            {
                // Backtrack over the literal string that ends here so that '<'/'>'/'%'
                // characters inside it cannot be mistaken for structure.
                pos = BacktrackLiteralString(data, pos);
                continue;
            }

            if (b == (byte)'<' && data[pos - 1] == (byte)'<')
            {
                int candidate = pos - 1;
                if (IsInsideComment(data, candidate))
                {
                    continue;
                }

                // Verify this dict encloses nearPos
                int end = FindMatchingDictEnd(data, candidate);
                if (end >= nearPos)
                {
                    return candidate;
                }
                // This dict closes before nearPos — keep searching further back
            }
        }
        return -1;
    }

    /// <summary>
    /// Backtracks from a closing ')' over the literal string it terminates, honouring
    /// escape sequences and nested parentheses. Returns the index before the matching '(',
    /// or -1 when no opening parenthesis is found.
    /// </summary>
    private static int BacktrackLiteralString(ReadOnlySpan<byte> data, int closePos)
    {
        int depth = 1;
        int i = closePos - 1;
        while (i >= 0 && depth > 0)
        {
            byte b = data[i];
            if (b == (byte)')')
            {
                depth++;
            }
            else if (b == (byte)'(')
            {
                depth--;
                if (depth == 0)
                {
                    return i - 1;
                }
            }
            else if (b == (byte)'\\')
            {
                // Skip the escaped character immediately before the backslash.
                i--;
            }

            i--;
        }

        return -1;
    }

    /// <summary>
    /// Determines whether the given position is inside a comment (% to end of line),
    /// by scanning backwards to the start of the line.
    /// </summary>
    private static bool IsInsideComment(ReadOnlySpan<byte> data, int pos)
    {
        int i = pos - 1;
        while (i >= 0 && data[i] != (byte)'\n' && data[i] != (byte)'\r')
        {
            if (data[i] == (byte)'%')
            {
                return true;
            }

            i--;
        }

        return false;
    }

    /// <summary>
    /// Finds the matching dictionary end (&gt;&gt;) for a given &lt;&lt;, handling nested dictionaries,
    /// literal strings (with escape sequences and nesting), hexadecimal strings, and comments.
    /// Returns the index of the first '&gt;' of the closing pair, or -1.
    /// </summary>
    private static int FindMatchingDictEnd(ReadOnlySpan<byte> data, int dictStart)
    {
        int nestingDepth = 0;
        int i = dictStart;
        while (i < data.Length)
        {
            byte b = data[i];
            if (b == (byte)'%')
            {
                while (i < data.Length && data[i] != (byte)'\n' && data[i] != (byte)'\r')
                {
                    i++;
                }
                continue;
            }

            if (b == (byte)'(')
            {
                i = SkipLiteralString(data, i) + 1;
                continue;
            }

            if (b == (byte)'<')
            {
                if (i + 1 < data.Length && data[i + 1] == (byte)'<')
                {
                    nestingDepth++;
                    i += 2;
                    continue;
                }

                i = SkipHexString(data, i) + 1;
                continue;
            }

            if (b == (byte)'>' && i + 1 < data.Length && data[i + 1] == (byte)'>')
            {
                nestingDepth--;
                i += 2;
                if (nestingDepth == 0)
                {
                    return i - 2; // index of the first '>'
                }
                continue;
            }

            i++;
        }

        return -1;
    }

    /// <summary>
    /// Skips a literal string starting at the '(' at <paramref name="openParenPos"/>,
    /// honouring escape sequences and nested parentheses, and returns the index of the
    /// closing ')'. Returns the last index when the string is unterminated.
    /// </summary>
    private static int SkipLiteralString(ReadOnlySpan<byte> data, int openParenPos)
    {
        int depth = 1;
        int i = openParenPos + 1;
        while (i < data.Length && depth > 0)
        {
            byte b = data[i];
            if (b == (byte)'\\')
            {
                if (i + 2 < data.Length && data[i + 1] == (byte)'\r' && data[i + 2] == (byte)'\n')
                {
                    i += 3; // line continuation \r\n
                }
                else
                {
                    i += 2; // escaped character
                }
                continue;
            }

            if (b == (byte)'(')
            {
                depth++;
            }
            else if (b == (byte)')')
            {
                depth--;
                if (depth == 0)
                {
                    return i;
                }
            }

            i++;
        }

        return data.Length - 1;
    }

    /// <summary>
    /// Skips a hexadecimal string starting at the '&lt;' at <paramref name="openAnglePos"/>
    /// and returns the index of the closing '&gt;'. Returns the last index when the string
    /// is unterminated.
    /// </summary>
    private static int SkipHexString(ReadOnlySpan<byte> data, int openAnglePos)
    {
        int i = openAnglePos + 1;
        while (i < data.Length && data[i] != (byte)'>')
        {
            i++;
        }

        return i < data.Length ? i : data.Length - 1;
    }

    /// <summary>
    /// Determines which PDF object owns a dictionary at the given position.
    /// First tries to find "N 0 obj" marker nearby, then falls back to closest xref entry.
    /// </summary>
    private static int FindOwningObject(ReadOnlySpan<byte> data, int beforePos, List<PdfCrossRef> crossRefs)
    {
        // Try to find "N 0 obj" in the 32 bytes before the dictionary
        for (int i = Math.Max(0, beforePos - 32); i < beforePos; i++)
        {
            if (TryParseObjMarker(data[i..], out int objNum))
            {
                return objNum;
            }
        }

        // Fall back to the xref entry closest to (but before) this position
        int closestObjNum = 0;
        long closestDistance = long.MaxValue;
        foreach (var xref in crossRefs)
        {
            long distance = beforePos - xref.Offset;
            if (distance >= 0 && distance < closestDistance)
            {
                closestDistance = distance;
                closestObjNum = xref.ObjectNumber;
            }
        }
        return closestObjNum;
    }

    /// <summary>
    /// Tries to parse an object marker "N 0 obj" from the beginning of a span.
    /// Extracts the object number N.
    /// </summary>
    private static bool TryParseObjMarker(ReadOnlySpan<byte> slice, out int objNum)
    {
        objNum = 0;
        int objKeyPos = IndexOf(slice, ObjMarker, 0);
        if (objKeyPos < 2)
        {
            return false;
        }

        // Walk backwards from " obj" to find: N <ws> gen <ws> obj
        // Skip generation number, whitespace, then read object number
        int pos = objKeyPos;
        while (pos > 0 && IsDigit(slice[pos - 1]))
        {
            pos--;       // skip gen digits
        }
        while (pos > 0 && IsWhitespace(slice[pos - 1]))
        {
            pos--;   // skip whitespace
        }
        while (pos > 0 && IsDigit(slice[pos - 1]))
        {
            pos--;       // skip obj number digits
        }

        if (!TryParseDecimalLong(slice[pos..], 0, out long value, out _))
        {
            return false;
        }

        objNum = (int)value;
        return true;
    }
    #endregion

    #region Low-Level Parsing Helpers

    private static int SkipToNextLine(ReadOnlySpan<byte> data, int pos)
    {
        while (pos < data.Length && data[pos] != '\n')
        {
            pos++;
        }
        return pos + 1;
    }

    internal static int SkipWhitespace(ReadOnlySpan<byte> data, int pos)
    {
        while (pos < data.Length && IsWhitespace(data[pos]))
        {
            pos++;
        }
        return pos;
    }

    /// <summary>
    /// Reads two consecutive integer values from a byte span at the given position.
    /// </summary>
    private static bool TryReadTwoIntegers(
        ReadOnlySpan<byte> data, int pos, out int first, out int second, out int afterPos)
    {
        first = second = afterPos = 0;

        if (!TryParseDecimalLong(data, pos, out long val1, out int nextPos))
        {
            return false;
        }

        while (nextPos < data.Length && IsWhitespace(data[nextPos]))
        {
            nextPos++;
        }

        if (!TryParseDecimalLong(data, nextPos, out long val2, out int endPos))
        {
            return false;
        }

        first = (int)val1;
        second = (int)val2;
        afterPos = endPos;
        return true;
    }

    /// <summary>
    /// Reads four consecutive long values for /ByteRange [offset1 length1 offset2 length2].
    /// </summary>
    private static bool TryReadFourLongs(
        ReadOnlySpan<byte> data, int pos,
        out long a, out long b, out long c, out long d)
    {
        b = c = d = 0;

        pos = SkipWhitespace(data, pos);
        if (!TryParseDecimalLong(data, pos, out a, out pos))
        {
            return false;
        }

        pos = SkipWhitespace(data, pos);
        if (!TryParseDecimalLong(data, pos, out b, out pos))
        {
            return false;
        }

        pos = SkipWhitespace(data, pos);
        if (!TryParseDecimalLong(data, pos, out c, out pos))
        {
            return false;
        }

        pos = SkipWhitespace(data, pos);
        if (!TryParseDecimalLong(data, pos, out d, out _))
        {
            return false;
        }

        return true;
    }

    /// <summary>
    /// Parses a fixed-width decimal integer from a byte span (used for 10-digit xref offsets).
    /// </summary>
    private static long ParseFixedInt(ReadOnlySpan<byte> data, int start, int length)
    {
        long value = 0;
        for (int i = start; i < start + length && i < data.Length; i++)
        {
            if (data[i] == ' ')
            {
                continue;
            }

            if (!IsDigit(data[i]))
            {
                break;
            }

            value = value * 10 + (data[i] - '0');
        }
        return value;
    }

    /// <summary>
    /// Parses a non-negative decimal long from a byte span, starting at pos.
    /// Returns the parsed value and the position after the last digit.
    /// </summary>
    internal static bool TryParseDecimalLong(ReadOnlySpan<byte> data, int pos, out long value, out int endPos)
    {
        value = 0;
        endPos = pos;
        if (pos >= data.Length || !IsDigit(data[pos]))
        {
            return false;
        }

        while (endPos < data.Length && IsDigit(data[endPos]))
        {
            long newValue = value * 10 + (data[endPos++] - '0');
            if (newValue < value) // overflow
            {
                return false;
            }

            value = newValue;
        }

        return true;
    }

    /// <summary>
    /// Parses a non-negative decimal long from a byte span. Returns -1 if invalid.
    /// </summary>
    private static long ParseDecimalLong(ReadOnlySpan<byte> data, int pos)
    {
        long value = 0;
        bool found = false;
        while (pos < data.Length && IsDigit(data[pos]))
        {
            long newValue = value * 10 + (data[pos++] - '0');
            if (newValue < value) // overflow
            {
                return -1;
            }

            value = newValue;
            found = true;
        }
        return found && value > 0 ? value : -1;
    }

    /// <summary>
    /// Finds the first occurrence of needle in haystack, starting at startAt.
    /// Returns the absolute position, or -1 if not found.
    /// </summary>
    internal static int IndexOf(ReadOnlySpan<byte> haystack, ReadOnlySpan<byte> needle, int startAt)
    {
        int relativePos = haystack[startAt..].IndexOf(needle);
        return relativePos >= 0 ? startAt + relativePos : -1;
    }
    #endregion

    #region Hex Decoding

    /// <summary>
    /// Decodes a hex-encoded byte string (e.g., from /Contents field), skipping whitespace.
    /// </summary>
    private static byte[] HexDecode(ReadOnlySpan<byte> hex)
    {
        // Strip whitespace first
        Span<byte> stripped = hex.Length > 4096 ? new byte[hex.Length] : stackalloc byte[hex.Length];
        int strippedLen = 0;
        foreach (byte b in hex)
        {
            if (!IsWhitespace(b))
            {
                stripped[strippedLen++] = b;
            }
        }
        stripped = stripped[..strippedLen];

        if (stripped.Length % 2 != 0)
        {
            return [];
        }

        byte[] result = new byte[stripped.Length / 2];
        for (int i = 0; i < result.Length; i++)
        {
            result[i] = (byte)((HexVal(stripped[i * 2]) << 4) | HexVal(stripped[i * 2 + 1]));
        }

        return result;
    }

    private static int HexVal(byte b) => b switch
    {
        >= (byte)'0' and <= (byte)'9' => b - '0',
        >= (byte)'a' and <= (byte)'f' => b - 'a' + 10,
        >= (byte)'A' and <= (byte)'F' => b - 'A' + 10,
        _ => 0
    };

    internal static bool IsDigit(byte b) => b is >= (byte)'0' and <= (byte)'9';

    internal static bool IsWhitespace(byte b) => b is (byte)' ' or (byte)'\n' or (byte)'\r' or (byte)'\t';
    #endregion

    #region Async I/O Helpers

    /// <summary>
    /// Reads as many bytes as possible from the stream into the buffer.
    /// </summary>
    private static async Task<int> ReadFullyAsync(Stream stream, byte[] buffer, CancellationToken ct)
    {
        int total = 0;
        while (total < buffer.Length)
        {
            int bytesRead = await stream.ReadAsync(buffer.AsMemory(total, buffer.Length - total), ct).ConfigureAwait(false);
            if (bytesRead == 0)
            {
                break;
            }

            total += bytesRead;
        }
        return total;
    }

    /// <summary>
    /// Reads exactly buffer.Length bytes from the stream, throwing on premature EOF.
    /// </summary>
    private static async Task ReadExactAsync(Stream stream, Memory<byte> buffer, CancellationToken ct)
    {
        int total = 0;
        while (total < buffer.Length)
        {
            int bytesRead = await stream.ReadAsync(buffer[total..], ct).ConfigureAwait(false);
            if (bytesRead == 0)
            {
                throw new EndOfStreamException("Unexpected end of PDF stream.");
            }

            total += bytesRead;
        }
    }
    #endregion

}
