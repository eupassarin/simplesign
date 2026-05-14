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

    /// <summary>Search window for /DocMDP after /Perms (bytes).</summary>
    private const int DocMdpSearchWindow = 512;

    /// <summary>Search window for /P permission level after /Perms (bytes).</summary>
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
    private static ReadOnlySpan<byte> PermsKey => "/Perms"u8;
    private static ReadOnlySpan<byte> DocMdpKey => "/DocMDP"u8;
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
    /// </summary>
    private static int GetDocMdpPermissionLevel(ReadOnlySpan<byte> data)
    {
        // The /P permission value lives in the TransformParams dictionary
        // inside the signature object, NOT near /Perms in the catalog.
        // Layout: /Perms << /DocMDP ref >> is in the catalog (just a reference).
        // The actual /TransformMethod /DocMDP ... /P 2 is in the signature object.

        // Confirm /Perms + /DocMDP exists in the document catalog
        int permsPos = IndexOf(data, PermsKey, 0);
        if (permsPos < 0)
        {
            return 0;
        }

        int searchEnd = Math.Min(permsPos + DocMdpSearchWindow, data.Length);
        if (IndexOf(data[permsPos..searchEnd], DocMdpKey, 0) < 0)
        {
            return 0;
        }

        // Find /TransformMethod /DocMDP in the signature object (may be before /Perms)
        int tmPos = IndexOf(data, TransformMethodDocMdp, 0);
        if (tmPos < 0)
        {
            return 1; // DocMDP exists but no TransformMethod — most restrictive
        }

        // Search for /P within a bounded window after /TransformMethod /DocMDP
        int permSearchEnd = Math.Min(tmPos + PermissionSearchWindow, data.Length);
        int permKeyPos = IndexOf(data[tmPos..permSearchEnd], PermissionKey, 0);
        if (permKeyPos < 0)
        {
            return 1;
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
        int encryptIdx = IndexOf(data[searchStart..], EncryptKey, 0);
        if (encryptIdx >= 0)
        {
            return true;
        }

        // Also check from the start (for linearized PDFs where trailer is near the beginning)
        int earlyEncrypt = IndexOf(data[..Math.Min(data.Length, 4096)], EncryptKey, 0);
        return earlyEncrypt >= 0;
    }

    /// <summary>
    /// Scans XMP metadata for pdfaid:part and pdfaid:conformance to determine PDF/A level.
    /// XMP metadata in PDFs is stored as XML inside a stream object.
    /// </summary>
    internal static PdfALevel DetectPdfALevel(ReadOnlySpan<byte> data)
    {
        // XMP metadata contains XML like: <pdfaid:part>1</pdfaid:part> <pdfaid:conformance>B</pdfaid:conformance>
        var partTag = "pdfaid:part>"u8;
        int partIdx = IndexOf(data, partTag, 0);
        if (partIdx < 0)
        {
            return PdfALevel.None;
        }

        int partStart = partIdx + partTag.Length;
        if (partStart >= data.Length)
        {
            return PdfALevel.Unknown;
        }
        int part = data[partStart] - '0';

        // Find conformance level
        var confTag = "pdfaid:conformance>"u8;
        int confIdx = IndexOf(data, confTag, partIdx);
        char conformance = 'B'; // default if not specified
        if (confIdx >= 0)
        {
            int confStart = confIdx + confTag.Length;
            if (confStart < data.Length)
            {
                conformance = char.ToUpperInvariant((char)data[confStart]);
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
        int searchEnd = dictEnd > absDictStart ? dictEnd + 2 : Math.Min(trailerPos + DocMdpSearchWindow, data.Length);

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
        catch (Exception ex)
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

        // Check if stream uses FlateDecode compression
        bool isCompressed = false;
        int filterKeyPos = IndexOf(dictRegion, "/Filter"u8, 0);
        if (filterKeyPos >= 0)
        {
            isCompressed = IndexOf(dictRegion[filterKeyPos..], "FlateDecode"u8, 0) >= 0;
        }

        byte[] decodedData;
        if (isCompressed)
        {
            decodedData = InflateZlib(rawStreamData);
            if (decodedData.Length == 0)
            {
                return;
            }
        }
        else
        {
            decodedData = rawStreamData.ToArray();
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
            catch (Exception ex)
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

        bool isCompressed = IndexOf(objStmDict, "FlateDecode"u8, 0) >= 0;
        byte[] decompressed = isCompressed ? InflateZlib(rawStream) : rawStream.ToArray();
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
    private static ReadOnlySpan<byte> ExtractStreamBytes(
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

        // Try /Length first for precise stream extraction
        int lengthKeyPos = IndexOf(dictRegion, "/Length "u8, 0);
        if (lengthKeyPos >= 0
            && TryParseDecimalLong(dictRegion, lengthKeyPos + "/Length "u8.Length, out long streamLength, out _)
            && streamLength > 0
            && streamStart + streamLength <= data.Length)
        {
            return data.Slice(streamStart, (int)streamLength);
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
        catch (Exception ex)
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

        byte[] contentsBytes = ExtractContents(byteRange, fullData);
        DateTimeOffset? signingTime = ExtractPdfDate(dictSpan);
        string? subFilter = ExtractPdfName(dictSpan, "/SubFilter"u8);
        string? reason = ExtractPdfString(dictSpan, "/Reason"u8);
        string? location = ExtractPdfString(dictSpan, "/Location"u8);
        string? contactInfo = ExtractPdfString(dictSpan, "/ContactInfo"u8);
        string? signerName = ExtractPdfString(dictSpan, "/Name"u8);

        return new PdfSignatureField
        {
            FieldName = $"Signature_{objNumber}",
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
    /// Extracts a parenthesized PDF string value for a given key (e.g., /Reason (text)).
    /// </summary>
    private static string? ExtractPdfString(ReadOnlySpan<byte> dictSpan, ReadOnlySpan<byte> key)
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

        if (pos >= dictSpan.Length || dictSpan[pos] != '(')
        {
            return null;
        }
        pos++; // skip '('

        // Read until closing paren, handling escaped parens
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

        return Encoding.UTF8.GetString(dictSpan[valueStart..valueEnd]);
    }

    /// <summary>
    /// Extracts the /M (modification date) from a signature dictionary.
    /// Format: /M (D:YYYYMMDDHHmmss+HH'mm')
    /// </summary>
    private static DateTimeOffset? ExtractPdfDate(ReadOnlySpan<byte> dictSpan)
    {
        // Try "/M(" first (no space), then "/M ("
        int keyPos = IndexOf(dictSpan, "/M("u8, 0);
        int openParenPos;
        if (keyPos >= 0)
        {
            openParenPos = keyPos + "/M("u8.Length - 1;
        }
        else
        {
            keyPos = IndexOf(dictSpan, "/M ("u8, 0);
            if (keyPos < 0)
            {
                return null;
            }
            openParenPos = keyPos + "/M ("u8.Length - 1;
        }

        // Read value between parentheses
        int valueStart = openParenPos + 1;
        int valueEnd = valueStart;
        while (valueEnd < dictSpan.Length && dictSpan[valueEnd] != ')')
        {
            valueEnd++;
        }

        if (valueEnd >= dictSpan.Length)
        {
            return null;
        }

        string dateString = Encoding.ASCII.GetString(dictSpan[valueStart..valueEnd]);
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
        catch (Exception ex)
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

        // Find hex string delimiters: <hexdata>
        int hexStart = -1;
        int hexEnd = -1;
        for (int i = 0; i < gapRegion.Length; i++)
        {
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
    /// Verifies the found dictionary actually encloses nearPos (handles nested dicts).
    /// </summary>
    private static int FindDictStart(ReadOnlySpan<byte> data, int nearPos)
    {
        for (int pos = nearPos; pos >= 1; pos--)
        {
            if (data[pos] == '<' && data[pos - 1] == '<')
            {
                int candidate = pos - 1;
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
    /// Finds the matching dictionary end (&gt;&gt;) for a given &lt;&lt;, handling nested dictionaries.
    /// </summary>
    private static int FindMatchingDictEnd(ReadOnlySpan<byte> data, int dictStart)
    {
        int nestingDepth = 0;
        for (int i = dictStart; i < data.Length - 1; i++)
        {
            if (data[i] == '<' && data[i + 1] == '<')
            {
                nestingDepth++;
                i++; // skip second '<'
            }
            else if (data[i] == '>' && data[i + 1] == '>')
            {
                nestingDepth--;
                i++; // skip second '>'
                if (nestingDepth == 0)
                {
                    return i - 1;
                }
            }
        }
        return -1;
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

    private static int SkipWhitespace(ReadOnlySpan<byte> data, int pos)
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
    private static bool TryParseDecimalLong(ReadOnlySpan<byte> data, int pos, out long value, out int endPos)
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
    private static int IndexOf(ReadOnlySpan<byte> haystack, ReadOnlySpan<byte> needle, int startAt)
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

    private static bool IsDigit(byte b) => b is >= (byte)'0' and <= (byte)'9';

    private static bool IsWhitespace(byte b) => b is (byte)' ' or (byte)'\n' or (byte)'\r' or (byte)'\t';
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
