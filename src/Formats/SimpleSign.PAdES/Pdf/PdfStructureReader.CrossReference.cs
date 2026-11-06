using System.IO.Compression;
using System.Text;
using Microsoft.Extensions.Logging;
using SimpleSign.Core.Constants;
using SimpleSign.PAdES.Pdf.Exceptions;
using SimpleSign.PAdES.Internal;

namespace SimpleSign.PAdES.Pdf;

public sealed partial class PdfStructureReader
{
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
}
