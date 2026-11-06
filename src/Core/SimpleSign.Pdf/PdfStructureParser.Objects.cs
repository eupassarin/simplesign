using System.Text;
using SimpleSign.Pdf.Constants;

namespace SimpleSign.Pdf;

internal static partial class PdfStructureParser
{
    internal static int FindTrailerSize(ReadOnlySpan<byte> data)
    {
        ReadOnlySpan<byte> sizeToken = "/Size "u8;
        int tokenPos = data.LastIndexOf(sizeToken);
        if (tokenPos < 0)
        {
            return 10;
        }

        int cursor = tokenPos + sizeToken.Length;
        int sizeValue = 0;
        while (cursor < data.Length && data[cursor] >= (byte)'0' && data[cursor] <= (byte)'9')
        {
            if (sizeValue > int.MaxValue / 10)
            {
                return 10;
            }

            sizeValue = sizeValue * 10 + (data[cursor++] - '0');
        }

        return sizeValue <= 0 ? 10 : sizeValue;
    }

    internal static int FindHighestObjectNumber(ReadOnlySpan<byte> data)
    {
        ReadOnlySpan<byte> objMarker = " 0 obj"u8;
        int highest = 0;
        int pos = 0;

        while (pos < data.Length)
        {
            int idx = data[pos..].IndexOf(objMarker);
            if (idx < 0)
            {
                break;
            }

            int absPos = pos + idx;
            int numEnd = absPos;
            int numStart = numEnd - 1;
            while (numStart >= 0 && data[numStart] >= (byte)'0' && data[numStart] <= (byte)'9')
            {
                numStart--;
            }
            numStart++;

            if (numStart < numEnd)
            {
                int objNum = 0;
                for (int i = numStart; i < numEnd; i++)
                {
                    if (objNum > int.MaxValue / 10)
                    {
                        break;
                    }

                    objNum = objNum * 10 + (data[i] - '0');
                }
                if (objNum > highest)
                {
                    highest = objNum;
                }
            }

            pos = absPos + objMarker.Length;
        }

        return highest;
    }

    /// <summary>
    /// Finds an existing empty signature field by name (/T value) and returns its object number.
    /// An empty signature field has /FT /Sig and either no /V entry or /V that is null.
    /// Returns -1 if not found, throws if the field is already signed.
    /// </summary>
    public static int FindEmptySignatureField(ReadOnlySpan<byte> data, string fieldName)
    {
        // Scan for /FT /Sig objects that match the field name
        string text = Encoding.Latin1.GetString(data);

        int pos = 0;
        while (pos < text.Length)
        {
            int ftPos = text.IndexOf(PdfKeys.FtSig, pos, StringComparison.Ordinal);
            if (ftPos < 0)
            {
                break;
            }

            // Find the enclosing object boundaries
            int objStart = text.LastIndexOf(" 0 obj", ftPos, StringComparison.Ordinal);
            int objEnd = text.IndexOf("endobj", ftPos, StringComparison.Ordinal);
            if (objStart < 0 || objEnd < 0)
            {
                pos = ftPos + 8;
                continue;
            }

            string fullObj = text.Substring(Math.Max(0, objStart - 20), objEnd - Math.Max(0, objStart - 20) + 6);

            // Compare /T with the requested name, decoding literal, hexadecimal,
            // and UTF-16 forms with the shared text-string decoder.
            string? tValue = PdfStructureReader.ExtractPdfString(Encoding.Latin1.GetBytes(fullObj), "/T"u8);
            if (!string.Equals(tValue, fieldName, StringComparison.Ordinal))
            {
                pos = ftPos + 8;
                continue;
            }

            // Parse the object number
            int lineStart = text.LastIndexOf('\n', Math.Max(0, objStart - 1)) + 1;
            string beforeObj = text.Substring(lineStart, objStart + 6 - lineStart);
            int spaceIdx = beforeObj.IndexOf(' ');
            if (spaceIdx > 0 && int.TryParse(beforeObj.AsSpan(0, spaceIdx), out int objNum))
            {
                // Check if /V references an object (signed) — null, names, and
                // literal/hexadecimal strings (including empty ones) are empty fields.
                int vKeyPos = FindTopLevelKey(fullObj, "/V");
                if (vKeyPos >= 0)
                {
                    int cursor = vKeyPos + 2;
                    while (cursor < fullObj.Length && IsPdfWhitespaceChar(fullObj[cursor]))
                    {
                        cursor++;
                    }

                    if (cursor < fullObj.Length && IsAsciiDigit(fullObj[cursor]))
                    {
                        // /V followed by an object reference means it's signed
                        throw new InvalidOperationException(
                            $"Signature field '{fieldName}' is already signed (has /V value).");
                    }
                }

                return objNum; // /V absent or empty value — empty field
            }

            pos = ftPos + 8;
        }

        return -1;
    }

    /// <summary>
    /// Extracts a PDF object's dictionary content from a compressed Object Stream (ObjStm).
    /// Returns the dictionary text (e.g. "&lt;&lt; /Type /Catalog /Pages 2 0 R ... &gt;&gt;"), or null if not found.
    /// Used as a fallback when <see cref="FindObjectBytes"/> cannot locate the object in the file body
    /// because it's stored in a compressed ObjStm (common with iText, Adobe, and other modern PDF generators).
    /// </summary>
    /// <param name="data">The full PDF data.</param>
    /// <param name="targetObjNum">The object number to search for in ObjStm streams.</param>
    public static string? ExtractObjectFromObjStm(ReadOnlySpan<byte> data, int targetObjNum)
    {
        ReadOnlySpan<byte> objStmMarker1 = "/Type /ObjStm"u8;
        ReadOnlySpan<byte> objStmMarker2 = "/Type/ObjStm"u8;
        ReadOnlySpan<byte> streamMarker = "stream"u8;
        // In incremental updates, multiple ObjStm objects may contain the same target object.
        // The LAST occurrence is the most recent revision — keep scanning instead of returning early.
        string? latestContent = null;

        int searchPos = 0;
        while (searchPos < data.Length)
        {
            int pos1 = data[searchPos..].IndexOf(objStmMarker1);
            int pos2 = data[searchPos..].IndexOf(objStmMarker2);
            int matchOffset;
            if (pos1 >= 0 && pos2 >= 0)
            {
                matchOffset = Math.Min(pos1, pos2);
            }
            else if (pos1 >= 0)
            {
                matchOffset = pos1;
            }
            else if (pos2 >= 0)
            {
                matchOffset = pos2;
            }
            else
            {
                break;
            }

            int absolutePos = searchPos + matchOffset;
            searchPos = absolutePos + 1;

            int objStart = FindObjStartBefore(data, absolutePos);
            if (objStart < 0)
            {
                continue;
            }

            int streamKeyPos = PdfStructureReader.IndexOf(data[objStart..], streamMarker, 0);
            if (streamKeyPos < 0)
            {
                continue;
            }

            ReadOnlySpan<byte> dictRegion = data.Slice(objStart, streamKeyPos);

            int nPos = PdfStructureReader.IndexOf(dictRegion, "/N "u8, 0);
            int firstPos = PdfStructureReader.IndexOf(dictRegion, "/First "u8, 0);
            if (nPos < 0 || firstPos < 0)
            {
                continue;
            }

            if (!PdfStructureReader.TryParseDecimalLong(dictRegion, nPos + 3, out long objCount, out _))
            {
                continue;
            }

            if (!PdfStructureReader.TryParseDecimalLong(dictRegion, firstPos + 7, out long firstObjDataOffset, out _))
            {
                continue;
            }

            byte[] decompressed;
            try
            {
                ReadOnlySpan<byte> rawStream = PdfStructureReader.ExtractStreamBytes(data, objStart, dictRegion);
                if (rawStream.IsEmpty)
                {
                    continue;
                }

                decompressed = PdfStructureReader.ApplyStreamFilters(rawStream, dictRegion);
                if (decompressed.Length == 0)
                {
                    continue;
                }
            }
            catch
            {
                continue;
            }

            var objOffsets = new List<(int ObjNum, int Offset)>();
            int headerPos = 0;
            for (int i = 0; i < (int)objCount && headerPos < decompressed.Length; i++)
            {
                headerPos = PdfStructureReader.SkipWhitespace(decompressed, headerPos);
                if (!PdfStructureReader.TryParseDecimalLong(decompressed, headerPos, out long num, out headerPos))
                {
                    break;
                }

                headerPos = PdfStructureReader.SkipWhitespace(decompressed, headerPos);
                if (!PdfStructureReader.TryParseDecimalLong(decompressed, headerPos, out long off, out headerPos))
                {
                    break;
                }

                objOffsets.Add(((int)num, (int)off));
            }

            int targetIdx = -1;
            for (int i = 0; i < objOffsets.Count; i++)
            {
                if (objOffsets[i].ObjNum == targetObjNum)
                {
                    targetIdx = i;
                    break;
                }
            }

            if (targetIdx < 0)
            {
                continue;
            }

            int dataStart = (int)firstObjDataOffset + objOffsets[targetIdx].Offset;
            int dataEnd = (targetIdx + 1 < objOffsets.Count)
                ? (int)firstObjDataOffset + objOffsets[targetIdx + 1].Offset
                : decompressed.Length;

            if (dataStart < 0 || dataStart >= decompressed.Length)
            {
                continue;
            }

            dataEnd = Math.Min(dataEnd, decompressed.Length);

            string content = Encoding.Latin1.GetString(decompressed.AsSpan(dataStart, dataEnd - dataStart)).Trim();
            if (content.Length > 0)
            {
                latestContent = content;
            }
        }

        return latestContent;
    }

    /// <summary>
    /// Extracts /Fields references from an AcroForm object stored in a compressed Object Stream
    /// (PDF 1.5+, ObjStm). Used as a fallback when <see cref="FindObjectBytes"/> cannot locate
    /// the AcroForm by text search (common with iText, Adobe, and other modern PDF generators).
    /// </summary>
    /// <param name="data">The full PDF data.</param>
    /// <param name="acroFormObjNum">The AcroForm object number to search for.</param>
    /// <returns>
    /// A list of indirect references (e.g., "5 0 R") found in the AcroForm's /Fields array,
    /// or an empty list if the object cannot be found or decompressed.
    /// </returns>
    public static List<string> ExtractFieldsFromCompressedAcroForm(ReadOnlySpan<byte> data, int acroFormObjNum)
    {
        // Scan for all Object Stream (ObjStm) objects in the PDF.
        // ObjStm objects are always stored as regular (type 1) objects — they cannot be nested.
        // In incremental updates, multiple ObjStm objects may contain the same AcroForm obj number
        // with progressively more /Fields entries. We need the LAST (most recent) version.
        ReadOnlySpan<byte> objStmMarker1 = "/Type /ObjStm"u8;
        ReadOnlySpan<byte> objStmMarker2 = "/Type/ObjStm"u8;
        ReadOnlySpan<byte> streamMarker = "stream"u8;
        List<string> latestFields = [];

        int searchPos = 0;
        while (searchPos < data.Length)
        {
            // Find the next ObjStm marker
            int pos1 = data[searchPos..].IndexOf(objStmMarker1);
            int pos2 = data[searchPos..].IndexOf(objStmMarker2);
            int matchOffset;
            if (pos1 >= 0 && pos2 >= 0)
            {
                matchOffset = Math.Min(pos1, pos2);
            }
            else if (pos1 >= 0)
            {
                matchOffset = pos1;
            }
            else if (pos2 >= 0)
            {
                matchOffset = pos2;
            }
            else
            {
                break;
            }

            int absolutePos = searchPos + matchOffset;
            searchPos = absolutePos + 1;

            // Walk backwards to find the start of this object ("N 0 obj")
            int objStart = FindObjStartBefore(data, absolutePos);
            if (objStart < 0)
            {
                continue;
            }

            // Find "stream" keyword to delimit the dictionary region
            int streamKeyPos = PdfStructureReader.IndexOf(data[objStart..], streamMarker, 0);
            if (streamKeyPos < 0)
            {
                continue;
            }

            ReadOnlySpan<byte> dictRegion = data.Slice(objStart, streamKeyPos);

            // Parse /N (number of objects) and /First (byte offset of first object data)
            int nPos = PdfStructureReader.IndexOf(dictRegion, "/N "u8, 0);
            int firstPos = PdfStructureReader.IndexOf(dictRegion, "/First "u8, 0);
            if (nPos < 0 || firstPos < 0)
            {
                continue;
            }

            if (!PdfStructureReader.TryParseDecimalLong(dictRegion, nPos + 3, out long objCount, out _))
            {
                continue;
            }

            if (!PdfStructureReader.TryParseDecimalLong(dictRegion, firstPos + 7, out long firstObjDataOffset, out _))
            {
                continue;
            }

            // Extract and decompress the stream
            byte[] decompressed;
            try
            {
                ReadOnlySpan<byte> rawStream = PdfStructureReader.ExtractStreamBytes(data, objStart, dictRegion);
                if (rawStream.IsEmpty)
                {
                    continue;
                }

                decompressed = PdfStructureReader.ApplyStreamFilters(rawStream, dictRegion);
                if (decompressed.Length == 0)
                {
                    continue;
                }
            }
            catch
            {
                continue;
            }

            // Parse the ObjStm header: N pairs of (objectNumber, byteOffset)
            // Offsets are relative to /First
            var objOffsets = new List<(int ObjNum, int Offset)>();
            int headerPos = 0;
            for (int i = 0; i < (int)objCount && headerPos < decompressed.Length; i++)
            {
                headerPos = PdfStructureReader.SkipWhitespace(decompressed, headerPos);
                if (!PdfStructureReader.TryParseDecimalLong(decompressed, headerPos, out long num, out headerPos))
                {
                    break;
                }

                headerPos = PdfStructureReader.SkipWhitespace(decompressed, headerPos);
                if (!PdfStructureReader.TryParseDecimalLong(decompressed, headerPos, out long off, out headerPos))
                {
                    break;
                }

                objOffsets.Add(((int)num, (int)off));
            }

            // Check if our target AcroForm object is in this ObjStm
            int targetIdx = -1;
            for (int i = 0; i < objOffsets.Count; i++)
            {
                if (objOffsets[i].ObjNum == acroFormObjNum)
                {
                    targetIdx = i;
                    break;
                }
            }

            if (targetIdx < 0)
            {
                continue;
            }

            // Extract the AcroForm dict content from the decompressed data
            int dataStart = (int)firstObjDataOffset + objOffsets[targetIdx].Offset;
            int dataEnd = (targetIdx + 1 < objOffsets.Count)
                ? (int)firstObjDataOffset + objOffsets[targetIdx + 1].Offset
                : decompressed.Length;

            if (dataStart < 0 || dataStart >= decompressed.Length)
            {
                continue;
            }

            dataEnd = Math.Min(dataEnd, decompressed.Length);

            string acroFormContent = Encoding.Latin1.GetString(decompressed.AsSpan(dataStart, dataEnd - dataStart));
            var fields = ParseFieldsArray(acroFormContent);
            if (fields.Count > 0)
            {
                // Don't return immediately — keep scanning for later ObjStm revisions
                // that may contain a more complete /Fields array (incremental updates
                // create new ObjStm objects with the same AcroForm object number).
                latestFields = fields;
            }
        }

        return latestFields;
    }

    /// <summary>
    /// Extracts the /ID array from the last trailer in the PDF (e.g. /ID [&lt;abc&gt; &lt;def&gt;]).
    /// Returns the full "/ID [...]" string suitable for inclusion in a new trailer, or null if not found.
    /// Per ISO 32000 §14.4, incremental updates must preserve the document identity.
    /// </summary>
    public static string? FindTrailerId(ReadOnlySpan<byte> data)
    {
        ReadOnlySpan<byte> idToken = "/ID"u8;
        int tokenPos = data.LastIndexOf(idToken);
        if (tokenPos < 0)
        {
            return null;
        }

        // Ensure it's /ID followed by whitespace or [, not /IDSomething
        int afterToken = tokenPos + idToken.Length;
        if (afterToken < data.Length && data[afterToken] != (byte)' '
            && data[afterToken] != (byte)'\n' && data[afterToken] != (byte)'\r'
            && data[afterToken] != (byte)'[')
        {
            return null;
        }

        // Find the opening [
        int cursor = afterToken;
        while (cursor < data.Length && data[cursor] != (byte)'[')
        {
            cursor++;
            if (cursor - afterToken > 20)
            {
                return null;
            }
        }

        if (cursor >= data.Length)
        {
            return null;
        }

        // Find the matching ]
        int bracketStart = cursor;
        int depth = 0;
        for (int i = bracketStart; i < data.Length && i - bracketStart < 200; i++)
        {
            if (data[i] == (byte)'[')
            {
                depth++;
            }
            else if (data[i] == (byte)']')
            {
                depth--;
                if (depth == 0)
                {
                    string idArray = Encoding.Latin1.GetString(data.Slice(bracketStart, i - bracketStart + 1));
                    return $"/ID {idArray}";
                }
            }
        }

        return null;
    }

    /// <summary>
    /// Extracts the /Info reference from the last trailer (e.g. "/Info 5 0 R").
    /// Returns the full "/Info N 0 R" string, or null if not found.
    /// </summary>
    public static string? FindTrailerInfo(ReadOnlySpan<byte> data)
    {
        ReadOnlySpan<byte> infoToken = "/Info "u8;
        int tokenPos = data.LastIndexOf(infoToken);
        if (tokenPos < 0)
        {
            return null;
        }

        int cursor = tokenPos + infoToken.Length;
        // Skip whitespace
        while (cursor < data.Length && (data[cursor] == (byte)' ' || data[cursor] == (byte)'\n' || data[cursor] == (byte)'\r'))
        {
            cursor++;
        }

        // Parse object number
        int objNum = 0;
        while (cursor < data.Length && data[cursor] >= (byte)'0' && data[cursor] <= (byte)'9')
        {
            if (objNum > int.MaxValue / 10)
            {
                return null;
            }

            objNum = objNum * 10 + (data[cursor++] - '0');
        }

        if (objNum <= 0)
        {
            return null;
        }

        // Expect " 0 R"
        int remaining = data.Length - cursor;
        if (remaining < 4)
        {
            return null;
        }

        // Skip space before generation number
        while (cursor < data.Length && data[cursor] == (byte)' ')
        {
            cursor++;
        }

        // Parse generation number (should be 0)
        int genNum = 0;
        while (cursor < data.Length && data[cursor] >= (byte)'0' && data[cursor] <= (byte)'9')
        {
            if (genNum > int.MaxValue / 10)
            {
                return null;
            }

            genNum = genNum * 10 + (data[cursor++] - '0');
        }

        // Skip space before R
        while (cursor < data.Length && data[cursor] == (byte)' ')
        {
            cursor++;
        }

        if (cursor < data.Length && data[cursor] == (byte)'R')
        {
            return $"/Info {objNum} {genNum} R";
        }

        return null;
    }

    /// <summary>
    /// Walks backwards from a given position to find the start of a PDF object definition (N 0 obj).
    /// Returns the byte offset of the object start, or -1 if not found.
    /// </summary>
    private static int FindObjStartBefore(ReadOnlySpan<byte> data, int fromPos)
    {
        // Search backwards for "obj" preceded by "N 0 "
        ReadOnlySpan<byte> objToken = " 0 obj"u8;
        int scanStart = Math.Max(0, fromPos - 200);
        int region = fromPos - scanStart;
        if (region <= 0)
        {
            return -1;
        }

        ReadOnlySpan<byte> slice = data.Slice(scanStart, region);
        int lastObjPos = slice.LastIndexOf(objToken);
        if (lastObjPos < 0)
        {
            return -1;
        }

        // Walk backwards to find the start of the object number
        int numEnd = lastObjPos;
        int numStart = numEnd - 1;
        while (numStart >= 0 && data[scanStart + numStart] >= (byte)'0' && data[scanStart + numStart] <= (byte)'9')
        {
            numStart--;
        }

        numStart++;

        if (numStart >= numEnd)
        {
            return -1;
        }

        // The object starts at the first digit of the object number
        int result = scanStart + numStart;

        // Validate it's preceded by whitespace or line start
        if (result > 0 && data[result - 1] != (byte)'\n' && data[result - 1] != (byte)'\r' && data[result - 1] != (byte)' ')
        {
            return -1;
        }

        return result;
    }
}
