using System.Globalization;
using System.Text;

namespace SimpleSign.Pdf;

/// <summary>
/// Minimal PDF structure parser that locates objects, cross-references, page trees,
/// AcroForm dictionaries, and MediaBox dimensions by scanning raw PDF bytes.
/// Does not build a full object graph — only extracts what is needed for incremental signing.
/// </summary>
internal static class PdfStructureParser
{
    /// <summary>
    /// Determines the next available PDF object number by taking the maximum of the
    /// trailer <c>/Size</c> value and the highest object number found in the file, plus one.
    /// </summary>
    public static int DetermineNextObjectNumber(ReadOnlySpan<byte> pdfData)
    {
        return Math.Max(FindTrailerSize(pdfData), FindHighestObjectNumber(pdfData) + 1);
    }

    /// <summary>
    /// Reads the <c>/Root N 0 R</c> reference from the trailer to find the catalog object number.
    /// Falls back to 1 if the trailer cannot be parsed.
    /// </summary>
    public static int FindRootObjectNumber(ReadOnlySpan<byte> data)
    {
        ReadOnlySpan<byte> rootToken = "/Root "u8;
        int tokenPos = data.LastIndexOf(rootToken);
        if (tokenPos < 0)
        {
            return 1;
        }

        int cursor = tokenPos + rootToken.Length;
        int rootObjNum = 0;
        while (cursor < data.Length && data[cursor] >= (byte)'0' && data[cursor] <= (byte)'9')
        {
            rootObjNum = rootObjNum * 10 + (data[cursor++] - '0');
        }

        return rootObjNum <= 0 ? 1 : rootObjNum;
    }

    /// <summary>
    /// Finds the byte boundaries of a PDF object (<c>N 0 obj ... endobj</c>) in the data.
    /// Returns the LAST occurrence (correct for incremental updates where later revisions override earlier ones).
    /// Returns (-1, -1) if not found.
    /// </summary>
    public static (int Start, int End) FindObjectBytes(ReadOnlySpan<byte> data, int objNum)
    {
        byte[] objHeader = Encoding.Latin1.GetBytes($"{objNum} 0 obj");
        int searchPos = 0;
        int lastMatchStart = -1;
        int lastMatchEnd = -1;

        while (searchPos < data.Length)
        {
            int matchPos = data.Slice(searchPos).IndexOf(objHeader);
            if (matchPos < 0)
            {
                break;
            }
            matchPos += searchPos;

            // Ensure this isn't a suffix match (e.g., "12 0 obj" matching inside "112 0 obj").
            if (matchPos > 0 && data[matchPos - 1] >= (byte)'0' && data[matchPos - 1] <= (byte)'9')
            {
                searchPos = matchPos + 1;
                continue;
            }

            // Ensure the token is followed by whitespace or '<<' (start of dictionary).
            int afterHeader = matchPos + objHeader.Length;
            if (afterHeader < data.Length
                && data[afterHeader] != (byte)'\n'
                && data[afterHeader] != (byte)'\r'
                && data[afterHeader] != (byte)' '
                && data[afterHeader] != (byte)'<')
            {
                searchPos = matchPos + 1;
                continue;
            }

            // Find the closing "endobj" marker.
            ReadOnlySpan<byte> endObjToken = "endobj"u8;
            int endObjRelative = data.Slice(matchPos).IndexOf(endObjToken);
            if (endObjRelative < 0)
            {
                break;
            }

            lastMatchStart = matchPos;
            lastMatchEnd = matchPos + endObjRelative + endObjToken.Length;
            searchPos = lastMatchEnd;
        }

        return (Start: lastMatchStart, End: lastMatchEnd);
    }

    /// <summary>
    /// Finds the AcroForm object number referenced by the catalog's <c>/AcroForm N 0 R</c> entry.
    /// Returns 0 if no AcroForm reference is found or if it's an inline dictionary.
    /// </summary>
    public static int FindAcroFormObjNum(ReadOnlySpan<byte> data, int catalogObjNum)
    {
        var (objStart, objEnd) = FindObjectBytes(data, catalogObjNum);
        if (objStart < 0)
        {
            return 0;
        }

        string catalogText = Encoding.Latin1.GetString(data.Slice(objStart, objEnd - objStart));
        int acroFormKeyPos = catalogText.IndexOf("/AcroForm", StringComparison.Ordinal);
        if (acroFormKeyPos < 0)
        {
            return 0;
        }

        int cursor;
        for (cursor = acroFormKeyPos + "/AcroForm".Length; cursor < catalogText.Length && (catalogText[cursor] == ' ' || catalogText[cursor] == '\n'); cursor++)
        {
        }

        if (cursor < catalogText.Length && catalogText[cursor] != '<')
        {
            int acroFormObjNum = 0;
            while (cursor < catalogText.Length && char.IsDigit(catalogText[cursor]))
            {
                acroFormObjNum = acroFormObjNum * 10 + (catalogText[cursor++] - '0');
            }
            return acroFormObjNum;
        }

        return 0;
    }

    /// <summary>
    /// Finds the first <c>/Type /Page</c> object in the PDF data and returns
    /// its object number, dictionary start offset, and object end offset.
    /// Returns the LAST revision of the page for incremental update correctness.
    /// </summary>
    public static (int ObjNum, int DictStart, int DictEnd) FindFirstPageObject(ReadOnlySpan<byte> data)
    {
        int typePos = FindPageTypeToken(data, 0);
        if (typePos < 0)
        {
            return (ObjNum: -1, DictStart: -1, DictEnd: -1);
        }

        int dictStart = -1;
        for (int pos = typePos - 1; pos >= 1; pos--)
        {
            if (data[pos] == (byte)'<' && data[pos - 1] == (byte)'<')
            {
                dictStart = pos - 1;
                break;
            }
        }
        if (dictStart < 0)
        {
            return (ObjNum: -1, DictStart: -1, DictEnd: -1);
        }

        int pageObjNum = FindObjNumBefore(data, dictStart);
        if (pageObjNum <= 0)
        {
            return (ObjNum: -1, DictStart: -1, DictEnd: -1);
        }

        // Use FindObjectBytes to get the LAST revision of this page object.
        var (latestStart, latestEnd) = FindObjectBytes(data, pageObjNum);
        if (latestStart < 0)
        {
            return (ObjNum: -1, DictStart: -1, DictEnd: -1);
        }

        int latestDictStart = -1;
        for (int pos = latestStart; pos < latestEnd - 1; pos++)
        {
            if (data[pos] == (byte)'<' && data[pos + 1] == (byte)'<')
            {
                latestDictStart = pos;
                break;
            }
        }
        if (latestDictStart < 0)
        {
            return (ObjNum: -1, DictStart: -1, DictEnd: -1);
        }

        return (ObjNum: pageObjNum, DictStart: latestDictStart, DictEnd: latestEnd);
    }

    /// <summary>
    /// Parses the page width from the <c>/MediaBox</c> array in the page dictionary or its parent Pages node.
    /// Falls back to 612 (US Letter width) if not found.
    /// </summary>
    public static float ParseMediaBoxWidth(ReadOnlySpan<byte> data, string pageDict)
    {
        float width = ExtractMediaBoxWidth(pageDict);
        if (width > 0)
        {
            return width;
        }

        string fullText = Encoding.Latin1.GetString(data);
        width = ExtractMediaBoxWidth(fullText);
        return width > 0 ? width : 612f;
    }

    /// <summary>
    /// Counts the number of existing visible signature annotations (with non-zero <c>/Rect</c>)
    /// by scanning for <c>/FT /Sig</c> widget annotations in the PDF data.
    /// </summary>
    public static int CountVisibleSignatureAnnotations(ReadOnlySpan<byte> data)
    {
        int count = 0;
        ReadOnlySpan<byte> token = "/FT /Sig"u8;
        int searchPos = 0;

        while (searchPos < data.Length)
        {
            int matchPos = data.Slice(searchPos).IndexOf(token);
            if (matchPos < 0)
            {
                break;
            }

            matchPos += searchPos;

            int windowStart = Math.Max(0, matchPos - 256);
            int windowEnd = Math.Min(data.Length, matchPos + 256);
            string window = Encoding.Latin1.GetString(data.Slice(windowStart, windowEnd - windowStart));

            int rectIdx = window.IndexOf("/Rect", StringComparison.Ordinal);
            if (rectIdx >= 0)
            {
                int bracketOpen = window.IndexOf('[', rectIdx);
                int bracketClose = window.IndexOf(']', rectIdx);
                if (bracketOpen >= 0 && bracketClose > bracketOpen)
                {
                    string rectContent = window.Substring(bracketOpen + 1, bracketClose - bracketOpen - 1).Trim();
                    if (rectContent != "0 0 0 0")
                    {
                        count++;
                    }
                }
            }

            searchPos = matchPos + token.Length;
        }

        return count;
    }

    /// <summary>
    /// Finds the <c>startxref</c> offset in the last 1024 bytes of the input PDF.
    /// </summary>
    public static async Task<long> FindPrevXRefAsync(Stream stream, CancellationToken ct)
    {
        const int TailSize = 1024;
        long readOffset = Math.Max(0L, stream.Length - TailSize);
        stream.Seek(readOffset, SeekOrigin.Begin);

        byte[] buffer = new byte[(int)Math.Min(TailSize, stream.Length)];
        Span<byte> tail = buffer.AsSpan(0, await stream.ReadAsync(buffer, ct).ConfigureAwait(false));

        ReadOnlySpan<byte> startxrefToken = "startxref"u8;
        int tokenPos = tail.LastIndexOf(startxrefToken);
        if (tokenPos < 0)
        {
            return 0L;
        }

        int cursor;
        for (cursor = tokenPos + startxrefToken.Length; cursor < tail.Length && (tail[cursor] == (byte)' ' || tail[cursor] == (byte)'\n' || tail[cursor] == (byte)'\r'); cursor++)
        {
        }

        long xrefOffset = 0L;
        while (cursor < tail.Length && tail[cursor] >= (byte)'0' && tail[cursor] <= (byte)'9')
        {
            xrefOffset = xrefOffset * 10 + (tail[cursor++] - '0');
        }

        return xrefOffset;
    }

    /// <summary>
    /// Parses the <c>/Fields [N 0 R ...]</c> array from a PDF object text,
    /// returning a list of indirect references like <c>"5 0 R"</c>.
    /// </summary>
    public static List<string> ParseFieldsArray(string objText)
    {
        List<string> references = new List<string>();
        int fieldsKeyPos = objText.IndexOf("/Fields", StringComparison.Ordinal);
        if (fieldsKeyPos < 0)
        {
            return references;
        }

        int arrayOpenPos = objText.IndexOf('[', fieldsKeyPos);
        int arrayClosePos = objText.IndexOf(']', fieldsKeyPos);
        if (arrayOpenPos < 0 || arrayClosePos < 0 || arrayClosePos <= arrayOpenPos)
        {
            return references;
        }

        int contentStart = arrayOpenPos + 1;
        string arrayContent = objText.Substring(contentStart, arrayClosePos - contentStart).Trim();
        if (string.IsNullOrEmpty(arrayContent))
        {
            return references;
        }

        string[] tokens = arrayContent.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        for (int i = 0; i + 2 < tokens.Length; i++)
        {
            if (int.TryParse(tokens[i], out _) && tokens[i + 1] == "0" && tokens[i + 2] == "R")
            {
                references.Add(tokens[i] + " 0 R");
                i += 2;
            }
        }

        return references;
    }

    /// <summary>
    /// Removes a key-value line from a PDF dictionary string.
    /// </summary>
    public static string RemoveKeyFromDict(string obj, string key)
    {
        int keyPos = obj.IndexOf(key, StringComparison.Ordinal);
        if (keyPos < 0)
        {
            return obj;
        }

        int lineEnd = obj.IndexOf('\n', keyPos);
        lineEnd = (lineEnd >= 0) ? (lineEnd + 1) : obj.Length;
        return string.Concat(obj.AsSpan(0, keyPos), obj.AsSpan(lineEnd));
    }

    /// <summary>
    /// Inserts a new key-value line into a PDF dictionary string, just before the closing <c>&gt;&gt;\nendobj</c>.
    /// </summary>
    public static string InsertIntoDict(string obj, string toInsert)
    {
        int insertPos = obj.LastIndexOf(">>\nendobj", StringComparison.Ordinal);
        if (insertPos < 0)
        {
            insertPos = obj.LastIndexOf(">>", StringComparison.Ordinal);
        }
        if (insertPos < 0)
        {
            return obj;
        }

        return string.Concat(obj.AsSpan(0, insertPos), toInsert, obj.AsSpan(insertPos));
    }

    // ── Private helpers ──────────────────────────────────────────────────────

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

    private static int FindPageTypeToken(ReadOnlySpan<byte> data, int startPos)
    {
        ReadOnlySpan<byte> token = "/Type /Page"u8;
        ReadOnlySpan<byte> tokenNoSpace = "/Type/Page"u8;

        int pos = startPos;
        while (pos < data.Length)
        {
            ReadOnlySpan<byte> slice = data.Slice(pos);
            int found = slice.IndexOf(token);
            int tokenLen = token.Length;

            if (found < 0)
            {
                found = slice.IndexOf(tokenNoSpace);
                tokenLen = tokenNoSpace.Length;
            }

            if (found < 0)
            {
                return -1;
            }

            int absolutePos = pos + found;
            int afterToken = absolutePos + tokenLen;

            if (afterToken < data.Length && data[afterToken] == (byte)'s')
            {
                pos = afterToken;
                continue;
            }

            return absolutePos;
        }

        return -1;
    }

    private static int FindObjNumBefore(ReadOnlySpan<byte> data, int beforePos)
    {
        int windowStart = Math.Max(0, beforePos - 64);
        ReadOnlySpan<byte> window = data.Slice(windowStart, beforePos - windowStart);

        ReadOnlySpan<byte> objToken = " obj"u8;
        int objTokenPos = window.LastIndexOf(objToken);
        if (objTokenPos < 2)
        {
            return 0;
        }

        int cursor = objTokenPos - 1;
        while (cursor >= 0 && (window[cursor] == (byte)' ' || window[cursor] == (byte)'\r' || window[cursor] == (byte)'\n'))
        {
            cursor--;
        }
        while (cursor >= 0 && window[cursor] >= (byte)'0' && window[cursor] <= (byte)'9')
        {
            cursor--;
        }
        while (cursor >= 0 && (window[cursor] == (byte)' ' || window[cursor] == (byte)'\r' || window[cursor] == (byte)'\n'))
        {
            cursor--;
        }

        int objNumEnd = cursor + 1;
        while (cursor >= 0 && window[cursor] >= (byte)'0' && window[cursor] <= (byte)'9')
        {
            cursor--;
        }
        int objNumStart = cursor + 1;

        if (objNumStart >= objNumEnd)
        {
            return 0;
        }

        int objNum = 0;
        for (int i = objNumStart; i < objNumEnd; i++)
        {
            objNum = objNum * 10 + (window[i] - '0');
        }

        return objNum;
    }

    private static float ExtractMediaBoxWidth(string text)
    {
        int idx = text.LastIndexOf("/MediaBox", StringComparison.Ordinal);
        if (idx < 0)
        {
            return 0f;
        }

        int open = text.IndexOf('[', idx);
        int close = text.IndexOf(']', idx);
        if (open < 0 || close < 0 || close <= open)
        {
            return 0f;
        }

        string[] parts = text.Substring(open + 1, close - open - 1).Trim().Split(' ', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length >= 4 && float.TryParse(parts[2], NumberStyles.Float, CultureInfo.InvariantCulture, out float w))
        {
            return w;
        }

        return 0f;
    }

    /// <summary>
    /// Finds an existing empty signature field by name (/T value) and returns its object number.
    /// An empty signature field has /FT /Sig and either no /V entry or /V that is null.
    /// Returns -1 if not found, throws if the field is already signed.
    /// </summary>
    public static int FindEmptySignatureField(ReadOnlySpan<byte> data, string fieldName)
    {
        // Scan for /FT /Sig objects that match the field name
        string searchToken = $"/T ({fieldName})";
        string altSearchToken = $"/T({fieldName})";
        string text = Encoding.Latin1.GetString(data);

        int pos = 0;
        while (pos < text.Length)
        {
            int ftPos = text.IndexOf("/FT /Sig", pos, StringComparison.Ordinal);
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

            // Check if this object contains the field name
            if (!fullObj.Contains(searchToken, StringComparison.Ordinal) &&
                !fullObj.Contains(altSearchToken, StringComparison.Ordinal))
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
                // Check if field already has a value
                if (fullObj.Contains("/V ", StringComparison.Ordinal) || fullObj.Contains("/V<", StringComparison.Ordinal))
                {
                    // Check if /V is a reference to a real object (signed) vs null/empty
                    int vIdx = fullObj.IndexOf("/V ", StringComparison.Ordinal);
                    if (vIdx >= 0)
                    {
                        string afterV = fullObj.Substring(vIdx + 3).TrimStart();
                        if (afterV.StartsWith("null", StringComparison.OrdinalIgnoreCase) ||
                            afterV.StartsWith('/') ||
                            afterV.StartsWith(">>", StringComparison.Ordinal))
                        {
                            return objNum; // Empty /V
                        }

                        // /V followed by an object reference means it's signed
                        throw new InvalidOperationException(
                            $"Signature field '{fieldName}' is already signed (has /V value).");
                    }
                }

                return objNum; // No /V at all — empty field
            }

            pos = ftPos + 8;
        }

        return -1;
    }
}
