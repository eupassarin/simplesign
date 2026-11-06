using System.Globalization;
using System.Text;
using SimpleSign.PAdES.Pdf.Constants;

namespace SimpleSign.PAdES.Pdf;

internal static partial class PdfStructureParser
{
    /// <summary>
    /// Finds the first <c>/Type /Page</c> object in the PDF data and returns
    /// its object number, dictionary start offset, and object end offset.
    /// Returns the LAST revision of the page for incremental update correctness.
    /// </summary>
    public static (int ObjNum, int DictStart, int DictEnd) FindFirstPageObject(ReadOnlySpan<byte> data)
    {
        int typePos = FindPageTypeToken(data, 0);
        if (typePos >= 0)
        {
            int dictStart = -1;
            for (int pos = typePos - 1; pos >= 1; pos--)
            {
                if (data[pos] == (byte)'<' && data[pos - 1] == (byte)'<')
                {
                    dictStart = pos - 1;
                    break;
                }
            }
            if (dictStart >= 0)
            {
                int pageObjNum = FindObjNumBefore(data, dictStart);
                if (pageObjNum > 0)
                {
                    // Use FindObjectBytes to get the LAST revision of this page object.
                    var (latestStart, latestEnd) = FindObjectBytes(data, pageObjNum);
                    if (latestStart >= 0)
                    {
                        int latestDictStart = -1;
                        for (int pos = latestStart; pos < latestEnd - 1; pos++)
                        {
                            if (data[pos] == (byte)'<' && data[pos + 1] == (byte)'<')
                            {
                                latestDictStart = pos;
                                break;
                            }
                        }
                        if (latestDictStart >= 0)
                        {
                            return (ObjNum: pageObjNum, DictStart: latestDictStart, DictEnd: latestEnd);
                        }
                    }
                }
            }
        }

        // Fallback: page objects may be in compressed ObjStm. Find the first page from
        // Catalog → /Pages → /Kids chain. The page obj num is sufficient for incremental
        // updates even though the page content must be extracted from ObjStm separately.
        int firstPageObjNum = FindFirstPageObjNumFromCatalog(data);
        if (firstPageObjNum > 0)
        {
            // Check if the page exists as a regular object (may have been written in a prior update)
            var (objStart, objEnd) = FindObjectBytes(data, firstPageObjNum);
            if (objStart >= 0)
            {
                int ds = -1;
                for (int pos = objStart; pos < objEnd - 1; pos++)
                {
                    if (data[pos] == (byte)'<' && data[pos + 1] == (byte)'<')
                    {
                        ds = pos;
                        break;
                    }
                }
                if (ds >= 0)
                {
                    return (ObjNum: firstPageObjNum, DictStart: ds, DictEnd: objEnd);
                }
            }

            // Page is compressed in ObjStm — return obj num with sentinel DictStart/End.
            // Callers that need the dict content must use ExtractObjectFromObjStm.
            return (ObjNum: firstPageObjNum, DictStart: -1, DictEnd: -1);
        }

        return (ObjNum: -1, DictStart: -1, DictEnd: -1);
    }

    /// <summary>
    /// Finds the first page object number by traversing Catalog → /Pages → /Kids,
    /// handling both uncompressed and ObjStm-compressed objects.
    /// </summary>
    internal static int FindFirstPageObjNumFromCatalog(ReadOnlySpan<byte> data)
    {
        int catalogObjNum = FindRootObjectNumber(data);
        if (catalogObjNum <= 0)
        {
            return -1;
        }

        // Get catalog content (may be compressed)
        string? catalogText = GetObjectContent(data, catalogObjNum);
        if (catalogText == null)
        {
            return -1;
        }

        // Extract /Pages reference
        int pagesObjNum = ExtractObjReference(catalogText, "/Pages");
        if (pagesObjNum <= 0)
        {
            return -1;
        }

        // Get Pages content (may be compressed)
        string? pagesText = GetObjectContent(data, pagesObjNum);
        if (pagesText == null)
        {
            return -1;
        }

        // Extract the /Kids child references
        int kidsPos = pagesText.IndexOf(PdfKeys.Kids, StringComparison.Ordinal);
        if (kidsPos < 0)
        {
            return -1;
        }

        List<int> childObjNums = ParseKidsArrayReferences(pagesText, kidsPos);
        return childObjNums.Count > 0 ? childObjNums[0] : -1;
    }

    /// <summary>
    /// Finds the Nth page object number (1-based) by traversing Catalog → /Pages → /Kids.
    /// Returns -1 if the page number exceeds the document's page count.
    /// </summary>
    internal static int FindNthPageObjNum(ReadOnlySpan<byte> data, int pageNumber)
    {
        if (pageNumber < 1)
        {
            return -1;
        }

        int catalogObjNum = FindRootObjectNumber(data);
        if (catalogObjNum <= 0)
        {
            return -1;
        }

        string? catalogText = GetObjectContent(data, catalogObjNum);
        if (catalogText == null)
        {
            return -1;
        }

        int pagesObjNum = ExtractObjReference(catalogText, "/Pages");
        if (pagesObjNum <= 0)
        {
            return -1;
        }

        string? pagesText = GetObjectContent(data, pagesObjNum);
        if (pagesText == null)
        {
            return -1;
        }

        // Extract the /Kids child references
        int kidsPos = pagesText.IndexOf(PdfKeys.Kids, StringComparison.Ordinal);
        if (kidsPos < 0)
        {
            return -1;
        }

        List<int> childObjNums = ParseKidsArrayReferences(pagesText, kidsPos);
        if (pageNumber > childObjNums.Count)
        {
            return -1;
        }

        return childObjNums[pageNumber - 1];
    }

    /// <summary>
    /// Parses the <c>/Kids</c> array that follows the given <c>/Kids</c> key position in a
    /// <c>/Pages</c> dictionary text, using PDF token rules rather than line-oriented matching.
    /// Each child entry is an indirect reference (<c>objNum genNum R</c>). Entries may be
    /// separated by any PDF whitespace character (NUL, TAB, LF, FF, CR, SP — ISO 32000-1 §7.2.2),
    /// and comments (<c>%</c> to end of line) are skipped where PDF syntax permits them.
    /// Line endings are not required between entries.
    /// </summary>
    /// <param name="pagesText">The text of the <c>/Pages</c> object (dictionary or extracted ObjStm content).</param>
    /// <param name="kidsKeyPos">The position of the <c>/Kids</c> key within <paramref name="pagesText"/>.</param>
    /// <returns>The object numbers of the /Kids children, in array order.</returns>
    private static List<int> ParseKidsArrayReferences(string pagesText, int kidsKeyPos)
    {
        List<int> childObjNums = [];

        int openBracket = pagesText.IndexOf('[', kidsKeyPos);
        if (openBracket < 0)
        {
            return childObjNums;
        }

        int cursor = openBracket + 1;
        while (cursor < pagesText.Length)
        {
            cursor = SkipPdfSeparators(pagesText, cursor);
            if (cursor >= pagesText.Length || pagesText[cursor] == ']')
            {
                break;
            }

            if (TryParseIndirectReference(pagesText, ref cursor, out int objNum))
            {
                childObjNums.Add(objNum);
                continue;
            }

            // Malformed entry: skip this token and resynchronise at the next separator.
            while (cursor < pagesText.Length && pagesText[cursor] != ']' && !IsPdfWhitespaceChar(pagesText[cursor]) && pagesText[cursor] != '%')
            {
                cursor++;
            }
        }

        return childObjNums;
    }

    /// <summary>
    /// Parses one indirect reference (<c>objNum genNum R</c>) at the current cursor position.
    /// On success, advances the cursor past the reference and returns the object number.
    /// On failure, the cursor is left at the first unparsable position.
    /// </summary>
    private static bool TryParseIndirectReference(string text, ref int cursor, out int objNum)
    {
        objNum = 0;
        int numStart = cursor;

        while (cursor < text.Length && IsAsciiDigit(text[cursor]))
        {
            if (objNum > int.MaxValue / 10)
            {
                // Overflow: consume the remaining digits and fail.
                while (cursor < text.Length && IsAsciiDigit(text[cursor]))
                {
                    cursor++;
                }

                return false;
            }

            objNum = (objNum * 10) + (text[cursor] - '0');
            cursor++;
        }

        // Object numbers are positive; "0" alone is not a valid reference.
        if (numStart == cursor || objNum <= 0)
        {
            return false;
        }

        cursor = SkipPdfSeparators(text, cursor);

        // Generation number.
        int genStart = cursor;
        while (cursor < text.Length && IsAsciiDigit(text[cursor]))
        {
            cursor++;
        }

        if (genStart == cursor)
        {
            return false;
        }

        cursor = SkipPdfSeparators(text, cursor);

        if (cursor >= text.Length || text[cursor] != 'R')
        {
            return false;
        }

        cursor++;
        return true;
    }

    /// <summary>
    /// Advances the cursor past PDF whitespace (NUL, TAB, LF, FF, CR, SP — ISO 32000-1 §7.2.2)
    /// and comments (<c>%</c> to end of line).
    /// </summary>
    private static int SkipPdfSeparators(string text, int cursor)
    {
        while (cursor < text.Length)
        {
            char c = text[cursor];
            if (IsPdfWhitespaceChar(c))
            {
                cursor++;
            }
            else if (c == '%')
            {
                // Comment runs to end of line (or end of the object text).
                while (cursor < text.Length && text[cursor] != '\n' && text[cursor] != '\r')
                {
                    cursor++;
                }
            }
            else
            {
                break;
            }
        }

        return cursor;
    }

    /// <summary>
    /// Determines whether a character is a PDF whitespace character
    /// (NUL, TAB, LF, FF, CR, SP — ISO 32000-1 §7.2.2).
    /// </summary>
    private static bool IsPdfWhitespaceChar(char c) => c is '\0' or '\t' or '\n' or '\f' or '\r' or ' ';

    /// <summary>
    /// Determines whether a character is an ASCII decimal digit. PDF numbers are ASCII-only.
    /// </summary>
    private static bool IsAsciiDigit(char c) => c is >= '0' and <= '9';

    /// <summary>
    /// Gets the text content of a PDF object, trying regular object bytes first,
    /// then falling back to ObjStm extraction.
    /// </summary>
    private static string? GetObjectContent(ReadOnlySpan<byte> data, int objNum)
    {
        var (objStart, objEnd) = FindObjectBytes(data, objNum);
        if (objStart >= 0)
        {
            return Encoding.Latin1.GetString(data.Slice(objStart, objEnd - objStart));
        }

        return ExtractObjectFromObjStm(data, objNum);
    }

    /// <summary>
    /// Extracts an indirect object reference number from a dictionary key
    /// (e.g., "/Pages 2 0 R" → 2), using PDF token rules (objNum genNum R with
    /// any PDF whitespace between the tokens). Returns -1 when the value is not
    /// a well-formed indirect reference.
    /// </summary>
    private static int ExtractObjReference(string dictText, string key)
    {
        int keyPos = dictText.IndexOf(key, StringComparison.Ordinal);
        if (keyPos < 0)
        {
            return -1;
        }

        int cursor = keyPos + key.Length;
        while (cursor < dictText.Length && IsPdfWhitespaceChar(dictText[cursor]))
        {
            cursor++;
        }

        if (cursor < dictText.Length
            && IsAsciiDigit(dictText[cursor])
            && TryParseIndirectReference(dictText, ref cursor, out int objNum))
        {
            return objNum;
        }

        return -1;
    }

    /// <summary>
    /// Parses the effective page width for signature positioning.
    /// Checks /CropBox first (visible region per §8.3.2.2), then /MediaBox (§8.3.2.1).
    /// Follows /Parent chain for inherited values. Falls back to 612 (US Letter width).
    /// </summary>
    public static float ParseMediaBoxWidth(ReadOnlySpan<byte> data, string pageDict)
    {
        // Try /CropBox on the page dict first (defines visible region)
        float width = ExtractBoxWidth(pageDict, "/CropBox");
        if (width > 0)
        {
            return width;
        }

        // Try /MediaBox on the page dict
        width = ExtractBoxWidth(pageDict, "/MediaBox");
        if (width > 0)
        {
            return width;
        }

        // Follow /Parent chain for inherited MediaBox/CropBox
        width = ResolveInheritedBoxWidth(data, pageDict);
        if (width > 0)
        {
            return width;
        }

        // Last resort: scan the whole PDF for any /MediaBox
        string fullText = Encoding.Latin1.GetString(data);
        width = ExtractBoxWidth(fullText, "/MediaBox");
        return width > 0 ? width : 612f;
    }

    /// <summary>
    /// Parses the effective page height for signature positioning.
    /// Same inheritance rules as width.
    /// </summary>
    public static float ParsePageHeight(ReadOnlySpan<byte> data, string pageDict)
    {
        float height = ExtractBoxHeight(pageDict, "/CropBox");
        if (height > 0)
        {
            return height;
        }

        height = ExtractBoxHeight(pageDict, "/MediaBox");
        if (height > 0)
        {
            return height;
        }

        // Follow /Parent chain for inherited MediaBox/CropBox
        height = ResolveInheritedBoxHeight(data, pageDict);
        if (height > 0)
        {
            return height;
        }

        // Scan full PDF as fallback
        string fullText = Encoding.Latin1.GetString(data);
        height = ExtractBoxHeight(fullText, "/MediaBox");
        return height > 0 ? height : 792f; // US Letter height
    }

    /// <summary>
    /// Extracts the /Rotate value from the page dictionary (§8.3.2.4).
    /// Values: 0, 90, 180, 270. Returns 0 if not found.
    /// </summary>
    public static int ParsePageRotation(ReadOnlySpan<byte> data, string pageDict)
    {
        int rotate = ExtractIntValue(pageDict, "/Rotate");
        if (rotate != 0)
        {
            return NormalizeRotation(rotate);
        }

        // Check /Parent chain for inherited /Rotate
        int parentObjNum = ExtractIntValue(pageDict, "/Parent");
        if (parentObjNum <= 0)
        {
            return 0;
        }

        for (int depth = 0; depth < 10; depth++)
        {
            var (objStart, objEnd) = FindObjectBytes(data, parentObjNum);
            if (objStart < 0)
            {
                break;
            }

            string parentText = Encoding.Latin1.GetString(data.Slice(objStart, objEnd - objStart));
            rotate = ExtractIntValue(parentText, "/Rotate");
            if (rotate != 0)
            {
                return NormalizeRotation(rotate);
            }

            parentObjNum = ExtractIntValue(parentText, "/Parent");
            if (parentObjNum <= 0)
            {
                break;
            }
        }

        return 0;
    }

    /// <summary>
    /// Counts the number of existing visible signature annotations (with non-zero <c>/Rect</c>)
    /// by scanning for <c>/FT /Sig</c> widget annotations in the PDF data. Each widget's own
    /// dictionary is located with the string-aware scanner and only a top-level /Rect entry is
    /// considered, so nested dictionaries and long entries cannot skew the count.
    /// </summary>
    public static int CountVisibleSignatureAnnotations(ReadOnlySpan<byte> data)
    {
        string text = Encoding.Latin1.GetString(data);
        int count = 0;
        int searchPos = 0;

        while (searchPos < text.Length)
        {
            int matchPos = text.IndexOf(PdfKeys.FtSig, searchPos, StringComparison.Ordinal);
            if (matchPos < 0)
            {
                break;
            }

            int dictStart = FindEnclosingDictStart(text, matchPos);
            if (dictStart >= 0)
            {
                int dictEnd = FindDictEnd(text, dictStart);
                if (dictEnd >= dictStart && HasNonZeroRect(text[dictStart..(dictEnd + 2)]))
                {
                    count++;
                }
            }

            searchPos = matchPos + PdfKeys.FtSig.Length;
        }

        return count;
    }

    /// <summary>
    /// Finds the start of the dictionary enclosing <paramref name="nearPos"/> by scanning
    /// backwards, skipping literal strings and comments, and verifying the candidate
    /// dictionary actually encloses the position.
    /// </summary>
    private static int FindEnclosingDictStart(string text, int nearPos)
    {
        for (int pos = nearPos; pos >= 1; pos--)
        {
            char c = text[pos];
            if (c == ')')
            {
                pos = BacktrackLiteralString(text, pos);
                continue;
            }

            if (c == '<' && text[pos - 1] == '<')
            {
                int candidate = pos - 1;
                if (IsInsideComment(text, candidate))
                {
                    continue;
                }

                int end = FindDictEnd(text, candidate);
                if (end >= nearPos)
                {
                    return candidate;
                }
            }
        }

        return -1;
    }

    /// <summary>
    /// Determines whether a widget dictionary declares a visible rectangle
    /// (a top-level /Rect array whose value is not [0 0 0 0]).
    /// </summary>
    private static bool HasNonZeroRect(string widgetDict)
    {
        int rectKeyPos = FindTopLevelKey(widgetDict, "/Rect");
        if (rectKeyPos < 0)
        {
            return false;
        }

        int cursor = rectKeyPos + "/Rect".Length;
        while (cursor < widgetDict.Length && IsPdfWhitespaceChar(widgetDict[cursor]))
        {
            cursor++;
        }

        if (cursor >= widgetDict.Length || widgetDict[cursor] != '[')
        {
            return false;
        }

        int closePos = FindArrayEnd(widgetDict, cursor);
        if (closePos <= cursor)
        {
            return false;
        }

        string content = widgetDict.Substring(cursor + 1, closePos - cursor - 1);
        string[] parts = content.Split([' ', '\n', '\r', '\t'], StringSplitOptions.RemoveEmptyEntries);
        return string.Join(' ', parts) != "0 0 0 0";
    }

    /// <summary>
    /// Backtracks from a closing ')' over the literal string it terminates, honouring
    /// escape sequences and nested parentheses. Returns the index before the matching '(',
    /// or -1 when no opening parenthesis is found.
    /// </summary>
    private static int BacktrackLiteralString(string text, int closePos)
    {
        int depth = 1;
        int i = closePos - 1;
        while (i >= 0 && depth > 0)
        {
            char c = text[i];
            if (c == ')')
            {
                depth++;
            }
            else if (c == '(')
            {
                depth--;
                if (depth == 0)
                {
                    return i - 1;
                }
            }
            else if (c == '\\')
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
    private static bool IsInsideComment(string text, int pos)
    {
        int i = pos - 1;
        while (i >= 0 && text[i] != '\n' && text[i] != '\r')
        {
            if (text[i] == '%')
            {
                return true;
            }

            i--;
        }

        return false;
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
            if (objNum > int.MaxValue / 10)
            {
                return 0;
            }

            objNum = objNum * 10 + (window[i] - '0');
        }

        return objNum;
    }

    private static float ExtractBoxWidth(string text, string boxName)
    {
        int idx = text.LastIndexOf(boxName, StringComparison.Ordinal);
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

        string[] parts = text.Substring(open + 1, close - open - 1).Trim()
            .Split([' ', '\n', '\r', '\t'], StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length >= 4
            && float.TryParse(parts[0], NumberStyles.Float, CultureInfo.InvariantCulture, out float llx)
            && float.TryParse(parts[2], NumberStyles.Float, CultureInfo.InvariantCulture, out float urx))
        {
            return urx - llx;
        }

        return 0f;
    }

    private static float ExtractBoxHeight(string text, string boxName)
    {
        int idx = text.LastIndexOf(boxName, StringComparison.Ordinal);
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

        string[] parts = text.Substring(open + 1, close - open - 1).Trim()
            .Split([' ', '\n', '\r', '\t'], StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length >= 4
            && float.TryParse(parts[1], NumberStyles.Float, CultureInfo.InvariantCulture, out float lly)
            && float.TryParse(parts[3], NumberStyles.Float, CultureInfo.InvariantCulture, out float ury))
        {
            return ury - lly;
        }

        return 0f;
    }

    /// <summary>
    /// Follows /Parent chain to find inherited /CropBox or /MediaBox width (§8.3.2.1).
    /// </summary>
    private static float ResolveInheritedBoxWidth(ReadOnlySpan<byte> data, string pageDict)
    {
        int parentObjNum = ExtractIntValue(pageDict, "/Parent");
        if (parentObjNum <= 0)
        {
            return 0f;
        }

        for (int depth = 0; depth < 10; depth++)
        {
            var (objStart, objEnd) = FindObjectBytes(data, parentObjNum);
            if (objStart < 0)
            {
                break;
            }

            string parentText = Encoding.Latin1.GetString(data.Slice(objStart, objEnd - objStart));

            float w = ExtractBoxWidth(parentText, "/CropBox");
            if (w > 0)
            {
                return w;
            }

            w = ExtractBoxWidth(parentText, "/MediaBox");
            if (w > 0)
            {
                return w;
            }

            parentObjNum = ExtractIntValue(parentText, "/Parent");
            if (parentObjNum <= 0)
            {
                break;
            }
        }

        return 0f;
    }

    /// <summary>
    /// Follows /Parent chain to find inherited /CropBox or /MediaBox height (§8.3.2.1).
    /// </summary>
    private static float ResolveInheritedBoxHeight(ReadOnlySpan<byte> data, string pageDict)
    {
        int parentObjNum = ExtractIntValue(pageDict, "/Parent");
        if (parentObjNum <= 0)
        {
            return 0f;
        }

        for (int depth = 0; depth < 10; depth++)
        {
            var (objStart, objEnd) = FindObjectBytes(data, parentObjNum);
            if (objStart < 0)
            {
                break;
            }

            string parentText = Encoding.Latin1.GetString(data.Slice(objStart, objEnd - objStart));

            float h = ExtractBoxHeight(parentText, "/CropBox");
            if (h > 0)
            {
                return h;
            }

            h = ExtractBoxHeight(parentText, "/MediaBox");
            if (h > 0)
            {
                return h;
            }

            parentObjNum = ExtractIntValue(parentText, "/Parent");
            if (parentObjNum <= 0)
            {
                break;
            }
        }

        return 0f;
    }
    /// <summary>
    /// For indirect references like "/Parent 5 0 R", returns just the object number (5).
    /// </summary>
    private static int ExtractIntValue(string text, string key)
    {
        int idx = text.IndexOf(key, StringComparison.Ordinal);
        if (idx < 0)
        {
            return 0;
        }

        int pos = idx + key.Length;
        while (pos < text.Length && (text[pos] == ' ' || text[pos] == '\n' || text[pos] == '\r'))
        {
            pos++;
        }

        int result = 0;
        bool negative = false;
        if (pos < text.Length && text[pos] == '-')
        {
            negative = true;
            pos++;
        }

        while (pos < text.Length && IsAsciiDigit(text[pos]))
        {
            result = result * 10 + (text[pos] - '0');
            pos++;
        }

        return negative ? -result : result;
    }

    private static int NormalizeRotation(int degrees)
    {
        int r = degrees % 360;
        if (r < 0)
        {
            r += 360;
        }

        return r;
    }
}
