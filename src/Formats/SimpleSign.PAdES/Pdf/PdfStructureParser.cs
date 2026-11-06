using System.Text;
using SimpleSign.PAdES.Pdf.Constants;

namespace SimpleSign.PAdES.Pdf;

/// <summary>
/// Minimal PDF structure parser that locates objects, cross-references, page trees,
/// AcroForm dictionaries, and MediaBox dimensions by scanning raw PDF bytes.
/// Does not build a full object graph — only extracts what is needed for incremental signing.
/// </summary>
internal static partial class PdfStructureParser
{
    /// <summary>
    /// Determines the next available PDF object number by taking the maximum of the
    /// trailer <c>/Size</c> value and the highest object number found in the file, plus one.
    /// </summary>
    public static int DetermineNextObjectNumber(ReadOnlySpan<byte> pdfData) => Math.Max(FindTrailerSize(pdfData), FindHighestObjectNumber(pdfData) + 1);

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
            if (rootObjNum > int.MaxValue / 10)
            {
                return 1;
            }

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
        int acroFormKeyPos = catalogText.IndexOf(PdfKeys.AcroForm, StringComparison.Ordinal);
        if (acroFormKeyPos < 0)
        {
            return 0;
        }

        int cursor;
        for (cursor = acroFormKeyPos + PdfKeys.AcroForm.Length; cursor < catalogText.Length && (catalogText[cursor] == ' ' || catalogText[cursor] == '\n' || catalogText[cursor] == '\r'); cursor++)
        {
        }

        if (cursor < catalogText.Length && catalogText[cursor] != '<')
        {
            int acroFormObjNum = 0;
            while (cursor < catalogText.Length && IsAsciiDigit(catalogText[cursor]))
            {
                if (acroFormObjNum > int.MaxValue / 10)
                {
                    return 0;
                }

                acroFormObjNum = acroFormObjNum * 10 + (catalogText[cursor++] - '0');
            }
            return acroFormObjNum;
        }

        return 0;
    }

    /// <summary>
    /// Extracts /Fields references from an inline AcroForm dictionary in the Catalog.
    /// Used when the AcroForm is embedded directly (not an indirect reference).
    /// Returns an empty list if no inline AcroForm or /Fields is found.
    /// </summary>
    public static List<string> ExtractInlineAcroFormFields(ReadOnlySpan<byte> data, int catalogObjNum)
    {
        var (objStart, objEnd) = FindObjectBytes(data, catalogObjNum);
        if (objStart < 0)
        {
            return [];
        }

        string catalogText = Encoding.Latin1.GetString(data.Slice(objStart, objEnd - objStart));
        var (dictStart, dictEnd) = FindInlineAcroFormBounds(catalogText);
        if (dictStart < 0)
        {
            return [];
        }

        return ParseFieldsArray(catalogText[dictStart..dictEnd]);
    }

    /// <summary>
    /// Determines whether the Catalog contains an inline <c>/AcroForm</c> dictionary whose
    /// <c>/Fields</c> entry is a direct array or absent — i.e. it can be updated in place
    /// without converting the AcroForm to an indirect object.
    /// </summary>
    public static bool HasUpdatableInlineAcroForm(ReadOnlySpan<byte> data, int catalogObjNum)
    {
        var (objStart, objEnd) = FindObjectBytes(data, catalogObjNum);
        if (objStart < 0)
        {
            return false;
        }

        string catalogText = Encoding.Latin1.GetString(data.Slice(objStart, objEnd - objStart));
        var (dictStart, dictEnd) = FindInlineAcroFormBounds(catalogText);
        if (dictStart < 0)
        {
            return false;
        }

        string inlineDict = catalogText[dictStart..dictEnd];
        int fieldsKeyPos = inlineDict.IndexOf(PdfKeys.Fields, StringComparison.Ordinal);
        if (fieldsKeyPos < 0)
        {
            return true;
        }

        int cursor = fieldsKeyPos + PdfKeys.Fields.Length;
        while (cursor < inlineDict.Length && IsPdfWhitespaceChar(inlineDict[cursor]))
        {
            cursor++;
        }

        return cursor < inlineDict.Length && inlineDict[cursor] == '[';
    }

    /// <summary>
    /// Appends a field reference to the <c>/Fields</c> array of an inline <c>/AcroForm</c>
    /// dictionary in a Catalog object text. When <c>/Fields</c> is a direct array, the
    /// reference is appended before the closing bracket; when <c>/Fields</c> is absent, a
    /// new array is inserted. All other inline dictionary entries are preserved unchanged.
    /// Returns the input text unchanged when the Catalog has no inline AcroForm with an
    /// updatable <c>/Fields</c> entry (e.g. <c>/Fields</c> is an indirect reference).
    /// </summary>
    public static string AppendFieldToInlineAcroForm(string catalogText, string fieldRef)
    {
        var (dictStart, dictEnd) = FindInlineAcroFormBounds(catalogText);
        if (dictStart < 0)
        {
            return catalogText;
        }

        string inlineDict = catalogText[dictStart..dictEnd];
        string updatedDict = AppendFieldRefToInlineDict(inlineDict, fieldRef);
        if (ReferenceEquals(updatedDict, inlineDict))
        {
            return catalogText;
        }

        return string.Concat(catalogText.AsSpan(0, dictStart), updatedDict, catalogText.AsSpan(dictEnd));
    }

    /// <summary>
    /// Locates the inline <c>/AcroForm &lt;&lt;…&gt;&gt;</c> dictionary in a Catalog object
    /// text and returns its bounds (the dictionary delimiters inclusive), or (-1, -1) when
    /// the Catalog has no inline AcroForm. Nested dictionaries (e.g. /DR), literal strings,
    /// hexadecimal strings, and comments are handled by the shared depth-aware scanner.
    /// </summary>
    private static (int Start, int End) FindInlineAcroFormBounds(string catalogText)
    {
        int acroFormKeyPos = catalogText.IndexOf(PdfKeys.AcroForm, StringComparison.Ordinal);
        if (acroFormKeyPos < 0)
        {
            return (-1, -1);
        }

        int cursor = acroFormKeyPos + PdfKeys.AcroForm.Length;
        while (cursor < catalogText.Length && IsPdfWhitespaceChar(catalogText[cursor]))
        {
            cursor++;
        }

        if (cursor >= catalogText.Length || catalogText[cursor] != '<')
        {
            return (-1, -1);
        }

        int dictStart = cursor;
        int dictClose = FindDictEnd(catalogText, dictStart);
        if (dictClose < 0)
        {
            return (-1, -1);
        }

        return (dictStart, dictClose + 2);
    }

    /// <summary>
    /// Appends a field reference to the /Fields entry of an inline AcroForm dictionary.
    /// Returns the input dictionary unchanged when /Fields is an indirect reference.
    /// </summary>
    private static string AppendFieldRefToInlineDict(string inlineDict, string fieldRef)
    {
        int fieldsKeyPos = inlineDict.IndexOf(PdfKeys.Fields, StringComparison.Ordinal);
        if (fieldsKeyPos >= 0)
        {
            int cursor = fieldsKeyPos + PdfKeys.Fields.Length;
            while (cursor < inlineDict.Length && IsPdfWhitespaceChar(inlineDict[cursor]))
            {
                cursor++;
            }

            if (cursor < inlineDict.Length && inlineDict[cursor] == '[')
            {
                int closePos = FindClosingBracket(inlineDict, cursor);
                if (closePos > cursor)
                {
                    bool isEmpty = true;
                    for (int i = cursor + 1; i < closePos; i++)
                    {
                        if (!IsPdfWhitespaceChar(inlineDict[i]))
                        {
                            isEmpty = false;
                            break;
                        }
                    }

                    string insert = isEmpty ? fieldRef : $" {fieldRef}";
                    return string.Concat(inlineDict.AsSpan(0, closePos), insert, inlineDict.AsSpan(closePos));
                }
            }

            // /Fields is an indirect reference — cannot be updated in place.
            return inlineDict;
        }

        // No /Fields entry: insert a new array before the inline dictionary's closing >>.
        int dictClosePos = inlineDict.LastIndexOf(">>", StringComparison.Ordinal);
        if (dictClosePos < 0)
        {
            return inlineDict;
        }

        return string.Concat(inlineDict.AsSpan(0, dictClosePos), $" /Fields [{fieldRef}] ", inlineDict.AsSpan(dictClosePos));
    }

    /// <summary>
    /// Finds the bracket that closes the array opened at the given position, tracking
    /// nested arrays, dictionaries, literal and hexadecimal strings, and comments.
    /// Returns -1 when no closing bracket is found.
    /// </summary>
    private static int FindClosingBracket(string text, int openBracketPos) => FindArrayEnd(text, openBracketPos);

    /// <summary>
    /// Finds the index of the first '&gt;' of the <c>&gt;&gt;</c> that closes the dictionary
    /// opened at <paramref name="dictStart"/>, tracking nested dictionaries and arrays while
    /// skipping literal strings (with escape sequences and nesting), hexadecimal strings, and
    /// comments. Returns -1 when no closing delimiter is found.
    /// </summary>
    internal static int FindDictEnd(string text, int dictStart)
    {
        int depth = 0;
        int i = dictStart;
        while (i < text.Length)
        {
            char c = text[i];
            if (c == '%')
            {
                i = SkipComment(text, i);
                continue;
            }

            if (c == '(')
            {
                i = SkipLiteralString(text, i) + 1;
                continue;
            }

            if (c == '<')
            {
                if (i + 1 < text.Length && text[i + 1] == '<')
                {
                    depth++;
                    i += 2;
                    continue;
                }

                i = SkipHexString(text, i) + 1;
                continue;
            }

            if (c == '>' && i + 1 < text.Length && text[i + 1] == '>')
            {
                depth--;
                i += 2;
                if (depth == 0)
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
    /// Finds the index of the ']' that closes the array opened at <paramref name="openBracketPos"/>,
    /// tracking nested arrays and dictionaries while skipping literal strings, hexadecimal
    /// strings, and comments. Returns -1 when no closing bracket is found.
    /// </summary>
    internal static int FindArrayEnd(string text, int openBracketPos)
    {
        int depth = 0;
        int i = openBracketPos;
        while (i < text.Length)
        {
            char c = text[i];
            if (c == '%')
            {
                i = SkipComment(text, i);
                continue;
            }

            if (c == '(')
            {
                i = SkipLiteralString(text, i) + 1;
                continue;
            }

            if (c == '<')
            {
                if (i + 1 < text.Length && text[i + 1] == '<')
                {
                    int dictEnd = FindDictEnd(text, i);
                    if (dictEnd < 0)
                    {
                        return -1;
                    }

                    i = dictEnd + 2;
                    continue;
                }

                i = SkipHexString(text, i) + 1;
                continue;
            }

            if (c == '[')
            {
                depth++;
                i++;
                continue;
            }

            if (c == ']')
            {
                depth--;
                i++;
                if (depth == 0)
                {
                    return i - 1;
                }
                continue;
            }

            i++;
        }

        return -1;
    }

    /// <summary>
    /// Skips a comment (% to end of line) starting at <paramref name="pos"/>
    /// and returns the index of the line terminator (or the end of the text).
    /// </summary>
    internal static int SkipComment(string text, int pos)
    {
        int i = pos;
        while (i < text.Length && text[i] != '\n' && text[i] != '\r')
        {
            i++;
        }

        return i;
    }

    /// <summary>
    /// Skips a literal string starting at the '(' at <paramref name="openParenPos"/>,
    /// honouring escape sequences and nested parentheses, and returns the index of the
    /// closing ')'. Returns the last character index when the string is unterminated.
    /// </summary>
    internal static int SkipLiteralString(string text, int openParenPos)
    {
        int depth = 1;
        int i = openParenPos + 1;
        while (i < text.Length && depth > 0)
        {
            char c = text[i];
            if (c == '\\')
            {
                if (i + 2 < text.Length && text[i + 1] == '\r' && text[i + 2] == '\n')
                {
                    i += 3; // line continuation \r\n
                }
                else
                {
                    i += 2; // escaped character
                }
                continue;
            }

            if (c == '(')
            {
                depth++;
            }
            else if (c == ')')
            {
                depth--;
                if (depth == 0)
                {
                    return i;
                }
            }

            i++;
        }

        return text.Length - 1;
    }

    /// <summary>
    /// Skips a hexadecimal string starting at the '&lt;' at <paramref name="openAnglePos"/>
    /// and returns the index of the closing '&gt;'. Returns the last character index when
    /// the string is unterminated.
    /// </summary>
    internal static int SkipHexString(string text, int openAnglePos)
    {
        int i = openAnglePos + 1;
        while (i < text.Length && text[i] != '>')
        {
            i++;
        }

        return i < text.Length ? i : text.Length - 1;
    }
}
