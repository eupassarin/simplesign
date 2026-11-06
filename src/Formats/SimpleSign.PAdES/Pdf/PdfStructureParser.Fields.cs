using System.Text;
using SimpleSign.PAdES.Pdf.Constants;

namespace SimpleSign.PAdES.Pdf;

internal static partial class PdfStructureParser
{
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
            if (xrefOffset > long.MaxValue / 10)
            {
                return 0L;
            }

            xrefOffset = xrefOffset * 10 + (tail[cursor++] - '0');
        }

        return xrefOffset;
    }

    /// <summary>
    /// Determines whether the PDF uses cross-reference streams (§7.5.8) or classic xref tables.
    /// When true, incremental updates should also use xref streams for compatibility.
    /// </summary>
    public static bool UsesXRefStreams(ReadOnlySpan<byte> data)
    {
        // Find the last startxref value
        ReadOnlySpan<byte> startxrefToken = "startxref"u8;
        int tokenPos = data.LastIndexOf(startxrefToken);
        if (tokenPos < 0)
        {
            return false;
        }

        int cursor = tokenPos + startxrefToken.Length;
        while (cursor < data.Length && (data[cursor] == (byte)' ' || data[cursor] == (byte)'\n' || data[cursor] == (byte)'\r'))
        {
            cursor++;
        }

        long xrefOffset = 0L;
        while (cursor < data.Length && data[cursor] >= (byte)'0' && data[cursor] <= (byte)'9')
        {
            if (xrefOffset > long.MaxValue / 10)
            {
                return false;
            }

            xrefOffset = xrefOffset * 10 + (data[cursor++] - '0');
        }

        if (xrefOffset <= 0 || xrefOffset >= data.Length)
        {
            return false;
        }

        // Classic xref tables start with "xref"
        ReadOnlySpan<byte> xrefKeyword = "xref"u8;
        if (data.Slice((int)xrefOffset).StartsWith(xrefKeyword))
        {
            return false;
        }

        // Xref streams start with "N 0 obj" and contain /Type /XRef
        ReadOnlySpan<byte> typeXRef1 = "/Type /XRef"u8;
        ReadOnlySpan<byte> typeXRef2 = "/Type/XRef"u8;
        int searchEnd = Math.Min((int)xrefOffset + 500, data.Length);
        var region = data.Slice((int)xrefOffset, searchEnd - (int)xrefOffset);
        return region.IndexOf(typeXRef1) >= 0 || region.IndexOf(typeXRef2) >= 0;
    }

    /// <summary>
    /// Parses the <c>/Fields [N 0 R ...]</c> array from a PDF object text,
    /// returning a list of indirect references like <c>"5 0 R"</c>.
    /// The array must directly follow the <c>/Fields</c> key; when <c>/Fields</c>
    /// holds an indirect reference (or anything else), an empty list is returned
    /// so callers can fall back to <see cref="ResolveIndirectFields"/> instead of
    /// mistaking a later key's array for the fields list.
    /// </summary>
    public static List<string> ParseFieldsArray(string objText)
    {
        List<string> references = new List<string>();
        int fieldsKeyPos = objText.IndexOf(PdfKeys.Fields, StringComparison.Ordinal);
        if (fieldsKeyPos < 0)
        {
            return references;
        }

        int cursor = fieldsKeyPos + PdfKeys.Fields.Length;
        while (cursor < objText.Length && IsPdfWhitespaceChar(objText[cursor]))
        {
            cursor++;
        }

        if (cursor >= objText.Length || objText[cursor] != '[')
        {
            return references;
        }

        int arrayOpenPos = cursor;
        int arrayClosePos = FindArrayEnd(objText, arrayOpenPos);
        if (arrayClosePos <= arrayOpenPos)
        {
            return references;
        }

        int contentStart = arrayOpenPos + 1;
        string arrayContent = objText.Substring(contentStart, arrayClosePos - contentStart).Trim();
        if (string.IsNullOrEmpty(arrayContent))
        {
            return references;
        }

        string[] tokens = arrayContent.Split([' ', '\n', '\r', '\t'], StringSplitOptions.RemoveEmptyEntries);
        for (int i = 0; i + 2 < tokens.Length; i++)
        {
            if (IsAsciiDigits(tokens[i]) && tokens[i + 1] == "0" && tokens[i + 2] == "R")
            {
                references.Add(tokens[i] + " 0 R");
                i += 2;
            }
        }

        return references;
    }

    /// <summary>
    /// Determines whether a string consists solely of ASCII decimal digits.
    /// </summary>
    private static bool IsAsciiDigits(string s) => s.Length > 0 && s.All(IsAsciiDigit);

    /// <summary>
    /// Resolves an indirect <c>/Fields N 0 R</c> reference from an AcroForm dictionary.
    /// When <c>/Fields</c> points to a separate array object instead of containing an inline array,
    /// this method resolves the referenced object and parses its contents.
    /// Returns the field references, or an empty list if the pattern is not found.
    /// </summary>
    public static List<string> ResolveIndirectFields(ReadOnlySpan<byte> data, string acroFormText)
    {
        int fieldsKeyPos = acroFormText.IndexOf(PdfKeys.Fields, StringComparison.Ordinal);
        if (fieldsKeyPos < 0)
        {
            return [];
        }

        int cursor = fieldsKeyPos + PdfKeys.Fields.Length;
        // Skip whitespace
        while (cursor < acroFormText.Length && (acroFormText[cursor] == ' ' || acroFormText[cursor] == '\n' || acroFormText[cursor] == '\r' || acroFormText[cursor] == '\t'))
        {
            cursor++;
        }

        // If it's an inline array, ParseFieldsArray handles it
        if (cursor >= acroFormText.Length || acroFormText[cursor] == '[')
        {
            return [];
        }

        // Check for indirect reference (digit starts object number)
        if (!IsAsciiDigit(acroFormText[cursor]))
        {
            return [];
        }

        int fieldsObjNum = 0;
        while (cursor < acroFormText.Length && IsAsciiDigit(acroFormText[cursor]))
        {
            if (fieldsObjNum > int.MaxValue / 10)
            {
                return [];
            }

            fieldsObjNum = fieldsObjNum * 10 + (acroFormText[cursor++] - '0');
        }

        if (fieldsObjNum <= 0)
        {
            return [];
        }

        // Resolve the indirect object
        var (refStart, refEnd) = FindObjectBytes(data, fieldsObjNum);
        if (refStart >= 0)
        {
            string refObj = Encoding.Latin1.GetString(data.Slice(refStart, refEnd - refStart));
            return ParseReferencesFromArray(refObj);
        }

        // Try in compressed Object Streams
        string? compressedContent = ExtractObjectFromObjStm(data, fieldsObjNum);
        if (compressedContent != null)
        {
            return ParseReferencesFromArray(compressedContent);
        }

        return [];
    }

    /// <summary>
    /// Parses indirect references (N 0 R) from a text that contains a PDF array [...].
    /// </summary>
    private static List<string> ParseReferencesFromArray(string text)
    {
        List<string> references = [];
        int openBracket = text.IndexOf('[');
        int closeBracket = text.LastIndexOf(']');
        if (openBracket < 0 || closeBracket <= openBracket)
        {
            return references;
        }

        string arrayContent = text.Substring(openBracket + 1, closeBracket - openBracket - 1).Trim();
        if (string.IsNullOrEmpty(arrayContent))
        {
            return references;
        }

        string[] tokens = arrayContent.Split([' ', '\n', '\r', '\t'], StringSplitOptions.RemoveEmptyEntries);
        for (int i = 0; i + 2 < tokens.Length; i++)
        {
            if (IsAsciiDigits(tokens[i]) && tokens[i + 1] == "0" && tokens[i + 2] == "R")
            {
                references.Add(tokens[i] + " 0 R");
                i += 2;
            }
        }

        return references;
    }

    /// <summary>
    /// Removes a key-value entry from a PDF dictionary string, honouring PDF token rules:
    /// the whole value is removed (dictionaries, arrays, literal strings, hexadecimal
    /// strings, names, and indirect references may span multiple lines). Normalises CRLF
    /// to LF so the search works uniformly across source PDFs produced on Windows / by
    /// iText / Adobe (CRLF) and macOS / Linux (LF). Returns the input unchanged when the
    /// key is not found.
    /// </summary>
    public static string RemoveKeyFromDict(string obj, string key)
    {
        string normalised = obj.Replace("\r\n", "\n", StringComparison.Ordinal);
        int keyPos = FindTopLevelKey(normalised, key);
        if (keyPos < 0)
        {
            return obj;
        }

        int cursor = keyPos + key.Length;
        while (cursor < normalised.Length && IsPdfWhitespaceChar(normalised[cursor]))
        {
            cursor++;
        }

        int valueEnd;
        if (cursor < normalised.Length)
        {
            char c = normalised[cursor];
            if (c == '<' && cursor + 1 < normalised.Length && normalised[cursor + 1] == '<')
            {
                // Dictionary value.
                int dictEnd = FindDictEnd(normalised, cursor);
                valueEnd = dictEnd >= 0 ? dictEnd + 2 : normalised.Length;
            }
            else if (c == '<')
            {
                // Hexadecimal string value.
                valueEnd = SkipHexString(normalised, cursor) + 1;
            }
            else if (c == '[')
            {
                // Array value.
                int arrayEnd = FindArrayEnd(normalised, cursor);
                valueEnd = arrayEnd >= 0 ? arrayEnd + 1 : normalised.Length;
            }
            else if (c == '(')
            {
                // Literal string value.
                valueEnd = SkipLiteralString(normalised, cursor) + 1;
            }
            else if (IsAsciiDigit(c))
            {
                // Indirect reference: objNum genNum R (tokens may be separated by whitespace).
                valueEnd = cursor;
                while (valueEnd < normalised.Length && IsAsciiDigit(normalised[valueEnd]))
                {
                    valueEnd++;
                }
                while (valueEnd < normalised.Length && IsHorizontalSpace(normalised[valueEnd]))
                {
                    valueEnd++;
                }
                if (valueEnd < normalised.Length && IsAsciiDigit(normalised[valueEnd]))
                {
                    while (valueEnd < normalised.Length && IsAsciiDigit(normalised[valueEnd]))
                    {
                        valueEnd++;
                    }
                    while (valueEnd < normalised.Length && IsHorizontalSpace(normalised[valueEnd]))
                    {
                        valueEnd++;
                    }
                    if (valueEnd < normalised.Length && normalised[valueEnd] == 'R')
                    {
                        valueEnd++;
                    }
                }
            }
            else
            {
                // Name or other single token.
                valueEnd = cursor;
                while (valueEnd < normalised.Length && !IsPdfWhitespaceChar(normalised[valueEnd]))
                {
                    valueEnd++;
                }
            }
        }
        else
        {
            valueEnd = cursor;
        }

        // Also strip trailing horizontal whitespace after the value.
        int removeEnd = valueEnd;
        while (removeEnd < normalised.Length && IsHorizontalSpace(normalised[removeEnd]))
        {
            removeEnd++;
        }

        return string.Concat(normalised.AsSpan(0, keyPos), normalised.AsSpan(removeEnd));
    }

    /// <summary>
    /// Finds a top-level dictionary key (at depth 1, directly inside the outermost
    /// dictionary) by token-aware scanning that skips literal strings, hexadecimal
    /// strings, comments, and nested dictionaries/arrays. Returns -1 when not found.
    /// </summary>
    internal static int FindTopLevelKey(string text, string key)
    {
        int depth = 0;
        int i = 0;
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

            if (c == '[')
            {
                depth++;
                i++;
                continue;
            }

            if (c == '>')
            {
                if (i + 1 < text.Length && text[i + 1] == '>')
                {
                    // The text may start in the middle of a document (e.g. a sliced
                    // object), so never let the depth go negative.
                    if (depth > 0)
                    {
                        depth--;
                    }

                    i += 2;
                    continue;
                }

                i++;
                continue;
            }

            if (c == ']')
            {
                depth--;
                i++;
                continue;
            }

            if (c == '/' && depth == 1 && text.AsSpan(i).StartsWith(key, StringComparison.Ordinal))
            {
                int after = i + key.Length;
                if (after >= text.Length
                    || IsPdfWhitespaceChar(text[after])
                    || text[after] == '('
                    || text[after] == '<'
                    || text[after] == '[')
                {
                    return i;
                }
            }

            i++;
        }

        return -1;
    }

    /// <summary>
    /// Determines whether a character is horizontal whitespace (SP or TAB).
    /// </summary>
    private static bool IsHorizontalSpace(char c) => c is ' ' or '\t';

    /// <summary>
    /// Inserts a new key-value line into a PDF dictionary string, just before the closing
    /// <c>&gt;&gt;\nendobj</c>. CRLF input is normalised to LF so the sentinel matches
    /// source PDFs produced on Windows / by iText / Adobe. If the sentinel is not found
    /// (e.g. unusual line endings), falls back to a depth-aware search for the closing
    /// <c>&gt;&gt;</c> of the top-level dictionary so the insert lands at the correct
    /// level instead of inside a nested dictionary.
    /// </summary>
    public static string InsertIntoDict(string obj, string toInsert)
    {
        string normalised = obj.Replace("\r\n", "\n", StringComparison.Ordinal);
        int insertPos = normalised.LastIndexOf(">>\nendobj", StringComparison.Ordinal);
        if (insertPos < 0)
        {
            insertPos = FindOutermostDictClose(normalised);
        }
        if (insertPos < 0)
        {
            return obj;
        }

        return string.Concat(normalised.AsSpan(0, insertPos), toInsert, normalised.AsSpan(insertPos));
    }

    /// <summary>
    /// Finds the position of the next top-level PDF dictionary key (starting with '/')
    /// or the end-of-dictionary marker ('&gt;&gt;'), skipping nested structures, literal
    /// strings, hexadecimal strings, and comments.
    /// </summary>
    internal static int FindNextTopLevelKey(string text, int start)
    {
        int depth = 0;
        int i = start;
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

            if (c == '[')
            {
                depth++;
                i++;
                continue;
            }

            if (c == '>')
            {
                if (i + 1 < text.Length && text[i + 1] == '>')
                {
                    if (depth > 0)
                    {
                        depth--;
                        i += 2;
                        continue;
                    }

                    return i;
                }

                i++;
                continue;
            }

            if (c == ']')
            {
                if (depth > 0)
                {
                    depth--;
                }

                i++;
                continue;
            }

            if (c == '/' && depth == 0 && i > start)
            {
                return i;
            }

            i++;
        }

        return text.Length;
    }

    /// <summary>
    /// Finds the offset of the closing <c>&gt;&gt;</c> of the top-level dictionary by
    /// tracking dictionary nesting depth. Returns the last <c>&gt;&gt;</c> that brings
    /// the depth from 1 back to 0, or -1 if no top-level dictionary is found.
    /// Avoids matching a <c>&gt;&gt;</c> inside a nested dictionary value such as
    /// <c>/DR &lt;&lt; /Font &lt;&lt; … &gt;&gt; &gt;&gt;</c>, and ignores <c>&lt;&lt;</c>/<c>&gt;&gt;</c>
    /// sequences inside literal strings, hexadecimal strings, and comments.
    /// </summary>
    public static int FindOutermostDictClose(string text)
    {
        // Locate the first top-level '<<', then let the depth-aware scanner find its
        // matching close (nested dictionaries are skipped internally).
        int firstOpen = -1;
        int i = 0;
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
                    firstOpen = i;
                    break;
                }

                i = SkipHexString(text, i) + 1;
                continue;
            }

            i++;
        }

        if (firstOpen < 0)
        {
            return -1;
        }

        return FindDictEnd(text, firstOpen);
    }

    /// <summary>
    /// Validates that a signature field object has the required /FT /Sig structure
    /// and that /V (if present) points to a valid /Type /Sig dictionary (§12.7.4.4).
    /// Returns a list of warnings (empty if the field is valid).
    /// </summary>
    public static List<string> ValidateSignatureField(ReadOnlySpan<byte> data, int objNum)
    {
        var warnings = new List<string>();
        var (objStart, objEnd) = FindObjectBytes(data, objNum);
        if (objStart < 0)
        {
            warnings.Add($"Object {objNum} not found in PDF data.");
            return warnings;
        }

        string objText = Encoding.Latin1.GetString(data.Slice(objStart, objEnd - objStart));

        if (!objText.Contains(PdfKeys.FtSig, StringComparison.Ordinal) &&
            !objText.Contains(PdfKeys.FtSigNoSpace, StringComparison.Ordinal))
        {
            warnings.Add($"Object {objNum}: missing /FT /Sig (not a signature field).");
        }

        // Check /V reference
        int vIdx = objText.IndexOf("/V ", StringComparison.Ordinal);
        if (vIdx >= 0)
        {
            string afterV = objText[(vIdx + 3)..].TrimStart();
            // Extract object number from "N 0 R"
            int refObjNum = 0;
            int pos = 0;
            while (pos < afterV.Length && IsAsciiDigit(afterV[pos]))
            {
                refObjNum = refObjNum * 10 + (afterV[pos++] - '0');
            }

            if (refObjNum > 0)
            {
                var (vStart, vEnd) = FindObjectBytes(data, refObjNum);
                if (vStart < 0)
                {
                    warnings.Add($"Object {objNum}: /V references object {refObjNum} which does not exist.");
                }
                else
                {
                    string vObj = Encoding.Latin1.GetString(data.Slice(vStart, vEnd - vStart));
                    if (!vObj.Contains(PdfKeys.TypeSig, StringComparison.Ordinal) &&
                        !vObj.Contains(PdfKeys.TypeSigNoSpace, StringComparison.Ordinal))
                    {
                        warnings.Add($"Object {objNum}: /V references object {refObjNum} which is not a /Type /Sig dictionary.");
                    }
                }
            }
        }

        return warnings;
    }

    /// <summary>
    /// Validates AcroForm /Fields integrity by checking that all referenced objects
    /// exist in the PDF data (§12.7.3). Returns a list of warnings for orphaned references.
    /// </summary>
    public static List<string> ValidateAcroFormFields(ReadOnlySpan<byte> data, List<string> fieldRefs)
    {
        var warnings = new List<string>();
        foreach (string fieldRef in fieldRefs)
        {
            // Parse "N 0 R" → extract N
            string[] parts = fieldRef.Split(' ');
            if (parts.Length < 1 || !int.TryParse(parts[0], out int objNum))
            {
                warnings.Add($"Invalid field reference format: '{fieldRef}'.");
                continue;
            }

            var (objStart, _) = FindObjectBytes(data, objNum);
            if (objStart < 0)
            {
                warnings.Add($"AcroForm /Fields references object {objNum} which does not exist (orphaned reference).");
            }
        }

        return warnings;
    }

    // ── Private helpers ──────────────────────────────────────────────────────
}
