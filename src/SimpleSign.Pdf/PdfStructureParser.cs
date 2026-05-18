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
        int acroFormKeyPos = catalogText.IndexOf("/AcroForm", StringComparison.Ordinal);
        if (acroFormKeyPos < 0)
        {
            return 0;
        }

        int cursor;
        for (cursor = acroFormKeyPos + "/AcroForm".Length; cursor < catalogText.Length && (catalogText[cursor] == ' ' || catalogText[cursor] == '\n' || catalogText[cursor] == '\r'); cursor++)
        {
        }

        if (cursor < catalogText.Length && catalogText[cursor] != '<')
        {
            int acroFormObjNum = 0;
            while (cursor < catalogText.Length && char.IsDigit(catalogText[cursor]))
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
        int acroFormKeyPos = catalogText.IndexOf("/AcroForm", StringComparison.Ordinal);
        if (acroFormKeyPos < 0)
        {
            return [];
        }

        // Skip whitespace after /AcroForm
        int cursor = acroFormKeyPos + "/AcroForm".Length;
        while (cursor < catalogText.Length && (catalogText[cursor] == ' ' || catalogText[cursor] == '\n' || catalogText[cursor] == '\r'))
        {
            cursor++;
        }

        // Only handle inline dict (starts with <<)
        if (cursor >= catalogText.Length || catalogText[cursor] != '<')
        {
            return [];
        }

        // Find matching >> for the inline dict
        int depth = 0;
        int dictStart = cursor;
        int dictEnd = -1;
        for (int i = dictStart; i < catalogText.Length - 1; i++)
        {
            if (catalogText[i] == '<' && catalogText[i + 1] == '<')
            {
                depth++;
                i++;
            }
            else if (catalogText[i] == '>' && catalogText[i + 1] == '>')
            {
                depth--;
                i++;
                if (depth == 0)
                {
                    dictEnd = i + 1;
                    break;
                }
            }
        }

        if (dictEnd < 0)
        {
            return [];
        }

        string inlineDict = catalogText[dictStart..dictEnd];
        return ParseFieldsArray(inlineDict);
    }

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

        // Extract first /Kids entry
        int kidsPos = pagesText.IndexOf("/Kids", StringComparison.Ordinal);
        if (kidsPos < 0)
        {
            return -1;
        }

        int bracketStart = pagesText.IndexOf('[', kidsPos);
        if (bracketStart < 0)
        {
            return -1;
        }

        // Parse first object reference in /Kids array
        int cursor = bracketStart + 1;
        while (cursor < pagesText.Length && !char.IsDigit(pagesText[cursor]))
        {
            cursor++;
        }

        int numStart = cursor;
        while (cursor < pagesText.Length && char.IsDigit(pagesText[cursor]))
        {
            cursor++;
        }

        if (numStart < cursor && int.TryParse(pagesText.AsSpan(numStart, cursor - numStart), out int firstPageObj))
        {
            return firstPageObj;
        }

        return -1;
    }

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
    /// Extracts an indirect object reference number from a dictionary key (e.g., "/Pages 2 0 R" → 2).
    /// </summary>
    private static int ExtractObjReference(string dictText, string key)
    {
        int keyPos = dictText.IndexOf(key, StringComparison.Ordinal);
        if (keyPos < 0)
        {
            return -1;
        }

        int cursor = keyPos + key.Length;
        while (cursor < dictText.Length && (dictText[cursor] == ' ' || dictText[cursor] == '\n' || dictText[cursor] == '\r'))
        {
            cursor++;
        }

        int numStart = cursor;
        while (cursor < dictText.Length && char.IsDigit(dictText[cursor]))
        {
            cursor++;
        }

        if (numStart < cursor && int.TryParse(dictText.AsSpan(numStart, cursor - numStart), out int objNum))
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

        string[] tokens = arrayContent.Split([' ', '\n', '\r', '\t'], StringSplitOptions.RemoveEmptyEntries);
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
    /// Resolves an indirect <c>/Fields N 0 R</c> reference from an AcroForm dictionary.
    /// When <c>/Fields</c> points to a separate array object instead of containing an inline array,
    /// this method resolves the referenced object and parses its contents.
    /// Returns the field references, or an empty list if the pattern is not found.
    /// </summary>
    public static List<string> ResolveIndirectFields(ReadOnlySpan<byte> data, string acroFormText)
    {
        int fieldsKeyPos = acroFormText.IndexOf("/Fields", StringComparison.Ordinal);
        if (fieldsKeyPos < 0)
        {
            return [];
        }

        int cursor = fieldsKeyPos + "/Fields".Length;
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
        if (!char.IsDigit(acroFormText[cursor]))
        {
            return [];
        }

        int fieldsObjNum = 0;
        while (cursor < acroFormText.Length && char.IsDigit(acroFormText[cursor]))
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

        // Must have /FT /Sig
        if (!objText.Contains("/FT /Sig", StringComparison.Ordinal) &&
            !objText.Contains("/FT/Sig", StringComparison.Ordinal))
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
            while (pos < afterV.Length && char.IsDigit(afterV[pos]))
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
                    if (!vObj.Contains("/Type /Sig", StringComparison.Ordinal) &&
                        !vObj.Contains("/Type/Sig", StringComparison.Ordinal))
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

        while (pos < text.Length && char.IsDigit(text[pos]))
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
