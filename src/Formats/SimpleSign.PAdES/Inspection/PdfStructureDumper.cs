using System.Formats.Asn1;
using System.Text;
using System.Text.RegularExpressions;
using SimpleSign.Core.Inspection;

namespace SimpleSign.PAdES.Inspection;

/// <summary>
/// Extracts and formats the raw PDF object structure related to digital signatures.
/// Produces a human-readable dump of /Sig dictionaries, /AcroForm, /DSS, /VRI,
/// and associated stream objects — omitting irrelevant page/content/font objects.
/// </summary>
public static partial class PdfStructureDumper
{
    /// <summary>A single key-value entry from a PDF dictionary.</summary>
    public sealed record DictEntry(string Key, string RawValue, string? Explanation = null);

    /// <summary>Stream compression information.</summary>
    public sealed record StreamInfo(int CompressedBytes, int? DecompressedBytes, bool IsFlateEncoded);

    /// <summary>ASN.1 content preview extracted from /Contents hex.</summary>
    public sealed record Asn1Preview(string ContentType, string? SignerSubject);

    /// <summary>
    /// A single extracted PDF object with rich structured data for rendering.
    /// </summary>
    public sealed record PdfObjectDump(
        int ObjectNumber,
        string Label,
        string Content,
        int? StreamSizeBytes = null,
        int? DecompressedSizeBytes = null)
    {
        /// <summary>Parsed dictionary entries for structured rendering.</summary>
        public IReadOnlyList<DictEntry> Entries { get; init; } = [];

        /// <summary>Stream compression details (null if no stream).</summary>
        public StreamInfo? Stream { get; init; }

        /// <summary>Decoded ASN.1 preview of /Contents (null if not a sig dict).</summary>
        public Asn1Preview? ContentsPreview { get; init; }

        /// <summary>Short badge tags summarizing the object.</summary>
        public IReadOnlyList<string> Badges { get; init; } = [];

        /// <summary>Cross-references: object numbers this object points to.</summary>
        public IReadOnlyList<int> References { get; init; } = [];

        /// <summary>Icon text for the object type (ASCII-safe for Windows terminals).</summary>
        public string Icon => Label switch
        {
            "Catalog" => "CAT",
            "AcroForm" => "FORM",
            "Signature Field" => "FLD",
            "Signature" => "SIG",
            "DocTimeStamp" => "TS",
            "DSS" => "DSS",
            "VRI Entry" => "VRI",
            "CRL Stream" => "CRL",
            "OCSP Stream" => "OCSP",
            "Cert Stream" => "CERT",
            "Data Stream" => "DATA",
            _ => "OBJ"
        };
    }

    /// <summary>
    /// Extracts all signature-related PDF objects from the document and returns them
    /// with rich structured data for rendering.
    /// </summary>
    public static IReadOnlyList<PdfObjectDump> ExtractSignatureObjects(
        byte[] pdfBytes,
        bool includeExplanations = false)
    {
        ArgumentNullException.ThrowIfNull(pdfBytes);
        var text = Encoding.Latin1.GetString(pdfBytes);
        var results = new List<PdfObjectDump>();

        var objects = FindAllObjects(text);
        var objectsByNum = new Dictionary<int, (int ObjNum, int StartPos, string Content)>();
        foreach (var obj in objects)
        {
            objectsByNum[obj.ObjNum] = obj; // last revision wins for lookup
        }

        var sigRelatedObjNums = new HashSet<int>();
        var dssReferencedObjNums = new HashSet<int>();

        // First pass: direct detection (use last revision of each object for complete references)
        foreach (var (objNum, objStart, dictContent) in objectsByNum.Values)
        {
            if (IsSignatureRelated(dictContent, out string label))
            {
                sigRelatedObjNums.Add(objNum);
                AddObjectToResults(results, objNum, objStart, dictContent, label, includeExplanations,
                    pdfBytes, text, dssReferencedObjNums);
            }
        }

        // Second pass: follow references from AcroForm/Catalog to discover fields and sig dicts
        // that weren't detected by pattern matching (e.g., missing /Type /Sig or /FT /Sig)
        var referencedFieldNums = new HashSet<int>();
        var referencedSigNums = new HashSet<int>();

        // Collect /Fields from ALL revisions of AcroForm/Catalog objects (not just the last),
        // because incremental updates may add new fields in each revision.
        foreach (var (_, _, dictContent) in objects)
        {
            if (dictContent.Contains("/AcroForm") || dictContent.Contains("/Fields"))
            {
                var entries = ParseDictEntries(dictContent, false, "");
                var fieldRefs = ExtractArrayReferences(entries, "/Fields");
                foreach (int refNum in fieldRefs)
                {
                    if (!sigRelatedObjNums.Contains(refNum))
                    {
                        referencedFieldNums.Add(refNum);
                    }
                }
            }
        }

        foreach (var result in results.ToArray())
        {
            if (result.Label is "AcroForm" or "Catalog")
            {
                var fieldRefs = ExtractArrayReferences(result.Entries, "/Fields");
                foreach (int refNum in fieldRefs)
                {
                    if (!sigRelatedObjNums.Contains(refNum))
                    {
                        referencedFieldNums.Add(refNum);
                    }
                }
            }
            else if (result.Label == "Signature Field")
            {
                // Follow /V reference only (not /P page, /AP appearance, etc.)
                var vRef = ExtractSingleReference(result.Entries, "/V");
                if (vRef.HasValue && !sigRelatedObjNums.Contains(vRef.Value))
                {
                    referencedSigNums.Add(vRef.Value);
                }
            }
        }

        // Add discovered field objects
        foreach (int fieldObjNum in referencedFieldNums)
        {
            if (objectsByNum.TryGetValue(fieldObjNum, out var fieldObj))
            {
                string content = fieldObj.Content;
                // Verify it looks like a form field (has /T for field name or /Subtype /Widget)
                if (content.Contains("/T (") || content.Contains("/T(") ||
                    content.Contains("/Subtype /Widget") || content.Contains("/Subtype/Widget"))
                {
                    sigRelatedObjNums.Add(fieldObjNum);
                    AddObjectToResults(results, fieldObj.ObjNum, fieldObj.StartPos, content,
                        "Signature Field", includeExplanations, pdfBytes, text, dssReferencedObjNums);

                    // Follow /V reference from this new field to sig dict
                    var fieldEntries = ParseDictEntries(content, false, "Signature Field");
                    var vRef = ExtractSingleReference(fieldEntries, "/V");
                    if (vRef.HasValue && !sigRelatedObjNums.Contains(vRef.Value))
                    {
                        referencedSigNums.Add(vRef.Value);
                    }
                }
            }
        }

        // Add discovered signature dict objects
        foreach (int sigObjNum in referencedSigNums)
        {
            if (objectsByNum.TryGetValue(sigObjNum, out var sigObj) && !sigRelatedObjNums.Contains(sigObjNum))
            {
                string content = sigObj.Content;
                // Must have /ByteRange — all real sig dicts have it. /Contents alone matches Page objects.
                if (content.Contains("/ByteRange"))
                {
                    sigRelatedObjNums.Add(sigObjNum);
                    string label = content.Contains("ETSI.RFC3161") ? "DocTimeStamp" : "Signature";
                    AddObjectToResults(results, sigObj.ObjNum, sigObj.StartPos, content,
                        label, includeExplanations, pdfBytes, text, dssReferencedObjNums);
                }
            }
        }

        // Add DSS stream objects (CRL/OCSP/Cert referenced by DSS but not yet added)
        foreach (var (objNum, objStart, dictContent) in objectsByNum.Values)
        {
            if (!sigRelatedObjNums.Contains(objNum) && dssReferencedObjNums.Contains(objNum))
            {
                int? streamSize = ExtractStreamLength(dictContent);
                if (streamSize is null or 0)
                {
                    continue;
                }

                bool hasFlate = dictContent.Contains("FlateDecode");
                int? decompressedSize = hasFlate ? TryDecompress(pdfBytes, objStart, text) : null;

                string streamLabel = DetermineStreamLabel(objNum, text);
                string header = hasFlate
                    ? $"<< /Filter /FlateDecode /Length {streamSize} >>"
                    : $"<< /Length {streamSize} >>";

                if (includeExplanations)
                {
                    string comment = streamLabel switch
                    {
                        "CRL Stream" => "% DER-encoded Certificate Revocation List",
                        "OCSP Stream" => "% DER-encoded OCSP response",
                        "Cert Stream" => "% DER-encoded X.509 certificate",
                        _ => "% DSS data stream"
                    };
                    header += $"  {comment}";
                }

                var streamBadges = new List<string>();
                if (hasFlate)
                {
                    streamBadges.Add("FlateDecode");
                }

                streamBadges.Add(streamLabel.Replace(" Stream", ""));

                results.Add(new PdfObjectDump(objNum, streamLabel, header, streamSize, decompressedSize)
                {
                    Entries = [new DictEntry("/Length", streamSize.Value.ToString())],
                    Stream = new StreamInfo(streamSize.Value, decompressedSize, hasFlate),
                    Badges = streamBadges,
                });
            }
        }

        results.Sort((a, b) => a.ObjectNumber.CompareTo(b.ObjectNumber));
        return results;
    }

    private static void AddObjectToResults(
        List<PdfObjectDump> results, int objNum, int objStart, string dictContent, string label,
        bool includeExplanations, byte[] pdfBytes, string text, HashSet<int> dssReferencedObjNums)
    {
        var formatted = FormatObject(dictContent, includeExplanations, label);
        int? streamSize = null;
        int? decompressedSize = null;

        if (dictContent.Contains("stream\n") || dictContent.Contains("stream\r\n"))
        {
            streamSize = ExtractStreamLength(dictContent);
            bool hasFlate = dictContent.Contains("FlateDecode");
            if (hasFlate && streamSize > 0)
            {
                decompressedSize = TryDecompress(pdfBytes, objStart, text);
            }
        }

        var entries = ParseDictEntries(dictContent, includeExplanations, label);
        var refs = ExtractObjectReferences(dictContent);
        var badges = InferBadges(label, dictContent, entries);
        var asn1 = TryExtractAsn1Preview(dictContent, pdfBytes, objStart, text);
        StreamInfo? streamInfo = streamSize.HasValue
            ? new StreamInfo(streamSize.Value, decompressedSize, dictContent.Contains("FlateDecode"))
            : null;

        results.Add(new PdfObjectDump(objNum, label, formatted, streamSize, decompressedSize)
        {
            Entries = entries,
            Stream = streamInfo,
            ContentsPreview = asn1,
            Badges = badges,
            References = refs,
        });

        if (label.Contains("DSS") || label.Contains("VRI"))
        {
            foreach (int refNum in refs)
            {
                dssReferencedObjNums.Add(refNum);
            }
        }
    }

    /// <summary>
    /// Formats extracted objects as a plain-text output (legacy, non-colored).
    /// </summary>
    public static string Format(IReadOnlyList<PdfObjectDump> objects)
    {
        var sb = new StringBuilder();
        foreach (var obj in objects)
        {
            string header = $"── {obj.Label}: {obj.ObjectNumber} 0 obj ";
            sb.Append(header);
            sb.Append(new string('─', Math.Max(1, 60 - header.Length)));
            sb.AppendLine();
            sb.AppendLine(obj.Content);

            if (obj.StreamSizeBytes.HasValue)
            {
                if (obj.DecompressedSizeBytes.HasValue)
                {
                    sb.AppendLine($"stream ({FormatSize(obj.StreamSizeBytes.Value)} compressed → {FormatSize(obj.DecompressedSizeBytes.Value)} decompressed)");
                }
                else if (obj.StreamSizeBytes > 0)
                {
                    sb.AppendLine($"stream ({FormatSize(obj.StreamSizeBytes.Value)})");
                }
            }

            sb.AppendLine();
        }

        return sb.ToString();
    }

    #region Object Discovery

    private static List<(int ObjNum, int StartPos, string Content)> FindAllObjects(string text)
    {
        var results = new List<(int, int, string)>();
        int pos = 0;

        while (pos < text.Length)
        {
            // Find next "N 0 obj"
            int objIdx = text.IndexOf(" 0 obj", pos, StringComparison.Ordinal);
            if (objIdx < 0)
            {
                break;
            }

            // Extract object number (digits before " 0 obj")
            int numEnd = objIdx;
            int numStart = numEnd - 1;
            while (numStart >= 0 && text[numStart] >= '0' && text[numStart] <= '9')
            {
                numStart--;
            }
            numStart++;

            if (numStart >= numEnd || (numStart > 0 && text[numStart - 1] != '\n' && text[numStart - 1] != '\r' && numStart != 0))
            {
                pos = objIdx + 6;
                continue;
            }

            if (!int.TryParse(text.AsSpan(numStart, numEnd - numStart), out int objNum))
            {
                pos = objIdx + 6;
                continue;
            }

            // Find endobj
            int contentStart = objIdx + 6; // after " 0 obj"
            int endObj = text.IndexOf("endobj", contentStart, StringComparison.Ordinal);
            if (endObj < 0)
            {
                break;
            }

            // Limit content extraction — cap at 2KB normally.
            // For sig dicts with /Contents hex, capture full content but truncate the huge
            // hex string inline so the dict stays parseable (closing >> isn't lost).
            int rawLen = endObj - contentStart;
            bool hasSigContents = rawLen > 2048 &&
                text.AsSpan(contentStart, Math.Min(rawLen, 500)).Contains("/Contents", StringComparison.Ordinal);

            string content;
            if (hasSigContents)
            {
                // Capture full object, then truncate /Contents hex to keep dict structure intact
                content = text.Substring(contentStart, rawLen);
                content = TruncateContentsHexInline(content);
            }
            else
            {
                int contentLen = Math.Min(rawLen, 2048);
                content = text.Substring(contentStart, contentLen);
            }

            results.Add((objNum, numStart, content));
            pos = endObj + 6;
        }

        return results;
    }

    private static bool IsSignatureRelated(string content, out string label)
    {
        // Signature dictionary — /Type /Sig is optional per spec
        bool hasTypeSig = content.Contains("/Type /Sig") || content.Contains("/Type/Sig");
        bool hasByteRange = content.Contains("/ByteRange");
        bool hasSubFilter = content.Contains("/SubFilter");
        bool hasAdobeFilter = content.Contains("/Adobe.PPKLite") || content.Contains("/Adobe.PPKMS");

        if ((hasTypeSig || hasAdobeFilter) && (hasByteRange || hasSubFilter))
        {
            label = content.Contains("ETSI.RFC3161") ? "DocTimeStamp" : "Signature";
            return true;
        }

        // Also match by /ByteRange + /SubFilter + /Contents (sig dict without /Type or /Filter name)
        if (hasByteRange && hasSubFilter && content.Contains("/Contents"))
        {
            label = content.Contains("ETSI.RFC3161") ? "DocTimeStamp" : "Signature";
            return true;
        }

        // Signature field — /FT may be absent if inherited from AcroForm parent
        bool hasFtSig = content.Contains("/FT /Sig") || content.Contains("/FT/Sig");
        bool hasFieldName = content.Contains("/T (") || content.Contains("/T(");
        bool isWidget = content.Contains("/Subtype /Widget") || content.Contains("/Subtype/Widget");

        if (hasFtSig && (hasFieldName || isWidget))
        {
            label = "Signature Field";
            return true;
        }

        // Widget annotation that references a sig value (/V points to sig dict)
        if (isWidget && hasFieldName && content.Contains("/V "))
        {
            label = "Signature Field";
            return true;
        }

        if (content.Contains("/Type /Catalog") && (content.Contains("/AcroForm") || content.Contains("/DSS")))
        {
            label = "Catalog";
            return true;
        }
        if (content.Contains("/Type /DSS") || (content.Contains("/CRLs") && content.Contains("/Certs")))
        {
            label = "DSS";
            return true;
        }
        if ((content.Contains("/CRL ") || content.Contains("/CRL\n") || content.Contains("/OCSP ")) &&
            (content.Contains("/TU ") || content.Contains("/Cert ")))
        {
            label = "VRI Entry";
            return true;
        }
        if (content.Contains("/Type /AcroForm") || (content.Contains("/Fields") && content.Contains("/SigFlags")))
        {
            label = "AcroForm";
            return true;
        }

        label = "";
        return false;
    }

    #endregion

    #region Formatting

    private static string FormatObject(string rawContent, bool explain, string context)
    {
        // Extract the dictionary portion (between << and >>)
        int dictStart = rawContent.IndexOf("<<", StringComparison.Ordinal);
        if (dictStart < 0)
        {
            return rawContent.Trim();
        }

        int dictEnd = FindMatchingDictEnd(rawContent, dictStart);

        // If matching >> not found (truncated content), parse from << to end
        string dictContent = dictEnd >= 0
            ? rawContent.Substring(dictStart + 2, dictEnd - dictStart - 2)
            : rawContent[(dictStart + 2)..].TrimEnd();

        var sb = new StringBuilder();
        sb.AppendLine("<<");

        var entries = ParseDictionaryLines(dictContent);
        foreach (var (key, value) in entries)
        {
            string displayValue = key == "/Contents" ? TruncateContents(value) : value;

            if (explain)
            {
                string? comment = GetFieldComment(key, context);
                sb.AppendLine(comment is not null
                    ? $"   {key} {displayValue}  % {comment}"
                    : $"   {key} {displayValue}");
            }
            else
            {
                sb.AppendLine($"   {key} {displayValue}");
            }
        }

        sb.Append(">>");
        return sb.ToString();
    }

    private static int FindMatchingDictEnd(string text, int startIdx)
    {
        if (startIdx < 0)
        {
            return -1;
        }

        int depth = 0;
        bool inHexString = false;
        for (int i = startIdx; i < text.Length - 1; i++)
        {
            if (inHexString)
            {
                if (text[i] == '>')
                {
                    inHexString = false;
                }

                continue;
            }

            if (text[i] == '<' && text[i + 1] == '<')
            {
                depth++;
                i++;
            }
            else if (text[i] == '>' && text[i + 1] == '>')
            {
                depth--;
                i++;
                if (depth == 0)
                {
                    return i + 1;
                }
            }
            else if (text[i] == '<' && text[i + 1] != '<')
            {
                // Single '<' starts a hex string
                inHexString = true;
            }
        }

        return -1;
    }

    private static string TruncateContents(string value)
    {
        if (value.StartsWith('<') && value.Length > 20)
        {
            int endBracket = value.IndexOf('>');
            if (endBracket > 0)
            {
                string hex = value[1..endBracket];
                int totalBytes = hex.Length / 2;
                int actualBytes = hex.TrimEnd('0').Length / 2;
                return $"<{hex[..Math.Min(16, hex.Length)]}...> ({FormatSize(actualBytes)} data, {FormatSize(totalBytes)} allocated)";
            }
        }
        return value;
    }

    /// <summary>
    /// Truncates the /Contents hex string within raw object content so the dict structure
    /// (closing &gt;&gt;) is preserved. Keeps first 200 hex chars (enough for ASN.1 OID detection)
    /// plus size info.
    /// </summary>
    private static string TruncateContentsHexInline(string content)
    {
        // Find /Contents followed by a hex string
        int idx = content.IndexOf("/Contents", StringComparison.Ordinal);
        if (idx < 0)
        {
            return content;
        }

        // Skip whitespace/newlines after /Contents
        int hexStart = idx + "/Contents".Length;
        while (hexStart < content.Length && (content[hexStart] == ' ' || content[hexStart] == '\n' || content[hexStart] == '\r' || content[hexStart] == '\t'))
        {
            hexStart++;
        }

        if (hexStart >= content.Length || content[hexStart] != '<')
        {
            return content;
        }

        // Make sure it's a hex string (not <<)
        if (hexStart + 1 < content.Length && content[hexStart + 1] == '<')
        {
            return content;
        }

        // Find closing >
        int hexEnd = content.IndexOf('>', hexStart + 1);
        if (hexEnd < 0)
        {
            // No closing > found — content was already truncated, reconstruct with valid hex
            string partialHex = content[(hexStart + 1)..];
            int partialBytes = partialHex.Length / 2;
            // Keep first 200 hex chars (enough for ASN.1 preview), close the hex string properly
            int keepLen = Math.Min(200, partialHex.Length);
            string keptHex = partialHex[..keepLen];
            return string.Concat(
                content.AsSpan(0, hexStart),
                $"<{keptHex}> (~{FormatSize(partialBytes)}+ data)");
        }

        int hexLen = hexEnd - hexStart - 1;
        if (hexLen <= 400)
        {
            return content; // small enough, no truncation needed
        }

        string fullHex = content[(hexStart + 1)..hexEnd];
        int totalBytes = fullHex.Length / 2;
        int actualBytes = fullHex.TrimEnd('0').Length / 2;
        // Keep first 200 hex chars for ASN.1 OID detection, store as valid hex + separate size info
        string hexPreview = fullHex[..Math.Min(200, fullHex.Length)];
        string sizeInfo = $"({FormatSize(actualBytes)} data, {FormatSize(totalBytes)} allocated)";
        string replacement = $"<{hexPreview}> {sizeInfo}";

        return string.Concat(
            content.AsSpan(0, hexStart),
            replacement,
            content.AsSpan(hexEnd + 1));
    }

    private static List<(string Key, string Value)> ParseDictionaryLines(string dictContent)
    {
        var entries = new List<(string, string)>();
        int pos = 0;

        while (pos < dictContent.Length)
        {
            // Find next /Key
            int slashIdx = dictContent.IndexOf('/', pos);
            if (slashIdx < 0)
            {
                break;
            }

            // Read key name (until whitespace or special char)
            int keyEnd = slashIdx + 1;
            while (keyEnd < dictContent.Length && dictContent[keyEnd] != ' ' && dictContent[keyEnd] != '\n' &&
                   dictContent[keyEnd] != '\r' && dictContent[keyEnd] != '/' && dictContent[keyEnd] != '<' &&
                   dictContent[keyEnd] != '[' && dictContent[keyEnd] != '(' && dictContent[keyEnd] != ')')
            {
                keyEnd++;
            }

            string key = string.Concat("/", dictContent.AsSpan(slashIdx + 1, keyEnd - slashIdx - 1));

            // Skip whitespace
            int valueStart = keyEnd;
            while (valueStart < dictContent.Length && (dictContent[valueStart] == ' ' || dictContent[valueStart] == '\t'))
            {
                valueStart++;
            }

            // Read value until next /Key at depth 0, newline, or end
            int valueEnd = valueStart;
            int bracketDepth = 0;
            int angleBracketDepth = 0;
            bool inHexString = false;
            while (valueEnd < dictContent.Length)
            {
                char c = dictContent[valueEnd];
                if (c == '[')
                {
                    bracketDepth++;
                }
                else if (c == ']')
                {
                    bracketDepth--;
                }
                else if (c == '<' && valueEnd + 1 < dictContent.Length && dictContent[valueEnd + 1] == '<')
                {
                    angleBracketDepth++;
                    valueEnd++;
                }
                else if (c == '>' && valueEnd + 1 < dictContent.Length && dictContent[valueEnd + 1] == '>')
                {
                    angleBracketDepth--;
                    valueEnd++;
                }
                else if (c == '<' && !(valueEnd + 1 < dictContent.Length && dictContent[valueEnd + 1] == '<'))
                {
                    inHexString = true;
                }
                else if (c == '>' && inHexString)
                {
                    inHexString = false;
                }
                else if (c == '/' && bracketDepth <= 0 && angleBracketDepth <= 0 && !inHexString && valueEnd > valueStart)
                {
                    // Slash at depth 0 = next key starting. Check if preceded by space/digit/letter/bracket.
                    char prev = dictContent[valueEnd - 1];
                    if (prev == ' ' || prev == '\t' || prev == ')' || prev == ']' ||
                        char.IsLetterOrDigit(prev) || prev == '>')
                    {
                        break;
                    }
                }
                else if (c == '\n' || c == '\r')
                {
                    if (bracketDepth <= 0 && angleBracketDepth <= 0)
                    {
                        break;
                    }
                }

                valueEnd++;
            }

            string value = dictContent[valueStart..valueEnd].Trim();
            // Strip trailing >> that leaks from outer dict close into the last value
            if (value.EndsWith(">>") && !value.StartsWith("<<"))
            {
                value = value[..^2].TrimEnd();
            }

            if (!string.IsNullOrEmpty(key) && key.Length > 1)
            {
                entries.Add((key, value));
            }

            pos = valueEnd;
        }

        return entries;
    }

    private static string? GetFieldComment(string key, string context)
    {
        var entry = SignatureGlossary.Lookup(key);
        if (entry is not null)
        {
            return entry.ShortDescription;
        }

        return (key, context) switch
        {
            ("/Type", "Catalog") => "Document catalog",
            ("/Filter", _) => "Signature handler (Adobe.PPKLite = standard PDF viewer)",
            ("/SubFilter", _) => "Encoding format of the signature value",
            ("/ByteRange", _) => "Byte ranges covered by the signature [offset1 len1 offset2 len2]",
            ("/Contents", _) => "Hex-encoded CMS/PKCS#7 SignedData (padded with zeros)",
            ("/M", _) => "Claimed signing time (not cryptographically bound)",
            ("/Reason", _) => "Declared reason for signing",
            ("/Name", _) => "Declared signer name (not verified)",
            ("/Location", _) => "Physical location of signer",
            ("/ContactInfo", _) => "Contact information",
            ("/CRLs", _) => "References to CRL stream objects",
            ("/OCSPs", _) => "References to OCSP response stream objects",
            ("/Certs", _) => "References to certificate stream objects",
            ("/VRI", _) => "Validation Related Information per signature",
            ("/TU", _) => "Time of VRI creation",
            ("/CRL", _) => "CRL references for this signature",
            ("/OCSP", _) => "OCSP references for this signature",
            ("/Cert", _) => "Certificate references for this signature",
            ("/AcroForm", _) => "Interactive form dictionary (holds signature fields)",
            ("/DSS", _) => "Document Security Store reference",
            ("/Fields", _) => "Array of form field objects",
            ("/FT", _) => "Field type (/Sig = signature field)",
            ("/V", _) => "Signature value (reference to /Sig dict)",
            ("/T", _) => "Field partial name",
            ("/Rect", _) => "Widget rectangle [x1 y1 x2 y2] in points",
            ("/AP", _) => "Appearance dictionary (/N = normal appearance)",
            ("/P", _) => "Page reference",
            ("/SigFlags", _) => "Signature flags (1=SignaturesExist, 2=AppendOnly)",
            ("/Prop_Build", _) => "Build properties of signing application",
            _ => null
        };
    }

    #endregion

    #region Rich Data Extraction

    private static List<DictEntry> ParseDictEntries(string rawContent, bool explain, string label)
    {
        int dictStart = rawContent.IndexOf("<<", StringComparison.Ordinal);
        if (dictStart < 0)
        {
            return [];
        }

        int dictEnd = FindMatchingDictEnd(rawContent, dictStart);

        // If matching >> not found (truncated content), parse from << to end
        string dictContent = dictEnd >= 0
            ? rawContent.Substring(dictStart + 2, dictEnd - dictStart - 2)
            : rawContent[(dictStart + 2)..].TrimEnd();
        var parsed = ParseDictionaryLines(dictContent);
        var result = new List<DictEntry>(parsed.Count);

        foreach (var (key, value) in parsed)
        {
            string? explanation = explain ? GetFieldComment(key, label) : null;
            result.Add(new DictEntry(key, value, explanation));
        }

        return result;
    }

    private static List<string> InferBadges(string label, string content, IReadOnlyList<DictEntry> entries)
    {
        var badges = new List<string>();

        if (label == "Signature")
        {
            var subFilter = entries.FirstOrDefault(e => e.Key == "/SubFilter");
            if (subFilter is not null)
            {
                if (subFilter.RawValue.Contains("CAdES"))
                {
                    badges.Add("PAdES / CAdES");
                }
                else if (subFilter.RawValue.Contains("pkcs7"))
                {
                    badges.Add("PKCS#7");
                }
            }

            badges.Add("Detached");

            var rect = entries.FirstOrDefault(e => e.Key == "/Rect");
            if (rect is not null && rect.RawValue.Contains("0 0 0 0"))
            {
                badges.Add("Invisible");
            }
        }
        else if (label == "DocTimeStamp")
        {
            badges.Add("RFC 3161");
            badges.Add("Archive");
        }
        else if (label == "DSS")
        {
            badges.Add("LTV Enabled");
            var crls = entries.FirstOrDefault(e => e.Key == "/CRLs");
            if (crls is not null)
            {
                int count = ObjRefRegex().Count(crls.RawValue);
                if (count > 0)
                {
                    badges.Add($"{count} CRL{(count != 1 ? "s" : "")}");
                }
            }

            var certs = entries.FirstOrDefault(e => e.Key == "/Certs");
            if (certs is not null)
            {
                int count = ObjRefRegex().Count(certs.RawValue);
                if (count > 0)
                {
                    badges.Add($"{count} Cert{(count != 1 ? "s" : "")}");
                }
            }

            var ocsps = entries.FirstOrDefault(e => e.Key == "/OCSPs");
            if (ocsps is not null)
            {
                int count = ObjRefRegex().Count(ocsps.RawValue);
                if (count > 0)
                {
                    badges.Add($"{count} OCSP{(count != 1 ? "s" : "")}");
                }
            }
        }
        else if (label == "Signature Field")
        {
            var rect = entries.FirstOrDefault(e => e.Key == "/Rect");
            if (rect is not null && rect.RawValue.Contains("0 0 0 0"))
            {
                badges.Add("Invisible");
            }
            else if (rect is not null)
            {
                badges.Add("Visible");
            }
        }
        else if (label == "AcroForm")
        {
            var sigFlags = entries.FirstOrDefault(e => e.Key == "/SigFlags");
            if (sigFlags is not null)
            {
                if (int.TryParse(sigFlags.RawValue.Trim(), out int flags))
                {
                    if ((flags & 1) != 0)
                    {
                        badges.Add("SignaturesExist");
                    }

                    if ((flags & 2) != 0)
                    {
                        badges.Add("AppendOnly");
                    }
                }
            }

            var fields = entries.FirstOrDefault(e => e.Key == "/Fields");
            if (fields is not null)
            {
                int count = ObjRefRegex().Count(fields.RawValue);
                badges.Add($"{count} field{(count != 1 ? "s" : "")}");
            }
        }
        else if (label == "Catalog")
        {
            if (content.Contains("/DSS"))
            {
                badges.Add("DSS");
            }

            if (content.Contains("/AcroForm"))
            {
                badges.Add("AcroForm");
            }
        }

        return badges;
    }

    private static Asn1Preview? TryExtractAsn1Preview(string dictContent, byte[] pdfBytes, int objStart, string text)
    {
        // Only for signature objects (may or may not have /Type /Sig)
        if (!dictContent.Contains("/Contents") || !dictContent.Contains("/ByteRange"))
        {
            return null;
        }

        try
        {
            // Find /Contents <hex...>
            int contIdx = dictContent.IndexOf("/Contents", StringComparison.Ordinal);
            if (contIdx < 0)
            {
                return null;
            }

            int hexStart = dictContent.IndexOf('<', contIdx);
            if (hexStart < 0 || (hexStart + 1 < dictContent.Length && dictContent[hexStart + 1] == '<'))
            {
                return null;
            }

            int hexEnd = dictContent.IndexOf('>', hexStart);
            if (hexEnd < 0 || hexEnd - hexStart < 10)
            {
                return null;
            }

            // Parse first portion of hex (enough for outer SEQUENCE + OID)
            int hexLen = Math.Min(hexEnd - hexStart - 1, 200);
            string hexStr = dictContent.Substring(hexStart + 1, hexLen);
            byte[] asn1Bytes = ConvertHexToBytes(hexStr);
            if (asn1Bytes.Length < 10)
            {
                return null;
            }

            var reader = new AsnReader(asn1Bytes, AsnEncodingRules.BER);
            var seq = reader.ReadSequence();
            string oid = seq.ReadObjectIdentifier();

            string contentType = oid switch
            {
                "1.2.840.113549.1.7.2" => "pkcs7-signedData",
                "1.2.840.113549.1.9.16.1.4" => "id-smime-ct-TSTInfo",
                "1.2.840.113549.1.7.1" => "pkcs7-data",
                _ => oid
            };

            return new Asn1Preview(contentType, null);
        }
        catch
        {
            return null;
        }
    }

    private static byte[] ConvertHexToBytes(string hex)
    {
        // Remove any whitespace
        var clean = new StringBuilder(hex.Length);
        foreach (char c in hex)
        {
            if (char.IsAsciiHexDigit(c))
            {
                clean.Append(c);
            }
        }

        string cleanStr = clean.ToString();
        int len = cleanStr.Length / 2;
        byte[] result = new byte[len];
        for (int i = 0; i < len; i++)
        {
            result[i] = Convert.ToByte(cleanStr.Substring(i * 2, 2), 16);
        }

        return result;
    }

    #endregion

    #region Helpers

    private static List<int> ExtractObjectReferences(string content)
    {
        var refs = new List<int>();
        var matches = ObjRefRegex().Matches(content);
        foreach (Match m in matches)
        {
            if (int.TryParse(m.Groups[1].Value, out int n))
            {
                refs.Add(n);
            }
        }
        return refs;
    }

    /// <summary>Extract object references from a specific /Key array entry (e.g., /Fields [15 0 R 23 0 R]).</summary>
    private static List<int> ExtractArrayReferences(IReadOnlyList<DictEntry> entries, string key)
    {
        var refs = new List<int>();
        foreach (var entry in entries)
        {
            if (entry.Key == key)
            {
                var matches = ObjRefRegex().Matches(entry.RawValue);
                foreach (Match m in matches)
                {
                    if (int.TryParse(m.Groups[1].Value, out int n))
                    {
                        refs.Add(n);
                    }
                }
                break;
            }
        }
        return refs;
    }

    /// <summary>Extract a single object reference from a specific /Key entry (e.g., /V 42 0 R).</summary>
    private static int? ExtractSingleReference(IReadOnlyList<DictEntry> entries, string key)
    {
        foreach (var entry in entries)
        {
            if (entry.Key == key)
            {
                var match = ObjRefRegex().Match(entry.RawValue);
                if (match.Success && int.TryParse(match.Groups[1].Value, out int n))
                {
                    return n;
                }
                break;
            }
        }
        return null;
    }

    private static int? ExtractStreamLength(string content)
    {
        var match = LengthRegex().Match(content);
        return match.Success ? int.Parse(match.Groups[1].Value) : null;
    }

    private static string DetermineStreamLabel(int objNum, string fullText)
    {
        string objRef = $"{objNum} 0 R";

        // Check DSS arrays
        var crlsMatch = Regex.Match(fullText, @"/CRLs\s*\[([^\]]*)\]");
        if (crlsMatch.Success && crlsMatch.Groups[1].Value.Contains(objRef))
        {
            return "CRL Stream";
        }

        var ocspsMatch = Regex.Match(fullText, @"/OCSPs\s*\[([^\]]*)\]");
        if (ocspsMatch.Success && ocspsMatch.Groups[1].Value.Contains(objRef))
        {
            return "OCSP Stream";
        }

        var certsMatch = Regex.Match(fullText, @"/Certs\s*\[([^\]]*)\]");
        if (certsMatch.Success && certsMatch.Groups[1].Value.Contains(objRef))
        {
            return "Cert Stream";
        }

        // Check VRI-level arrays
        var crlMatch = Regex.Match(fullText, @"/CRL\s*\[([^\]]*)\]");
        if (crlMatch.Success && crlMatch.Groups[1].Value.Contains(objRef))
        {
            return "CRL Stream";
        }

        var ocspMatch = Regex.Match(fullText, @"/OCSP\s*\[([^\]]*)\]");
        if (ocspMatch.Success && ocspMatch.Groups[1].Value.Contains(objRef))
        {
            return "OCSP Stream";
        }

        var certMatch = Regex.Match(fullText, @"/Cert\s*\[([^\]]*)\]");
        if (certMatch.Success && certMatch.Groups[1].Value.Contains(objRef))
        {
            return "Cert Stream";
        }

        return "Data Stream";
    }

    private static int? TryDecompress(byte[] pdfBytes, int objStartPos, string text)
    {
        int streamIdx = text.IndexOf("stream\n", objStartPos, Math.Min(500, text.Length - objStartPos), StringComparison.Ordinal);
        if (streamIdx < 0)
        {
            streamIdx = text.IndexOf("stream\r\n", objStartPos, Math.Min(500, text.Length - objStartPos), StringComparison.Ordinal);
            if (streamIdx < 0)
            {
                return null;
            }
            streamIdx += 8;
        }
        else
        {
            streamIdx += 7;
        }

        int endIdx = text.IndexOf("\nendstream", streamIdx, StringComparison.Ordinal);
        if (endIdx < 0 || endIdx - streamIdx > 10_000_000)
        {
            return null;
        }

        try
        {
            var compressed = pdfBytes.AsSpan(streamIdx, endIdx - streamIdx);
            using var ms = new System.IO.MemoryStream(compressed.ToArray());
            using var zlib = new System.IO.Compression.ZLibStream(ms, System.IO.Compression.CompressionMode.Decompress);
            using var output = new System.IO.MemoryStream();
            zlib.CopyTo(output);
            return (int)output.Length;
        }
        catch
        {
            return null;
        }
    }

    private static string FormatSize(int bytes) => bytes switch
    {
        0 => "0 bytes",
        < 1024 => $"{bytes:N0} bytes",
        < 1048576 => $"{bytes / 1024.0:N1} KB",
        _ => $"{bytes / 1048576.0:N1} MB"
    };

    [GeneratedRegex(@"(\d+)\s+0\s+R")]
    private static partial Regex ObjRefRegex();

    [GeneratedRegex(@"/Length\s+(\d+)")]
    private static partial Regex LengthRegex();

    #endregion
}
