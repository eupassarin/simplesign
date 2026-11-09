using System.Text;
using System.Text.RegularExpressions;
using SimpleSign.Core.Validation.Policy;

namespace SimpleSign.PAdES.Pdf;

/// <summary>
/// The indirect objects of a PDF, in file order, with the offset where each is defined
/// (an object of an object stream takes the offset of its stream). One index serves every signature.
/// </summary>
internal sealed class PdfObjectIndex
{
    private static readonly TimeSpan s_timeout = TimeSpan.FromSeconds(5);
    private readonly List<(int Number, long Offset, string Text)> _entries = [];

    private PdfObjectIndex(long length)
    {
        Length = length;
    }

    /// <summary>The length of the indexed file.</summary>
    public long Length { get; }

    /// <summary>Indexes the objects of the PDF.</summary>
    public static PdfObjectIndex Build(byte[] pdf)
    {
        var index = new PdfObjectIndex(pdf.Length);
        string text = Encoding.Latin1.GetString(pdf);
        foreach (Match header in Regex.Matches(text, @"(?<![0-9])(\d{1,9})\s+(\d{1,5})\s+obj\b", RegexOptions.None, s_timeout))
        {
            int bodyStart = header.Index + header.Length;
            int end = text.IndexOf("endobj", bodyStart, StringComparison.Ordinal);
            if (end < 0)
            {
                break;
            }

            int number = int.Parse(header.Groups[1].ValueSpan, System.Globalization.CultureInfo.InvariantCulture);
            string body = text[bodyStart..end].Trim();
            index._entries.Add((number, header.Index, body));
            if (Regex.IsMatch(PdfDictionary.Head(body), @"/Type\s*/ObjStm\b", RegexOptions.None, s_timeout))
            {
                index.AddObjectStream(pdf, header.Index, body);
            }
        }

        return index;
    }

    /// <summary>The objects as of the revision ending at <paramref name="end"/>: the last definition of each number before it.</summary>
    public Dictionary<int, string> Revision(long end)
    {
        var objects = new Dictionary<int, string>();
        foreach (var (number, offset, text) in _entries)
        {
            if (offset < end)
            {
                objects[number] = text;
            }
        }

        return objects;
    }

    private void AddObjectStream(byte[] pdf, int objStart, string body)
    {
        string head = PdfDictionary.Head(body);
        var dictionary = PdfDictionary.Parse(head);
        if (!int.TryParse(dictionary.GetValueOrDefault("N"), out int count) || !int.TryParse(dictionary.GetValueOrDefault("First"), out int first))
        {
            return;
        }

        byte[] decompressed;
        try
        {
            ReadOnlySpan<byte> data = pdf;
            int streamKey = PdfStructureReader.IndexOf(data[objStart..], "stream"u8, 0);
            if (streamKey < 0)
            {
                return;
            }

            ReadOnlySpan<byte> dictRegion = data.Slice(objStart, streamKey);
            ReadOnlySpan<byte> raw = PdfStructureReader.ExtractStreamBytes(data, objStart, dictRegion);
            decompressed = raw.IsEmpty ? [] : PdfStructureReader.ApplyStreamFilters(raw, dictRegion);
        }
#pragma warning disable CA1031 // A damaged object stream leaves its objects out of the comparison.
        catch (Exception)
#pragma warning restore CA1031
        {
            return;
        }

        string content = Encoding.Latin1.GetString(decompressed);
        string[] numbers = content[..Math.Min(first, content.Length)].Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
        for (int i = 0; i < count && 2 * i + 1 < numbers.Length; i++)
        {
            if (!int.TryParse(numbers[2 * i], out int number) || !int.TryParse(numbers[2 * i + 1], out int offset))
            {
                return;
            }

            int start = first + offset;
            int end = 2 * i + 3 < numbers.Length && int.TryParse(numbers[2 * i + 3], out int next) ? first + next : content.Length;
            if (start >= 0 && start <= end && end <= content.Length)
            {
                _entries.Add((number, objStart, content[start..end].Trim()));
            }
        }
    }
}

/// <summary>Reads the top-level entries of a PDF dictionary, as raw value text.</summary>
internal static class PdfDictionary
{
    /// <summary>The dictionary part of an object body (what comes before <c>stream</c>).</summary>
    public static string Head(string body)
    {
        int stream = body.IndexOf("stream", StringComparison.Ordinal);
        while (stream > 0 && !body.AsSpan(0, stream).TrimEnd().EndsWith(">>", StringComparison.Ordinal))
        {
            stream = body.IndexOf("stream", stream + 6, StringComparison.Ordinal);
        }

        return stream > 0 ? body[..stream] : body;
    }

    /// <summary>The top-level entries of the dictionary that starts the text; empty when it is not one.</summary>
    public static Dictionary<string, string> Parse(string text)
    {
        var entries = new Dictionary<string, string>(StringComparer.Ordinal);
        int pos = Skip(text, 0);
        if (!text.AsSpan(pos).StartsWith("<<", StringComparison.Ordinal))
        {
            return entries;
        }

        pos += 2;
        while (true)
        {
            pos = Skip(text, pos);
            if (pos >= text.Length || text[pos] != '/')
            {
                return entries;
            }

            int nameEnd = NameEnd(text, pos + 1);
            string key = text[(pos + 1)..nameEnd];
            int valueStart = Skip(text, nameEnd);
            int valueEnd = ValueEnd(text, valueStart);
            if (valueEnd <= valueStart)
            {
                return entries;
            }

            entries[key] = text[valueStart..valueEnd].Trim();
            pos = valueEnd;
        }
    }

    /// <summary>The object numbers referenced (<c>N G R</c>) in the text.</summary>
    public static IReadOnlyList<int> References(string? text) => text is null ? [] :
        [.. Regex.Matches(text, @"(?<![0-9])(\d{1,9})\s+\d{1,5}\s+R\b", RegexOptions.None, TimeSpan.FromSeconds(1))
            .Select(m => int.Parse(m.Groups[1].ValueSpan, System.Globalization.CultureInfo.InvariantCulture))];

    /// <summary>The object number of a single reference value; 0 when the value is not one.</summary>
    public static int Reference(string? value)
    {
        var match = value is null ? null : Regex.Match(value, @"^(\d{1,9})\s+\d{1,5}\s+R$", RegexOptions.None, TimeSpan.FromSeconds(1));
        return match is { Success: true } ? int.Parse(match.Groups[1].ValueSpan, System.Globalization.CultureInfo.InvariantCulture) : 0;
    }

    /// <summary>A value with its white space collapsed, to compare two revisions.</summary>
    public static string Normalize(string value) =>
        Regex.Replace(value, @"\s+", " ", RegexOptions.None, TimeSpan.FromSeconds(1))
            .Replace("[ ", "[", StringComparison.Ordinal).Replace(" ]", "]", StringComparison.Ordinal)
            .Replace("<< ", "<<", StringComparison.Ordinal).Replace(" >>", ">>", StringComparison.Ordinal);

    /// <summary>The text of a PDF string value (literal or hexadecimal).</summary>
    public static string Text(string? value)
    {
        if (string.IsNullOrEmpty(value))
        {
            return "";
        }

        if (value.StartsWith('<') && value.EndsWith('>'))
        {
            string hex = string.Concat(value[1..^1].Where(char.IsAsciiHexDigit));
            if (hex.Length % 2 == 1)
            {
                hex += "0";
            }

            byte[] bytes = Convert.FromHexString(hex);
            return bytes.Length >= 2 && bytes[0] == 0xFE && bytes[1] == 0xFF
                ? Encoding.BigEndianUnicode.GetString(bytes, 2, bytes.Length - 2)
                : Encoding.Latin1.GetString(bytes);
        }

        if (value.StartsWith('(') && value.EndsWith(')'))
        {
            var text = new StringBuilder();
            string inner = value[1..^1];
            for (int i = 0; i < inner.Length; i++)
            {
                text.Append(inner[i] == '\\' && i + 1 < inner.Length ? inner[++i] : inner[i]);
            }

            return text.ToString();
        }

        return value;
    }

    private static int Skip(string text, int pos)
    {
        while (pos < text.Length)
        {
            if (char.IsWhiteSpace(text[pos]) || text[pos] == '\0')
            {
                pos++;
            }
            else if (text[pos] == '%')
            {
                while (pos < text.Length && text[pos] is not '\n' and not '\r')
                {
                    pos++;
                }
            }
            else
            {
                break;
            }
        }

        return pos;
    }

    private static int NameEnd(string text, int pos)
    {
        while (pos < text.Length && !char.IsWhiteSpace(text[pos]) && "/[]<>()%{}".IndexOf(text[pos], StringComparison.Ordinal) < 0)
        {
            pos++;
        }

        return pos;
    }

    private static int ValueEnd(string text, int pos)
    {
        if (pos >= text.Length)
        {
            return pos;
        }

        switch (text[pos])
        {
            case '/':
                return NameEnd(text, pos + 1);
            case '(':
                return StringEnd(text, pos);
            case '[':
                return Nested(text, pos);
            case '<' when pos + 1 < text.Length && text[pos + 1] == '<':
                return Nested(text, pos);
            case '<':
                int close = text.IndexOf('>', pos);
                return close < 0 ? text.Length : close + 1;
            default:
                // A number, a keyword, or an indirect reference "N G R".
                var reference = Regex.Match(text[pos..], @"^\d{1,9}\s+\d{1,5}\s+R\b", RegexOptions.None, TimeSpan.FromSeconds(1));
                if (reference.Success)
                {
                    return pos + reference.Length;
                }

                int end = pos;
                while (end < text.Length && !char.IsWhiteSpace(text[end]) && "/[]<>()%".IndexOf(text[end], StringComparison.Ordinal) < 0)
                {
                    end++;
                }

                return end;
        }
    }

    private static int StringEnd(string text, int pos)
    {
        int depth = 0;
        for (int i = pos; i < text.Length; i++)
        {
            switch (text[i])
            {
                case '\\':
                    i++;
                    break;
                case '(':
                    depth++;
                    break;
                case ')' when --depth == 0:
                    return i + 1;
            }
        }

        return text.Length;
    }

    /// <summary>The end of an array or a dictionary, skipping strings inside it.</summary>
    private static int Nested(string text, int pos)
    {
        int depth = 0;
        for (int i = pos; i < text.Length; i++)
        {
            char c = text[i];
            if (c == '(')
            {
                i = StringEnd(text, i) - 1;
            }
            else if (c == '<' && i + 1 < text.Length && text[i + 1] != '<')
            {
                int close = text.IndexOf('>', i);
                i = close < 0 ? text.Length : close;
            }
            else if (c == '[' || (c == '<' && i + 1 < text.Length && text[i + 1] == '<'))
            {
                depth++;
                i += c == '<' ? 1 : 0;
            }
            else if (c == ']' || (c == '>' && i + 1 < text.Length && text[i + 1] == '>'))
            {
                i += c == '>' ? 1 : 0;
                if (--depth == 0)
                {
                    return i + 1;
                }
            }
        }

        return text.Length;
    }
}

/// <summary>
/// Compares the revision a signature covers with the final one and sorts each change the way the PDF
/// modification constraints need: signatures, form filling, annotations, page count, and anything else
/// ("undefined"). Validation data (DSS) and document timestamps are not changes (ETSI EN 319 142-1).
/// </summary>
internal static class PdfRevisionComparer
{
    private static readonly HashSet<string> s_catalogKeysAllowed = new(StringComparer.Ordinal) { "DSS", "AcroForm", "Extensions" };
    private static readonly HashSet<string> s_acroFormKeysAllowed = new(StringComparer.Ordinal) { "Fields", "SigFlags", "DR", "DA", "NeedAppearances" };
    private static readonly HashSet<string> s_fieldValueKeys = new(StringComparer.Ordinal) { "V", "AP", "AS" };
    private static readonly HashSet<string> s_infoKeys = new(StringComparer.Ordinal)
    {
        "Title", "Author", "Subject", "Keywords", "Creator", "Producer", "CreationDate", "ModDate", "Trapped",
    };

    /// <summary>What changed after the signature whose ByteRange ends at <paramref name="signedEnd"/>.</summary>
    public static PdfChangeFacts Compare(PdfObjectIndex index, ReadOnlySpan<byte> pdf, long signedEnd, int sigDictObjectNumber)
    {
        int end = (int)Math.Clamp(signedEnd, 0, pdf.Length);
        var signed = new Revision(index.Revision(end), PdfStructureParser.FindRootObjectNumber(pdf[..end]));
        var final = new Revision(index.Revision(long.MaxValue), PdfStructureParser.FindRootObjectNumber(pdf));
        var changes = new Changes();

        if (end < pdf.Length)
        {
            CompareCatalog(signed, final, changes);
            CompareFields(signed, final, changes);
            bool overlap = ComparePages(signed, final, changes);
            CompareOtherObjects(signed, final, changes);
            changes.Overlap = overlap;
        }

        return new PdfChangeFacts
        {
            SignedPageCount = signed.Pages.Count,
            FinalPageCount = end < pdf.Length ? final.Pages.Count : signed.Pages.Count,
            AnnotationsOverlap = changes.Overlap,
            Signatures = changes.Signatures,
            FormFills = changes.FormFills,
            Annotations = changes.Annotations,
            Undefined = changes.Undefined,
            ChangedFields = [.. changes.ChangedFields.Distinct(StringComparer.Ordinal)],
            DocMdpLevel = PdfStructureReader.GetDocMdpPermissionLevel(pdf[..end]),
            FieldMdp = FieldMdpOf(signed, sigDictObjectNumber),
            SigFieldLock = SigFieldLockOf(signed, sigDictObjectNumber),
        };
    }

    private static void CompareCatalog(Revision signed, Revision final, Changes changes)
    {
        changes.Handled.Add(final.Root);
        if (signed.Root != final.Root)
        {
            changes.Undefined.Add("The document catalog was replaced.");
            return;
        }

        if (Differs(signed.Dict(signed.Root), final.Dict(final.Root), s_catalogKeysAllowed))
        {
            changes.Undefined.Add("The document catalog changed.");
        }

        changes.Handled.Add(final.AcroFormNumber);
        if (Differs(signed.AcroForm, final.AcroForm, s_acroFormKeysAllowed))
        {
            changes.Undefined.Add("The form dictionary (AcroForm) changed.");
        }
    }

    private static void CompareFields(Revision signed, Revision final, Changes changes)
    {
        changes.Handled.Add(final.FieldsArrayNumber);
        foreach (int field in final.TopFields.Except(signed.TopFields))
        {
            string name = final.FieldName(field);
            if (final.FieldType(field) == "Sig")
            {
                int value = PdfDictionary.Reference(final.Dict(field).GetValueOrDefault("V"));
                if (value == 0)
                {
                    changes.Signatures.Add($"Signature field '{name}' added.");
                }
                else if (!final.IsDocumentTimestamp(value))
                {
                    changes.Signatures.Add($"Signature '{name}' added.");
                }
            }
            else
            {
                changes.Undefined.Add($"Form field '{name}' added.");
            }
        }

        foreach (int field in signed.TopFields.Except(final.TopFields))
        {
            changes.Undefined.Add($"Form field '{signed.FieldName(field)}' removed.");
        }
    }

    /// <summary>Page content and annotations; returns whether an added annotation overlaps another one.</summary>
    private static bool ComparePages(Revision signed, Revision final, Changes changes)
    {
        bool sameCount = signed.Pages.Count == final.Pages.Count;
        foreach (int node in final.PageTreeNodes)
        {
            changes.Handled.Add(node);
            if (sameCount && signed.Objects.TryGetValue(node, out string? before) && Modified(before, final.Objects[node])
                && Differs(signed.Dict(node), final.Dict(node), []))
            {
                changes.Undefined.Add("The page tree changed.");
            }
        }

        bool overlap = false;
        for (int i = 0; i < final.Pages.Count; i++)
        {
            int page = final.Pages[i];
            changes.Handled.Add(page);
            if (!signed.Pages.Contains(page))
            {
                continue;
            }

            if (Differs(signed.Dict(page), final.Dict(page), ["Annots"]))
            {
                changes.Undefined.Add($"Page {i + 1} changed (content or resources).");
            }

            changes.Handled.Add(final.AnnotsArrayNumber(page));
            var before = signed.Annots(page);
            var after = final.Annots(page);
            foreach (int annotation in after.Except(before))
            {
                var dictionary = final.Dict(annotation);
                if (dictionary.GetValueOrDefault("Subtype") == "/Widget")
                {
                    if (!final.FieldSet.Contains(annotation) && !final.FieldSet.Contains(PdfDictionary.Reference(dictionary.GetValueOrDefault("Parent"))))
                    {
                        changes.Undefined.Add($"A form widget outside the form was added on page {i + 1}.");
                    }
                }
                else
                {
                    changes.Annotations.Add($"Annotation {dictionary.GetValueOrDefault("Subtype") ?? "(no subtype)"} added on page {i + 1}.");
                }

                overlap |= Rect(dictionary) is { } rect && after.Where(other => other != annotation)
                    .Any(other => Rect(final.Dict(other)) is { } otherRect && Intersect(rect, otherRect));
            }

            foreach (int annotation in before.Except(after))
            {
                var dictionary = signed.Dict(annotation);
                if (dictionary.GetValueOrDefault("Subtype") == "/Widget")
                {
                    changes.Undefined.Add($"A form widget was removed from page {i + 1}.");
                }
                else
                {
                    changes.Annotations.Add($"Annotation {dictionary.GetValueOrDefault("Subtype") ?? "(no subtype)"} removed from page {i + 1}.");
                }
            }
        }

        return overlap;
    }

    private static void CompareOtherObjects(Revision signed, Revision final, Changes changes)
    {
        var appearanceOwners = final.AppearanceOwners();
        foreach (var (number, text) in final.Objects)
        {
            if (changes.Handled.Contains(number) || !signed.Objects.TryGetValue(number, out string? before) || !Modified(before, text))
            {
                continue;
            }

            var dictionary = final.Dict(number);
            string? type = dictionary.GetValueOrDefault("Type");
            if (signed.DssObjects.Contains(number) || final.DssObjects.Contains(number)
                || type is "/Sig" or "/DocTimeStamp" or "/XRef" or "/ObjStm" or "/Metadata" or "/DSS"
                || (dictionary.Count > 0 && dictionary.Keys.All(s_infoKeys.Contains)))
            {
                continue;
            }

            if (final.FieldSet.Contains(number) || dictionary.ContainsKey("FT") || dictionary.GetValueOrDefault("Subtype") == "/Widget")
            {
                CompareField(number, signed, final, changes);
            }
            else if (appearanceOwners.TryGetValue(number, out int owner))
            {
                if (final.Dict(owner).GetValueOrDefault("Subtype") == "/Widget")
                {
                    AppearanceOfField(owner, signed, final, changes);
                }
                else
                {
                    changes.Annotations.Add("The appearance of an annotation changed.");
                }
            }
            else if (type == "/Annot" || (dictionary.ContainsKey("Subtype") && dictionary.ContainsKey("Rect")))
            {
                changes.Annotations.Add($"Annotation {dictionary.GetValueOrDefault("Subtype") ?? "(no subtype)"} changed.");
            }
            else
            {
                changes.Undefined.Add($"Object {number} changed.");
            }
        }
    }

    private static void CompareField(int number, Revision signed, Revision final, Changes changes)
    {
        var before = signed.Dict(number);
        var after = final.Dict(number);
        string name = final.FieldName(number);
        if (Differs(before, after, s_fieldValueKeys))
        {
            changes.Undefined.Add($"Field '{name}' changed beyond its value.");
            return;
        }

        string? oldValue = before.GetValueOrDefault("V");
        string? newValue = after.GetValueOrDefault("V");
        bool signature = final.FieldType(number) == "Sig";
        if (!string.Equals(oldValue is null ? null : PdfDictionary.Normalize(oldValue), newValue is null ? null : PdfDictionary.Normalize(newValue), StringComparison.Ordinal))
        {
            if (!signature)
            {
                changes.FormFills.Add($"Field '{name}' filled.");
                changes.ChangedFields.Add(name);
            }
            else if (oldValue is null && newValue is not null)
            {
                if (!final.IsDocumentTimestamp(PdfDictionary.Reference(newValue)))
                {
                    changes.Signatures.Add($"Signature field '{name}' signed.");
                }

                changes.ChangedFields.Add(name);
            }
            else
            {
                changes.Undefined.Add($"The signature of field '{name}' was replaced or removed.");
            }
        }
        else if (signature && oldValue is not null)
        {
            changes.Undefined.Add($"The appearance of the signed field '{name}' changed.");
        }
        else if (!signature)
        {
            changes.FormFills.Add($"The appearance of field '{name}' changed.");
            changes.ChangedFields.Add(name);
        }
    }

    private static void AppearanceOfField(int widget, Revision signed, Revision final, Changes changes)
    {
        string name = final.FieldName(widget);
        if (final.FieldType(widget) != "Sig")
        {
            changes.FormFills.Add($"The appearance of field '{name}' changed.");
            changes.ChangedFields.Add(name);
        }
        else if (signed.Dict(widget).ContainsKey("V") || signed.Dict(PdfDictionary.Reference(signed.Dict(widget).GetValueOrDefault("Parent"))).ContainsKey("V"))
        {
            changes.Undefined.Add($"The appearance of the signed field '{name}' changed.");
        }
    }

    private static PdfFieldLock? FieldMdpOf(Revision revision, int sigDict)
    {
        string? reference = revision.Dict(sigDict).GetValueOrDefault("Reference");
        if (reference is null)
        {
            return null;
        }

        string text = reference + string.Concat(PdfDictionary.References(reference).Select(n => revision.Objects.GetValueOrDefault(n)));
        int method = text.IndexOf("/FieldMDP", StringComparison.Ordinal);
        return method < 0 ? null : LockOf(revision, text[method..]);
    }

    private static PdfFieldLock? SigFieldLockOf(Revision revision, int sigDict)
    {
        foreach (int field in revision.FieldSet)
        {
            var dictionary = revision.Dict(field);
            if (PdfDictionary.Reference(dictionary.GetValueOrDefault("V")) == sigDict && dictionary.GetValueOrDefault("Lock") is { } value)
            {
                int number = PdfDictionary.Reference(value);
                return LockOf(revision, number > 0 ? revision.Objects.GetValueOrDefault(number) ?? "" : value);
            }
        }

        return null;
    }

    private static PdfFieldLock? LockOf(Revision revision, string text)
    {
        var action = Regex.Match(text, @"/Action\s*/(All|Include|Exclude)\b", RegexOptions.None, TimeSpan.FromSeconds(1));
        if (!action.Success)
        {
            return null;
        }

        var fields = Regex.Match(text, @"/Fields\s*(\[(?:[^\]\\]|\\.)*\]|\d+\s+\d+\s+R)", RegexOptions.Singleline, TimeSpan.FromSeconds(1));
        string array = fields.Success ? revision.ArrayText(fields.Groups[1].Value) : "";
        var names = Regex.Matches(array, @"\((?:\\.|[^\\)])*\)|<[0-9A-Fa-f\s]*>", RegexOptions.None, TimeSpan.FromSeconds(1))
            .Select(m => PdfDictionary.Text(m.Value)).ToList();
        return new PdfFieldLock(action.Groups[1].Value, names);
    }

    private static bool Modified(string before, string after) =>
        !string.Equals(PdfDictionary.Normalize(before), PdfDictionary.Normalize(after), StringComparison.Ordinal);

    /// <summary>Whether two dictionaries differ in any entry but the ignored ones.</summary>
    private static bool Differs(Dictionary<string, string> before, Dictionary<string, string> after, IReadOnlySet<string> ignored) =>
        before.Keys.Union(after.Keys).Where(key => !ignored.Contains(key)).Any(key =>
            !string.Equals(
                before.TryGetValue(key, out string? a) ? PdfDictionary.Normalize(a) : null,
                after.TryGetValue(key, out string? b) ? PdfDictionary.Normalize(b) : null,
                StringComparison.Ordinal));

    private static bool Differs(Dictionary<string, string> before, Dictionary<string, string> after, string[] ignored) =>
        Differs(before, after, new HashSet<string>(ignored, StringComparer.Ordinal));

    private static (double X1, double Y1, double X2, double Y2)? Rect(Dictionary<string, string> annotation)
    {
        string? rect = annotation.GetValueOrDefault("Rect");
        if (rect is null || !rect.StartsWith('['))
        {
            return null;
        }

        var numbers = rect.Trim('[', ']').Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries)
            .Select(v => double.TryParse(v, System.Globalization.NumberStyles.Float, System.Globalization.CultureInfo.InvariantCulture, out double d) ? d : double.NaN)
            .ToArray();
        if (numbers.Length != 4 || numbers.Any(double.IsNaN))
        {
            return null;
        }

        var box = (Math.Min(numbers[0], numbers[2]), Math.Min(numbers[1], numbers[3]), Math.Max(numbers[0], numbers[2]), Math.Max(numbers[1], numbers[3]));
        return box.Item3 - box.Item1 > 0 && box.Item4 - box.Item2 > 0 ? box : null;
    }

    private static bool Intersect((double X1, double Y1, double X2, double Y2) a, (double X1, double Y1, double X2, double Y2) b) =>
        a.X1 < b.X2 && b.X1 < a.X2 && a.Y1 < b.Y2 && b.Y1 < a.Y2;

    private sealed class Changes
    {
        public HashSet<int> Handled { get; } = [];
        public List<string> Signatures { get; } = [];
        public List<string> FormFills { get; } = [];
        public List<string> Annotations { get; } = [];
        public List<string> Undefined { get; } = [];
        public List<string> ChangedFields { get; } = [];
        public bool Overlap { get; set; }
    }

    /// <summary>One revision: its objects and the structures the comparison walks.</summary>
    private sealed class Revision
    {
        private const int MaxDepth = 64;
        private readonly Dictionary<int, Dictionary<string, string>> _dictionaries = [];

        public Revision(Dictionary<int, string> objects, int root)
        {
            Objects = objects;
            Root = root;
            var catalog = Dict(root);
            WalkPages(PdfDictionary.Reference(catalog.GetValueOrDefault("Pages")), 0);

            string? acroForm = catalog.GetValueOrDefault("AcroForm");
            AcroFormNumber = PdfDictionary.Reference(acroForm);
            AcroForm = AcroFormNumber > 0 ? Dict(AcroFormNumber) : acroForm is null ? [] : PdfDictionary.Parse(acroForm);
            string? fields = AcroForm.GetValueOrDefault("Fields");
            FieldsArrayNumber = PdfDictionary.Reference(fields);
            TopFields = [.. PdfDictionary.References(ArrayText(fields))];
            foreach (int field in TopFields)
            {
                WalkFields(field, 0);
            }

            string? dss = catalog.GetValueOrDefault("DSS");
            var queue = new Queue<(int Number, int Depth)>(PdfDictionary.References(dss).Select(n => (n, 0)));
            while (queue.Count > 0 && DssObjects.Count < 100_000)
            {
                var (number, depth) = queue.Dequeue();
                if (!DssObjects.Add(number) || depth >= 4 || !Objects.TryGetValue(number, out string? text))
                {
                    continue;
                }

                foreach (int child in PdfDictionary.References(PdfDictionary.Head(text)))
                {
                    queue.Enqueue((child, depth + 1));
                }
            }
        }

        public Dictionary<int, string> Objects { get; }

        public int Root { get; }

        public List<int> Pages { get; } = [];

        public HashSet<int> PageTreeNodes { get; } = [];

        public int AcroFormNumber { get; }

        public Dictionary<string, string> AcroForm { get; }

        public int FieldsArrayNumber { get; }

        public List<int> TopFields { get; }

        public HashSet<int> FieldSet { get; } = [];

        public HashSet<int> DssObjects { get; } = [];

        public Dictionary<string, string> Dict(int number)
        {
            if (!_dictionaries.TryGetValue(number, out var dictionary))
            {
                dictionary = Objects.TryGetValue(number, out string? text) ? PdfDictionary.Parse(PdfDictionary.Head(text)) : [];
                _dictionaries[number] = dictionary;
            }

            return dictionary;
        }

        /// <summary>An array value, following it when it is an indirect reference.</summary>
        public string ArrayText(string? value)
        {
            int number = PdfDictionary.Reference(value);
            return number > 0 ? Objects.GetValueOrDefault(number) ?? "" : value ?? "";
        }

        public List<int> Annots(int page) => [.. PdfDictionary.References(ArrayText(Dict(page).GetValueOrDefault("Annots")))];

        public int AnnotsArrayNumber(int page) => PdfDictionary.Reference(Dict(page).GetValueOrDefault("Annots"));

        public bool IsDocumentTimestamp(int sigDict) =>
            Dict(sigDict).GetValueOrDefault("SubFilter") == "/ETSI.RFC3161" || Dict(sigDict).GetValueOrDefault("Type") == "/DocTimeStamp";

        /// <summary>The fully qualified name of a field (its /T and its parents').</summary>
        public string FieldName(int field)
        {
            var parts = new List<string>();
            for (int number = field, depth = 0; number > 0 && depth < MaxDepth; depth++)
            {
                var dictionary = Dict(number);
                if (dictionary.GetValueOrDefault("T") is { } name)
                {
                    parts.Insert(0, PdfDictionary.Text(name));
                }

                number = PdfDictionary.Reference(dictionary.GetValueOrDefault("Parent"));
            }

            return string.Join('.', parts);
        }

        /// <summary>The field type (/FT, inherited from the parents), without the slash.</summary>
        public string? FieldType(int field)
        {
            for (int number = field, depth = 0; number > 0 && depth < MaxDepth; depth++)
            {
                var dictionary = Dict(number);
                if (dictionary.GetValueOrDefault("FT") is { } type)
                {
                    return type.TrimStart('/');
                }

                number = PdfDictionary.Reference(dictionary.GetValueOrDefault("Parent"));
            }

            return null;
        }

        /// <summary>The appearance streams of the annotations, by the annotation that owns them.</summary>
        public Dictionary<int, int> AppearanceOwners()
        {
            var owners = new Dictionary<int, int>();
            foreach (int annotation in Pages.SelectMany(Annots).Concat(FieldSet).Distinct())
            {
                string? appearance = Dict(annotation).GetValueOrDefault("AP");
                var references = PdfDictionary.References(appearance).ToList();
                // /AP << /N 12 0 R >> or /AP 12 0 R, and a state dictionary one level down.
                foreach (int number in references.ToList())
                {
                    if (Objects.TryGetValue(number, out string? text) && !text.Contains("stream", StringComparison.Ordinal))
                    {
                        references.AddRange(PdfDictionary.References(text));
                    }
                }

                foreach (int number in references)
                {
                    owners.TryAdd(number, annotation);
                }
            }

            return owners;
        }

        private void WalkPages(int node, int depth)
        {
            if (node <= 0 || depth > MaxDepth || PageTreeNodes.Contains(node) || Pages.Contains(node))
            {
                return;
            }

            var dictionary = Dict(node);
            if (dictionary.GetValueOrDefault("Type") == "/Pages" || dictionary.ContainsKey("Kids"))
            {
                PageTreeNodes.Add(node);
                foreach (int kid in PdfDictionary.References(ArrayText(dictionary.GetValueOrDefault("Kids"))))
                {
                    WalkPages(kid, depth + 1);
                }
            }
            else
            {
                Pages.Add(node);
            }
        }

        private void WalkFields(int field, int depth)
        {
            if (field <= 0 || depth > MaxDepth || !FieldSet.Add(field))
            {
                return;
            }

            foreach (int kid in PdfDictionary.References(ArrayText(Dict(field).GetValueOrDefault("Kids"))))
            {
                WalkFields(kid, depth + 1);
            }
        }
    }
}
