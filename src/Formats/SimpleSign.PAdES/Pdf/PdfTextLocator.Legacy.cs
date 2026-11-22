using System.Globalization;
using System.Text;

namespace SimpleSign.PAdES.Pdf;

/// <summary>
/// The text locator as it read the document before the object model (ADR 0032): by scanning the file's text
/// (<see cref="PdfObjectIndex"/>) and parsing dictionaries as text (<see cref="PdfRawDictionary"/>). Kept to check the
/// model-based reading against it until the old code is removed.
/// </summary>
internal static partial class PdfTextLocator
{
    /// <summary>The text of each page as the scanning reader reads it; null for a page that cannot be read.</summary>
    internal static List<(string Text, List<(float X, float Y)> Origins)?> ReadPagesLegacy(byte[] pdf)
    {
        ArgumentNullException.ThrowIfNull(pdf);
        var pages = new List<(string Text, List<(float X, float Y)> Origins)?>();
        var document = new Document(PdfObjectIndex.Build(pdf).Revision(pdf.Length));
        int root = PdfStructureParser.FindRootObjectNumber(pdf);
        string? pagesRef = document.Dict(document.Object(root)).GetValueOrDefault("Pages");
        foreach (var (page, resources) in document.Pages(PdfRawDictionary.Reference(pagesRef)))
        {
            try
            {
                pages.Add(Join(document.ReadPage(page, resources)));
            }
#pragma warning disable CA1031 // A page that cannot be read has no text to find; the others are still searched.
            catch (Exception)
#pragma warning restore CA1031
            {
                pages.Add(null);
            }
        }

        return pages;
    }

    /// <summary>Every place where <paramref name="text"/> starts, found by the scanning reader.</summary>
    internal static IReadOnlyList<PdfTextMatch> FindLegacy(byte[] pdf, string text, bool ignoreCase) =>
        Match(ReadPagesLegacy(pdf), text, ignoreCase);

    /// <summary>The objects of the document, and what is read from them: pages, resources, fonts, streams.</summary>
    private sealed class Document(Dictionary<int, string> objects) : IContentSource
    {
        private readonly Dictionary<string, Font> _fonts = new(StringComparer.Ordinal);
        private int _operators;

        public string? Object(int number) => number > 0 ? objects.GetValueOrDefault(number) : null;

        /// <summary>The value, or the object it refers to.</summary>
        public string? Resolve(string? value)
        {
            int number = PdfRawDictionary.Reference(value);
            return number > 0 ? Object(number) : value;
        }

        /// <summary>The entries of a dictionary value (inline, or the object it refers to; a stream's dictionary).</summary>
        public Dictionary<string, string> Dict(string? value)
        {
            string? body = Resolve(value);
            return body is null ? new Dictionary<string, string>(StringComparer.Ordinal) : PdfRawDictionary.Parse(PdfRawDictionary.Head(body));
        }

        /// <summary>The pages under a page tree node, in order, with the resources each inherits or has.</summary>
        public IEnumerable<(Dictionary<string, string> Page, string? Resources)> Pages(int node)
        {
            var visited = new HashSet<int>();
            var stack = new Stack<(int Node, string? Resources, int Depth)>();
            stack.Push((node, null, 0));
            while (stack.Count > 0)
            {
                var (number, inherited, depth) = stack.Pop();
                if (number <= 0 || depth > MaxPageDepth || !visited.Add(number))
                {
                    continue;
                }

                var dict = Dict(Object(number));
                string? resources = dict.GetValueOrDefault("Resources") ?? inherited;
                if (dict.TryGetValue("Kids", out string? kids))
                {
                    var children = PdfRawDictionary.References(Resolve(kids));
                    for (int i = children.Count - 1; i >= 0; i--)
                    {
                        stack.Push((children[i], resources, depth + 1));
                    }
                }
                else
                {
                    yield return (dict, resources);
                }
            }
        }

        /// <summary>The glyphs a page draws, in content order.</summary>
        public List<Glyph> ReadPage(Dictionary<string, string> page, string? resources)
        {
            var glyphs = new List<Glyph>();
            _operators = 0;
            string? contents = Resolve(page.GetValueOrDefault("Contents"));
            if (contents is null)
            {
                return glyphs;
            }

            var content = new List<byte>();
            if (contents.TrimStart().StartsWith('['))
            {
                foreach (int part in PdfRawDictionary.References(contents))
                {
                    content.AddRange(StreamData(Object(part)) ?? []);
                    content.Add((byte)'\n');
                }
            }
            else
            {
                content.AddRange(StreamData(contents) ?? []);
            }

            new ContentReader(this, glyphs).Run([.. content], resources, Matrix.Identity, 0);
            return glyphs;
        }

        /// <summary>Counts an operator; false once the document has run too many.</summary>
        public bool Count() => ++_operators <= MaxOperators;

        /// <summary>The decoded data of a stream object; null when it is not a stream or cannot be decoded.</summary>
        public byte[]? StreamData(string? body)
        {
            if (body is null)
            {
                return null;
            }

            string head = PdfRawDictionary.Head(body);
            if (head.Length >= body.Length || !body.AsSpan(head.Length).TrimStart().StartsWith("stream", StringComparison.Ordinal))
            {
                return null;
            }

            int start = body.IndexOf("stream", head.Length, StringComparison.Ordinal) + 6;
            if (start < body.Length && body[start] == '\r')
            {
                start++;
            }

            if (start < body.Length && body[start] == '\n')
            {
                start++;
            }

            var dict = PdfRawDictionary.Parse(head);
            int end = int.TryParse(Resolve(dict.GetValueOrDefault("Length"))?.Trim(), NumberStyles.None, CultureInfo.InvariantCulture, out int length)
                && length >= 0 && start + length <= body.Length
                ? start + length
                : body.LastIndexOf("endstream", StringComparison.Ordinal);
            if (end < start)
            {
                return null;
            }

            byte[] raw = Encoding.Latin1.GetBytes(body[start..end]);
            return PdfStructureReader.ApplyStreamFilters(raw, Encoding.Latin1.GetBytes(head));
        }

        public Font? Font(object? resources, string name) => FontOf(resources as string, name);

        /// <summary>The form XObject a resource name refers to.</summary>
        public FormXObject? Form(object? resources, string name)
        {
            string? value = Dict(resources as string).GetValueOrDefault("XObject") is { } xobjects ? Dict(xobjects).GetValueOrDefault(name) : null;
            string? body = Resolve(value);
            var dict = Dict(body);
            if (body is null || dict.GetValueOrDefault("Subtype") != "/Form" || StreamData(body) is not { } content)
            {
                return null;
            }

            Matrix matrix = Matrix.Identity;
            if (dict.TryGetValue("Matrix", out string? m) && ContentLexer.ReadArray(m) is { Count: 6 } values && values.All(v => v is double))
            {
                matrix = new Matrix((double)values[0], (double)values[1], (double)values[2], (double)values[3], (double)values[4], (double)values[5]);
            }

            return new FormXObject(content, matrix, dict.GetValueOrDefault("Resources"));
        }

        /// <summary>The font a resource name refers to; a font read once is kept.</summary>
        private Font? FontOf(string? resources, string name)
        {
            string? value = Dict(resources).GetValueOrDefault("Font") is { } fonts ? Dict(fonts).GetValueOrDefault(name) : null;
            if (value is null)
            {
                return null;
            }

            string key = PdfRawDictionary.Reference(value) is > 0 and var number ? number.ToString(CultureInfo.InvariantCulture) : value;
            if (!_fonts.TryGetValue(key, out var font))
            {
                font = LegacyFonts.Read(this, Dict(value));
                _fonts[key] = font;
            }

            return font;
        }
    }

    /// <summary>Reads fonts from dictionaries parsed as text.</summary>
    private static class LegacyFonts
    {
        public static Font Read(Document document, Dictionary<string, string> font)
        {
            Dictionary<int, string>? toUnicode = font.TryGetValue("ToUnicode", out string? map)
                && document.StreamData(document.Resolve(map)) is { } cmap
                ? Fonts.ReadCMap(System.Text.Encoding.Latin1.GetString(cmap))
                : null;

            if (font.GetValueOrDefault("Subtype") == "/Type0")
            {
                string? descendants = document.Resolve(font.GetValueOrDefault("DescendantFonts"))?.Trim();
                var descendant = document.Dict(descendants is null ? null
                    : PdfRawDictionary.References(descendants) is { Count: > 0 } refs ? document.Object(refs[0])
                    : descendants.TrimStart('[').TrimEnd(']'));
                double dw = double.TryParse(descendant.GetValueOrDefault("DW"), NumberStyles.Float, CultureInfo.InvariantCulture, out double d) ? d : 1000;
                return Fonts.Composite(toUnicode, Array(document.Resolve(descendant.GetValueOrDefault("W"))), dw);
            }

            return Fonts.Simple(
                toUnicode,
                ReadEncoding(document, font.GetValueOrDefault("Encoding")),
                int.TryParse(font.GetValueOrDefault("FirstChar"), out int first) ? first : null,
                Array(document.Resolve(font.GetValueOrDefault("Widths"))),
                font.GetValueOrDefault("BaseFont") ?? "");
        }

        private static string?[] ReadEncoding(Document document, string? value)
        {
            string? resolved = document.Resolve(value)?.Trim();
            if (resolved is null)
            {
                return Fonts.Encoding(null, null, null);
            }

            if (resolved.StartsWith('/'))
            {
                return Fonts.Encoding(resolved[1..], null, null);
            }

            var dict = PdfRawDictionary.Parse(resolved);
            return Fonts.Encoding(null, dict.GetValueOrDefault("BaseEncoding")?.TrimStart('/'), Array(dict.GetValueOrDefault("Differences")));
        }

        private static List<object>? Array(string? value) => value is null ? null : ContentLexer.ReadArray(value);
    }
}
