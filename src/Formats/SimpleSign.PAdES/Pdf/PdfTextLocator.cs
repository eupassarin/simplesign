using System.Globalization;
using System.Text;
using SimpleSign.PAdES.Pdf.Model;

namespace SimpleSign.PAdES.Pdf;

/// <summary>Where a text starts on a page: the origin of its first glyph, in the page's default user space.</summary>
/// <param name="Page">The page number (1 is the first).</param>
/// <param name="X">The left edge of the first glyph.</param>
/// <param name="Y">The baseline of the first glyph.</param>
internal readonly record struct PdfTextMatch(int Page, float X, float Y);

/// <summary>
/// Finds a text in the pages of a PDF and where it starts (ISO 32000-1 §9: text objects, fonts, ToUnicode). Reads only
/// what places text: the graphics state's matrix, the text state, the text-showing operators and form XObjects. Simple
/// fonts are read with their ToUnicode map, or their encoding (WinAnsi, MacRoman, Standard and /Differences); composite
/// fonts with two-byte codes through their ToUnicode map. A page that cannot be read gives no text.
/// </summary>
internal static partial class PdfTextLocator
{
    private const int MaxFormDepth = 8;
    private const int MaxOperators = 5_000_000;
    private const int MaxGlyphs = 2_000_000;

    /// <summary>Every place where <paramref name="text"/> starts, in reading order: pages in order, then content order.</summary>
    public static IReadOnlyList<PdfTextMatch> Find(byte[] pdf, string text, bool ignoreCase)
    {
        ArgumentNullException.ThrowIfNull(pdf);
        return Match(ReadPages(pdf), text, ignoreCase);
    }

    /// <summary>
    /// The text of each page with the origin of each character, read through the object model (ADR 0032); null for a
    /// page that cannot be read.
    /// </summary>
    internal static List<(string Text, List<(float X, float Y)> Origins)?> ReadPages(byte[] pdf)
    {
        var pages = new List<(string Text, List<(float X, float Y)> Origins)?>();
        var source = new ModelSource(PdfDocument.Open(pdf).View());
        foreach (var page in source.View.Pages)
        {
            try
            {
                pages.Add(Join(source.ReadPage(page)));
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

    /// <summary>Where <paramref name="text"/> starts in pages already read.</summary>
    private static List<PdfTextMatch> Match(List<(string Text, List<(float X, float Y)> Origins)?> pages, string text, bool ignoreCase)
    {
        string needle = Collapse(text.Normalize(NormalizationForm.FormC)).Trim();
        var matches = new List<PdfTextMatch>();
        if (needle.Length == 0)
        {
            return matches;
        }

        StringComparison comparison = ignoreCase ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
        for (int i = 0; i < pages.Count; i++)
        {
            if (pages[i] is not var (line, origins))
            {
                continue;
            }

            for (int at = line.IndexOf(needle, comparison); at >= 0; at = line.IndexOf(needle, at + needle.Length, comparison))
            {
                var (x, y) = origins[at];
                matches.Add(new PdfTextMatch(i + 1, x, y));
            }
        }

        return matches;
    }

    /// <summary>
    /// The text of a page as one string, with the origin of the glyph each character comes from. A space goes where
    /// glyphs are apart (more than a fifth of the font size) or on another line, so words drawn by separate operators
    /// still read as words; runs of white space are one space.
    /// </summary>
    internal static (string Text, List<(float X, float Y)> Origins) Join(List<Glyph> glyphs)
    {
        var text = new StringBuilder();
        var origins = new List<(float X, float Y)>();
        Glyph? previous = null;
        foreach (var glyph in glyphs)
        {
            if (previous is { } p && text.Length > 0 && text[^1] != ' ')
            {
                float size = Math.Max(Math.Max(p.Size, glyph.Size), 0.1f);
                bool otherLine = Math.Abs(glyph.Y - p.Y) > size * 0.5f;
                float gap = glyph.X - p.EndX;
                if (otherLine || gap > size * 0.2f || glyph.X < p.X - size)
                {
                    text.Append(' ');
                    origins.Add((glyph.X, glyph.Y));
                }
            }

            foreach (char c in glyph.Text)
            {
                bool space = char.IsWhiteSpace(c) || c == ' ';
                if (space && (text.Length == 0 || text[^1] == ' '))
                {
                    continue;
                }

                text.Append(space ? ' ' : c);
                origins.Add((glyph.X, glyph.Y));
            }

            previous = glyph;
        }

        return (text.ToString(), origins);
    }

    /// <summary>The text with every run of white space made one space.</summary>
    private static string Collapse(string text)
    {
        var sb = new StringBuilder(text.Length);
        foreach (char c in text)
        {
            bool space = char.IsWhiteSpace(c) || c == ' ';
            if (!space)
            {
                sb.Append(c);
            }
            else if (sb.Length > 0 && sb[^1] != ' ')
            {
                sb.Append(' ');
            }
        }

        return sb.ToString();
    }

    /// <summary>A glyph drawn on the page: its text, origin, where it ends and its size, in user space.</summary>
    internal readonly record struct Glyph(string Text, float X, float Y, float EndX, float Size);

    /// <summary>An affine matrix [a b c d e f] of ISO 32000-1 §8.3.4; points are row vectors (p' = p × M).</summary>
    internal readonly record struct Matrix(double A, double B, double C, double D, double E, double F)
    {
        public static readonly Matrix Identity = new(1, 0, 0, 1, 0, 0);

        /// <summary>This matrix followed by <paramref name="m"/> (this × m).</summary>
        public Matrix Then(Matrix m) => new(
            (A * m.A) + (B * m.C), (A * m.B) + (B * m.D),
            (C * m.A) + (D * m.C), (C * m.B) + (D * m.D),
            (E * m.A) + (F * m.C) + m.E, (E * m.B) + (F * m.D) + m.F);

        public (double X, double Y) Apply(double x, double y) => ((x * A) + (y * C) + E, (x * B) + (y * D) + F);

        public static Matrix Translate(double x, double y) => new(1, 0, 0, 1, x, y);
    }

    /// <summary>A form XObject to run: its content, matrix and resources (null: the caller's).</summary>
    private sealed record FormXObject(byte[] Content, Matrix Matrix, object? Resources);

    /// <summary>What running a content stream needs from the document: fonts and form XObjects by resource name.</summary>
    private interface IContentSource
    {
        /// <summary>Counts an operator; false once the document has run too many.</summary>
        bool Count();

        /// <summary>The font a resource name refers to; null when there is none.</summary>
        Font? Font(object? resources, string name);

        /// <summary>The form XObject a resource name refers to; null when it is not one, or cannot be read.</summary>
        FormXObject? Form(object? resources, string name);
    }

    /// <summary>The pages, resources, fonts and streams of a document, read through the object model (ADR 0032).</summary>
    private sealed class ModelSource(PdfRevisionView view) : IContentSource
    {
        private static readonly PdfName s_contents = PdfName.Of("Contents");
        private static readonly PdfName s_font = PdfName.Of("Font");
        private static readonly PdfName s_xObject = PdfName.Of("XObject");
        private static readonly PdfName s_form = PdfName.Of("Form");
        private static readonly PdfName s_matrix = PdfName.Of("Matrix");
        private static readonly PdfName s_resources = PdfName.Of("Resources");

        private readonly Dictionary<object, Font> _fonts = [];
        private int _operators;

        public PdfRevisionView View => view;

        /// <summary>The glyphs a page draws, in content order.</summary>
        public List<Glyph> ReadPage(PdfPage page)
        {
            var glyphs = new List<Glyph>();
            _operators = 0;
            var content = new List<byte>();
            switch (view.Resolve(page.Dictionary.Get(s_contents)))
            {
                case PdfStream stream:
                    content.AddRange(Decode(stream));
                    break;
                case PdfArray parts:
                    foreach (var part in parts)
                    {
                        if (view.Resolve(part) is PdfStream stream)
                        {
                            content.AddRange(Decode(stream));
                            content.Add((byte)'\n');
                        }
                    }

                    break;
                default:
                    return glyphs;
            }

            new ContentReader(this, glyphs).Run([.. content], page.Resources, Matrix.Identity, 0);
            return glyphs;
        }

        public bool Count() => ++_operators <= MaxOperators;

        public Font? Font(object? resources, string name)
        {
            var entry = (view.Resolve((resources as PdfDictionary)?.Get(s_font)) as PdfDictionary)?.Get(name);
            if (view.Resolve(entry) is not PdfDictionary font)
            {
                return null;
            }

            object key = entry is PdfReference reference ? reference.Id : font;
            if (!_fonts.TryGetValue(key, out var read))
            {
                read = ReadFont(font);
                _fonts[key] = read;
            }

            return read;
        }

        public FormXObject? Form(object? resources, string name)
        {
            if (view.Resolve((view.Resolve((resources as PdfDictionary)?.Get(s_xObject)) as PdfDictionary)?.Get(name)) is not PdfStream stream
                || !s_form.Equals(stream.Dictionary.Get(PdfName.Subtype)))
            {
                return null;
            }

            byte[] content;
            try
            {
                content = Decode(stream);
            }
            catch (Exception ex) when (ex is PdfFilterException or PdfUnsupportedFilterException)
            {
                return null;
            }

            var matrix = Matrix.Identity;
            if (Values(stream.Dictionary.Get(s_matrix)) is { Count: 6 } m && m.All(v => v is double))
            {
                matrix = new Matrix((double)m[0], (double)m[1], (double)m[2], (double)m[3], (double)m[4], (double)m[5]);
            }

            return new FormXObject(content, matrix, view.Resolve(stream.Dictionary.Get(s_resources)) as PdfDictionary);
        }

        private byte[] Decode(PdfStream stream) => view.Document.DecodeStream(stream, view.Revision);

        private Font ReadFont(PdfDictionary font)
        {
            Dictionary<int, string>? toUnicode = null;
            if (view.Resolve(font.Get("ToUnicode")) is PdfStream map)
            {
                try
                {
                    toUnicode = Fonts.ReadCMap(System.Text.Encoding.Latin1.GetString(Decode(map)));
                }
                catch (Exception ex) when (ex is PdfFilterException or PdfUnsupportedFilterException)
                {
                    toUnicode = null;
                }
            }

            if ((font.Get(PdfName.Subtype) as PdfName)?.Value == "Type0")
            {
                var descendants = view.Resolve(font.Get("DescendantFonts"));
                var descendant = view.Resolve(descendants is PdfArray { Count: > 0 } array ? array[0] : descendants) as PdfDictionary;
                return Fonts.Composite(toUnicode, Values(descendant?.Get("W")), Number(descendant?.Get("DW")));
            }

            var encoding = view.Resolve(font.Get("Encoding"));
            var differences = encoding as PdfDictionary;
            return Fonts.Simple(
                toUnicode,
                Fonts.Encoding((encoding as PdfName)?.Value, (view.Resolve(differences?.Get("BaseEncoding")) as PdfName)?.Value, Values(differences?.Get("Differences"))),
                Number(font.Get("FirstChar")) is double first ? (int)first : null,
                Values(font.Get("Widths")),
                (view.Resolve(font.Get("BaseFont")) as PdfName)?.Value ?? "");
        }

        private double? Number(PdfObject? value) => view.Resolve(value) switch
        {
            PdfInteger integer => integer.Value,
            PdfReal real => real.Value,
            _ => null,
        };

        /// <summary>An array as the content lexer gives one: numbers as doubles, names, nested arrays; null when it is not one.</summary>
        private List<object>? Values(PdfObject? value)
        {
            if (view.Resolve(value) is not PdfArray array)
            {
                return null;
            }

            var values = new List<object>(array.Count);
            foreach (var item in array)
            {
                var resolved = item is PdfReference ? view.Resolve(item) : item;
                object? converted = resolved switch
                {
                    PdfInteger integer => (double)integer.Value,
                    PdfReal real => real.Value,
                    PdfName name => new Name(name.Value),
                    PdfArray nested => Values(nested),
                    _ => null,
                };

                if (converted is not null)
                {
                    values.Add(converted);
                }
            }

            return values;
        }
    }

    /// <summary>Runs a content stream and records the glyphs it draws.</summary>
    private sealed class ContentReader(IContentSource document, List<Glyph> glyphs)
    {
        private struct State
        {
            public Matrix Ctm;
            public double CharSpacing;
            public double WordSpacing;
            public double Scale;
            public double Leading;
            public double Rise;
            public Font? Font;
            public double FontSize;
        }

        private State _state = new() { Ctm = Matrix.Identity, Scale = 1 };
        private Matrix _tm = Matrix.Identity;
        private Matrix _tlm = Matrix.Identity;

        public void Run(byte[] content, object? resources, Matrix ctm, int depth)
        {
            _state.Ctm = ctm;
            var saved = new Stack<State>();
            var operands = new List<object>();
            var lexer = new ContentLexer(content);
            while (lexer.Next() is { } token)
            {
                if (token is not Operator op)
                {
                    operands.Add(token);
                    continue;
                }

                if (!document.Count() || glyphs.Count > MaxGlyphs)
                {
                    return;
                }

                Execute(op.Name, operands, resources, saved, depth, lexer);
                operands.Clear();
            }
        }

        private void Execute(string op, List<object> operands, object? resources, Stack<State> saved, int depth, ContentLexer lexer)
        {
            switch (op)
            {
                case "q":
                    saved.Push(_state);
                    break;
                case "Q":
                    if (saved.Count > 0)
                    {
                        _state = saved.Pop();
                    }

                    break;
                case "cm" when Numbers(operands, 6) is { } m:
                    _state.Ctm = new Matrix(m[0], m[1], m[2], m[3], m[4], m[5]).Then(_state.Ctm);
                    break;
                case "BT":
                    _tm = _tlm = Matrix.Identity;
                    break;
                case "Tf" when operands.Count >= 2 && operands[^2] is Name font && operands[^1] is double size:
                    _state.Font = document.Font(resources, font.Value);
                    _state.FontSize = size;
                    break;
                case "Tc" when Numbers(operands, 1) is { } n:
                    _state.CharSpacing = n[0];
                    break;
                case "Tw" when Numbers(operands, 1) is { } n:
                    _state.WordSpacing = n[0];
                    break;
                case "Tz" when Numbers(operands, 1) is { } n:
                    _state.Scale = n[0] / 100;
                    break;
                case "TL" when Numbers(operands, 1) is { } n:
                    _state.Leading = n[0];
                    break;
                case "Ts" when Numbers(operands, 1) is { } n:
                    _state.Rise = n[0];
                    break;
                case "Td" when Numbers(operands, 2) is { } n:
                    MoveLine(n[0], n[1]);
                    break;
                case "TD" when Numbers(operands, 2) is { } n:
                    _state.Leading = -n[1];
                    MoveLine(n[0], n[1]);
                    break;
                case "Tm" when Numbers(operands, 6) is { } m:
                    _tm = _tlm = new Matrix(m[0], m[1], m[2], m[3], m[4], m[5]);
                    break;
                case "T*":
                    MoveLine(0, -_state.Leading);
                    break;
                case "Tj" when operands.Count >= 1 && operands[^1] is byte[] s:
                    Show(s);
                    break;
                case "'" when operands.Count >= 1 && operands[^1] is byte[] s:
                    MoveLine(0, -_state.Leading);
                    Show(s);
                    break;
                case "\"" when operands.Count >= 3 && operands[^3] is double aw && operands[^2] is double ac && operands[^1] is byte[] s:
                    _state.WordSpacing = aw;
                    _state.CharSpacing = ac;
                    MoveLine(0, -_state.Leading);
                    Show(s);
                    break;
                case "TJ" when operands.Count >= 1 && operands[^1] is List<object> array:
                    foreach (object item in array)
                    {
                        if (item is byte[] s)
                        {
                            Show(s);
                        }
                        else if (item is double adjust)
                        {
                            _tm = Matrix.Translate(-adjust / 1000 * _state.FontSize * _state.Scale, 0).Then(_tm);
                        }
                    }

                    break;
                case "Do" when operands.Count >= 1 && operands[^1] is Name name && depth < MaxFormDepth:
                    RunForm(name.Value, resources, depth);
                    break;
                case "BI":
                    lexer.SkipInlineImage();
                    break;
                default:
                    break;
            }
        }

        private void MoveLine(double tx, double ty)
        {
            _tlm = Matrix.Translate(tx, ty).Then(_tlm);
            _tm = _tlm;
        }

        private void Show(byte[] bytes)
        {
            if (_state.Font is not { } font)
            {
                return;
            }

            Matrix trm = _tm.Then(_state.Ctm);
            double size = _state.FontSize * Math.Sqrt((trm.C * trm.C) + (trm.D * trm.D));
            foreach (int code in font.Codes(bytes))
            {
                double w0 = font.Width(code) / 1000;
                var (x, y) = trm.Apply(0, _state.Rise);
                var (endX, _) = trm.Apply(w0 * _state.FontSize * _state.Scale, _state.Rise);
                glyphs.Add(new Glyph(font.Text(code), (float)x, (float)y, (float)endX, (float)size));

                double wordSpacing = !font.TwoByte && code == 32 ? _state.WordSpacing : 0;
                double tx = ((w0 * _state.FontSize) + _state.CharSpacing + wordSpacing) * _state.Scale;
                _tm = Matrix.Translate(tx, 0).Then(_tm);
                trm = _tm.Then(_state.Ctm);
            }
        }

        private void RunForm(string name, object? resources, int depth)
        {
            if (document.Form(resources, name) is not { } form)
            {
                return;
            }

            var reader = new ContentReader(document, glyphs) { _state = _state };
            reader.Run(form.Content, form.Resources ?? resources, form.Matrix.Then(_state.Ctm), depth + 1);
        }

        private static double[]? Numbers(List<object> operands, int count)
        {
            if (operands.Count < count)
            {
                return null;
            }

            double[] numbers = new double[count];
            for (int i = 0; i < count; i++)
            {
                if (operands[operands.Count - count + i] is not double d)
                {
                    return null;
                }

                numbers[i] = d;
            }

            return numbers;
        }
    }

    /// <summary>A PDF name token (without the slash).</summary>
    private sealed record Name(string Value);

    /// <summary>An operator token.</summary>
    private sealed record Operator(string Name);

    /// <summary>Splits a content stream into operands (numbers, names, strings, arrays) and operators.</summary>
    private sealed class ContentLexer(byte[] data)
    {
        private int _pos;

        /// <summary>The values of an array written as text (a dictionary entry), or null when it is not one.</summary>
        public static List<object>? ReadArray(string text)
        {
            var lexer = new ContentLexer(Encoding.Latin1.GetBytes(text));
            return lexer.Next() as List<object>;
        }

        public object? Next()
        {
            while (true)
            {
                SkipSpace();
                if (_pos >= data.Length)
                {
                    return null;
                }

                byte b = data[_pos];
                switch (b)
                {
                    case (byte)'(':
                        return LiteralString();
                    case (byte)'<' when _pos + 1 < data.Length && data[_pos + 1] == (byte)'<':
                        _pos += 2;
                        SkipDictionary();
                        continue;
                    case (byte)'<':
                        return HexString();
                    case (byte)'[':
                        _pos++;
                        return Array();
                    case (byte)']':
                    case (byte)'>':
                    case (byte)')':
                    case (byte)'{':
                    case (byte)'}':
                        _pos++;
                        continue;
                    case (byte)'/':
                        _pos++;
                        return new Name(Word());
                    default:
                        string word = Word();
                        if (word.Length == 0)
                        {
                            _pos++;
                            continue;
                        }

                        return double.TryParse(word, NumberStyles.Float, CultureInfo.InvariantCulture, out double number)
                            ? number
                            : word is "true" or "false" or "null" ? word : new Operator(word);
                }
            }
        }

        /// <summary>Steps over an inline image (§8.9.7): its dictionary up to <c>ID</c>, then its data up to <c>EI</c>.</summary>
        public void SkipInlineImage()
        {
            while (Next() is { } token)
            {
                if (token is Operator { Name: "ID" })
                {
                    break;
                }
            }

            _pos++;
            while (_pos + 2 < data.Length)
            {
                if (data[_pos] == (byte)'E' && data[_pos + 1] == (byte)'I' && IsSpace(data[_pos - 1]) && (IsSpace(data[_pos + 2]) || IsDelimiter(data[_pos + 2])))
                {
                    _pos += 2;
                    return;
                }

                _pos++;
            }

            _pos = data.Length;
        }

        private List<object> Array()
        {
            var items = new List<object>();
            while (true)
            {
                SkipSpace();
                if (_pos >= data.Length)
                {
                    return items;
                }

                if (data[_pos] == (byte)']')
                {
                    _pos++;
                    return items;
                }

                if (Next() is { } item and not Operator)
                {
                    items.Add(item);
                }
            }
        }

        private void SkipDictionary()
        {
            int depth = 1;
            while (_pos < data.Length && depth > 0)
            {
                if (data[_pos] == (byte)'(')
                {
                    LiteralString();
                    continue;
                }

                if (data[_pos] == (byte)'<' && _pos + 1 < data.Length && data[_pos + 1] == (byte)'<')
                {
                    depth++;
                    _pos += 2;
                }
                else if (data[_pos] == (byte)'>' && _pos + 1 < data.Length && data[_pos + 1] == (byte)'>')
                {
                    depth--;
                    _pos += 2;
                }
                else
                {
                    _pos++;
                }
            }
        }

        private byte[] LiteralString()
        {
            _pos++;
            var bytes = new List<byte>();
            int depth = 1;
            while (_pos < data.Length)
            {
                byte b = data[_pos++];
                if (b == (byte)'\\' && _pos < data.Length)
                {
                    byte e = data[_pos++];
                    switch (e)
                    {
                        case (byte)'n':
                            bytes.Add((byte)'\n');
                            break;
                        case (byte)'r':
                            bytes.Add((byte)'\r');
                            break;
                        case (byte)'t':
                            bytes.Add((byte)'\t');
                            break;
                        case (byte)'b':
                            bytes.Add((byte)'\b');
                            break;
                        case (byte)'f':
                            bytes.Add((byte)'\f');
                            break;
                        case (byte)'\r':
                            if (_pos < data.Length && data[_pos] == (byte)'\n')
                            {
                                _pos++;
                            }

                            break;
                        case (byte)'\n':
                            break;
                        case >= (byte)'0' and <= (byte)'7':
                            int value = e - '0';
                            for (int i = 0; i < 2 && _pos < data.Length && data[_pos] is >= (byte)'0' and <= (byte)'7'; i++)
                            {
                                value = (value * 8) + (data[_pos++] - '0');
                            }

                            bytes.Add((byte)value);
                            break;
                        default:
                            bytes.Add(e);
                            break;
                    }
                }
                else if (b == (byte)'(')
                {
                    depth++;
                    bytes.Add(b);
                }
                else if (b == (byte)')')
                {
                    if (--depth == 0)
                    {
                        break;
                    }

                    bytes.Add(b);
                }
                else
                {
                    bytes.Add(b);
                }
            }

            return [.. bytes];
        }

        private byte[] HexString()
        {
            _pos++;
            var hex = new StringBuilder();
            while (_pos < data.Length && data[_pos] != (byte)'>')
            {
                char c = (char)data[_pos++];
                if (char.IsAsciiHexDigit(c))
                {
                    hex.Append(c);
                }
            }

            _pos++;
            if (hex.Length % 2 == 1)
            {
                hex.Append('0');
            }

            return Convert.FromHexString(hex.ToString());
        }

        private string Word()
        {
            int start = _pos;
            while (_pos < data.Length && !IsSpace(data[_pos]) && !IsDelimiter(data[_pos]))
            {
                _pos++;
            }

            return Encoding.Latin1.GetString(data, start, _pos - start);
        }

        private void SkipSpace()
        {
            while (_pos < data.Length)
            {
                if (IsSpace(data[_pos]))
                {
                    _pos++;
                }
                else if (data[_pos] == (byte)'%')
                {
                    while (_pos < data.Length && data[_pos] is not (byte)'\n' and not (byte)'\r')
                    {
                        _pos++;
                    }
                }
                else
                {
                    return;
                }
            }
        }

        private static bool IsSpace(byte b) => b is (byte)' ' or (byte)'\n' or (byte)'\r' or (byte)'\t' or (byte)'\f' or 0;

        private static bool IsDelimiter(byte b) => b is (byte)'(' or (byte)')' or (byte)'<' or (byte)'>' or (byte)'[' or (byte)']' or (byte)'{' or (byte)'}' or (byte)'/' or (byte)'%';
    }

    /// <summary>What a font says about its codes: how many bytes each takes, its text and its width.</summary>
    internal sealed class Font
    {
        public bool TwoByte { get; init; }

        public Dictionary<int, string>? ToUnicode { get; init; }

        /// <summary>A simple font's text of each code, from its encoding; null for a composite font.</summary>
        public string?[]? Encoding { get; init; }

        public Dictionary<int, double> Widths { get; init; } = [];

        public double DefaultWidth { get; init; } = 500;

        /// <summary>The standard 14 font whose metrics give the widths a simple font does not list; null when it is not one.</summary>
        public string? Standard { get; init; }

        public IEnumerable<int> Codes(byte[] bytes)
        {
            if (!TwoByte)
            {
                foreach (byte b in bytes)
                {
                    yield return b;
                }

                yield break;
            }

            for (int i = 0; i + 1 < bytes.Length; i += 2)
            {
                yield return (bytes[i] << 8) | bytes[i + 1];
            }
        }

        public string Text(int code) =>
            ToUnicode is not null && ToUnicode.TryGetValue(code, out string? text) ? text
            : Encoding is not null && code < Encoding.Length ? Encoding[code] ?? ""
            : "";

        public double Width(int code)
        {
            if (Widths.TryGetValue(code, out double width))
            {
                return width;
            }

            if (Standard is not null && Text(code) is { Length: 1 } text)
            {
                return Signing.AppearanceText.Measure(text, Standard, 1000);
            }

            return DefaultWidth;
        }
    }

    /// <summary>Reads fonts: their kind, encoding, ToUnicode map and widths.</summary>
    private static class Fonts
    {
        internal static readonly string[] s_standard14 =
        [
            "Helvetica", "Helvetica-Bold", "Helvetica-Oblique", "Helvetica-BoldOblique",
            "Times-Roman", "Times-Bold", "Times-Italic", "Times-BoldItalic",
            "Courier", "Courier-Bold", "Courier-Oblique", "Courier-BoldOblique",
        ];

        /// <summary>A Type 0 font (§9.7): two-byte codes, read through its ToUnicode map, with its CIDFont's widths.</summary>
        internal static Font Composite(Dictionary<int, string>? toUnicode, List<object>? cidWidths, double? defaultWidth) => new()
        {
            TwoByte = true,
            ToUnicode = toUnicode,
            Widths = CidWidths(cidWidths),
            DefaultWidth = defaultWidth ?? 1000,
        };

        /// <summary>A simple font (§9.6): one-byte codes, its encoding, its widths from FirstChar on.</summary>
        internal static Font Simple(
            Dictionary<int, string>? toUnicode, string?[] encoding, int? firstChar, List<object>? widthValues, string baseFont)
        {
            baseFont = baseFont.TrimStart('/');
            int plus = baseFont.IndexOf('+', StringComparison.Ordinal);
            if (plus == 6)
            {
                baseFont = baseFont[(plus + 1)..];
            }

            var widths = new Dictionary<int, double>();
            if (firstChar is int first && widthValues is not null)
            {
                for (int i = 0; i < widthValues.Count; i++)
                {
                    if (widthValues[i] is double w)
                    {
                        widths[first + i] = w;
                    }
                }
            }

            return new Font
            {
                ToUnicode = toUnicode,
                Encoding = encoding,
                Widths = widths,
                Standard = Array.Find(s_standard14, f => f.Equals(baseFont, StringComparison.OrdinalIgnoreCase)) ?? (baseFont.Length == 0 ? null : StandardFor(baseFont)),
            };
        }

        /// <summary>A simple font's encoding (§9.6.6): a named one, or a base encoding changed by /Differences.</summary>
        internal static string?[] Encoding(string? name, string? baseEncoding, List<object>? differences)
        {
            string?[] table = Tables.WinAnsi();
            if (name is not null)
            {
                return Tables.ByName(name) ?? table;
            }

            if (baseEncoding is not null)
            {
                table = Tables.ByName(baseEncoding) ?? table;
            }

            if (differences is not null)
            {
                table = (string?[])table.Clone();
                int code = 0;
                foreach (object item in differences)
                {
                    if (item is double d)
                    {
                        code = (int)d;
                    }
                    else if (item is Name glyph)
                    {
                        if (code is >= 0 and < 256)
                        {
                            table[code] = GlyphNames.Text(glyph.Value);
                        }

                        code++;
                    }
                }
            }

            return table;
        }

        /// <summary>The /W array of a CIDFont (§9.7.4.3): <c>c [w1 w2 …]</c> and <c>cfirst clast w</c>.</summary>
        internal static Dictionary<int, double> CidWidths(List<object>? items)
        {
            var widths = new Dictionary<int, double>();
            if (items is null)
            {
                return widths;
            }

            for (int i = 0; i < items.Count;)
            {
                if (items[i] is double start && i + 1 < items.Count && items[i + 1] is List<object> list)
                {
                    for (int j = 0; j < list.Count && widths.Count < MaxGlyphs; j++)
                    {
                        if (list[j] is double w)
                        {
                            widths[(int)start + j] = w;
                        }
                    }

                    i += 2;
                }
                else if (items[i] is double first && i + 2 < items.Count && items[i + 1] is double last && items[i + 2] is double w)
                {
                    for (int c = (int)first; c <= (int)last && c - (int)first < 65536; c++)
                    {
                        widths[c] = w;
                    }

                    i += 3;
                }
                else
                {
                    i++;
                }
            }

            return widths;
        }

        /// <summary>The standard font with the metrics of a font named like one (Arial is Helvetica, TimesNewRoman is Times).</summary>
        internal static string? StandardFor(string baseFont)
        {
            string name = baseFont.Replace(",", "-", StringComparison.Ordinal);
            bool bold = name.Contains("Bold", StringComparison.OrdinalIgnoreCase);
            if (name.StartsWith("Arial", StringComparison.OrdinalIgnoreCase) || name.StartsWith("Helvetica", StringComparison.OrdinalIgnoreCase))
            {
                return bold ? "Helvetica-Bold" : "Helvetica";
            }

            return name.StartsWith("Times", StringComparison.OrdinalIgnoreCase) ? (bold ? "Times-Bold" : "Times-Roman") : null;
        }

        /// <summary>The code → text map of a ToUnicode CMap (§9.10.3): its bfchar and bfrange sections.</summary>
        internal static Dictionary<int, string> ReadCMap(string cmap)
        {
            var map = new Dictionary<int, string>();
            var tokens = new List<string>();
            for (int i = 0; i < cmap.Length;)
            {
                char c = cmap[i];
                if (c == '<')
                {
                    int end = cmap.IndexOf('>', i);
                    if (end < 0)
                    {
                        break;
                    }

                    tokens.Add(cmap[i..(end + 1)]);
                    i = end + 1;
                }
                else if (c is '[' or ']')
                {
                    tokens.Add(c.ToString());
                    i++;
                }
                else if (char.IsWhiteSpace(c))
                {
                    i++;
                }
                else
                {
                    int start = i;
                    while (i < cmap.Length && !char.IsWhiteSpace(cmap[i]) && cmap[i] is not '<' and not '[' and not ']')
                    {
                        i++;
                    }

                    tokens.Add(cmap[start..i]);
                }
            }

            for (int i = 0; i < tokens.Count; i++)
            {
                if (tokens[i] == "beginbfchar")
                {
                    for (i++; i + 1 < tokens.Count && tokens[i] != "endbfchar"; i += 2)
                    {
                        if (Hex(tokens[i]) is { } code && Utf16(tokens[i + 1]) is { } text)
                        {
                            map[code] = text;
                        }
                    }
                }
                else if (tokens[i] == "beginbfrange")
                {
                    for (i++; i + 2 < tokens.Count && tokens[i] != "endbfrange";)
                    {
                        int? low = Hex(tokens[i]);
                        int? high = Hex(tokens[i + 1]);
                        if (tokens[i + 2] == "[")
                        {
                            int j = i + 3;
                            for (int code = low ?? 0; j < tokens.Count && tokens[j] != "]"; j++, code++)
                            {
                                if (low is not null && Utf16(tokens[j]) is { } text)
                                {
                                    map[code] = text;
                                }
                            }

                            i = j + 1;
                            continue;
                        }

                        if (low is { } lo && high is { } hi && hi >= lo && hi - lo < 65536 && Utf16(tokens[i + 2]) is { Length: > 0 } first)
                        {
                            for (int code = lo; code <= hi; code++)
                            {
                                // The last UTF-16 unit counts up through the range.
                                map[code] = string.Concat(first.AsSpan(0, first.Length - 1), ((char)(first[^1] + (code - lo))).ToString());
                            }
                        }

                        i += 3;
                    }
                }
            }

            return map;
        }

        private static int? Hex(string token) =>
            token.Length >= 3 && token[0] == '<' && int.TryParse(token[1..^1], NumberStyles.HexNumber, CultureInfo.InvariantCulture, out int value) ? value : null;

        private static string? Utf16(string token)
        {
            if (token.Length < 2 || token[0] != '<')
            {
                return null;
            }

            string hex = string.Concat(token[1..^1].Where(char.IsAsciiHexDigit));
            if (hex.Length % 4 != 0)
            {
                hex = hex.PadRight(hex.Length + (4 - (hex.Length % 4)), '0');
            }

            return System.Text.Encoding.BigEndianUnicode.GetString(Convert.FromHexString(hex));
        }
    }

    /// <summary>The simple-font encodings of ISO 32000-1 Annex D.</summary>
    internal static class Tables
    {
        // WinAnsiEncoding 0x80–0x9F (the rest is Latin-1); unused codes are null.
        private const string WinAnsiHigh = "€\0‚ƒ„…†‡ˆ‰Š‹Œ\0Ž\0\0‘’“”•–—˜™š›œ\0žŸ";

        // MacRomanEncoding 0x80–0xFF (Annex D; 0xDB is the euro, 0xF0 unused).
        internal const string MacRomanHigh =
            "ÄÅÇÉÑÖÜáàâäãåçéèêëíìîïñóòôöõúùûü†°¢£§•¶ß®©™´¨≠ÆØ∞±≤≥¥µ∂∑∏π∫ªºΩæø¿¡¬√ƒ≈∆«»…\u00A0ÀÃÕŒœ–—“”‘’÷◊ÿŸ⁄€‹›ﬁﬂ‡·‚„‰ÂÊÁËÈÍÎÏÌÓÔ\0ÒÚÛÙıˆ˜¯˘˙˚¸˝˛ˇ";

        public static string?[] WinAnsi()
        {
            var table = new string?[256];
            for (int c = 32; c < 256; c++)
            {
                table[c] = c is >= 0x80 and <= 0x9F
                    ? WinAnsiHigh[c - 0x80] == '\0' ? null : WinAnsiHigh[c - 0x80].ToString()
                    : ((char)c).ToString();
            }

            table[127] = null;
            return table;
        }

        public static string?[]? ByName(string name) => name switch
        {
            "WinAnsiEncoding" => WinAnsi(),
            "MacRomanEncoding" => MacRoman(),
            "StandardEncoding" => Standard(),
            _ => null,
        };

        private static string?[] MacRoman()
        {
            var table = new string?[256];
            for (int c = 32; c < 127; c++)
            {
                table[c] = ((char)c).ToString();
            }

            for (int c = 0x80; c < 256; c++)
            {
                char ch = MacRomanHigh[c - 0x80];
                table[c] = ch == '\0' ? null : ch.ToString();
            }

            return table;
        }

        private static string?[] Standard()
        {
            // ASCII, with the two quotes StandardEncoding puts where ASCII has the apostrophe and grave accent.
            var table = new string?[256];
            for (int c = 32; c < 127; c++)
            {
                table[c] = ((char)c).ToString();
            }

            table[0x27] = "’";
            table[0x60] = "‘";
            return table;
        }
    }

    /// <summary>Text of the glyph names a /Differences array uses (Adobe Glyph List, the Latin part).</summary>
    internal static class GlyphNames
    {
        private static readonly Dictionary<string, string> s_names = new(StringComparer.Ordinal)
        {
            ["space"] = " ",
            ["exclam"] = "!",
            ["quotedbl"] = "\"",
            ["numbersign"] = "#",
            ["dollar"] = "$",
            ["percent"] = "%",
            ["ampersand"] = "&",
            ["quotesingle"] = "'",
            ["quoteright"] = "’",
            ["quoteleft"] = "‘",
            ["parenleft"] = "(",
            ["parenright"] = ")",
            ["asterisk"] = "*",
            ["plus"] = "+",
            ["comma"] = ",",
            ["hyphen"] = "-",
            ["period"] = ".",
            ["slash"] = "/",
            ["zero"] = "0",
            ["one"] = "1",
            ["two"] = "2",
            ["three"] = "3",
            ["four"] = "4",
            ["five"] = "5",
            ["six"] = "6",
            ["seven"] = "7",
            ["eight"] = "8",
            ["nine"] = "9",
            ["colon"] = ":",
            ["semicolon"] = ";",
            ["less"] = "<",
            ["equal"] = "=",
            ["greater"] = ">",
            ["question"] = "?",
            ["at"] = "@",
            ["bracketleft"] = "[",
            ["backslash"] = "\\",
            ["bracketright"] = "]",
            ["underscore"] = "_",
            ["braceleft"] = "{",
            ["bar"] = "|",
            ["braceright"] = "}",
            ["asciitilde"] = "~",
            ["asciicircum"] = "^",
            ["grave"] = "`",
            ["endash"] = "–",
            ["emdash"] = "—",
            ["quotedblleft"] = "“",
            ["quotedblright"] = "”",
            ["bullet"] = "•",
            ["ellipsis"] = "…",
            ["ordfeminine"] = "ª",
            ["ordmasculine"] = "º",
            ["degree"] = "°",
            ["germandbls"] = "ß",
            ["nbspace"] = " ",
            ["fi"] = "fi",
            ["fl"] = "fl",
            ["ff"] = "ff",
            ["ffi"] = "ffi",
            ["ffl"] = "ffl",
            ["dotlessi"] = "ı",
            ["AE"] = "Æ",
            ["ae"] = "æ",
            ["OE"] = "Œ",
            ["oe"] = "œ",
            ["Oslash"] = "Ø",
            ["oslash"] = "ø",
            ["Euro"] = "€",
        };

        private static readonly (string Suffix, char Mark)[] s_accents =
        [
            ("acute", '́'), ("grave", '̀'), ("circumflex", '̂'), ("tilde", '̃'),
            ("dieresis", '̈'), ("cedilla", '̧'), ("ring", '̊'), ("caron", '̌'),
        ];

        public static string Text(string name)
        {
            int dot = name.IndexOf('.', StringComparison.Ordinal);
            if (dot > 0)
            {
                name = name[..dot];
            }

            if (name.Length == 1 && char.IsAsciiLetter(name[0]))
            {
                return name;
            }

            if (s_names.TryGetValue(name, out string? text))
            {
                return text;
            }

            if (name.Length is 7 && name.StartsWith("uni", StringComparison.Ordinal)
                && int.TryParse(name.AsSpan(3), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out int uni))
            {
                return ((char)uni).ToString();
            }

            if (name.Length is >= 5 and <= 7 && name[0] == 'u'
                && int.TryParse(name.AsSpan(1), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out int u) && u <= 0x10FFFF)
            {
                return char.ConvertFromUtf32(u);
            }

            foreach (var (suffix, mark) in s_accents)
            {
                if (name.Length == suffix.Length + 1 && name.EndsWith(suffix, StringComparison.Ordinal) && char.IsAsciiLetter(name[0]))
                {
                    return string.Concat(name[0].ToString(), mark.ToString()).Normalize(NormalizationForm.FormC);
                }
            }

            return "";
        }
    }
}
