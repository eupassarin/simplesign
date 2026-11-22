using System.Globalization;
using System.Text;

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
internal static class PdfTextLocator
{
    private const int MaxFormDepth = 8;
    private const int MaxPageDepth = 64;
    private const int MaxOperators = 5_000_000;
    private const int MaxGlyphs = 2_000_000;

    /// <summary>Every place where <paramref name="text"/> starts, in reading order: pages in order, then content order.</summary>
    public static IReadOnlyList<PdfTextMatch> Find(byte[] pdf, string text, bool ignoreCase)
    {
        ArgumentNullException.ThrowIfNull(pdf);
        string needle = Collapse(text.Normalize(NormalizationForm.FormC)).Trim();
        var matches = new List<PdfTextMatch>();
        if (needle.Length == 0)
        {
            return matches;
        }

        var document = new Document(PdfObjectIndex.Build(pdf).Revision(pdf.Length));
        int root = PdfStructureParser.FindRootObjectNumber(pdf);
        string? pagesRef = document.Dict(document.Object(root)).GetValueOrDefault("Pages");
        int pageNumber = 0;
        foreach (var (page, resources) in document.Pages(PdfRawDictionary.Reference(pagesRef)))
        {
            pageNumber++;
            List<Glyph> glyphs;
            try
            {
                glyphs = document.ReadPage(page, resources);
            }
#pragma warning disable CA1031 // A page that cannot be read has no text to find; the others are still searched.
            catch (Exception)
#pragma warning restore CA1031
            {
                continue;
            }

            var (line, origins) = Join(glyphs);
            StringComparison comparison = ignoreCase ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
            for (int at = line.IndexOf(needle, comparison); at >= 0; at = line.IndexOf(needle, at + needle.Length, comparison))
            {
                var (x, y) = origins[at];
                matches.Add(new PdfTextMatch(pageNumber, x, y));
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

    /// <summary>The objects of the document, and what is read from them: pages, resources, fonts, streams.</summary>
    private sealed class Document(Dictionary<int, string> objects)
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

        /// <summary>The font a resource name refers to; a font read once is kept.</summary>
        public Font? Font(string? resources, string name)
        {
            string? value = Dict(resources).GetValueOrDefault("Font") is { } fonts ? Dict(fonts).GetValueOrDefault(name) : null;
            if (value is null)
            {
                return null;
            }

            string key = PdfRawDictionary.Reference(value) is > 0 and var number ? number.ToString(CultureInfo.InvariantCulture) : value;
            if (!_fonts.TryGetValue(key, out var font))
            {
                font = Fonts.Read(this, Dict(value));
                _fonts[key] = font;
            }

            return font;
        }
    }

    /// <summary>Runs a content stream and records the glyphs it draws.</summary>
    private sealed class ContentReader(Document document, List<Glyph> glyphs)
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

        public void Run(byte[] content, string? resources, Matrix ctm, int depth)
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

        private void Execute(string op, List<object> operands, string? resources, Stack<State> saved, int depth, ContentLexer lexer)
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

        private void RunForm(string name, string? resources, int depth)
        {
            string? value = document.Dict(resources).GetValueOrDefault("XObject") is { } xobjects ? document.Dict(xobjects).GetValueOrDefault(name) : null;
            string? body = document.Resolve(value);
            var dict = document.Dict(body);
            if (body is null || dict.GetValueOrDefault("Subtype") != "/Form" || document.StreamData(body) is not { } content)
            {
                return;
            }

            Matrix matrix = Matrix.Identity;
            if (dict.TryGetValue("Matrix", out string? m) && ContentLexer.ReadArray(m) is { Count: 6 } values && values.All(v => v is double))
            {
                matrix = new Matrix((double)values[0], (double)values[1], (double)values[2], (double)values[3], (double)values[4], (double)values[5]);
            }

            var form = new ContentReader(document, glyphs) { _state = _state };
            form.Run(content, dict.GetValueOrDefault("Resources") ?? resources, matrix.Then(_state.Ctm), depth + 1);
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
        private static readonly string[] s_standard14 =
        [
            "Helvetica", "Helvetica-Bold", "Helvetica-Oblique", "Helvetica-BoldOblique",
            "Times-Roman", "Times-Bold", "Times-Italic", "Times-BoldItalic",
            "Courier", "Courier-Bold", "Courier-Oblique", "Courier-BoldOblique",
        ];

        public static Font Read(Document document, Dictionary<string, string> font)
        {
            Dictionary<int, string>? toUnicode = font.TryGetValue("ToUnicode", out string? map)
                && document.StreamData(document.Resolve(map)) is { } cmap
                ? ReadCMap(System.Text.Encoding.Latin1.GetString(cmap))
                : null;

            if (font.GetValueOrDefault("Subtype") == "/Type0")
            {
                string? descendants = document.Resolve(font.GetValueOrDefault("DescendantFonts"))?.Trim();
                var descendant = document.Dict(descendants is null ? null
                    : PdfRawDictionary.References(descendants) is { Count: > 0 } refs ? document.Object(refs[0])
                    : descendants.TrimStart('[').TrimEnd(']'));
                double dw = double.TryParse(descendant.GetValueOrDefault("DW"), NumberStyles.Float, CultureInfo.InvariantCulture, out double d) ? d : 1000;
                return new Font
                {
                    TwoByte = true,
                    ToUnicode = toUnicode,
                    Widths = ReadCidWidths(document.Resolve(descendant.GetValueOrDefault("W"))),
                    DefaultWidth = dw,
                };
            }

            string baseFont = (font.GetValueOrDefault("BaseFont") ?? "").TrimStart('/');
            int plus = baseFont.IndexOf('+', StringComparison.Ordinal);
            if (plus == 6)
            {
                baseFont = baseFont[(plus + 1)..];
            }

            var widths = new Dictionary<int, double>();
            if (int.TryParse(font.GetValueOrDefault("FirstChar"), out int first)
                && document.Resolve(font.GetValueOrDefault("Widths")) is { } widthArray
                && ContentLexer.ReadArray(widthArray) is { } values)
            {
                for (int i = 0; i < values.Count; i++)
                {
                    if (values[i] is double w)
                    {
                        widths[first + i] = w;
                    }
                }
            }

            return new Font
            {
                ToUnicode = toUnicode,
                Encoding = ReadEncoding(document, font.GetValueOrDefault("Encoding")),
                Widths = widths,
                Standard = Array.Find(s_standard14, f => f.Equals(baseFont, StringComparison.OrdinalIgnoreCase)) ?? (baseFont.Length == 0 ? null : StandardFor(baseFont)),
            };
        }

        /// <summary>The standard font with the metrics of a font named like one (Arial is Helvetica, TimesNewRoman is Times).</summary>
        private static string? StandardFor(string baseFont)
        {
            string name = baseFont.Replace(",", "-", StringComparison.Ordinal);
            bool bold = name.Contains("Bold", StringComparison.OrdinalIgnoreCase);
            if (name.StartsWith("Arial", StringComparison.OrdinalIgnoreCase) || name.StartsWith("Helvetica", StringComparison.OrdinalIgnoreCase))
            {
                return bold ? "Helvetica-Bold" : "Helvetica";
            }

            return name.StartsWith("Times", StringComparison.OrdinalIgnoreCase) ? (bold ? "Times-Bold" : "Times-Roman") : null;
        }

        private static string?[] ReadEncoding(Document document, string? value)
        {
            string?[] table = Tables.WinAnsi();
            string? resolved = document.Resolve(value)?.Trim();
            if (resolved is null)
            {
                return table;
            }

            if (resolved.StartsWith('/'))
            {
                return Tables.ByName(resolved[1..]) ?? table;
            }

            var dict = PdfRawDictionary.Parse(resolved);
            if (dict.GetValueOrDefault("BaseEncoding") is { } baseEncoding)
            {
                table = Tables.ByName(baseEncoding.TrimStart('/')) ?? table;
            }

            if (dict.TryGetValue("Differences", out string? differences) && ContentLexer.ReadArray(differences) is { } items)
            {
                table = (string?[])table.Clone();
                int code = 0;
                foreach (object item in items)
                {
                    if (item is double d)
                    {
                        code = (int)d;
                    }
                    else if (item is Name name)
                    {
                        if (code is >= 0 and < 256)
                        {
                            table[code] = GlyphNames.Text(name.Value);
                        }

                        code++;
                    }
                }
            }

            return table;
        }

        /// <summary>The /W array of a CIDFont (§9.7.4.3): <c>c [w1 w2 …]</c> and <c>cfirst clast w</c>.</summary>
        private static Dictionary<int, double> ReadCidWidths(string? value)
        {
            var widths = new Dictionary<int, double>();
            if (value is null || ContentLexer.ReadArray(value) is not { } items)
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
