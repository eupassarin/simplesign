using System.Globalization;
using System.Text;

namespace SimpleSign.PAdES.Pdf.Model;

/// <summary>The kind of a token of PDF syntax (ISO 32000-1 §7.2).</summary>
internal enum PdfTokenKind
{
    /// <summary>No more input.</summary>
    EndOfInput,

    /// <summary>An integer: digits with an optional sign.</summary>
    Integer,

    /// <summary>A real number, or anything made of digits, signs and points that is not an integer.</summary>
    Real,

    /// <summary>A name, <c>/…</c>.</summary>
    Name,

    /// <summary>A literal string, <c>(…)</c>.</summary>
    LiteralString,

    /// <summary>A hexadecimal string, <c>&lt;…&gt;</c>.</summary>
    HexString,

    /// <summary><c>[</c>.</summary>
    ArrayStart,

    /// <summary><c>]</c>.</summary>
    ArrayEnd,

    /// <summary><c>&lt;&lt;</c>.</summary>
    DictionaryStart,

    /// <summary><c>&gt;&gt;</c>.</summary>
    DictionaryEnd,

    /// <summary>A run of regular characters that is not a number: <c>true</c>, <c>null</c>, <c>R</c>, <c>obj</c>, <c>stream</c>…</summary>
    Keyword,

    /// <summary>A delimiter that cannot start a token where it stands: <c>)</c>, a lone <c>&gt;</c>, <c>{</c>, <c>}</c>.</summary>
    Invalid,
}

/// <summary>A token: its kind and where it is.</summary>
/// <param name="Kind">The kind.</param>
/// <param name="Start">The offset of its first byte.</param>
/// <param name="End">The offset just after its last byte.</param>
/// <param name="Terminated">False for a string or a name cut off by the end of the input.</param>
internal readonly record struct PdfToken(PdfTokenKind Kind, int Start, int End, bool Terminated = true)
{
    /// <summary>The token's length in bytes.</summary>
    public int Length => End - Start;
}

/// <summary>
/// Splits PDF bytes into tokens (ISO 32000-1 §7.2), skipping white-space and comments. It reads a span and builds no
/// strings: a token is its position, decoded on demand by <see cref="Name"/>, <see cref="LiteralString"/>,
/// <see cref="HexString"/> and <see cref="Integer"/>.
/// </summary>
internal ref struct PdfLexer
{
    /// <summary>Creates a lexer.</summary>
    /// <param name="data">The bytes to read.</param>
    /// <param name="position">Where to start.</param>
    public PdfLexer(ReadOnlySpan<byte> data, int position = 0)
    {
        Data = data;
        Position = position;
    }

    /// <summary>Where the next token is looked for.</summary>
    public int Position { get; set; }

    /// <summary>The bytes being read.</summary>
    public ReadOnlySpan<byte> Data { get; }

    /// <summary>Whether a byte is PDF white-space (ISO 32000-1 Table 1).</summary>
    public static bool IsWhitespace(byte b) => b is (byte)' ' or (byte)'\n' or (byte)'\r' or (byte)'\t' or (byte)'\f' or 0;

    /// <summary>Whether a byte is a PDF delimiter (ISO 32000-1 Table 2).</summary>
    public static bool IsDelimiter(byte b) =>
        b is (byte)'(' or (byte)')' or (byte)'<' or (byte)'>' or (byte)'[' or (byte)']' or (byte)'{' or (byte)'}' or (byte)'/' or (byte)'%';

    /// <summary>Whether a byte is a regular character: neither white-space nor a delimiter.</summary>
    public static bool IsRegular(byte b) => !IsWhitespace(b) && !IsDelimiter(b);

    /// <summary>Reads the next token and moves past it.</summary>
    public PdfToken Next()
    {
        SkipWhitespaceAndComments();
        int start = Position;
        if (start >= Data.Length)
        {
            return new PdfToken(PdfTokenKind.EndOfInput, start, start);
        }

        byte b = Data[start];
        switch (b)
        {
            case (byte)'[':
                Position++;
                return new PdfToken(PdfTokenKind.ArrayStart, start, Position);
            case (byte)']':
                Position++;
                return new PdfToken(PdfTokenKind.ArrayEnd, start, Position);
            case (byte)'<' when At(start + 1) == '<':
                Position += 2;
                return new PdfToken(PdfTokenKind.DictionaryStart, start, Position);
            case (byte)'<':
                return ScanHexString(start);
            case (byte)'>' when At(start + 1) == '>':
                Position += 2;
                return new PdfToken(PdfTokenKind.DictionaryEnd, start, Position);
            case (byte)'(':
                return ScanLiteralString(start);
            case (byte)'/':
                Position++;
                SkipRegular();
                return new PdfToken(PdfTokenKind.Name, start, Position);
            case (byte)')' or (byte)'>' or (byte)'{' or (byte)'}':
                Position++;
                return new PdfToken(PdfTokenKind.Invalid, start, Position);
            default:
                SkipRegular();
                return new PdfToken(Classify(Data[start..Position]), start, Position);
        }
    }

    /// <summary>Reads the next token without moving past it.</summary>
    public readonly PdfToken Peek()
    {
        var copy = this;
        return copy.Next();
    }

    /// <summary>Whether a token is the keyword given.</summary>
    /// <param name="token">The token.</param>
    /// <param name="keyword">The keyword, as bytes.</param>
    public readonly bool Is(PdfToken token, ReadOnlySpan<byte> keyword) =>
        token.Kind == PdfTokenKind.Keyword && Data[token.Start..token.End].SequenceEqual(keyword);

    /// <summary>The bytes of a token, as written.</summary>
    /// <param name="token">The token.</param>
    public readonly ReadOnlySpan<byte> Raw(PdfToken token) => Data[token.Start..token.End];

    /// <summary>The value of an integer token; false when it does not fit in a <see cref="long"/>.</summary>
    /// <param name="token">An <see cref="PdfTokenKind.Integer"/> token.</param>
    /// <param name="value">The value.</param>
    public readonly bool Integer(PdfToken token, out long value)
    {
        var digits = Raw(token);
        bool negative = false;
        if (digits[0] is (byte)'+' or (byte)'-')
        {
            negative = digits[0] == '-';
            digits = digits[1..];
        }

        value = 0;
        foreach (byte d in digits)
        {
            int digit = d - '0';
            if (value > (long.MaxValue - digit) / 10)
            {
                return false;
            }

            value = (value * 10) + digit;
        }

        if (negative)
        {
            value = -value;
        }

        return true;
    }

    /// <summary>
    /// The value of a number token read leniently, as other readers do: extra leading signs count once
    /// (<c>--5</c> is -5), and what follows a second point or a sign inside the number is ignored.
    /// </summary>
    /// <param name="token">An <see cref="PdfTokenKind.Integer"/> or <see cref="PdfTokenKind.Real"/> token.</param>
    /// <param name="value">The value.</param>
    /// <param name="clean">False when something was ignored.</param>
    /// <returns>False when no digit could be read.</returns>
    public readonly bool Real(PdfToken token, out double value, out bool clean)
    {
        var raw = Raw(token);
        int i = 0;
        bool negative = false;
        while (i < raw.Length && raw[i] is (byte)'+' or (byte)'-')
        {
            negative |= raw[i] == '-';
            i++;
        }

        clean = i <= 1;
        int start = i;
        bool point = false;
        bool digits = false;
        for (; i < raw.Length; i++)
        {
            byte b = raw[i];
            if (b == '.' && !point)
            {
                point = true;
            }
            else if (b is >= (byte)'0' and <= (byte)'9')
            {
                digits = true;
            }
            else
            {
                clean = false;
                break;
            }
        }

        value = 0;
        if (!digits)
        {
            return false;
        }

        // Digits and at most one point: always a valid invariant number.
        value = double.Parse(raw[start..i], NumberStyles.AllowDecimalPoint, CultureInfo.InvariantCulture);
        if (negative)
        {
            value = -value;
        }

        return true;
    }

    /// <summary>The value of a name token: the bytes after the slash, <c>#xx</c> escapes resolved, read as Latin-1.</summary>
    /// <param name="token">A <see cref="PdfTokenKind.Name"/> token.</param>
    public readonly string Name(PdfToken token)
    {
        var raw = Data[(token.Start + 1)..token.End];
        if (raw.IndexOf((byte)'#') < 0)
        {
            return Encoding.Latin1.GetString(raw);
        }

        var bytes = new byte[raw.Length];
        int n = 0;
        for (int i = 0; i < raw.Length; i++)
        {
            if (raw[i] == '#' && i + 2 < raw.Length
                && HexValue(raw[i + 1]) is var high and >= 0 && HexValue(raw[i + 2]) is var low and >= 0)
            {
                bytes[n++] = (byte)((high << 4) | low);
                i += 2;
            }
            else
            {
                bytes[n++] = raw[i];
            }
        }

        return Encoding.Latin1.GetString(bytes, 0, n);
    }

    /// <summary>
    /// The bytes of a literal string token, escapes resolved (ISO 32000-1 §7.3.4.2). An end of line written in the
    /// string (CR, LF or CR LF) is read as LF, as the standard says.
    /// </summary>
    /// <param name="token">A <see cref="PdfTokenKind.LiteralString"/> token.</param>
    public readonly byte[] LiteralString(PdfToken token)
    {
        var raw = Data[(token.Start + 1)..(token.Terminated ? token.End - 1 : token.End)];
        var bytes = new byte[raw.Length];
        int n = 0;
        for (int i = 0; i < raw.Length; i++)
        {
            byte c = raw[i];
            if (c == '\r')
            {
                bytes[n++] = (byte)'\n';
                if (i + 1 < raw.Length && raw[i + 1] == '\n')
                {
                    i++;
                }

                continue;
            }

            if (c != '\\' || i + 1 >= raw.Length)
            {
                bytes[n++] = c;
                continue;
            }

            c = raw[++i];
            switch (c)
            {
                case (byte)'\r':
                    // A backslash at the end of a line continues the string on the next one.
                    if (i + 1 < raw.Length && raw[i + 1] == '\n')
                    {
                        i++;
                    }

                    break;
                case (byte)'\n':
                    break;
                case >= (byte)'0' and <= (byte)'7':
                    int code = c - '0';
                    for (int k = 0; k < 2 && i + 1 < raw.Length && raw[i + 1] is >= (byte)'0' and <= (byte)'7'; k++)
                    {
                        code = (code * 8) + (raw[++i] - '0');
                    }

                    bytes[n++] = (byte)code;
                    break;
                default:
                    bytes[n++] = c switch
                    {
                        (byte)'n' => (byte)'\n',
                        (byte)'r' => (byte)'\r',
                        (byte)'t' => (byte)'\t',
                        (byte)'b' => (byte)'\b',
                        (byte)'f' => (byte)'\f',
                        _ => c,
                    };
                    break;
            }
        }

        return bytes.AsSpan(0, n).ToArray();
    }

    /// <summary>The bytes of a hexadecimal string token (ISO 32000-1 §7.3.4.3): white-space ignored, an odd last digit followed by 0.</summary>
    /// <param name="token">A <see cref="PdfTokenKind.HexString"/> token.</param>
    /// <param name="invalidDigit">True when the string held a character that is neither a digit nor white-space (it is skipped).</param>
    public readonly byte[] HexString(PdfToken token, out bool invalidDigit)
    {
        var raw = Data[(token.Start + 1)..(token.Terminated ? token.End - 1 : token.End)];
        var bytes = new byte[(raw.Length + 1) / 2];
        int n = 0;
        int high = -1;
        invalidDigit = false;
        foreach (byte c in raw)
        {
            int digit = HexValue(c);
            if (digit < 0)
            {
                invalidDigit |= !IsWhitespace(c);
                continue;
            }

            if (high < 0)
            {
                high = digit;
            }
            else
            {
                bytes[n++] = (byte)((high << 4) | digit);
                high = -1;
            }
        }

        if (high >= 0)
        {
            bytes[n++] = (byte)(high << 4);
        }

        return bytes.AsSpan(0, n).ToArray();
    }

    /// <summary>Skips white-space and comments.</summary>
    public void SkipWhitespaceAndComments()
    {
        while (Position < Data.Length)
        {
            byte b = Data[Position];
            if (IsWhitespace(b))
            {
                Position++;
            }
            else if (b == '%')
            {
                while (Position < Data.Length && Data[Position] is not ((byte)'\r' or (byte)'\n'))
                {
                    Position++;
                }
            }
            else
            {
                return;
            }
        }
    }

    private static int HexValue(byte c) => c switch
    {
        >= (byte)'0' and <= (byte)'9' => c - '0',
        >= (byte)'a' and <= (byte)'f' => c - 'a' + 10,
        >= (byte)'A' and <= (byte)'F' => c - 'A' + 10,
        _ => -1,
    };

    /// <summary>Integer when the run is an optional sign and digits; Real when it is otherwise made of digits, signs and points; else Keyword.</summary>
    private static PdfTokenKind Classify(ReadOnlySpan<byte> run)
    {
        bool digit = false;
        bool other = false;
        for (int i = 0; i < run.Length; i++)
        {
            byte b = run[i];
            if (b is >= (byte)'0' and <= (byte)'9')
            {
                digit = true;
            }
            else if (b is (byte)'+' or (byte)'-' or (byte)'.')
            {
                other |= b == '.' || i > 0;
            }
            else
            {
                return PdfTokenKind.Keyword;
            }
        }

        if (!digit)
        {
            // Only signs and points ("-", "."): read as a number with no digit, which the parser reports.
            return PdfTokenKind.Real;
        }

        return other ? PdfTokenKind.Real : PdfTokenKind.Integer;
    }

    private readonly int At(int index) => index < Data.Length ? Data[index] : -1;

    private void SkipRegular()
    {
        while (Position < Data.Length && IsRegular(Data[Position]))
        {
            Position++;
        }
    }

    private PdfToken ScanLiteralString(int start)
    {
        int depth = 0;
        for (int i = start; i < Data.Length; i++)
        {
            byte c = Data[i];
            if (c == '\\')
            {
                i++;
            }
            else if (c == '(')
            {
                depth++;
            }
            else if (c == ')' && --depth == 0)
            {
                Position = i + 1;
                return new PdfToken(PdfTokenKind.LiteralString, start, Position);
            }
        }

        Position = Data.Length;
        return new PdfToken(PdfTokenKind.LiteralString, start, Position, Terminated: false);
    }

    private PdfToken ScanHexString(int start)
    {
        int end = Data[(start + 1)..].IndexOf((byte)'>');
        if (end < 0)
        {
            Position = Data.Length;
            return new PdfToken(PdfTokenKind.HexString, start, Position, Terminated: false);
        }

        Position = start + 1 + end + 1;
        return new PdfToken(PdfTokenKind.HexString, start, Position);
    }
}
