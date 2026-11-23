using System.Globalization;
using System.Text;
using SimpleSign.PAdES.Pdf.Model;

namespace SimpleSign.PAdES.Pdf.Writing;

/// <summary>An object written by <see cref="PdfObjectSerializer"/>: its bytes and where each of its top-level values is.</summary>
/// <param name="Bytes">The bytes, <c>N G obj</c> to <c>endobj</c> and the line end after it.</param>
/// <param name="ValueRanges">For each top-level dictionary key, where its value is in <paramref name="Bytes"/>.</param>
internal sealed record PdfSerializedObject(byte[] Bytes, IReadOnlyDictionary<string, (int Start, int Length)> ValueRanges);

/// <summary>
/// Writes PDF objects (ISO 32000-1 §7.3) in the layout the library's writers have always written them (ADR 0032), so
/// that moving a writer to the object model leaves its output byte for byte the same:
/// <code>
/// N 0 obj
/// &lt;&lt; /Type /Sig
///    /Filter /Adobe.PPKLite
///    /Reference [&lt;&lt; /Type /SigRef /TransformMethod /DocMDP &gt;&gt;]
/// &gt;&gt;
/// endobj
/// </code>
/// The top-level dictionary has its first entry on the <c>&lt;&lt;</c> line and each other on a line of its own,
/// indented by three spaces; nested arrays and dictionaries are written on one line. A stream's data follows
/// <c>stream</c> and a line feed, and is followed by a line feed and <c>endstream</c>.
/// </summary>
internal static class PdfObjectSerializer
{
    private const string Indent = "   ";

    /// <summary>
    /// Writes an indirect object.
    /// </summary>
    /// <param name="number">The object number.</param>
    /// <param name="value">The object: a dictionary or a stream in the block layout, anything else on one line.</param>
    /// <param name="generation">The generation number.</param>
    /// <param name="raw">
    /// Top-level values written as given instead of serialized (a placeholder such as
    /// <c>[0000000000 0000000000 0000000000 0000000000]</c> that is filled in later), by key without the slash.
    /// </param>
    /// <param name="inline">
    /// Whether the dictionary (a stream's included) is written on one line (<c>&lt;&lt; /Filter /FlateDecode /Length 9 &gt;&gt;</c>),
    /// as the writers write the streams they embed; its values' places are then not given.
    /// </param>
    public static PdfSerializedObject Write(int number, PdfObject value, int generation = 0, IReadOnlyDictionary<string, string>? raw = null, bool inline = false)
    {
        ArgumentNullException.ThrowIfNull(value);
        var text = new StringBuilder();
        text.Append(CultureInfo.InvariantCulture, $"{number} {generation} obj\n");
        var ranges = new Dictionary<string, (int, int)>(StringComparer.Ordinal);
        byte[]? data = null;
        switch (value)
        {
            case PdfStream stream when inline:
                text.Append(ToText(stream.Dictionary)).Append("\nstream\n");
                data = stream.Encoded.ToArray();
                break;
            case PdfStream stream:
                WriteBlock(text, stream.Dictionary, raw, ranges);
                text.Append("\nstream\n");
                data = stream.Encoded.ToArray();
                break;
            case PdfDictionary dictionary when inline:
                text.Append(ToText(dictionary));
                break;
            case PdfDictionary dictionary:
                WriteBlock(text, dictionary, raw, ranges);
                break;
            default:
                WriteValue(text, value);
                break;
        }

        string tail = data is null ? "\nendobj\n" : "\nendstream\nendobj\n";
        if (data is null)
        {
            return new PdfSerializedObject(Encoding.Latin1.GetBytes(text.Append(tail).ToString()), ranges);
        }

        byte[] head = Encoding.Latin1.GetBytes(text.ToString());
        return new PdfSerializedObject([.. head, .. data, .. Encoding.Latin1.GetBytes(tail)], ranges);
    }

    /// <summary>A value on one line: <c>&lt;&lt; /N 12 0 R &gt;&gt;</c>, <c>[0 0 0]</c>, <c>(text)</c>, <c>/Name</c>…</summary>
    /// <param name="value">The value (not a stream: a stream is always an indirect object).</param>
    public static string ToText(PdfObject value)
    {
        ArgumentNullException.ThrowIfNull(value);
        var text = new StringBuilder();
        WriteValue(text, value);
        return text.ToString();
    }

    /// <summary>
    /// A text string (§7.9.2.2) as the writers have always written one: a literal string when PDFDocEncoding holds the
    /// text byte for byte, else UTF-16BE with its byte order mark, in hexadecimal.
    /// </summary>
    /// <param name="text">The text.</param>
    public static PdfString TextString(string text)
    {
        ArgumentNullException.ThrowIfNull(text);
        return text.All(IsLiteralSafe)
            ? new PdfString(Encoding.Latin1.GetBytes(text), PdfStringForm.Literal)
            : new PdfString((byte[])[0xFE, 0xFF, .. Encoding.BigEndianUnicode.GetBytes(text)], PdfStringForm.Hexadecimal);
    }

    /// <summary>A real number written with two decimals, as the writers write coordinates (<c>72.00</c>).</summary>
    /// <param name="value">The number.</param>
    public static PdfReal Coordinate(float value) => new(value, value.ToString("F2", CultureInfo.InvariantCulture));

    private static void WriteBlock(StringBuilder text, PdfDictionary dictionary, IReadOnlyDictionary<string, string>? raw, Dictionary<string, (int, int)> ranges)
    {
        text.Append("<<");
        bool first = true;
        foreach (var (key, value) in dictionary)
        {
            text.Append(first ? " " : Indent);
            first = false;
            text.Append('/').Append(EscapeName(key.Value)).Append(' ');
            int start = text.Length;
            if (raw is not null && raw.TryGetValue(key.Value, out string? given))
            {
                text.Append(given);
            }
            else
            {
                WriteValue(text, value);
            }

            ranges[key.Value] = (start, text.Length - start);
            text.Append('\n');
        }

        if (first)
        {
            text.Append(' ');
        }

        text.Append(">>");
    }

    private static void WriteValue(StringBuilder text, PdfObject value)
    {
        // An explicit stack, as everywhere objects are walked: a value may come from a hostile file.
        var pending = new Stack<object>();
        pending.Push(value);
        while (pending.Count > 0)
        {
            switch (pending.Pop())
            {
                case string literal:
                    text.Append(literal);
                    break;
                case PdfNull:
                    text.Append("null");
                    break;
                case PdfBoolean boolean:
                    text.Append(boolean.Value ? "true" : "false");
                    break;
                case PdfInteger integer:
                    text.Append(integer.Value.ToString(CultureInfo.InvariantCulture));
                    break;
                case PdfReal real:
                    text.Append(real.Text ?? real.Value.ToString("0.##########", CultureInfo.InvariantCulture));
                    break;
                case PdfName name:
                    text.Append('/').Append(EscapeName(name.Value));
                    break;
                case PdfString str:
                    WriteString(text, str);
                    break;
                case PdfReference reference:
                    text.Append(CultureInfo.InvariantCulture, $"{reference.Id.Number} {reference.Id.Generation} R");
                    break;
                case PdfArray array:
                    // Pushed in reverse: the closing bracket last.
                    pending.Push("]");
                    for (int i = array.Count - 1; i >= 0; i--)
                    {
                        pending.Push(array[i]);
                        if (i > 0)
                        {
                            pending.Push(" ");
                        }
                    }

                    text.Append('[');
                    break;
                case PdfDictionary dictionary:
                    var entries = dictionary.ToList();
                    pending.Push(" >>");
                    for (int i = entries.Count - 1; i >= 0; i--)
                    {
                        pending.Push(entries[i].Value);
                        pending.Push($" /{EscapeName(entries[i].Key.Value)} ");
                    }

                    text.Append("<<");
                    break;
                case PdfStream:
                    throw new InvalidOperationException("A stream can only be written as an indirect object.");
            }
        }
    }

    /// <summary>
    /// A string as the writers write one: literal with <c>\</c>, <c>(</c>, <c>)</c> and the control characters
    /// escaped (§7.3.4.2, Table 3), or hexadecimal in upper case.
    /// </summary>
    private static void WriteString(StringBuilder text, PdfString value)
    {
        var bytes = value.Bytes.Span;
        if (value.Form == PdfStringForm.Hexadecimal)
        {
            text.Append('<').Append(Convert.ToHexString(bytes)).Append('>');
            return;
        }

        text.Append('(');
        foreach (byte b in bytes)
        {
            text.Append(b switch
            {
                (byte)'\\' => "\\\\",
                (byte)'(' => "\\(",
                (byte)')' => "\\)",
                (byte)'\n' => "\\n",
                (byte)'\r' => "\\r",
                (byte)'\t' => "\\t",
                (byte)'\b' => "\\b",
                (byte)'\f' => "\\f",
                _ => ((char)b).ToString(),
            });
        }

        text.Append(')');
    }

    /// <summary>A name's characters, with those a name cannot hold as they are written <c>#xx</c> (§7.3.5).</summary>
    private static string EscapeName(string name)
    {
        var text = new StringBuilder(name.Length);
        foreach (byte b in Encoding.UTF8.GetBytes(name))
        {
            bool regular = b is > 0x20 and < 0x7F && b is not ((byte)'#' or (byte)'/' or (byte)'%' or (byte)'(' or (byte)')'
                or (byte)'<' or (byte)'>' or (byte)'[' or (byte)']' or (byte)'{' or (byte)'}');
            text.Append(regular ? ((char)b).ToString() : string.Create(CultureInfo.InvariantCulture, $"#{b:X2}"));
        }

        return text.ToString();
    }

    /// <summary>
    /// True when the character has the same code in PDFDocEncoding and Latin-1: printable ASCII, tab and line breaks,
    /// and U+00A1–U+00FF but the soft hyphen (the writers' rule, <c>PdfTextString</c>).
    /// </summary>
    private static bool IsLiteralSafe(char c) =>
        c is (>= ' ' and <= '~') or '\t' or '\n' or '\r' or (>= '¡' and <= 'ÿ' and not '­');
}
