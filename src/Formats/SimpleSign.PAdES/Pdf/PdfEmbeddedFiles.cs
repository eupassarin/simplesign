using System.Globalization;
using System.IO.Compression;
using System.Text;
using SimpleSign.PAdES.Pdf.Exceptions;
using SimpleSign.PAdES.Pdf.Model;

namespace SimpleSign.PAdES.Pdf;

/// <summary>A file embedded in a PDF document (ISO 32000-1 §7.11.4), as <see cref="PdfEmbeddedFiles.Read"/> returns it.</summary>
/// <param name="Name">The file's name: the file specification's <c>/UF</c> or <c>/F</c>, else its key in the name tree.</param>
/// <param name="Data">The file's bytes, decoded.</param>
public sealed record PdfEmbeddedFile(string Name, ReadOnlyMemory<byte> Data);

/// <summary>
/// Reads the files embedded in a PDF document: the entries of the catalog's <c>/Names /EmbeddedFiles</c> name tree
/// (ISO 32000-1 §7.11.4, §7.9.6), each decoded (<c>/FlateDecode</c> with its predictors, <c>/ASCII85Decode</c>,
/// <c>/ASCIIHexDecode</c>).
/// <para>
/// The document is read as it is now, its last revision, through its cross-reference. To know that a signature
/// covers what is read, check that the signature's byte range covers the whole file
/// (<see cref="PdfByteRange.CoversEntireFile"/>) and that the bytes it leaves out — the signature's own
/// <c>/Contents</c> — hold a hexadecimal string and nothing else: an object written there is read like any other.
/// </para>
/// </summary>
/// <example>
/// <code>
/// foreach (var file in PdfEmbeddedFiles.Read(File.ReadAllBytes("invoice.pdf")))
/// {
///     Console.WriteLine($"{file.Name}: {file.Data.Length} bytes");
/// }
/// </code>
/// </example>
public static class PdfEmbeddedFiles
{
    /// <summary>The largest file read, decoded: a larger one is refused (a decompression bomb).</summary>
    public const int MaxFileSize = 64 * 1024 * 1024;

    /// <summary>The most files read from one document.</summary>
    public const int MaxFiles = 1024;

    private const int MaxTreeDepth = 32;
    private const int MaxValueDepth = 64;
    private const int MaxReferenceHops = 16;

    /// <summary>Reads the embedded files of a PDF document.</summary>
    /// <param name="pdf">The PDF document.</param>
    /// <returns>The files, in the order of the name tree; empty when the document embeds none.</returns>
    /// <exception cref="EncryptedPdfException">The document is encrypted.</exception>
    /// <exception cref="PdfStructureException">
    /// The catalog cannot be read, a file is larger than <see cref="MaxFileSize"/>, the document has more than
    /// <see cref="MaxFiles"/> files, or a file uses a filter that is not supported.
    /// </exception>
    public static IReadOnlyList<PdfEmbeddedFile> Read(ReadOnlyMemory<byte> pdf)
    {
        var document = PdfDocument.Open(pdf);
        if (document.IsEncrypted)
        {
            throw new EncryptedPdfException("This PDF is encrypted: its embedded files cannot be read. Decrypt it first.");
        }

        var view = document.View();
        if (view.Catalog is null)
        {
            throw new PdfStructureException("The PDF's catalog cannot be read.");
        }

        var files = new List<PdfEmbeddedFile>();
        foreach (var (key, value) in view.NameTree("EmbeddedFiles"))
        {
            if (File(view, key, value) is not { } file)
            {
                continue;
            }

            if (files.Count == MaxFiles)
            {
                throw new PdfStructureException($"The PDF embeds more than {MaxFiles} files.");
            }

            files.Add(file);
        }

        return files;
    }

    /// <summary>The file of a name tree entry; null when the entry has no embedded file stream.</summary>
    private static PdfEmbeddedFile? File(PdfRevisionView view, PdfString key, PdfObject value)
    {
        if (view.Resolve(value) is not PdfDictionary specification
            || view.Resolve(specification.Get("EF")) is not PdfDictionary streams
            || view.Resolve(streams.Get("UF") ?? streams.Get("F")) is not PdfStream stream)
        {
            return null;
        }

        string name = (view.Resolve(specification.Get("UF")) as PdfString)?.Text
            ?? (view.Resolve(specification.Get("F")) as PdfString)?.Text
            ?? key.Text;
        try
        {
            byte[] content = PdfStreamDecoding.Decode(stream, MaxFileSize, item => view.Resolve(item));

            // Without a filter the data is not decoded, so not held to the limit by the filters.
            return content.Length > MaxFileSize ? throw TooLarge(name) : new PdfEmbeddedFile(name, content);
        }
        catch (PdfDecodedSizeLimitException)
        {
            throw TooLarge(name);
        }
        catch (PdfUnsupportedFilterException ex)
        {
            throw new PdfStructureException($"The embedded file '{name}' uses the filter /{ex.FilterName}, which is not supported.", ex);
        }
        catch (PdfFilterException ex)
        {
            throw new PdfStructureException($"The embedded file '{name}' cannot be decoded: {ex.Message}", ex);
        }
    }

    /// <summary>
    /// Reads the embedded files as the scanning reader did before the object model (ADR 0032): kept to check
    /// <see cref="Read"/> against it until the old code is removed.
    /// </summary>
    internal static IReadOnlyList<PdfEmbeddedFile> ReadLegacy(ReadOnlyMemory<byte> pdf)
    {
        var data = pdf.Span;
        if (PdfStructureReader.IsEncrypted(data))
        {
            throw new EncryptedPdfException("This PDF is encrypted: its embedded files cannot be read. Decrypt it first.");
        }

        var files = new List<PdfEmbeddedFile>();
        if (Dictionary(data, new Reference(PdfStructureParser.FindRootObjectNumber(data))) is not { } catalog)
        {
            throw new PdfStructureException("The PDF's catalog cannot be read.");
        }

        if (Dictionary(data, catalog.GetValueOrDefault("Names")) is { } names
            && Dictionary(data, names.GetValueOrDefault("EmbeddedFiles")) is { } tree)
        {
            Walk(data, tree, 0, [], files);
        }

        return files;
    }

    /// <summary>Adds the files of a name tree node and of its kids.</summary>
    private static void Walk(ReadOnlySpan<byte> data, Dictionary<string, object?> node, int depth, HashSet<int> visited, List<PdfEmbeddedFile> files)
    {
        if (Resolve(data, node.GetValueOrDefault("Names")) is List<object?> entries)
        {
            for (int i = 0; i + 1 < entries.Count; i += 2)
            {
                if (LegacyFile(data, entries[i], entries[i + 1]) is not { } file)
                {
                    continue;
                }

                if (files.Count == MaxFiles)
                {
                    throw new PdfStructureException($"The PDF embeds more than {MaxFiles} files.");
                }

                files.Add(file);
            }
        }

        if (depth == MaxTreeDepth || Resolve(data, node.GetValueOrDefault("Kids")) is not List<object?> kids)
        {
            return;
        }

        foreach (object? kid in kids)
        {
            // A node reached twice is a loop in the tree: read once.
            if (kid is Reference reference && !visited.Add(reference.Number))
            {
                continue;
            }

            if (Dictionary(data, kid) is { } child)
            {
                Walk(data, child, depth + 1, visited, files);
            }
        }
    }

    /// <summary>The file of a name tree entry; null when the entry has no embedded file stream.</summary>
    private static PdfEmbeddedFile? LegacyFile(ReadOnlySpan<byte> data, object? key, object? value)
    {
        if (Dictionary(data, value) is not { } specification || Dictionary(data, specification.GetValueOrDefault("EF")) is not { } streams)
        {
            return null;
        }

        if ((streams.GetValueOrDefault("UF") ?? streams.GetValueOrDefault("F")) is not Reference stream)
        {
            return null;
        }

        string name = Text(Resolve(data, specification.GetValueOrDefault("UF")))
            ?? Text(Resolve(data, specification.GetValueOrDefault("F")))
            ?? Text(Resolve(data, key))
            ?? "";
        return Stream(data, stream.Number, name) is { } content ? new PdfEmbeddedFile(name, content) : null;
    }

    /// <summary>The decoded content of a stream object; null when the object is not a stream.</summary>
    private static byte[]? Stream(ReadOnlySpan<byte> data, int objectNumber, string name)
    {
        var (start, end) = PdfStructureParser.FindObjectBytes(data, objectNumber);
        if (start < 0)
        {
            return null;
        }

        var parser = new Parser(Encoding.Latin1.GetString(data[start..end]));
        if (!parser.SkipObjectHeader() || parser.Value(0) is not Dictionary<string, object?> dictionary)
        {
            return null;
        }

        // The keyword is looked for after the dictionary: a name inside it may contain "stream" (/application#2Foctet-stream).
        int position = PdfStructureReader.SkipWhitespace(data, start + parser.Position);
        if (!data[position..].StartsWith("stream"u8))
        {
            return null;
        }

        position += "stream"u8.Length;
        if (position < data.Length && data[position] == (byte)'\r')
        {
            position++;
        }

        if (position < data.Length && data[position] == (byte)'\n')
        {
            position++;
        }

        ReadOnlySpan<byte> raw;
        if (Resolve(data, dictionary.GetValueOrDefault("Length")) is double length && length >= 0 && position + (long)length <= data.Length)
        {
            raw = data.Slice(position, (int)length);
        }
        else
        {
            int found = data[position..].IndexOf("endstream"u8);
            if (found < 0)
            {
                return null;
            }

            raw = data.Slice(position, found);
        }

        if (Resolve(data, dictionary.GetValueOrDefault("DecodeParms")) is not null)
        {
            throw new PdfStructureException($"The embedded file '{name}' has decode parameters (/DecodeParms), which are not supported.");
        }

        byte[] content = raw.ToArray();
        foreach (string filter in Filters(Resolve(data, dictionary.GetValueOrDefault("Filter"))))
        {
            content = filter switch
            {
                "FlateDecode" or "Fl" => Inflate(content, name),
                "ASCII85Decode" or "A85" => PdfStructureReader.DecodeAscii85(content),
                _ => throw new PdfStructureException($"The embedded file '{name}' uses the filter /{filter}, which is not supported."),
            };
        }

        return content.Length > MaxFileSize ? throw TooLarge(name) : content;
    }

    private static List<string> Filters(object? filter) => filter switch
    {
        Name single => [single.Value],
        List<object?> several => [.. several.OfType<Name>().Select(n => n.Value)],
        _ => [],
    };

    private static byte[] Inflate(byte[] compressed, string name)
    {
        try
        {
            using var input = new ZLibStream(new MemoryStream(compressed), CompressionMode.Decompress);
            using var output = new MemoryStream();
            byte[] buffer = new byte[81920];
            int read;
            while ((read = input.Read(buffer, 0, buffer.Length)) > 0)
            {
                if (output.Length + read > MaxFileSize)
                {
                    throw TooLarge(name);
                }

                output.Write(buffer, 0, read);
            }

            return output.ToArray();
        }
        catch (InvalidDataException ex)
        {
            throw new PdfStructureException($"The embedded file '{name}' cannot be decompressed: {ex.Message}", ex);
        }
    }

    private static PdfStructureException TooLarge(string name) =>
        new($"The embedded file '{name}' is larger than {MaxFileSize / (1024 * 1024)} MB.");

    /// <summary>A text string (ISO 32000-1 §7.9.2.2): UTF-16BE or UTF-8 with its byte order mark, else PDFDocEncoding (read as Latin-1).</summary>
    private static string? Text(object? value) => value switch
    {
        byte[] bytes when bytes.Length >= 2 && bytes[0] == 0xFE && bytes[1] == 0xFF => Encoding.BigEndianUnicode.GetString(bytes, 2, bytes.Length - 2),
        byte[] bytes when bytes.Length >= 3 && bytes[0] == 0xEF && bytes[1] == 0xBB && bytes[2] == 0xBF => Encoding.UTF8.GetString(bytes, 3, bytes.Length - 3),
        byte[] bytes => Encoding.Latin1.GetString(bytes),
        _ => null,
    };

    private static Dictionary<string, object?>? Dictionary(ReadOnlySpan<byte> data, object? value) => Resolve(data, value) as Dictionary<string, object?>;

    /// <summary>The value itself, or the object an indirect reference points to (followed while it points to another).</summary>
    private static object? Resolve(ReadOnlySpan<byte> data, object? value)
    {
        for (int hop = 0; value is Reference reference && hop < MaxReferenceHops; hop++)
        {
            value = Object(data, reference.Number);
        }

        return value is Reference ? null : value;
    }

    /// <summary>The object with this number: in the file body (its last revision), else in an object stream.</summary>
    private static object? Object(ReadOnlySpan<byte> data, int objectNumber)
    {
        var (start, end) = PdfStructureParser.FindObjectBytes(data, objectNumber);
        if (start >= 0)
        {
            var parser = new Parser(Encoding.Latin1.GetString(data[start..end]));
            return parser.SkipObjectHeader() ? parser.Value(0) : null;
        }

        return PdfStructureParser.ExtractObjectFromObjStm(data, objectNumber) is { } text ? new Parser(text).Value(0) : null;
    }

    private readonly record struct Reference(int Number);

    private sealed record Name(string Value);

    /// <summary>
    /// A reader of PDF objects (ISO 32000-1 §7.3) over the Latin-1 text of an object: dictionaries
    /// (<c>Dictionary&lt;string, object?&gt;</c>), arrays (<c>List&lt;object?&gt;</c>), names, strings (<c>byte[]</c>),
    /// numbers (<c>double</c>), booleans, null and indirect references.
    /// </summary>
    private sealed class Parser(string text)
    {
        public int Position { get; private set; }

        /// <summary>Skips <c>N G obj</c>; false when the text does not start with it.</summary>
        public bool SkipObjectHeader()
        {
            int keyword = text.IndexOf("obj", StringComparison.Ordinal);
            if (keyword < 0)
            {
                return false;
            }

            Position = keyword + 3;
            return true;
        }

        /// <summary>The value at the position, which moves past it; null for the null object and for what cannot be read.</summary>
        public object? Value(int depth)
        {
            SkipWhitespaceAndComments();
            if (Position >= text.Length || depth > MaxValueDepth)
            {
                return null;
            }

            char c = text[Position];
            if (c == '<')
            {
                return Position + 1 < text.Length && text[Position + 1] == '<' ? DictionaryValue(depth) : HexString();
            }

            return c switch
            {
                '[' => Array(depth),
                '(' => LiteralString(),
                '/' => new Name(NameToken()),
                _ => Keyword(),
            };
        }

        private Dictionary<string, object?> DictionaryValue(int depth)
        {
            var dictionary = new Dictionary<string, object?>(StringComparer.Ordinal);
            Position += 2;
            while (true)
            {
                SkipWhitespaceAndComments();
                if (Position >= text.Length)
                {
                    return dictionary;
                }

                if (text[Position] == '>')
                {
                    Position = Math.Min(Position + 2, text.Length);
                    return dictionary;
                }

                if (text[Position] != '/')
                {
                    // Not a key: the dictionary is malformed from here on.
                    return dictionary;
                }

                string key = NameToken();
                dictionary[key] = Value(depth + 1);
            }
        }

        private List<object?> Array(int depth)
        {
            var array = new List<object?>();
            Position++;
            while (true)
            {
                SkipWhitespaceAndComments();
                if (Position >= text.Length)
                {
                    return array;
                }

                if (text[Position] == ']')
                {
                    Position++;
                    return array;
                }

                int before = Position;
                array.Add(Value(depth + 1));
                if (Position == before)
                {
                    // Nothing was read (a stray delimiter): skip it so the loop ends.
                    Position++;
                }
            }
        }

        private string NameToken()
        {
            var name = new StringBuilder();
            Position++;
            while (Position < text.Length && !IsDelimiter(text[Position]) && !IsWhitespace(text[Position]))
            {
                if (text[Position] == '#' && Position + 2 < text.Length
                    && int.TryParse(text.AsSpan(Position + 1, 2), NumberStyles.AllowHexSpecifier, CultureInfo.InvariantCulture, out int code))
                {
                    name.Append((char)code);
                    Position += 3;
                }
                else
                {
                    name.Append(text[Position++]);
                }
            }

            return name.ToString();
        }

        private byte[] LiteralString()
        {
            var bytes = new List<byte>();
            Position++;
            int open = 1;
            while (Position < text.Length)
            {
                char c = text[Position++];
                if (c == '\\' && Position < text.Length)
                {
                    Escape(bytes);
                }
                else if (c == '(')
                {
                    open++;
                    bytes.Add((byte)c);
                }
                else if (c == ')')
                {
                    if (--open == 0)
                    {
                        break;
                    }

                    bytes.Add((byte)c);
                }
                else
                {
                    bytes.Add((byte)c);
                }
            }

            return [.. bytes];
        }

        private void Escape(List<byte> bytes)
        {
            char c = text[Position++];
            if (c == '\r')
            {
                // A backslash at the end of a line continues the string on the next one.
                if (Position < text.Length && text[Position] == '\n')
                {
                    Position++;
                }
            }
            else if (c is >= '0' and <= '7')
            {
                int code = c - '0';
                for (int i = 0; i < 2 && Position < text.Length && text[Position] is >= '0' and <= '7'; i++)
                {
                    code = (code * 8) + (text[Position++] - '0');
                }

                bytes.Add((byte)code);
            }
            else if (c != '\n')
            {
                bytes.Add(c switch
                {
                    'n' => (byte)'\n',
                    'r' => (byte)'\r',
                    't' => (byte)'\t',
                    'b' => (byte)'\b',
                    'f' => (byte)'\f',
                    _ => (byte)c,
                });
            }
        }

        private byte[] HexString()
        {
            var bytes = new List<byte>();
            Position++;
            int high = -1;
            while (Position < text.Length && text[Position] != '>')
            {
                int digit = HexDigit(text[Position++]);
                if (digit < 0)
                {
                    continue;
                }

                if (high < 0)
                {
                    high = digit;
                }
                else
                {
                    bytes.Add((byte)((high << 4) | digit));
                    high = -1;
                }
            }

            if (high >= 0)
            {
                // An odd number of digits: the last one is followed by an implied 0.
                bytes.Add((byte)(high << 4));
            }

            Position = Math.Min(Position + 1, text.Length);
            return [.. bytes];
        }

        /// <summary>A number, an indirect reference (<c>N G R</c>), true, false or null.</summary>
        private object? Keyword()
        {
            string token = Token();
            if (token.Length == 0)
            {
                return null;
            }

            if (token == "true")
            {
                return true;
            }

            if (token == "false")
            {
                return false;
            }

            if (!double.TryParse(token, NumberStyles.AllowLeadingSign | NumberStyles.AllowDecimalPoint, CultureInfo.InvariantCulture, out double number))
            {
                return null;
            }

            // "N G R": two integers and the keyword R make an indirect reference.
            int after = Position;
            if (IsObjectNumber(token) && IsObjectNumber(Token()) && Token() == "R")
            {
                return new Reference((int)number);
            }

            Position = after;
            return number;
        }

        private string Token()
        {
            SkipWhitespaceAndComments();
            int start = Position;
            while (Position < text.Length && !IsDelimiter(text[Position]) && !IsWhitespace(text[Position]))
            {
                Position++;
            }

            return text[start..Position];
        }

        private void SkipWhitespaceAndComments()
        {
            while (Position < text.Length)
            {
                if (IsWhitespace(text[Position]))
                {
                    Position++;
                }
                else if (text[Position] == '%')
                {
                    while (Position < text.Length && text[Position] is not ('\r' or '\n'))
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

        private static bool IsObjectNumber(string token) =>
            token.Length is > 0 and < 10 && token.All(char.IsAsciiDigit);

        private static bool IsWhitespace(char c) => c is ' ' or '\n' or '\r' or '\t' or '\f' or '\0';

        private static bool IsDelimiter(char c) => c is '(' or ')' or '<' or '>' or '[' or ']' or '{' or '}' or '/' or '%';

        private static int HexDigit(char c) => c switch
        {
            >= '0' and <= '9' => c - '0',
            >= 'a' and <= 'f' => c - 'a' + 10,
            >= 'A' and <= 'F' => c - 'A' + 10,
            _ => -1,
        };
    }
}
