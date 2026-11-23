using System.Globalization;
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

    private const int MaxValueDepth = 64;

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

    private static PdfStructureException TooLarge(string name) =>
        new($"The embedded file '{name}' is larger than {MaxFileSize / (1024 * 1024)} MB.");

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
