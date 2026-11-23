using System.Text;
using SimpleSign.PAdES.Pdf.Model;

namespace SimpleSign.PAdES.Pdf.Writing;

/// <summary>
/// Changes some entries of an existing dictionary object and keeps every other byte of it as it was: line ends (CRLF
/// included), spacing, comments and the order of the entries (ADR 0032). The edits are those the writers make:
/// <list type="bullet">
/// <item>remove an entry (its key, value and the spaces or tabs after it);</item>
/// <item>set an entry: its key and value replaced by <c>/Key value</c>, or, when absent, <c>   /Key value</c> and a
/// line feed inserted before the dictionary's <c>&gt;&gt;</c>;</item>
/// <item>append an item to an array entry, at the top level or in an inline dictionary.</item>
/// </list>
/// </summary>
internal sealed class PdfDictionaryPatch
{
    private readonly byte[] _object;
    private readonly List<(int Start, int End, string Text)> _edits = [];
    private readonly HashSet<string> _removed = new(StringComparer.Ordinal);

    /// <summary>Reads the object to change.</summary>
    /// <param name="objectBytes">The object's bytes, from <c>N G obj</c> to <c>endobj</c> (and what follows, kept as it is).</param>
    /// <exception cref="ArgumentException">The bytes are not a dictionary or stream object.</exception>
    public PdfDictionaryPatch(ReadOnlyMemory<byte> objectBytes)
    {
        _object = objectBytes.ToArray();
        var parsed = PdfParser.ParseIndirectObject(_object, 0, new PdfParseContext());
        Dictionary = parsed?.Value switch
        {
            PdfDictionary dictionary => dictionary,
            PdfStream stream => stream.Dictionary,
            _ => throw new ArgumentException("The bytes are not a dictionary object.", nameof(objectBytes)),
        };
        Id = parsed!.Id;
    }

    /// <summary>The object changed.</summary>
    public PdfObjectId Id { get; }

    /// <summary>The dictionary as it was read.</summary>
    public PdfDictionary Dictionary { get; }

    /// <summary>The patch of an object of a document, as the file holds it; null when it is inside an object stream.</summary>
    /// <param name="document">The document.</param>
    /// <param name="number">The object number.</param>
    public static PdfDictionaryPatch? Of(PdfDocument document, int number)
    {
        ArgumentNullException.ThrowIfNull(document);
        if (document.Lookup(number) is not { Type: PdfXrefEntryType.InUse } || document.GetObject(number) is not { } obj)
        {
            return null;
        }

        return new PdfDictionaryPatch(document.Data.Slice((int)obj.Source.Offset, obj.Source.Length));
    }

    /// <summary>Removes a top-level entry; nothing when there is none.</summary>
    /// <param name="key">The key, without the slash.</param>
    public PdfDictionaryPatch Remove(string key)
    {
        if (_removed.Add(key) && Dictionary.Entry(PdfName.Of(key))?.Source is { } source)
        {
            int end = (int)source.End;
            while (end < _object.Length && _object[end] is (byte)' ' or (byte)'\t')
            {
                end++;
            }

            _edits.Add(((int)source.Offset, end, ""));
        }

        return this;
    }

    /// <summary>Sets a top-level entry to a value written as given.</summary>
    /// <param name="key">The key, without the slash.</param>
    /// <param name="value">The value as it is to be written (<see cref="PdfObjectSerializer.ToText"/>).</param>
    /// <param name="indent">What precedes an entry inserted before the <c>&gt;&gt;</c>.</param>
    public PdfDictionaryPatch Set(string key, string value, string indent = "   ")
    {
        string entry = $"/{key} {value}";

        // A key removed first is written anew before the close, as removing then inserting it always did.
        if (!_removed.Contains(key) && Dictionary.Entry(PdfName.Of(key))?.Source is { } source)
        {
            _edits.Add(((int)source.Offset, (int)source.End, entry));
        }
        else
        {
            int close = DictionaryClose(Dictionary);
            _edits.Add((close, close, $"{indent}{entry}\n"));
        }

        return this;
    }

    /// <summary>Sets a top-level entry to a value.</summary>
    /// <param name="key">The key, without the slash.</param>
    /// <param name="value">The value.</param>
    public PdfDictionaryPatch Set(string key, PdfObject value) => Set(key, PdfObjectSerializer.ToText(value));

    /// <summary>
    /// Appends an item to an array entry written inline: in the top-level dictionary (<c>["Annots"]</c>) or in an
    /// inline dictionary of it (<c>["AcroForm", "Fields"]</c>). When the inline dictionary has no such entry, one is
    /// inserted before its <c>&gt;&gt;</c> as <c> /Key [item] </c>.
    /// </summary>
    /// <param name="path">The keys from the top-level dictionary to the array's key.</param>
    /// <param name="item">The item as it is to be written (<c>12 0 R</c>).</param>
    /// <param name="spaceWhenEmpty">Whether an empty array gets <c>[ item]</c> (as the page writer has always written it) rather than <c>[item]</c>.</param>
    /// <returns>False when the array is not written inline (a reference to an array object), or a dictionary on the path is not inline.</returns>
    public bool AppendToArray(IReadOnlyList<string> path, string item, bool spaceWhenEmpty = false)
    {
        ArgumentNullException.ThrowIfNull(path);
        ArgumentOutOfRangeException.ThrowIfZero(path.Count);
        var dictionary = Dictionary;
        for (int i = 0; i < path.Count - 1; i++)
        {
            if (dictionary.Get(path[i]) is not PdfDictionary { Source: not null } inner)
            {
                return false;
            }

            dictionary = inner;
        }

        switch (dictionary.Get(path[^1]))
        {
            case PdfArray { Source: { } source } array:
                int closing = (int)source.End - 1;
                _edits.Add((closing, closing, array.Count == 0 && !spaceWhenEmpty ? item : $" {item}"));
                return true;
            case null when path.Count > 1:
                int close = DictionaryClose(dictionary);
                _edits.Add((close, close, $" /{path[^1]} [{item}] "));
                return true;
            default:
                return false;
        }
    }

    /// <summary>The object with the edits applied, as bytes.</summary>
    public byte[] ToBytes()
    {
        var result = new StringBuilder(Encoding.Latin1.GetString(_object));
        // From the end back, so each edit's offsets still hold; edits at one place keep the order they were made in.
        foreach (var (start, end, text) in _edits.Select((e, i) => (e, i)).OrderByDescending(x => x.e.Start).ThenByDescending(x => x.e.End).ThenByDescending(x => x.i).Select(x => x.e))
        {
            result.Remove(start, end - start).Insert(start, text);
        }

        return Encoding.Latin1.GetBytes(result.ToString());
    }

    /// <summary>The offset of a dictionary's closing <c>&gt;&gt;</c>.</summary>
    private static int DictionaryClose(PdfDictionary dictionary) =>
        dictionary.Source is { } source
            ? (int)source.End - 2
            : throw new InvalidOperationException("The dictionary was not read from the object's bytes.");
}
