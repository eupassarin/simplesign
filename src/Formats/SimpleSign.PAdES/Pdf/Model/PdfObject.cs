using System.Globalization;

namespace SimpleSign.PAdES.Pdf.Model;

/// <summary>The kind of a PDF object (ISO 32000-1 §7.3).</summary>
internal enum PdfObjectKind
{
    /// <summary>The null object.</summary>
    Null,

    /// <summary><c>true</c> or <c>false</c>.</summary>
    Boolean,

    /// <summary>An integer.</summary>
    Integer,

    /// <summary>A real number.</summary>
    Real,

    /// <summary>A literal or hexadecimal string.</summary>
    String,

    /// <summary>A name.</summary>
    Name,

    /// <summary>An array.</summary>
    Array,

    /// <summary>A dictionary.</summary>
    Dictionary,

    /// <summary>A stream: a dictionary and its data.</summary>
    Stream,

    /// <summary>An indirect reference, <c>N G R</c>.</summary>
    Reference,
}

/// <summary>Where a parsed object was read from: its offset in the bytes parsed and its length.</summary>
/// <param name="Offset">The offset of the object's first byte.</param>
/// <param name="Length">The number of bytes the object takes, delimiters included.</param>
internal readonly record struct PdfSourceRange(long Offset, int Length)
{
    /// <summary>The offset just after the object.</summary>
    public long End => Offset + Length;
}

/// <summary>
/// A PDF object (ISO 32000-1 §7.3). Parsed objects are immutable, so views of different revisions of a document can share
/// them. Containers (<see cref="PdfArray"/>, <see cref="PdfDictionary"/>) remember the bytes they were read from, so an
/// edit can keep the original bytes of what it does not change (ADR 0032).
/// </summary>
internal abstract class PdfObject
{
    /// <summary>The kind of the object.</summary>
    public abstract PdfObjectKind Kind { get; }

    /// <summary>
    /// Whether two objects mean the same: numbers by value (<c>1</c> and <c>1.0</c> are equal), strings by their bytes
    /// whatever their form, names by their value, arrays and dictionaries entry by entry (the order of a dictionary's
    /// keys does not matter), streams by their dictionary and their encoded data. References are compared, not resolved.
    /// </summary>
    /// <param name="left">One object; null is the null object.</param>
    /// <param name="right">The other object; null is the null object.</param>
    /// <returns>True when the objects mean the same.</returns>
    public static bool SemanticEquals(PdfObject? left, PdfObject? right)
    {
        // An explicit stack instead of recursion: the objects may come from a hostile file.
        var pending = new Stack<(PdfObject Left, PdfObject Right)>();
        pending.Push((left ?? PdfNull.Instance, right ?? PdfNull.Instance));
        while (pending.Count > 0)
        {
            var (a, b) = pending.Pop();
            if (ReferenceEquals(a, b))
            {
                continue;
            }

            if (a is PdfInteger or PdfReal && b is PdfInteger or PdfReal)
            {
                if (!NumbersEqual(a, b))
                {
                    return false;
                }

                continue;
            }

            if (a.Kind != b.Kind)
            {
                return false;
            }

            switch (a)
            {
                case PdfBoolean boolean when boolean.Value != ((PdfBoolean)b).Value:
                case PdfString text when !text.Bytes.Span.SequenceEqual(((PdfString)b).Bytes.Span):
                case PdfName name when name.Value != ((PdfName)b).Value:
                case PdfReference reference when reference.Id != ((PdfReference)b).Id:
                    return false;
                case PdfArray array:
                    var other = (PdfArray)b;
                    if (array.Count != other.Count)
                    {
                        return false;
                    }

                    for (int i = 0; i < array.Count; i++)
                    {
                        pending.Push((array[i], other[i]));
                    }

                    break;
                case PdfDictionary dictionary:
                    if (!PushDictionary(pending, dictionary, (PdfDictionary)b))
                    {
                        return false;
                    }

                    break;
                case PdfStream stream:
                    var otherStream = (PdfStream)b;
                    if (!stream.Encoded.Span.SequenceEqual(otherStream.Encoded.Span)
                        || !PushDictionary(pending, stream.Dictionary, otherStream.Dictionary))
                    {
                        return false;
                    }

                    break;
                default:
                    break;
            }
        }

        return true;
    }

    private static bool PushDictionary(Stack<(PdfObject Left, PdfObject Right)> pending, PdfDictionary left, PdfDictionary right)
    {
        if (left.Count != right.Count)
        {
            return false;
        }

        foreach (var (key, value) in left)
        {
            if (right.Get(key) is not { } otherValue)
            {
                return false;
            }

            pending.Push((value, otherValue));
        }

        return true;
    }

    private static bool NumbersEqual(PdfObject a, PdfObject b) => (a, b) switch
    {
        (PdfInteger x, PdfInteger y) => x.Value == y.Value,
        _ => ToDouble(a).Equals(ToDouble(b)),
    };

    private static double ToDouble(PdfObject number) => number switch
    {
        PdfInteger integer => integer.Value,
        PdfReal real => real.Value,
        _ => double.NaN,
    };
}

/// <summary>The null object. A missing dictionary entry and an entry whose value is null mean the same (ISO 32000-1 §7.3.9).</summary>
internal sealed class PdfNull : PdfObject
{
    /// <summary>The only null object.</summary>
    public static readonly PdfNull Instance = new();

    private PdfNull()
    {
    }

    /// <inheritdoc/>
    public override PdfObjectKind Kind => PdfObjectKind.Null;

    /// <inheritdoc/>
    public override string ToString() => "null";
}

/// <summary>A boolean object.</summary>
internal sealed class PdfBoolean : PdfObject
{
    /// <summary><c>true</c>.</summary>
    public static readonly PdfBoolean True = new(true);

    /// <summary><c>false</c>.</summary>
    public static readonly PdfBoolean False = new(false);

    private PdfBoolean(bool value)
    {
        Value = value;
    }

    /// <summary>The value.</summary>
    public bool Value { get; }

    /// <inheritdoc/>
    public override PdfObjectKind Kind => PdfObjectKind.Boolean;

    /// <summary>The boolean object of a value.</summary>
    public static PdfBoolean Of(bool value) => value ? True : False;

    /// <inheritdoc/>
    public override string ToString() => Value ? "true" : "false";
}

/// <summary>An integer object.</summary>
internal sealed class PdfInteger : PdfObject
{
    /// <summary>Creates an integer object.</summary>
    /// <param name="value">The value.</param>
    public PdfInteger(long value)
    {
        Value = value;
    }

    /// <summary>The value.</summary>
    public long Value { get; }

    /// <inheritdoc/>
    public override PdfObjectKind Kind => PdfObjectKind.Integer;

    /// <inheritdoc/>
    public override string ToString() => Value.ToString(CultureInfo.InvariantCulture);
}

/// <summary>A real number. The text it was read from is kept, so it can be written back exactly as it was.</summary>
internal sealed class PdfReal : PdfObject
{
    /// <summary>Creates a real number object.</summary>
    /// <param name="value">The value.</param>
    /// <param name="text">The text it was read from; null for a value created in code.</param>
    public PdfReal(double value, string? text = null)
    {
        Value = value;
        Text = text;
    }

    /// <summary>The value.</summary>
    public double Value { get; }

    /// <summary>The text the number was read from; null for a number created in code.</summary>
    public string? Text { get; }

    /// <inheritdoc/>
    public override PdfObjectKind Kind => PdfObjectKind.Real;

    /// <inheritdoc/>
    public override string ToString() => Text ?? Value.ToString("0.##########", CultureInfo.InvariantCulture);
}

/// <summary>How a string was written in the file.</summary>
internal enum PdfStringForm
{
    /// <summary><c>(…)</c>.</summary>
    Literal,

    /// <summary><c>&lt;…&gt;</c>.</summary>
    Hexadecimal,
}

/// <summary>A string object: a sequence of bytes, written as a literal or a hexadecimal string.</summary>
internal sealed class PdfString : PdfObject
{
    /// <summary>Creates a string object.</summary>
    /// <param name="bytes">The string's bytes, escapes resolved.</param>
    /// <param name="form">How the string is written.</param>
    public PdfString(ReadOnlyMemory<byte> bytes, PdfStringForm form = PdfStringForm.Literal)
    {
        Bytes = bytes;
        Form = form;
    }

    /// <summary>The string's bytes, escapes resolved.</summary>
    public ReadOnlyMemory<byte> Bytes { get; }

    /// <summary>How the string was written.</summary>
    public PdfStringForm Form { get; }

    /// <summary>The string read as a text string (ISO 32000-1 §7.9.2.2): UTF-16 or UTF-8 with a byte order mark, else PDFDocEncoding.</summary>
    public string Text => PdfText.Decode(Bytes.Span);

    /// <inheritdoc/>
    public override PdfObjectKind Kind => PdfObjectKind.String;

    /// <inheritdoc/>
    public override string ToString() => Text;
}

/// <summary>A name object. Its value is the name's bytes, <c>#xx</c> escapes resolved, read as Latin-1 so no byte is lost.</summary>
internal sealed class PdfName : PdfObject, IEquatable<PdfName>
{
    /// <summary><c>/Type</c>.</summary>
    public static readonly PdfName Type = new("Type");

    /// <summary><c>/Subtype</c>.</summary>
    public static readonly PdfName Subtype = new("Subtype");

    /// <summary><c>/Length</c>.</summary>
    public static readonly PdfName Length = new("Length");

    /// <summary><c>/Filter</c>.</summary>
    public static readonly PdfName Filter = new("Filter");

    /// <summary><c>/DecodeParms</c>.</summary>
    public static readonly PdfName DecodeParms = new("DecodeParms");

    /// <summary><c>/Root</c>.</summary>
    public static readonly PdfName Root = new("Root");

    /// <summary><c>/Size</c>.</summary>
    public static readonly PdfName Size = new("Size");

    /// <summary><c>/Prev</c>.</summary>
    public static readonly PdfName Prev = new("Prev");

    /// <summary><c>/Info</c>.</summary>
    public static readonly PdfName Info = new("Info");

    /// <summary><c>/ID</c>.</summary>
    public static readonly PdfName ID = new("ID");

    /// <summary><c>/Encrypt</c>.</summary>
    public static readonly PdfName Encrypt = new("Encrypt");

    /// <summary><c>/Pages</c>.</summary>
    public static readonly PdfName Pages = new("Pages");

    /// <summary><c>/Kids</c>.</summary>
    public static readonly PdfName Kids = new("Kids");

    /// <summary><c>/Parent</c>.</summary>
    public static readonly PdfName Parent = new("Parent");

    /// <summary><c>/AcroForm</c>.</summary>
    public static readonly PdfName AcroForm = new("AcroForm");

    /// <summary><c>/Fields</c>.</summary>
    public static readonly PdfName Fields = new("Fields");

    /// <summary><c>/FT</c>.</summary>
    public static readonly PdfName FT = new("FT");

    /// <summary><c>/Sig</c>.</summary>
    public static readonly PdfName Sig = new("Sig");

    /// <summary><c>/T</c>.</summary>
    public static readonly PdfName T = new("T");

    /// <summary><c>/V</c>.</summary>
    public static readonly PdfName V = new("V");

    /// <summary><c>/ByteRange</c>.</summary>
    public static readonly PdfName ByteRange = new("ByteRange");

    /// <summary><c>/Contents</c>.</summary>
    public static readonly PdfName Contents = new("Contents");

    /// <summary><c>/Names</c>.</summary>
    public static readonly PdfName Names = new("Names");

    private static readonly Dictionary<string, PdfName> s_common = new[]
    {
        Type, Subtype, Length, Filter, DecodeParms, Root, Size, Prev, Info, ID, Encrypt, Pages, Kids, Parent,
        AcroForm, Fields, FT, Sig, T, V, ByteRange, Contents, Names,
    }.ToDictionary(name => name.Value, StringComparer.Ordinal);

    private PdfName(string value)
    {
        Value = value;
    }

    /// <summary>The name without its slash, escapes resolved.</summary>
    public string Value { get; }

    /// <inheritdoc/>
    public override PdfObjectKind Kind => PdfObjectKind.Name;

    /// <summary>The name object with this value; a common name is shared, not created again.</summary>
    /// <param name="value">The name without its slash.</param>
    public static PdfName Of(string value) => s_common.TryGetValue(value, out var common) ? common : new PdfName(value);

    /// <inheritdoc/>
    public bool Equals(PdfName? other) => other is not null && (ReferenceEquals(this, other) || string.Equals(Value, other.Value, StringComparison.Ordinal));

    /// <inheritdoc/>
    public override bool Equals(object? obj) => Equals(obj as PdfName);

    /// <inheritdoc/>
    public override int GetHashCode() => StringComparer.Ordinal.GetHashCode(Value);

    /// <inheritdoc/>
    public override string ToString() => "/" + Value;
}

/// <summary>An array object.</summary>
internal sealed class PdfArray : PdfObject, IReadOnlyList<PdfObject>
{
    private readonly PdfObject[] _items;

    /// <summary>Creates an array object.</summary>
    /// <param name="items">The elements, in order.</param>
    /// <param name="source">Where the array was read from; null for an array created in code.</param>
    public PdfArray(IEnumerable<PdfObject> items, PdfSourceRange? source = null)
    {
        _items = [.. items];
        Source = source;
    }

    /// <summary>Where the array was read from, brackets included; null for an array created in code.</summary>
    public PdfSourceRange? Source { get; }

    /// <inheritdoc/>
    public override PdfObjectKind Kind => PdfObjectKind.Array;

    /// <inheritdoc/>
    public int Count => _items.Length;

    /// <inheritdoc/>
    public PdfObject this[int index] => _items[index];

    /// <inheritdoc/>
    public IEnumerator<PdfObject> GetEnumerator() => ((IEnumerable<PdfObject>)_items).GetEnumerator();

    System.Collections.IEnumerator System.Collections.IEnumerable.GetEnumerator() => GetEnumerator();
}

/// <summary>One entry of a dictionary, as it was read.</summary>
/// <param name="Key">The key.</param>
/// <param name="Value">The value.</param>
/// <param name="Source">Where the entry was read from, from the key's slash to the end of the value; null for an entry created in code.</param>
internal sealed record PdfDictionaryEntry(PdfName Key, PdfObject Value, PdfSourceRange? Source = null);

/// <summary>
/// A dictionary object. The entries keep the order they were read in. When a key appears twice the last value is the
/// one read (as both earlier readers did); <see cref="RawEntries"/> keeps every entry as it was in the file.
/// </summary>
internal sealed class PdfDictionary : PdfObject, IReadOnlyCollection<KeyValuePair<PdfName, PdfObject>>
{
    private readonly PdfDictionaryEntry[] _entries;
    private readonly Dictionary<PdfName, int> _index;

    /// <summary>Creates a dictionary object.</summary>
    /// <param name="entries">The entries, in order; a later entry with the same key replaces an earlier one.</param>
    /// <param name="source">Where the dictionary was read from, <c>&lt;&lt;</c> to <c>&gt;&gt;</c>; null for one created in code.</param>
    public PdfDictionary(IEnumerable<PdfDictionaryEntry> entries, PdfSourceRange? source = null)
    {
        _entries = [.. entries];
        Source = source;
        _index = new Dictionary<PdfName, int>(_entries.Length);
        for (int i = 0; i < _entries.Length; i++)
        {
            _index[_entries[i].Key] = i;
        }
    }

    /// <summary>Creates a dictionary object from keys and values.</summary>
    /// <param name="entries">The keys and values, in order.</param>
    public PdfDictionary(params (string Key, PdfObject Value)[] entries)
        : this(entries.Select(entry => new PdfDictionaryEntry(PdfName.Of(entry.Key), entry.Value)))
    {
    }

    /// <summary>An empty dictionary.</summary>
    public static PdfDictionary Empty { get; } = new([]);

    /// <summary>Where the dictionary was read from; null for one created in code.</summary>
    public PdfSourceRange? Source { get; }

    /// <summary>Every entry as it was read, duplicate keys included.</summary>
    public IReadOnlyList<PdfDictionaryEntry> RawEntries => _entries;

    /// <summary>Whether a key appears more than once.</summary>
    public bool HasDuplicateKeys => _index.Count != _entries.Length;

    /// <inheritdoc/>
    public override PdfObjectKind Kind => PdfObjectKind.Dictionary;

    /// <summary>The number of distinct keys.</summary>
    public int Count => _index.Count;

    /// <summary>The distinct keys, in the order they were first read.</summary>
    public IEnumerable<PdfName> Keys => this.Select(entry => entry.Key);

    /// <summary>The value of a key; null when the key is absent.</summary>
    /// <param name="key">The key.</param>
    public PdfObject? Get(PdfName key) => _index.TryGetValue(key, out int i) ? _entries[i].Value : null;

    /// <summary>The value of a key; null when the key is absent.</summary>
    /// <param name="key">The key, without its slash.</param>
    public PdfObject? Get(string key) => Get(PdfName.Of(key));

    /// <summary>The entry of a key, as it was read (the last one when the key appears twice); null when it is absent.</summary>
    /// <param name="key">The key.</param>
    public PdfDictionaryEntry? Entry(PdfName key) => _index.TryGetValue(key, out int i) ? _entries[i] : null;

    /// <summary>Whether the dictionary has a key.</summary>
    /// <param name="key">The key.</param>
    public bool ContainsKey(PdfName key) => _index.ContainsKey(key);

    /// <summary>The distinct entries, in the order their keys were first read, each with its last value.</summary>
    public IEnumerator<KeyValuePair<PdfName, PdfObject>> GetEnumerator()
    {
        var seen = new HashSet<PdfName>();
        foreach (var entry in _entries)
        {
            if (seen.Add(entry.Key))
            {
                yield return new KeyValuePair<PdfName, PdfObject>(entry.Key, _entries[_index[entry.Key]].Value);
            }
        }
    }

    System.Collections.IEnumerator System.Collections.IEnumerable.GetEnumerator() => GetEnumerator();
}

/// <summary>
/// A stream object: its dictionary and its data as written in the file (still encoded by its filters). The data is a
/// slice of the bytes the document was read from, not a copy.
/// </summary>
internal sealed class PdfStream : PdfObject
{
    /// <summary>Creates a stream object.</summary>
    /// <param name="dictionary">The stream's dictionary.</param>
    /// <param name="encoded">The data as written, still encoded.</param>
    /// <param name="dataOffset">The offset of the data's first byte in the bytes parsed; -1 for a stream created in code.</param>
    public PdfStream(PdfDictionary dictionary, ReadOnlyMemory<byte> encoded, long dataOffset = -1)
    {
        Dictionary = dictionary;
        Encoded = encoded;
        DataOffset = dataOffset;
    }

    /// <summary>The stream's dictionary.</summary>
    public PdfDictionary Dictionary { get; }

    /// <summary>The data as written in the file, still encoded by the stream's filters.</summary>
    public ReadOnlyMemory<byte> Encoded { get; }

    /// <summary>The offset of the data's first byte in the bytes parsed; -1 for a stream created in code.</summary>
    public long DataOffset { get; }

    /// <inheritdoc/>
    public override PdfObjectKind Kind => PdfObjectKind.Stream;
}

/// <summary>The number and generation of an indirect object.</summary>
/// <param name="Number">The object number, from 1.</param>
/// <param name="Generation">The generation number.</param>
internal readonly record struct PdfObjectId(int Number, int Generation)
{
    /// <inheritdoc/>
    public override string ToString() => $"{Number} {Generation}";
}

/// <summary>An indirect reference, <c>N G R</c>.</summary>
internal sealed class PdfReference : PdfObject
{
    /// <summary>Creates an indirect reference.</summary>
    /// <param name="id">The object referred to.</param>
    public PdfReference(PdfObjectId id)
    {
        Id = id;
    }

    /// <summary>Creates an indirect reference.</summary>
    /// <param name="number">The object number.</param>
    /// <param name="generation">The generation number.</param>
    public PdfReference(int number, int generation = 0)
        : this(new PdfObjectId(number, generation))
    {
    }

    /// <summary>The object referred to.</summary>
    public PdfObjectId Id { get; }

    /// <inheritdoc/>
    public override PdfObjectKind Kind => PdfObjectKind.Reference;

    /// <inheritdoc/>
    public override string ToString() => $"{Id} R";
}

/// <summary>An indirect object as read from the file: <c>N G obj … endobj</c>.</summary>
/// <param name="Id">The object's number and generation.</param>
/// <param name="Value">The object's value.</param>
/// <param name="Source">Where the object was read from, from its number to the end of <c>endobj</c> (or of what stood for it).</param>
internal sealed record PdfIndirectObject(PdfObjectId Id, PdfObject Value, PdfSourceRange Source);
