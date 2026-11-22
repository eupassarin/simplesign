using System.Collections.Concurrent;
using SimpleSign.PAdES.Pdf.Exceptions;

namespace SimpleSign.PAdES.Pdf.Model;

/// <summary>
/// A PDF read through its cross-reference (ADR 0032): its revisions, and its objects as each revision sees them.
/// Objects are parsed when first asked for and kept; streams stay slices of the input until decoded. One document may
/// be read from several threads.
/// </summary>
/// <remarks>
/// <para>
/// An object is found through the cross-reference of the revision asked for (the latest by default), never by searching
/// the file's text. When an entry's offset misses its object, or the chain could not be read in full, the object is
/// found by its <c>N G obj</c> header; when no cross-reference can be read at all, it is rebuilt from the headers. Each
/// such repair is in <see cref="Diagnostics"/>.
/// </para>
/// <para>
/// A reference to an object a revision does not have, or has as free, or with another generation, is a reference to
/// null (ISO 32000-1 §7.3.10).
/// </para>
/// </remarks>
internal sealed class PdfDocument
{
    private static readonly PdfName s_n = PdfName.Of("N");
    private static readonly PdfName s_first = PdfName.Of("First");
    private static readonly PdfName s_linearized = PdfName.Of("Linearized");

    /// <summary>
    /// What this thread is parsing: an object whose <c>/Length</c>, or an object stream whose <c>/N</c>, leads back to
    /// itself is read as missing instead of recursing.
    /// </summary>
    [ThreadStatic]
    private static HashSet<(PdfDocument Document, long Key)>? t_inProgress;

    private readonly PdfParseContext _context;
    private readonly bool _chainComplete;
    private readonly ConcurrentDictionary<long, Lazy<PdfIndirectObject?>> _objectsByOffset = new();
    private readonly ConcurrentDictionary<long, Lazy<ObjectStreamContents>> _objectStreams = new();
    private readonly ConcurrentDictionary<int, PdfRevisionView> _views = new();
    private readonly Lazy<Dictionary<int, List<(long Offset, PdfObjectId Id)>>> _headers;
    private readonly Lazy<bool> _linearized;
    private long _objectStreamBytes;

    private PdfDocument(ReadOnlyMemory<byte> data, PdfParseContext context)
    {
        Data = data;
        _context = context;
        _headers = new Lazy<Dictionary<int, List<(long, PdfObjectId)>>>(IndexHeaders);
        _linearized = new Lazy<bool>(ReadLinearized);
        Version = ReadVersion(data.Span);

        var chain = PdfXrefReader.ReadChain(data, context);
        StartXref = chain.StartXref;
        _chainComplete = chain.Complete;
        if (chain.Sections.Count == 0 || !chain.Sections.Any(s => s.Trailer.Get(PdfName.Root) is PdfReference))
        {
            var rebuilt = PdfXrefReader.Reconstruct(data, context, ObjectStreamNumbers);
            IsReconstructed = true;
            Revisions = [new PdfRevision(0, [rebuilt], null, data.Length)];
        }
        else
        {
            Revisions = BuildRevisions(chain.Sections);
        }
    }

    /// <summary>The bytes of the file.</summary>
    public ReadOnlyMemory<byte> Data { get; }

    /// <summary>The limits the document is read with.</summary>
    public PdfReadLimits Limits => _context.Limits;

    /// <summary>What was repaired while reading it.</summary>
    public PdfDiagnostics Diagnostics => _context.Diagnostics;

    /// <summary>The version of the header, <c>%PDF-1.7</c> → <c>1.7</c>; null when there is no header.</summary>
    public string? Version { get; }

    /// <summary>The offset after the last <c>startxref</c>; −1 when there is none.</summary>
    public long StartXref { get; }

    /// <summary>The revisions, oldest first.</summary>
    public IReadOnlyList<PdfRevision> Revisions { get; }

    /// <summary>The latest revision.</summary>
    public PdfRevision Latest => Revisions[^1];

    /// <summary>The latest revision's trailer.</summary>
    public PdfDictionary Trailer => Latest.Trailer;

    /// <summary>Whether the cross-reference was rebuilt from the object headers.</summary>
    public bool IsReconstructed { get; }

    /// <summary>Whether the trailer has <c>/Encrypt</c>.</summary>
    public bool IsEncrypted => Trailer.ContainsKey(PdfName.Encrypt);

    /// <summary>Whether the first object of the file is a linearization dictionary (ISO 32000-1 Annex F).</summary>
    public bool IsLinearized => _linearized.Value;

    /// <summary>The catalog's reference, from the latest trailer that has one.</summary>
    public PdfObjectId? RootId => RootOf(Latest);

    /// <summary>The catalog of the latest revision; null when it cannot be found.</summary>
    public PdfDictionary? Catalog => CatalogOf(Latest);

    /// <summary>
    /// The number the next new object gets: the larger of the trailer's <c>/Size</c> and one more than the largest
    /// object number any section lists.
    /// </summary>
    public int NextObjectNumber
    {
        get
        {
            long size = Trailer.Get(PdfName.Size) is PdfInteger { Value: > 0 } s ? s.Value : 0;
            int highest = Revisions.SelectMany(r => r.Sections).SelectMany(s => s.Entries.Keys).DefaultIfEmpty(0).Max();
            return (int)Math.Min(Math.Max(size, highest + 1L), Limits.MaxObjectNumber + 1L);
        }
    }

    /// <summary>Reads a document.</summary>
    /// <param name="data">The file. It must not change while the document is used: objects are slices of it.</param>
    /// <param name="limits">The limits; <see cref="PdfReadLimits.Default"/> when null.</param>
    /// <exception cref="PdfStructureException">The file is larger than <see cref="PdfReadLimits.MaxFileSize"/>.</exception>
    public static PdfDocument Open(ReadOnlyMemory<byte> data, PdfReadLimits? limits = null)
    {
        limits ??= PdfReadLimits.Default;
        if (data.Length > limits.MaxFileSize)
        {
            throw new PdfStructureException($"PDF is larger than the limit of {limits.MaxFileSize} bytes.");
        }

        return new PdfDocument(data, new PdfParseContext(limits));
    }

    /// <summary>What a revision holds: pages, fields, name trees, DSS, signatures (one view per revision, kept).</summary>
    /// <param name="revision">The revision; the latest when null.</param>
    public PdfRevisionView View(PdfRevision? revision = null)
    {
        var at = revision ?? Latest;
        return _views.GetOrAdd(at.Index, _ => new PdfRevisionView(this, at));
    }

    /// <summary>The catalog's reference as a revision sees it: its trailer's, or the nearest older one's.</summary>
    /// <param name="revision">The revision.</param>
    public static PdfObjectId? RootOf(PdfRevision revision)
    {
        ArgumentNullException.ThrowIfNull(revision);
        for (var r = revision; r is not null; r = r.Previous)
        {
            if (r.Trailer.Get(PdfName.Root) is PdfReference root)
            {
                return root.Id;
            }
        }

        return null;
    }

    /// <summary>The catalog of a revision; null when it cannot be found.</summary>
    /// <param name="revision">The revision.</param>
    public PdfDictionary? CatalogOf(PdfRevision revision) =>
        RootOf(revision) is { } root ? GetObject(root, revision)?.Value as PdfDictionary : null;

    /// <summary>
    /// The cross-reference entry of an object as a revision sees it: its own sections, then each older revision's.
    /// Null when no revision up to it lists the object.
    /// </summary>
    /// <param name="number">The object number.</param>
    /// <param name="revision">The revision; the latest when null.</param>
    public PdfXrefEntry? Lookup(int number, PdfRevision? revision = null)
    {
        for (var r = revision ?? Latest; r is not null; r = r.Previous)
        {
            if (r.OwnEntry(number) is { } entry)
            {
                return entry;
            }
        }

        return null;
    }

    /// <summary>The numbers of the objects a revision has (in use or compressed), in ascending order.</summary>
    /// <param name="revision">The revision; the latest when null.</param>
    public IReadOnlyList<int> ObjectNumbers(PdfRevision? revision = null)
    {
        var seen = new SortedDictionary<int, bool>();
        for (var r = revision ?? Latest; r is not null; r = r.Previous)
        {
            foreach (var section in r.Sections)
            {
                foreach (var (number, entry) in section.Entries)
                {
                    seen.TryAdd(number, entry.Type != PdfXrefEntryType.Free);
                }
            }
        }

        return [.. seen.Where(e => e.Value).Select(e => e.Key)];
    }

    /// <summary>An object by number, whatever its generation, as a revision sees it.</summary>
    /// <param name="number">The object number.</param>
    /// <param name="revision">The revision; the latest when null.</param>
    /// <returns>The object; null when the revision does not have it, or it cannot be read.</returns>
    public PdfIndirectObject? GetObject(int number, PdfRevision? revision = null) =>
        GetObjectCore(number, null, revision ?? Latest, 0);

    /// <summary>An object by number and generation, as a revision sees it.</summary>
    /// <param name="id">The object number and generation.</param>
    /// <param name="revision">The revision; the latest when null.</param>
    /// <returns>The object; null when the revision does not have it with that generation, or it cannot be read.</returns>
    public PdfIndirectObject? GetObject(PdfObjectId id, PdfRevision? revision = null) =>
        GetObjectCore(id.Number, id.Generation, revision ?? Latest, 0);

    /// <summary>
    /// A value with its references followed, as a revision sees them, up to <see cref="PdfReadLimits.MaxReferenceHops"/>.
    /// </summary>
    /// <param name="value">The value; a reference or a direct object.</param>
    /// <param name="revision">The revision; the latest when null.</param>
    /// <returns>The direct value; null for null, a missing object or too many hops.</returns>
    public PdfObject? Resolve(PdfObject? value, PdfRevision? revision = null) => Resolve(value, revision ?? Latest, 0);

    /// <summary>Decodes a stream through its filters, following indirect filter values as a revision sees them.</summary>
    /// <param name="stream">The stream.</param>
    /// <param name="revision">The revision; the latest when null.</param>
    /// <exception cref="PdfUnsupportedFilterException">A filter is not supported.</exception>
    /// <exception cref="PdfFilterException">The data is corrupt, or decodes to more than <see cref="PdfReadLimits.MaxDecodedStreamBytes"/>.</exception>
    public byte[] DecodeStream(PdfStream stream, PdfRevision? revision = null)
    {
        var at = revision ?? Latest;
        return PdfStreamDecoding.Decode(stream, Limits.MaxDecodedStreamBytes, value => Resolve(value, at, 0));
    }

    private PdfObject? Resolve(PdfObject? value, PdfRevision revision, int depth)
    {
        int hops = 0;
        while (value is PdfReference reference)
        {
            if (++hops > Limits.MaxReferenceHops || depth > Limits.MaxReferenceHops)
            {
                _context.Repair(PdfRepairKind.ReferenceHopsExceeded, 0);
                return null;
            }

            value = GetObjectCore(reference.Id.Number, reference.Id.Generation, revision, depth + 1)?.Value;
        }

        return value is PdfNull ? null : value;
    }

    private PdfIndirectObject? GetObjectCore(int number, int? generation, PdfRevision revision, int depth)
    {
        if (depth > Limits.MaxReferenceHops)
        {
            _context.Repair(PdfRepairKind.ReferenceHopsExceeded, 0);
            return null;
        }

        var entry = Lookup(number, revision);
        if (entry is null && (!_chainComplete || IsReconstructed))
        {
            // Sections of the chain were lost: an object they listed is looked for by its header.
            return FromHeader(number, generation, revision, depth);
        }

        switch (entry)
        {
            case { Type: PdfXrefEntryType.InUse } inUse when generation is null || generation == inUse.Generation:
                var found = AtOffset(inUse.Offset, revision, depth);
                if (found is not null && found.Id.Number == number)
                {
                    return found;
                }

                _context.Repair(PdfRepairKind.ObjectOffsetWrong, (int)Math.Min(inUse.Offset, int.MaxValue));
                return FromHeader(number, generation ?? inUse.Generation, revision, depth);
            case { Type: PdfXrefEntryType.Compressed } compressed when generation is null or 0:
                return FromObjectStream(number, compressed, revision, depth);
            default:
                return null;
        }
    }

    private PdfIndirectObject? AtOffset(long offset, PdfRevision revision, int depth)
    {
        if (offset < 0 || offset >= Data.Length)
        {
            return null;
        }

        var lazy = _objectsByOffset.GetOrAdd(offset, at => new Lazy<PdfIndirectObject?>(() =>
            PdfParser.ParseIndirectObject(Data, (int)at, _context, id => LengthValue(id, revision, depth))));
        return Guarded(offset, lazy);
    }

    /// <summary>The value of a cached parse, or null when this thread is already inside it (a cycle).</summary>
    private T? Guarded<T>(long key, Lazy<T> lazy)
        where T : class?
    {
        if (lazy.IsValueCreated)
        {
            return lazy.Value;
        }

        t_inProgress ??= [];
        if (!t_inProgress.Add((this, key)))
        {
            return null;
        }

        try
        {
            return lazy.Value;
        }
        finally
        {
            t_inProgress.Remove((this, key));
        }
    }

    /// <summary>An indirect <c>/Length</c>: the integer the object holds.</summary>
    private long? LengthValue(PdfObjectId id, PdfRevision revision, int depth) =>
        GetObjectCore(id.Number, id.Generation, revision, depth + 1)?.Value is PdfInteger integer ? integer.Value : null;

    /// <summary>The object found by its last <c>N G obj</c> header before the end of the revision.</summary>
    private PdfIndirectObject? FromHeader(int number, int? generation, PdfRevision revision, int depth)
    {
        if (!_headers.Value.TryGetValue(number, out var headers))
        {
            return null;
        }

        for (int i = headers.Count - 1; i >= 0; i--)
        {
            var (offset, id) = headers[i];
            if (offset < revision.EndOffset && (generation is null || generation == id.Generation))
            {
                var found = AtOffset(offset, revision, depth);
                return found is not null && found.Id.Number == number ? found : null;
            }
        }

        return null;
    }

    private PdfIndirectObject? FromObjectStream(int number, PdfXrefEntry entry, PdfRevision revision, int depth)
    {
        if (entry.StreamNumber == number
            || GetObjectCore(entry.StreamNumber, null, revision, depth + 1)?.Value is not PdfStream stream)
        {
            _context.Repair(PdfRepairKind.ObjectStreamUnreadable, 0);
            return null;
        }

        var lazy = _objectStreams.GetOrAdd(
            stream.DataOffset, _ => new Lazy<ObjectStreamContents>(() => ReadObjectStream(stream, revision, depth)));

        // Object streams are keyed apart from objects: −1 − the data offset.
        var contents = Guarded(-1 - stream.DataOffset, lazy) ?? ObjectStreamContents.Empty;

        // The index says where the object is; when it names another object, the object is looked for by number.
        int index = entry.StreamIndex;
        if (index < 0 || index >= contents.Objects.Count || contents.Objects[index].Id.Number != number)
        {
            index = contents.Objects.FindIndex(o => o.Id.Number == number);
            if (index < 0)
            {
                _context.Repair(PdfRepairKind.ObjectStreamUnreadable, (int)Math.Min(stream.DataOffset, int.MaxValue));
                return null;
            }
        }

        return contents.Objects[index];
    }

    /// <summary>
    /// Decodes an object stream (§7.5.7) and parses its objects, within the document's budget. Its objects' source
    /// ranges are offsets in the decoded data.
    /// </summary>
    private ObjectStreamContents ReadObjectStream(PdfStream stream, PdfRevision revision, int depth)
    {
        int at = (int)Math.Min(Math.Max(stream.DataOffset, 0), int.MaxValue);
        if (Resolve(stream.Dictionary.Get(s_n), revision, depth + 1) is not PdfInteger { Value: >= 0 } n
            || Resolve(stream.Dictionary.Get(s_first), revision, depth + 1) is not PdfInteger { Value: >= 0 } first
            || n.Value > Limits.MaxObjectStreamObjects)
        {
            _context.Repair(PdfRepairKind.ObjectStreamUnreadable, at);
            return ObjectStreamContents.Empty;
        }

        long remaining = Limits.MaxTotalObjectStreamBytes - Interlocked.Read(ref _objectStreamBytes);
        if (remaining <= 0)
        {
            _context.Repair(PdfRepairKind.ObjectStreamBudgetExceeded, at);
            return ObjectStreamContents.Empty;
        }

        byte[] decoded;
        try
        {
            decoded = PdfStreamDecoding.Decode(
                stream, (int)Math.Min(Limits.MaxDecodedStreamBytes, remaining), value => Resolve(value, revision, depth + 1));
        }
        catch (PdfDecodedSizeLimitException)
        {
            _context.Repair(remaining < Limits.MaxDecodedStreamBytes ? PdfRepairKind.ObjectStreamBudgetExceeded : PdfRepairKind.ObjectStreamUnreadable, at);
            return ObjectStreamContents.Empty;
        }
        catch (Exception ex) when (ex is PdfFilterException or PdfUnsupportedFilterException)
        {
            _context.Repair(PdfRepairKind.ObjectStreamUnreadable, at);
            return ObjectStreamContents.Empty;
        }

        Interlocked.Add(ref _objectStreamBytes, decoded.Length);
        if (first.Value > decoded.Length)
        {
            _context.Repair(PdfRepairKind.ObjectStreamUnreadable, at);
            return ObjectStreamContents.Empty;
        }

        // The header: n pairs of object number and offset (relative to /First).
        var pairs = new List<(int Number, long Offset)>((int)n.Value);
        var lexer = new PdfLexer(decoded.AsSpan(0, (int)first.Value));
        for (long i = 0; i < n.Value; i++)
        {
            var numberToken = lexer.Next();
            var offsetToken = lexer.Next();
            if (!lexer.Integer(numberToken, out long objectNumber) || !lexer.Integer(offsetToken, out long offset)
                || objectNumber <= 0 || objectNumber > Limits.MaxObjectNumber || offset < 0)
            {
                _context.Repair(PdfRepairKind.ObjectStreamUnreadable, at);
                break;
            }

            pairs.Add(((int)objectNumber, offset));
        }

        var context = new PdfParseContext(Limits, Diagnostics);
        var objects = new List<PdfIndirectObject>(pairs.Count);
        foreach (var (objectNumber, offset) in pairs)
        {
            long start = first.Value + offset;
            if (start >= decoded.Length)
            {
                objects.Add(new PdfIndirectObject(new PdfObjectId(objectNumber, 0), PdfNull.Instance, new PdfSourceRange(start, 0)));
                continue;
            }

            int position = (int)start;
            var value = PdfParser.ParseObject(decoded, ref position, context);
            objects.Add(new PdfIndirectObject(new PdfObjectId(objectNumber, 0), value, new PdfSourceRange(start, position - (int)start)));
        }

        return new ObjectStreamContents(objects);
    }

    /// <summary>The object numbers an object stream holds, for reconstruction.</summary>
    private IReadOnlyList<int> ObjectStreamNumbers(PdfStream stream) =>
        ReadObjectStream(stream, new PdfRevision(0, [new PdfXrefSection(PdfXrefSectionKind.Reconstructed, -1, new Dictionary<int, PdfXrefEntry>(), PdfDictionary.Empty, null)], null, Data.Length), 0)
            .Objects.ConvertAll(o => o.Id.Number);

    private Dictionary<int, List<(long Offset, PdfObjectId Id)>> IndexHeaders()
    {
        var index = new Dictionary<int, List<(long, PdfObjectId)>>();
        foreach (var header in PdfXrefReader.ScanObjectHeaders(Data.Span, Limits))
        {
            if (!index.TryGetValue(header.Id.Number, out var list))
            {
                list = [];
                index[header.Id.Number] = list;
            }

            list.Add(header);
        }

        return index;
    }

    private bool ReadLinearized()
    {
        var headers = PdfXrefReader.ScanObjectHeaders(Data.Span[..Math.Min(Data.Length, 1024)], Limits);
        if (headers.Count == 0)
        {
            return false;
        }

        var first = PdfParser.ParseIndirectObject(Data, (int)headers[0].Offset, new PdfParseContext(Limits));
        return first?.Value is PdfDictionary dictionary && dictionary.ContainsKey(s_linearized);
    }

    /// <summary>
    /// Groups the chain's sections into revisions, oldest first. A section whose <c>/Prev</c> points forward (to the next
    /// section of the chain) is a linearized file's first-page section: it and that section make one revision.
    /// </summary>
    private List<PdfRevision> BuildRevisions(IReadOnlyList<PdfXrefSection> chain)
    {
        var groups = new List<List<PdfXrefSection>>();
        for (int i = 0; i < chain.Count; i++)
        {
            var group = new List<PdfXrefSection> { chain[i] };
            if (i + 1 < chain.Count && chain[i].Prev > chain[i].Offset)
            {
                group.Add(chain[++i]);
            }

            groups.Add(group);
        }

        groups.Reverse();
        var revisions = new List<PdfRevision>(groups.Count);
        PdfRevision? previous = null;
        for (int i = 0; i < groups.Count; i++)
        {
            long end = i == groups.Count - 1 ? Math.Max(EndAfter(groups[i]), Data.Length) : EndAfter(groups[i]);
            previous = new PdfRevision(i, groups[i], previous, end);
            revisions.Add(previous);
        }

        return revisions;
    }

    /// <summary>The offset just after the first <c>%%EOF</c> (and its line end) after a revision's sections.</summary>
    private long EndAfter(List<PdfXrefSection> sections)
    {
        var span = Data.Span;
        int from = (int)Math.Clamp(sections.Max(s => s.Offset), 0, span.Length);
        int found = span[from..].IndexOf("%%EOF"u8);
        if (found < 0)
        {
            return span.Length;
        }

        int end = from + found + "%%EOF"u8.Length;
        if (end < span.Length && span[end] == '\r')
        {
            end++;
        }

        if (end < span.Length && span[end] == '\n')
        {
            end++;
        }

        return end;
    }

    private static string? ReadVersion(ReadOnlySpan<byte> data)
    {
        var head = data[..Math.Min(data.Length, 1024)];
        int at = head.IndexOf("%PDF-"u8);
        if (at < 0)
        {
            return null;
        }

        int start = at + 5;
        int end = start;
        while (end < head.Length && (head[end] is >= (byte)'0' and <= (byte)'9' || head[end] == '.'))
        {
            end++;
        }

        return end > start ? System.Text.Encoding.ASCII.GetString(head[start..end]) : null;
    }

    /// <summary>The objects of one object stream, their source ranges offsets in the decoded data.</summary>
    private sealed record ObjectStreamContents(List<PdfIndirectObject> Objects)
    {
        public static ObjectStreamContents Empty { get; } = new([]);
    }
}
