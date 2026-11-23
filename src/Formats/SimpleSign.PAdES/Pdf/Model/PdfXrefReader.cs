namespace SimpleSign.PAdES.Pdf.Model;

/// <summary>The cross-reference chain of a file, as read.</summary>
/// <param name="StartXref">The offset after the last <c>startxref</c>; −1 when there is none.</param>
/// <param name="Sections">The sections, newest first (the one <c>startxref</c> points to, then each <c>/Prev</c>).</param>
/// <param name="Complete">
/// False when a section of the chain could not be read: the objects only older sections list are then looked for by
/// their headers.
/// </param>
internal sealed record PdfXrefChain(long StartXref, IReadOnlyList<PdfXrefSection> Sections, bool Complete);

/// <summary>
/// Reads cross-reference sections (ISO 32000-1 §7.5.4, §7.5.5, §7.5.8): tables, streams and hybrid files, following
/// <c>/Prev</c> with a limit and loop detection. What it reads past is recorded in the diagnostics (ADR 0032). When
/// nothing can be read, <see cref="Reconstruct"/> rebuilds the cross-reference from the <c>N G obj</c> headers.
/// </summary>
internal static class PdfXrefReader
{
    /// <summary>How far before and after a wrong offset a section is looked for, in bytes.</summary>
    private const int NearbySearchWindow = 1024;

    /// <summary>How far from the end of the file <c>startxref</c> is expected (ISO 32000-1 §7.5.5).</summary>
    private const int StartXrefWindow = 1024;

    private static readonly PdfName s_xrefStm = PdfName.Of("XRefStm");
    private static readonly PdfName s_xref = PdfName.Of("XRef");
    private static readonly PdfName s_w = PdfName.Of("W");
    private static readonly PdfName s_index = PdfName.Of("Index");
    private static readonly PdfName s_objStm = PdfName.Of("ObjStm");
    private static readonly PdfName s_catalog = PdfName.Of("Catalog");

    /// <summary>Reads the chain from the last <c>startxref</c>.</summary>
    /// <param name="data">The file.</param>
    /// <param name="context">The limits and the diagnostics.</param>
    public static PdfXrefChain ReadChain(ReadOnlyMemory<byte> data, PdfParseContext context)
    {
        ArgumentNullException.ThrowIfNull(context);
        long startXref = FindStartXref(data.Span, context);
        if (startXref < 0)
        {
            return new PdfXrefChain(-1, [], false);
        }

        var sections = new List<PdfXrefSection>();
        var visited = new HashSet<long>();
        bool complete = true;
        long? offset = startXref;
        while (offset is long at)
        {
            if (!visited.Add(at))
            {
                // The section /Prev should have led to is not known: what it listed is looked for by header.
                context.Repair(PdfRepairKind.PrevLoop, ClampOffset(at, data.Length));
                complete = false;
                break;
            }

            if (sections.Count >= context.Limits.MaxXrefSections)
            {
                context.Repair(PdfRepairKind.TooManyXrefSections, ClampOffset(at, data.Length));
                complete = false;
                break;
            }

            var section = ReadSection(data, at, context, readHybrid: true) ?? ReadSectionNearby(data, at, context);
            if (section is null)
            {
                context.Repair(PdfRepairKind.XrefSectionUnreadable, ClampOffset(at, data.Length));
                complete = false;
                break;
            }

            if (section.Offset != at && !visited.Add(section.Offset))
            {
                context.Repair(PdfRepairKind.PrevLoop, (int)section.Offset);
                complete = false;
                break;
            }

            sections.Add(section);
            offset = section.Prev;
        }

        return new PdfXrefChain(startXref, sections, complete);
    }

    /// <summary>
    /// Rebuilds the cross-reference from the file's <c>N G obj</c> headers (the last header of an object number wins),
    /// the objects of its object streams, and the last trailer with a <c>/Root</c>; or, without one, the last catalog.
    /// </summary>
    /// <param name="data">The file.</param>
    /// <param name="context">The limits and the diagnostics.</param>
    /// <param name="decodeObjectStream">Reads the object numbers an object stream holds; null to skip object streams.</param>
    public static PdfXrefSection Reconstruct(
        ReadOnlyMemory<byte> data, PdfParseContext context, Func<PdfStream, IReadOnlyList<int>>? decodeObjectStream = null)
    {
        ArgumentNullException.ThrowIfNull(context);
        context.Repair(PdfRepairKind.XrefRebuilt, 0);

        var headers = ScanObjectHeaders(data.Span, context.Limits);
        var entries = new Dictionary<int, PdfXrefEntry>();
        foreach (var (offset, id) in headers)
        {
            entries[id.Number] = PdfXrefEntry.InUse(offset, id.Generation);
        }

        PdfDictionary? trailer = LastTrailer(data.Span, context, withRoot: true);
        PdfObjectId? catalog = null;
        var compressed = new Dictionary<int, (PdfXrefEntry Entry, long StreamOffset)>();

        // Newest first, so the first cross-reference stream with a /Root is the latest.
        foreach (var (offset, id) in Enumerable.Reverse(headers))
        {
            if (entries[id.Number].Offset != offset)
            {
                continue;
            }

            var parsed = PdfParser.ParseIndirectObject(data, (int)offset, context);
            switch (parsed?.Value)
            {
                case PdfStream { Dictionary: var dictionary } when IsType(dictionary, s_xref):
                    if (trailer is null && dictionary.Get(PdfName.Root) is PdfReference)
                    {
                        trailer = dictionary;
                    }

                    break;
                case PdfStream stream when IsType(stream.Dictionary, s_objStm) && decodeObjectStream is not null:
                    var numbers = decodeObjectStream(stream);
                    for (int i = 0; i < numbers.Count; i++)
                    {
                        compressed.TryAdd(numbers[i], (PdfXrefEntry.Compressed(id.Number, i), offset));
                    }

                    break;
                case PdfDictionary dictionary when catalog is null && IsType(dictionary, s_catalog):
                    catalog = id;
                    break;
            }
        }

        // The latest copy in the file wins: an object stream written after an object's header replaces it.
        foreach (var (number, (entry, streamOffset)) in compressed)
        {
            if (!entries.TryGetValue(number, out var direct) || direct.Offset < streamOffset)
            {
                entries[number] = entry;
            }
        }

        if (trailer is null)
        {
            // No trailer has a /Root: the last trailer still says what it says (/Encrypt, /Info, /ID), and the catalog
            // found among the objects is its /Root.
            context.Repair(PdfRepairKind.TrailerMissing, 0);
            int size = entries.Count == 0 ? 1 : entries.Keys.Max() + 1;
            var kept = LastTrailer(data.Span, context, withRoot: false)?.RawEntries
                .Where(e => !e.Key.Equals(PdfName.Root) && !e.Key.Equals(PdfName.Size) && !e.Key.Equals(PdfName.Prev)) ?? [];
            trailer = new PdfDictionary(
                [
                    new PdfDictionaryEntry(PdfName.Size, new PdfInteger(size)),
                    .. catalog is { } root ? [new PdfDictionaryEntry(PdfName.Root, new PdfReference(root))] : Array.Empty<PdfDictionaryEntry>(),
                    .. kept,
                ]);
        }

        return new PdfXrefSection(PdfXrefSectionKind.Reconstructed, -1, entries, trailer, null);
    }

    /// <summary>
    /// The <c>N G obj</c> headers of the file, in file order: where each starts and the object it names. A header is
    /// two integers and <c>obj</c>, separated by white-space and preceded by white-space, a delimiter or the start.
    /// </summary>
    public static List<(long Offset, PdfObjectId Id)> ScanObjectHeaders(ReadOnlySpan<byte> data, PdfReadLimits limits)
    {
        ArgumentNullException.ThrowIfNull(limits);
        var headers = new List<(long, PdfObjectId)>();
        int position = 0;
        while (position < data.Length)
        {
            int found = data[position..].IndexOf("obj"u8);
            if (found < 0)
            {
                break;
            }

            int keyword = position + found;
            position = keyword + 3;
            if (position < data.Length && PdfLexer.IsRegular(data[position]))
            {
                continue;
            }

            if (HeaderBefore(data, keyword, limits) is { } header)
            {
                headers.Add(header);
            }
        }

        return headers;
    }

    /// <summary>The header that ends with the <c>obj</c> keyword at <paramref name="keyword"/>; null when there is none.</summary>
    private static (long Offset, PdfObjectId Id)? HeaderBefore(ReadOnlySpan<byte> data, int keyword, PdfReadLimits limits)
    {
        int i = keyword - 1;
        if (!SkipWhitespaceBack(data, ref i)
            || !ReadDigitsBack(data, ref i, out long generation)
            || !SkipWhitespaceBack(data, ref i)
            || !ReadDigitsBack(data, ref i, out long number))
        {
            return null;
        }

        // i is now just before the object number: the start of the data, white-space or a delimiter.
        if (i >= 0 && PdfLexer.IsRegular(data[i]))
        {
            return null;
        }

        if (number > limits.MaxObjectNumber || generation > limits.MaxGeneration)
        {
            return null;
        }

        return (i + 1, new PdfObjectId((int)number, (int)generation));
    }

    private static bool SkipWhitespaceBack(ReadOnlySpan<byte> data, ref int i)
    {
        int start = i;
        while (i >= 0 && PdfLexer.IsWhitespace(data[i]))
        {
            i--;
        }

        return i < start && i >= 0;
    }

    private static bool ReadDigitsBack(ReadOnlySpan<byte> data, ref int i, out long value)
    {
        value = 0;
        long scale = 1;
        int digits = 0;
        while (i >= 0 && data[i] is >= (byte)'0' and <= (byte)'9')
        {
            if (++digits > 10)
            {
                return false;
            }

            value += (data[i] - '0') * scale;
            scale *= 10;
            i--;
        }

        return digits > 0;
    }

    /// <summary>The offset after the last <c>startxref</c>, or −1.</summary>
    private static long FindStartXref(ReadOnlySpan<byte> data, PdfParseContext context)
    {
        int keyword = data.LastIndexOf("startxref"u8);
        if (keyword < 0)
        {
            context.Repair(PdfRepairKind.StartXrefMissing, data.Length);
            return -1;
        }

        if (data.Length - keyword > StartXrefWindow)
        {
            context.Repair(PdfRepairKind.StartXrefNotAtEnd, keyword);
        }

        var lexer = new PdfLexer(data, keyword + "startxref"u8.Length);
        var token = lexer.Next();
        if (token.Kind != PdfTokenKind.Integer || !lexer.Integer(token, out long offset) || offset < 0)
        {
            context.Repair(PdfRepairKind.StartXrefMissing, keyword);
            return -1;
        }

        return offset;
    }

    /// <summary>Reads the section at an offset: <c>xref</c> or a cross-reference stream; null when neither is there.</summary>
    private static PdfXrefSection? ReadSection(ReadOnlyMemory<byte> data, long offset, PdfParseContext context, bool readHybrid)
    {
        if (offset < 0 || offset >= data.Length)
        {
            return null;
        }

        var span = data.Span;
        var lexer = new PdfLexer(span, (int)offset);
        var first = lexer.Next();
        if (lexer.Is(first, "xref"u8))
        {
            return ReadTable(data, first.Start, lexer.Position, context, readHybrid);
        }

        if (first.Kind != PdfTokenKind.Integer)
        {
            return null;
        }

        var parsed = PdfParser.ParseIndirectObject(data, first.Start, context);
        return parsed?.Value is PdfStream stream && (IsType(stream.Dictionary, s_xref) || stream.Dictionary.ContainsKey(s_w))
            ? ReadStream(stream, first.Start, context)
            : null;
    }

    /// <summary>Looks for a section close to a wrong offset: the nearest <c>xref</c>, else the nearest cross-reference stream.</summary>
    private static PdfXrefSection? ReadSectionNearby(ReadOnlyMemory<byte> data, long offset, PdfParseContext context)
    {
        var span = data.Span;
        long center = Math.Clamp(offset, 0, span.Length);
        int from = (int)Math.Max(0, center - NearbySearchWindow);
        int to = (int)Math.Min(span.Length, center + NearbySearchWindow);
        var window = span[from..to];

        var candidates = new List<int>();
        for (int i = window.IndexOf("xref"u8); i >= 0;)
        {
            int at = from + i;
            bool startsToken = at == 0 || !PdfLexer.IsRegular(span[at - 1]);
            bool endsToken = at + 4 >= span.Length || !PdfLexer.IsRegular(span[at + 4]);
            if (startsToken && endsToken)
            {
                candidates.Add(at);
            }

            int next = window[(i + 1)..].IndexOf("xref"u8);
            i = next < 0 ? -1 : i + 1 + next;
        }

        foreach (var (at, _) in ScanObjectHeaders(window, context.Limits))
        {
            candidates.Add(from + (int)at);
        }

        foreach (int candidate in candidates.OrderBy(c => Math.Abs(c - center)))
        {
            if (candidate != offset && ReadSection(data, candidate, context, readHybrid: true) is { } section)
            {
                context.Repair(PdfRepairKind.XrefOffsetWrong, ClampOffset(offset, span.Length));
                return section;
            }
        }

        return null;
    }

    /// <summary>Reads a table section: subsections of entries, then <c>trailer</c> and its dictionary.</summary>
    private static PdfXrefSection ReadTable(ReadOnlyMemory<byte> data, int offset, int position, PdfParseContext context, bool readHybrid)
    {
        var span = data.Span;
        var lexer = new PdfLexer(span, position);
        var entries = new Dictionary<int, PdfXrefEntry>();

        while (true)
        {
            var token = lexer.Peek();
            if (lexer.Is(token, "trailer"u8) || token.Kind == PdfTokenKind.EndOfInput)
            {
                break;
            }

            if (!ReadSubsection(ref lexer, entries, context))
            {
                // Resynchronize on the trailer.
                int trailer = span[lexer.Position..].IndexOf("trailer"u8);
                if (trailer < 0)
                {
                    lexer.Position = span.Length;
                    break;
                }

                lexer.Position += trailer;
            }
        }

        PdfDictionary trailerDictionary = PdfDictionary.Empty;
        if (lexer.Is(lexer.Peek(), "trailer"u8))
        {
            lexer.Next();
            int at = lexer.Position;
            if (PdfParser.ParseObject(span, ref at, context) is PdfDictionary dictionary)
            {
                trailerDictionary = dictionary;
            }
        }

        long? prev = OffsetValue(trailerDictionary.Get(PdfName.Prev));
        long? xrefStream = readHybrid ? OffsetValue(trailerDictionary.Get(s_xrefStm)) : null;
        if (xrefStream is long streamOffset)
        {
            // Hybrid file (§7.5.8.4): the stream's entries come after the table's, before the previous section's. An
            // object the table marks free for older readers is found in the stream.
            if (ReadSection(data, streamOffset, context, readHybrid: false) is { Kind: PdfXrefSectionKind.Stream } hidden)
            {
                foreach (var (number, entry) in hidden.Entries)
                {
                    if (!entries.TryGetValue(number, out var existing) || existing.Type == PdfXrefEntryType.Free)
                    {
                        entries[number] = entry;
                    }
                }
            }
            else
            {
                context.Repair(PdfRepairKind.XrefSectionUnreadable, ClampOffset(streamOffset, span.Length));
                xrefStream = null;
            }
        }

        return new PdfXrefSection(PdfXrefSectionKind.Table, offset, entries, trailerDictionary, prev, xrefStream);
    }

    /// <summary>Reads one subsection, <c>first count</c> and its entries; false when it could not be read.</summary>
    private static bool ReadSubsection(ref PdfLexer lexer, Dictionary<int, PdfXrefEntry> entries, PdfParseContext context)
    {
        var firstToken = lexer.Next();
        var countToken = lexer.Next();
        if (!lexer.Integer(firstToken, out long first) || !lexer.Integer(countToken, out long count)
            || first < 0 || count < 0 || first + count > (long)context.Limits.MaxObjectNumber + 1)
        {
            context.Repair(PdfRepairKind.XrefEntryInvalid, firstToken.Start);
            return false;
        }

        for (long i = 0; i < count; i++)
        {
            var offsetToken = lexer.Next();
            var generationToken = lexer.Next();
            var typeToken = lexer.Next();
            if (!lexer.Integer(offsetToken, out long offset) || !lexer.Integer(generationToken, out long generation)
                || !(lexer.Is(typeToken, "n"u8) || lexer.Is(typeToken, "f"u8)))
            {
                context.Repair(PdfRepairKind.XrefEntryInvalid, offsetToken.Start);
                return false;
            }

            bool free = lexer.Is(typeToken, "f"u8);
            if (i == 0 && first == 1 && free && offset == 0 && generation == 65535)
            {
                // A common writer bug: object 0's entry under "1 n". The subsection really starts at 0.
                context.Repair(PdfRepairKind.XrefSubsectionShifted, firstToken.Start);
                first = 0;
            }

            long number = first + i;
            if (number == 0)
            {
                continue;
            }

            if (generation is < 0 or > 65535 || (!free && offset <= 0))
            {
                context.Repair(PdfRepairKind.XrefEntryInvalid, offsetToken.Start);
                continue;
            }

            entries.TryAdd((int)number, free ? PdfXrefEntry.Free((int)generation) : PdfXrefEntry.InUse(offset, (int)generation));
        }

        return true;
    }

    /// <summary>Reads a cross-reference stream's entries (§7.5.8.2, §7.5.8.3).</summary>
    private static PdfXrefSection? ReadStream(PdfStream stream, int offset, PdfParseContext context)
    {
        var dictionary = stream.Dictionary;
        if (dictionary.Get(s_w) is not PdfArray { Count: 3 } w
            || w[0] is not PdfInteger { Value: >= 0 and <= 8 } w0
            || w[1] is not PdfInteger { Value: >= 0 and <= 8 } w1
            || w[2] is not PdfInteger { Value: >= 0 and <= 8 } w2
            || w0.Value + w1.Value + w2.Value == 0)
        {
            return null;
        }

        byte[] decoded;
        try
        {
            decoded = PdfStreamDecoding.Decode(stream, context.Limits.MaxDecodedStreamBytes);
        }
        catch (Exception ex) when (ex is PdfFilterException or PdfUnsupportedFilterException)
        {
            return null;
        }

        int typeWidth = (int)w0.Value;
        int valueWidth = (int)w1.Value;
        int thirdWidth = (int)w2.Value;
        int entrySize = typeWidth + valueWidth + thirdWidth;

        var subsections = new List<(long First, long Count)>();
        if (dictionary.Get(s_index) is PdfArray index)
        {
            for (int i = 0; i + 1 < index.Count; i += 2)
            {
                if (index[i] is PdfInteger { Value: >= 0 } first && index[i + 1] is PdfInteger { Value: >= 0 } count)
                {
                    subsections.Add((first.Value, count.Value));
                }
            }
        }
        else if (dictionary.Get(PdfName.Size) is PdfInteger { Value: > 0 } size)
        {
            subsections.Add((0, size.Value));
        }

        var entries = new Dictionary<int, PdfXrefEntry>();
        int position = 0;
        foreach (var (first, count) in subsections)
        {
            for (long i = 0; i < count; i++)
            {
                if (position + entrySize > decoded.Length)
                {
                    context.Repair(PdfRepairKind.XrefStreamTruncated, offset);
                    return Section();
                }

                // A type field of width 0 means type 1 (§7.5.8.2, Table 17).
                long type = typeWidth == 0 ? 1 : ReadBigEndian(decoded, position, typeWidth);
                long second = ReadBigEndian(decoded, position + typeWidth, valueWidth);
                long third = ReadBigEndian(decoded, position + typeWidth + valueWidth, thirdWidth);
                position += entrySize;

                long number = first + i;
                if (number == 0 || number > context.Limits.MaxObjectNumber)
                {
                    continue;
                }

                PdfXrefEntry? entry = type switch
                {
                    0 => PdfXrefEntry.Free((int)Math.Min(third, 65535)),
                    1 when second > 0 && third <= 65535 => PdfXrefEntry.InUse(second, (int)third),
                    2 when second is > 0 and <= int.MaxValue && third <= int.MaxValue => PdfXrefEntry.Compressed((int)second, (int)third),
                    _ => null,
                };

                if (entry is { } valid)
                {
                    entries.TryAdd((int)number, valid);
                }
                else if (type is 1 or 2)
                {
                    context.Repair(PdfRepairKind.XrefEntryInvalid, offset);
                }
            }
        }

        return Section();

        PdfXrefSection Section()
        {
            return new PdfXrefSection(PdfXrefSectionKind.Stream, offset, entries, dictionary, OffsetValue(dictionary.Get(PdfName.Prev)));
        }
    }

    private static long ReadBigEndian(byte[] data, int position, int width)
    {
        long value = 0;
        for (int i = 0; i < width; i++)
        {
            value = (value << 8) | data[position + i];
        }

        return value;
    }

    /// <summary>The last <c>trailer</c> dictionary of the file (that has a <c>/Root</c>, when asked).</summary>
    private static PdfDictionary? LastTrailer(ReadOnlySpan<byte> data, PdfParseContext context, bool withRoot)
    {
        int end = data.Length;
        while (end > 0)
        {
            int keyword = data[..end].LastIndexOf("trailer"u8);
            if (keyword < 0)
            {
                return null;
            }

            int position = keyword + "trailer"u8.Length;
            if (PdfParser.ParseObject(data, ref position, context) is PdfDictionary trailer && (!withRoot || trailer.Get(PdfName.Root) is PdfReference))
            {
                return trailer;
            }

            end = keyword;
        }

        return null;
    }

    private static bool IsType(PdfDictionary dictionary, PdfName type) => type.Equals(dictionary.Get(PdfName.Type));

    private static long? OffsetValue(PdfObject? value) => value is PdfInteger { Value: >= 0 } integer ? integer.Value : null;

    private static int ClampOffset(long offset, int length) => (int)Math.Clamp(offset, 0, length);
}
