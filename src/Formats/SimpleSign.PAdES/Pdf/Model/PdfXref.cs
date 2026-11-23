namespace SimpleSign.PAdES.Pdf.Model;

/// <summary>What a cross-reference entry says about an object (ISO 32000-1 §7.5.4, §7.5.8.3).</summary>
internal enum PdfXrefEntryType
{
    /// <summary>The object is free (deleted, or never used): a reference to it is a reference to null.</summary>
    Free,

    /// <summary>The object is in the file, at <see cref="PdfXrefEntry.Offset"/>.</summary>
    InUse,

    /// <summary>The object is inside an object stream (§7.5.7).</summary>
    Compressed,
}

/// <summary>One entry of a cross-reference section.</summary>
/// <param name="Type">Free, in use, or compressed.</param>
/// <param name="Offset">For an object in use, the offset of its <c>N G obj</c> header; otherwise 0.</param>
/// <param name="Generation">The generation number; 0 for a compressed object.</param>
/// <param name="StreamNumber">For a compressed object, the object number of its object stream.</param>
/// <param name="StreamIndex">For a compressed object, its index in that object stream.</param>
internal readonly record struct PdfXrefEntry(PdfXrefEntryType Type, long Offset, int Generation, int StreamNumber = 0, int StreamIndex = 0)
{
    /// <summary>A free entry.</summary>
    public static PdfXrefEntry Free(int generation) => new(PdfXrefEntryType.Free, 0, generation);

    /// <summary>An object in use at an offset.</summary>
    public static PdfXrefEntry InUse(long offset, int generation) => new(PdfXrefEntryType.InUse, offset, generation);

    /// <summary>An object inside an object stream.</summary>
    public static PdfXrefEntry Compressed(int streamNumber, int index) => new(PdfXrefEntryType.Compressed, 0, 0, streamNumber, index);
}

/// <summary>How a cross-reference section was written, or that it was rebuilt.</summary>
internal enum PdfXrefSectionKind
{
    /// <summary>A table: <c>xref</c>, subsections of 20-byte entries, <c>trailer</c> (§7.5.4).</summary>
    Table,

    /// <summary>A cross-reference stream (§7.5.8).</summary>
    Stream,

    /// <summary>
    /// Not read from the file: rebuilt by scanning it for <c>N G obj</c> headers, because the sections could not be read.
    /// </summary>
    Reconstructed,
}

/// <summary>
/// One cross-reference section and its trailer. A hybrid file's table section (§7.5.8.4) includes the entries of the
/// stream its <c>/XRefStm</c> points to.
/// </summary>
internal sealed class PdfXrefSection
{
    /// <summary>Creates a section.</summary>
    public PdfXrefSection(
        PdfXrefSectionKind kind, long offset, IReadOnlyDictionary<int, PdfXrefEntry> entries, PdfDictionary trailer, long? prev, long? xrefStream = null)
    {
        Kind = kind;
        Offset = offset;
        Entries = entries;
        Trailer = trailer;
        Prev = prev;
        XrefStream = xrefStream;
    }

    /// <summary>How the section was written.</summary>
    public PdfXrefSectionKind Kind { get; }

    /// <summary>The offset of <c>xref</c>, or of the cross-reference stream's object; −1 for a reconstructed section.</summary>
    public long Offset { get; }

    /// <summary>The entries, by object number.</summary>
    public IReadOnlyDictionary<int, PdfXrefEntry> Entries { get; }

    /// <summary>The trailer: the dictionary after <c>trailer</c>, or the cross-reference stream's dictionary.</summary>
    public PdfDictionary Trailer { get; }

    /// <summary>The <c>/Prev</c> offset, when there is one.</summary>
    public long? Prev { get; }

    /// <summary>A hybrid file's <c>/XRefStm</c> offset, when its entries were read into this section.</summary>
    public long? XrefStream { get; }
}
