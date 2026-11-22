namespace SimpleSign.PAdES.Pdf.Model;

/// <summary>What the reader found wrong in a PDF and read past (ADR 0032).</summary>
internal enum PdfRepairKind
{
    /// <summary>A token that has no place where it stands was skipped.</summary>
    UnexpectedToken,

    /// <summary>An array or a dictionary was not closed before the end of the object.</summary>
    UnclosedContainer,

    /// <summary>A closing bracket with nothing to close was skipped.</summary>
    UnmatchedClose,

    /// <summary>A dictionary key had no value: it was read as null.</summary>
    MissingValue,

    /// <summary>Arrays and dictionaries nested deeper than the limit: the deeper value was read as null.</summary>
    NestingTooDeep,

    /// <summary>A number could not be read, or did not fit: it was read as null or as a real.</summary>
    InvalidNumber,

    /// <summary>An indirect reference with an object or generation number out of range was read as null.</summary>
    InvalidReference,

    /// <summary>A string or a name was not terminated before the end of the input.</summary>
    UnterminatedToken,

    /// <summary>A hexadecimal string held a character that is not a hexadecimal digit.</summary>
    InvalidHexDigit,

    /// <summary>A key appeared twice in a dictionary: the last value is the one read.</summary>
    DuplicateKey,

    /// <summary>An indirect object had no <c>endobj</c>.</summary>
    MissingEndObj,

    /// <summary>The line end after <c>stream</c> was a lone carriage return, or missing.</summary>
    StreamLineEnd,

    /// <summary>A stream's <c>/Length</c> was missing or wrong: its end was found by looking for <c>endstream</c>.</summary>
    StreamLength,

    /// <summary>A stream had no <c>endstream</c>: its data runs to the end of what could be read.</summary>
    MissingEndStream,

    /// <summary>No <c>startxref</c> was found: the cross-reference was rebuilt.</summary>
    StartXrefMissing,

    /// <summary>The last <c>startxref</c> is further than 1024 bytes from the end of the file.</summary>
    StartXrefNotAtEnd,

    /// <summary>
    /// A <c>startxref</c> or <c>/Prev</c> offset did not point at a cross-reference section; one was found close by.
    /// </summary>
    XrefOffsetWrong,

    /// <summary>A cross-reference section could not be read: the sections before it in the chain are lost.</summary>
    XrefSectionUnreadable,

    /// <summary>A cross-reference entry could not be read, or pointed at offset 0: it was skipped.</summary>
    XrefEntryInvalid,

    /// <summary>
    /// A table subsection started at 1 but its first entry was object 0's (<c>0000000000 65535 f</c>): it was read from 0.
    /// </summary>
    XrefSubsectionShifted,

    /// <summary>A cross-reference stream had fewer entries than its <c>/Index</c> says.</summary>
    XrefStreamTruncated,

    /// <summary>A <c>/Prev</c> pointed back at a section already read: the chain stops there.</summary>
    PrevLoop,

    /// <summary>The chain had more sections than <see cref="PdfReadLimits.MaxXrefSections"/>: the oldest are not read.</summary>
    TooManyXrefSections,

    /// <summary>The cross-reference was rebuilt from the <c>N G obj</c> headers of the file.</summary>
    XrefRebuilt,

    /// <summary>No trailer with a <c>/Root</c> was found: the catalog was looked for among the objects.</summary>
    TrailerMissing,

    /// <summary>
    /// A cross-reference entry's offset did not point at the object it names: the object was found by its header.
    /// </summary>
    ObjectOffsetWrong,

    /// <summary>An object stream could not be read, or did not hold the object asked for.</summary>
    ObjectStreamUnreadable,

    /// <summary>
    /// The object streams of the document decoded to more than <see cref="PdfReadLimits.MaxTotalObjectStreamBytes"/>.
    /// </summary>
    ObjectStreamBudgetExceeded,

    /// <summary>A chain of references was longer than <see cref="PdfReadLimits.MaxReferenceHops"/>: read as null.</summary>
    ReferenceHopsExceeded,
}

/// <summary>One repair: what was wrong and where.</summary>
/// <param name="Kind">What was wrong.</param>
/// <param name="Offset">Where in the bytes parsed it was found.</param>
internal readonly record struct PdfRepair(PdfRepairKind Kind, long Offset);

/// <summary>
/// The repairs made while reading a document. Reading a document may happen from several threads (a validator shares
/// one document), so adding is synchronized; the list keeps at most <see cref="MaxRepairs"/> entries and counts the rest.
/// </summary>
internal sealed class PdfDiagnostics
{
    /// <summary>The most repairs kept; more are counted, not kept.</summary>
    public const int MaxRepairs = 1000;

    private readonly List<PdfRepair> _repairs = [];
#if NET9_0_OR_GREATER
    private readonly Lock _lock = new();
#else
    private readonly object _lock = new();
#endif
    private long _count;

    /// <summary>The repairs kept, in the order they were made.</summary>
    public IReadOnlyList<PdfRepair> Repairs
    {
        get
        {
            lock (_lock)
            {
                return [.. _repairs];
            }
        }
    }

    /// <summary>How many repairs were made, those not kept included.</summary>
    public long Count
    {
        get
        {
            lock (_lock)
            {
                return _count;
            }
        }
    }

    /// <summary>Records a repair.</summary>
    /// <param name="kind">What was wrong.</param>
    /// <param name="offset">Where it was found.</param>
    public void Add(PdfRepairKind kind, long offset)
    {
        lock (_lock)
        {
            _count++;
            if (_repairs.Count < MaxRepairs)
            {
                _repairs.Add(new PdfRepair(kind, offset));
            }
        }
    }

    /// <summary>Whether a repair of this kind was made.</summary>
    /// <param name="kind">The kind.</param>
    public bool Has(PdfRepairKind kind)
    {
        lock (_lock)
        {
            return _repairs.Exists(repair => repair.Kind == kind);
        }
    }
}
