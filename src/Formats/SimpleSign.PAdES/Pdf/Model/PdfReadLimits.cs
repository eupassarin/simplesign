namespace SimpleSign.PAdES.Pdf.Model;

/// <summary>
/// The limits that keep reading a hostile PDF bounded in time and memory. The defaults are the limits the library
/// already applied before the object model (ADR 0032).
/// </summary>
internal sealed record PdfReadLimits
{
    /// <summary>The limits used unless others are given.</summary>
    public static PdfReadLimits Default { get; } = new();

    /// <summary>The largest file read, in bytes (<see cref="PdfStructureReader.MaxPdfSize"/>).</summary>
    public long MaxFileSize { get; init; } = PdfStructureReader.MaxPdfSize;

    /// <summary>The most cross-reference sections followed through <c>/Prev</c>.</summary>
    public int MaxXrefSections { get; init; } = 100;

    /// <summary>The largest object number accepted (ISO 32000-1 Annex C).</summary>
    public int MaxObjectNumber { get; init; } = 8_388_607;

    /// <summary>The largest generation number accepted.</summary>
    public int MaxGeneration { get; init; } = 65_535;

    /// <summary>How deep arrays and dictionaries may nest; a value nested deeper is read as null.</summary>
    public int MaxNestingDepth { get; init; } = 64;

    /// <summary>The most indirect references followed to reach one value.</summary>
    public int MaxReferenceHops { get; init; } = 16;

    /// <summary>The largest stream decoded, in bytes.</summary>
    public int MaxDecodedStreamBytes { get; init; } = 50 * 1024 * 1024;

    /// <summary>The most bytes decoded from all the object streams of a document.</summary>
    public long MaxTotalObjectStreamBytes { get; init; } = 256L * 1024 * 1024;

    /// <summary>The most objects read from one object stream.</summary>
    public int MaxObjectStreamObjects { get; init; } = 100_000;

    /// <summary>How far past a stream's start <c>endstream</c> is looked for when its <c>/Length</c> is wrong, in bytes.</summary>
    public int MaxStreamScanBytes { get; init; } = 10 * 1024 * 1024;

    /// <summary>How deep the page tree and the field tree may nest.</summary>
    public int MaxTreeDepth { get; init; } = 64;

    /// <summary>How deep a name tree may nest.</summary>
    public int MaxNameTreeDepth { get; init; } = 32;

    /// <summary>The most pages read.</summary>
    public int MaxPages { get; init; } = 100_000;
}
