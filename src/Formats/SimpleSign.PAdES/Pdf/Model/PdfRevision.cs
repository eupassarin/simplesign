namespace SimpleSign.PAdES.Pdf.Model;

/// <summary>
/// One revision of a document (ADR 0032): a section of the cross-reference chain, the original file or one incremental
/// update (ISO 32000-1 §7.5.6). A linearized file's first-page section and its main section make one revision.
/// </summary>
internal sealed class PdfRevision
{
    /// <summary>Creates a revision.</summary>
    /// <param name="index">0 for the original file, then one more for each update.</param>
    /// <param name="sections">Its sections, newest first (two only for a linearized file's first revision).</param>
    /// <param name="previous">The revision before it; null for the first.</param>
    /// <param name="endOffset">The offset just after its <c>%%EOF</c> (and the line end after it).</param>
    public PdfRevision(int index, IReadOnlyList<PdfXrefSection> sections, PdfRevision? previous, long endOffset)
    {
        ArgumentNullException.ThrowIfNull(sections);
        ArgumentOutOfRangeException.ThrowIfZero(sections.Count);
        Index = index;
        Sections = sections;
        Previous = previous;
        EndOffset = endOffset;
        Trailer = sections.Select(s => s.Trailer).FirstOrDefault(t => t.ContainsKey(PdfName.Root)) ?? sections[0].Trailer;
    }

    /// <summary>0 for the original file, then one more for each update.</summary>
    public int Index { get; }

    /// <summary>Its cross-reference sections, newest first.</summary>
    public IReadOnlyList<PdfXrefSection> Sections { get; }

    /// <summary>The revision before it; null for the first.</summary>
    public PdfRevision? Previous { get; }

    /// <summary>
    /// The offset just after its <c>%%EOF</c> and the line end after it: the bytes of the file this revision ends.
    /// The length of the file for the last revision when no <c>%%EOF</c> follows its section.
    /// </summary>
    public long EndOffset { get; }

    /// <summary>
    /// Its trailer: the dictionary after <c>trailer</c>, or its cross-reference stream's dictionary (the one with a
    /// <c>/Root</c>, for a linearized file).
    /// </summary>
    public PdfDictionary Trailer { get; }

    /// <summary>The offset of its newest section; −1 when the cross-reference was rebuilt.</summary>
    public long XrefOffset => Sections[0].Offset;

    /// <summary>The entry this revision's own sections give an object; null when they do not list it.</summary>
    /// <param name="number">The object number.</param>
    public PdfXrefEntry? OwnEntry(int number)
    {
        foreach (var section in Sections)
        {
            if (section.Entries.TryGetValue(number, out var entry))
            {
                return entry;
            }
        }

        return null;
    }
}
