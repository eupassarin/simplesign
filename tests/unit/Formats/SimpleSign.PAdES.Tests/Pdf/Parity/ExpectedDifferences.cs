using System.Reflection;
using Shouldly;
using SimpleSign.PAdES.Pdf;
using SimpleSign.PAdES.Pdf.Model;

namespace SimpleSign.PAdES.Tests.Pdf.Parity;

/// <summary>A difference between the readers that is intended, with why, and the test that recognizes it.</summary>
/// <param name="Name">A short name.</param>
/// <param name="Reason">Why the model reads it differently.</param>
/// <param name="Explains">Whether the rule explains a difference, given the document.</param>
internal sealed record ExpectedDifference(string Name, string Reason, Func<ParityContext, FactDifference, bool> Explains);

/// <summary>
/// The catalogue of intended differences between the legacy reader and the object model (ADR 0032). A rule must name
/// the precise condition it explains: a difference that matches none fails the parity harness.
/// </summary>
internal static class ExpectedDifferences
{
    public static IReadOnlyList<ExpectedDifference> All { get; } =
    [
        new(
            "RebuiltWhereLegacyFailed",
            "Without a readable startxref the legacy reader throws; the model rebuilds the cross-reference from the object headers.",
            (c, d) => c.Model.IsReconstructed && c.Legacy["error"] is not null),

        new(
            "HybridXRefStm",
            "The legacy reader ignores a hybrid file's /XRefStm (ISO 32000-1 §7.5.8.4): the objects only that stream lists "
            + "(compressed ones) are unknown to it.",
            (c, d) => d.ObjectNumber is int n && d.Legacy is null && Providing(c.Model, n) is { XrefStream: not null }),

        new(
            "LegacyMisreadsTable",
            "The legacy table reader is position-exact: it needs 'xref' at the very offset, LF line ends, 20-byte entries "
            + "and 'trailer' right after the last entry. A table with white-space before 'xref' or 'trailer', or lines "
            + "ending with a lone CR (all allowed by ISO 32000-1 §7.5.4), is lost to it, with the sections before it; "
            + "a subsection written '1 n' with object 0's entry first (a writer bug the model repairs, as pdf.js and "
            + "PDFBox do) is read one object too high.",
            (c, d) => d.ObjectNumber is int n && LegacyMisreadsUpTo(c.Data, c.Model, n)),

        new(
            "FreeEntryHonoured",
            "A free entry in a newer section deletes the object (§7.5.4); the legacy reader skips free entries and keeps an "
            + "older section's offset.",
            (c, d) => d.ObjectNumber is int n && d.Model is null or "missing" && c.Model.Lookup(n) is { Type: PdfXrefEntryType.Free }),

        new(
            "GenerationAboveZero",
            "The legacy reader looks for 'N 0 obj' only; the model finds an object with the generation its entry gives.",
            (c, d) => d.Key.StartsWith("object/", StringComparison.Ordinal) && d.Legacy == "missing"
                && c.Model.Lookup(d.ObjectNumber!.Value) is { Type: PdfXrefEntryType.InUse, Generation: > 0 }),

        new(
            "LookupByXref",
            "The legacy reader takes the last 'N 0 obj' text of the file; the model takes the object the cross-reference "
            + "points to. They differ when an object is written again where no cross-reference section lists it.",
            (c, d) => d.Key.StartsWith("object/", StringComparison.Ordinal)
                && c.Legacy.ObjectStarts.TryGetValue(d.ObjectNumber!.Value, out int legacyStart)
                && c.Model.GetObject(d.ObjectNumber.Value) is { } obj && obj.Source.Offset != legacyStart),
    ];

    /// <summary>The section the latest revision takes an object's entry from.</summary>
    private static PdfXrefSection? Providing(PdfDocument doc, int number)
    {
        for (var revision = doc.Latest; revision is not null; revision = revision.Previous)
        {
            foreach (var section in revision.Sections)
            {
                if (section.Entries.ContainsKey(number))
                {
                    return section;
                }
            }
        }

        return null;
    }

    private delegate long LegacyTable(ReadOnlySpan<byte> data, int start, List<PdfCrossRef> refs, HashSet<int> seen);

    private static readonly LegacyTable s_legacyTable = typeof(PdfStructureReader)
        .GetMethod("ParseClassicXrefRevision", BindingFlags.NonPublic | BindingFlags.Static)
        .ShouldNotBeNull()
        .CreateDelegate<LegacyTable>();

    /// <summary>
    /// Whether the legacy reader misreads a table section of the chain, from the newest down to the one the latest
    /// revision takes the object's entry from: it would lose that entry, or stop the chain before it.
    /// </summary>
    private static bool LegacyMisreadsUpTo(byte[] data, PdfDocument doc, int number)
    {
        var providing = Providing(doc, number);
        long? pointer = doc.StartXref;
        for (var revision = doc.Latest; revision is not null; revision = revision.Previous)
        {
            foreach (var section in revision.Sections)
            {
                if (section.Kind == PdfXrefSectionKind.Table && section.XrefStream is null
                    && !LegacyReadsTableAsModel(data, pointer ?? section.Offset, section))
                {
                    return true;
                }

                if (ReferenceEquals(section, providing))
                {
                    return false;
                }

                pointer = section.Prev;
            }
        }

        return providing is null;
    }

    /// <summary>Whether the legacy table reader gets the same in-use entries and /Prev as the model from a table.</summary>
    /// <param name="data">The file.</param>
    /// <param name="pointer">The offset the chain gives for the section (<c>startxref</c> or the newer section's /Prev).</param>
    /// <param name="section">The section as the model read it.</param>
    private static bool LegacyReadsTableAsModel(byte[] data, long pointer, PdfXrefSection section)
    {
        if (pointer < 0 || pointer >= data.Length || !data.AsSpan((int)pointer).StartsWith("xref"u8))
        {
            return false;
        }

        var refs = new List<PdfCrossRef>();
        long prev = s_legacyTable(data, (int)pointer, refs, []);
        var expected = section.Entries.Where(e => e.Value.Type == PdfXrefEntryType.InUse).Select(e => (e.Key, e.Value.Offset)).Order();
        long? legacyPrev = prev > 0 ? prev : null;
        return legacyPrev == section.Prev
            && refs.Select(r => (r.ObjectNumber, r.Offset)).Order().SequenceEqual(expected);
    }
}
