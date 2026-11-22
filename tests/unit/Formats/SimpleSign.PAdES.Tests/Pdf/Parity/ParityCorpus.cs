using SimpleSign.TestHelpers;

namespace SimpleSign.PAdES.Tests.Pdf.Parity;

/// <summary>
/// The documents the parity harness compares the readers on: every PDF committed under <c>tests/integration</c>, and
/// documents generated in memory with each kind of cross-reference and the usual breakages.
/// </summary>
internal static class ParityCorpus
{
    /// <summary>
    /// The committed fixtures, by a short name (<c>Integration/51sigs.pdf</c>: the test project without
    /// <c>SimpleSign.</c> and <c>.Tests</c>, then the path under its <c>Fixtures</c>), and their full paths.
    /// </summary>
    public static IReadOnlyDictionary<string, string> Fixtures { get; } = FindFixtures();

    private static SortedDictionary<string, string> FindFixtures()
    {
        var fixtures = new SortedDictionary<string, string>(StringComparer.Ordinal);
        foreach (string project in Directory.EnumerateDirectories(RepositoryPaths.Get("tests", "integration")))
        {
            string dir = Path.Combine(project, "Fixtures");
            if (!Directory.Exists(dir))
            {
                continue;
            }

            string shortName = Path.GetFileName(project).Replace("SimpleSign.", "", StringComparison.Ordinal).Replace(".Tests", "", StringComparison.Ordinal);
            foreach (string path in Directory.EnumerateFiles(dir, "*.pdf", SearchOption.AllDirectories))
            {
                fixtures[shortName + "/" + Path.GetRelativePath(dir, path).Replace('\\', '/')] = path;
            }
        }

        return fixtures;
    }

    private static PdfFileBuilder Base(string eol = "\n") => new PdfFileBuilder(eol: eol)
        .Object(1, "<< /Type /Catalog /Pages 2 0 R >>")
        .Object(2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
        .Object(3, "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>");

    /// <summary>
    /// The catalogued differences each generated document must show (by rule name); a document not listed must show none.
    /// </summary>
    public static IReadOnlyDictionary<string, string[]> ExpectedRules { get; } = new Dictionary<string, string[]>(StringComparer.Ordinal)
    {
        ["hybrid"] = ["HybridXRefStm"],
        ["generation-2"] = ["GenerationAboveZero"],
        ["free-in-update"] = ["FreeEntryHonoured"],
        ["subsection-shifted"] = ["LegacyMisreadsTable"],
        ["lone-cr-table"] = ["LegacyMisreadsTable"],
        ["blank-line-before-trailer"] = ["LegacyMisreadsTable"],
        ["no-startxref"] = ["RebuiltWhereLegacyFailed"],
        ["stray-object-after-eof"] = ["LookupByXref"],
    };

    /// <summary>The generated documents, by name.</summary>
    public static IReadOnlyDictionary<string, Func<byte[]>> Generated { get; } = new Dictionary<string, Func<byte[]>>(StringComparer.Ordinal)
    {
        ["table"] = () => Base().EndRevision().ToArray(),
        ["table-crlf"] = () => Base("\r\n").EndRevision(options: new RevisionOptions { EntryEnd = "\r\n" }).ToArray(),
        ["table-updates"] = () => Base().EndRevision()
            .Object(3, "<< /Type /Page /Parent 2 0 R /Rotate 90 >>").EndRevision()
            .Object(4, "<< /Producer (update) >>").EndRevision().ToArray(),
        ["stream"] = () => Base().EndRevision(XrefStyle.Stream, new RevisionOptions { XrefStreamNumber = 4 }).ToArray(),
        ["stream-predictor"] = () => Base().EndRevision(XrefStyle.Stream, new RevisionOptions { XrefStreamNumber = 4, Predictor = true }).ToArray(),
        ["stream-updates"] = () => Base().EndRevision(XrefStyle.Stream, new RevisionOptions { XrefStreamNumber = 4 })
            .Object(3, "<< /Type /Page /Parent 2 0 R /Rotate 180 >>")
            .EndRevision(XrefStyle.Stream, new RevisionOptions { XrefStreamNumber = 5 }).ToArray(),
        ["table-then-stream"] = () => Base().EndRevision()
            .Object(3, "<< /Type /Page /Parent 2 0 R /Rotate 270 >>")
            .EndRevision(XrefStyle.Stream, new RevisionOptions { XrefStreamNumber = 4 }).ToArray(),
        ["objstm"] = () => new PdfFileBuilder()
            .Compressed(1, "<< /Type /Catalog /Pages 2 0 R >>")
            .Compressed(2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
            .Object(3, "<< /Type /Page /Parent 2 0 R >>")
            .EndRevision(XrefStyle.Stream, new RevisionOptions { XrefStreamNumber = 5, ObjectStreamNumber = 4 }).ToArray(),
        ["hybrid"] = () => new PdfFileBuilder()
            .Object(1, "<< /Type /Catalog /Pages 2 0 R >>")
            .Compressed(2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
            .Object(3, "<< /Type /Page /Parent 2 0 R >>")
            .EndRevision(XrefStyle.Hybrid, new RevisionOptions { XrefStreamNumber = 5, ObjectStreamNumber = 4 }).ToArray(),
        ["generation-2"] = () => Base().Object(4, "<< /Tag (gen 2) >>", generation: 2).EndRevision().ToArray(),
        ["free-in-update"] = () => Base().Object(4, "<< /Tag (to delete) >>").EndRevision()
            .Free(4, 1).Object(2, "<< /Type /Pages /Kids [3 0 R] /Count 1 /Tag (after delete) >>").EndRevision().ToArray(),
        ["offsets-shifted"] = () => Base().EndRevision(options: new RevisionOptions { OffsetShift = 2 }).ToArray(),
        ["subsection-shifted"] = () => Base().EndRevision(options: new RevisionOptions { ShiftedSubsection = true }).ToArray(),
        ["no-startxref"] = () => Base().EndRevision(options: new RevisionOptions { OmitStartXref = true }).ToArray(),
        ["stray-object-after-eof"] = () => Base().EndRevision()
            .Raw("3 0 obj\n<< /Type /Page /Tag (not in any xref) >>\nendobj\n").ToArray(),
        ["lone-cr-table"] = () => Base("\r").EndRevision(options: new RevisionOptions { EntryEnd = "\r\n" })
            .Object(3, "<< /Type /Page /Parent 2 0 R /Rotate 90 >>").EndRevision(options: new RevisionOptions { EntryEnd = "\r\n" }).ToArray(),
        ["blank-line-before-trailer"] = () => Base().EndRevision()
            .Object(3, "<< /Type /Page /Parent 2 0 R /Rotate 90 >>").EndRevision(options: new RevisionOptions { BeforeTrailer = "\n" }).ToArray(),
        ["prev-loop"] = () =>
        {
            var builder = Base().EndRevision().Object(3, "<< /Type /Page /Parent 2 0 R /Rotate 90 >>");
            return builder.EndRevision(options: new RevisionOptions { Prev = builder.Position }).ToArray();
        },
    };
}
