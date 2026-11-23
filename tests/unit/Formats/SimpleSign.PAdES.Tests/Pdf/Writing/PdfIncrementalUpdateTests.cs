using System.Text;
using Shouldly;
using SimpleSign.PAdES.Pdf;
using SimpleSign.PAdES.Pdf.Model;
using SimpleSign.PAdES.Pdf.Writing;
using SimpleSign.PAdES.Signing;
using SimpleSign.PAdES.Tests.Pdf.Parity;
using Xunit;
using Xunit.Abstractions;

namespace SimpleSign.PAdES.Tests.Pdf.Writing;

/// <summary>
/// The incremental update writes what the writers write (ADR 0032): golden, over every committed PDF, against the
/// cross-reference builders they use (<c>BuildXrefTableAndTrailer</c>, <c>BuildXrefStream</c>) with the trailer values
/// they read.
/// </summary>
[Trait("Category", "Unit")]
public sealed class PdfIncrementalUpdateTests(ITestOutputHelper output)
{
    /// <summary>The documents whose update differs from the legacy one, and why.</summary>
    private static readonly Dictionary<string, string> s_expectedDifferences = new(StringComparer.Ordinal);

    public static TheoryData<string> Fixtures()
    {
        var data = new TheoryData<string>();
        foreach (string name in ParityCorpus.Fixtures.Keys)
        {
            data.Add(name);
        }

        return data;
    }

    public static TheoryData<string> GeneratedDocuments()
    {
        var data = new TheoryData<string>();
        foreach (string name in ParityCorpus.Generated.Keys)
        {
            data.Add(name);
        }

        return data;
    }

    [Theory]
    [MemberData(nameof(Fixtures))]
    public Task Finish_Fixture_IsWhatTheWritersWrite(string fixture) =>
        AssertIsWhatTheWritersWrite(fixture, File.ReadAllBytes(ParityCorpus.Fixtures[fixture]));

    [Theory]
    [MemberData(nameof(GeneratedDocuments))]
    public Task Finish_GeneratedDocument_IsWhatTheWritersWrite(string name) =>
        AssertIsWhatTheWritersWrite("generated:" + name, ParityCorpus.Generated[name]());

    private async Task AssertIsWhatTheWritersWrite(string fixture, byte[] original)
    {
        var document = PdfDocument.Open(original);
        if (document.IsEncrypted || !original.AsSpan().StartsWith("%PDF-"u8) || document.Catalog is null)
        {
            output.WriteLine("skipped: encrypted, not a PDF or no catalog");
            return;
        }

        int first = PdfStructureParser.DetermineNextObjectNumber(original);
        int root = PdfStructureParser.FindRootObjectNumber(original);
        byte[] a = Encoding.Latin1.GetBytes($"{first} 0 obj\n<< /Producer (test) >>\nendobj\n");
        byte[] b = Encoding.Latin1.GetBytes($"{first + 1} 0 obj\n[1 2 3]\nendobj\n");

        var update = new PdfIncrementalUpdate(document);
        update.Add(first, a);
        update.Add(first + 1, b);
        byte[] actual = update.Finish(first + 2, root);

        // What the writers do: copy, a line feed when needed, the objects, then the cross-reference they build.
        using var stream = new MemoryStream();
        stream.Write(original);
        IncrementalUpdateUtility.EnsureTrailingEol(stream);
        var offsets = new SortedDictionary<int, long> { [first] = stream.Position };
        stream.Write(a);
        offsets[first + 1] = stream.Position;
        stream.Write(b);
        using var input = new MemoryStream(original);
        long prev = await PdfStructureParser.FindPrevXRefAsync(input, CancellationToken.None);
        string? id = PdfStructureParser.FindTrailerId(original);
        string? info = PdfStructureParser.FindTrailerInfo(original);
        long xref = stream.Position;
        stream.Write(PdfStructureParser.UsesXRefStreams(original)
            ? PdfSignatureWriter.BuildXrefStream(offsets, offsets.Keys.Max() + 1, Math.Max(first + 2, offsets.Keys.Max() + 2), root, prev, xref, id, info).Bytes
            : PdfSignatureWriter.BuildXrefTableAndTrailer(offsets, first + 2, root, prev, xref, id, info));
        byte[] expected = stream.ToArray();

        if (s_expectedDifferences.TryGetValue(fixture, out string? why))
        {
            output.WriteLine($"differs: {why}");
            actual.ShouldNotBe(expected);
            return;
        }

        if (!actual.AsSpan().SequenceEqual(expected))
        {
            int at = actual.AsSpan().CommonPrefixLength(expected);
            output.WriteLine($"first difference at {at} of {expected.Length}");
            output.WriteLine("legacy: " + Encoding.Latin1.GetString(expected, Math.Max(0, at - 60), Math.Min(200, expected.Length - Math.Max(0, at - 60))));
            output.WriteLine("model : " + Encoding.Latin1.GetString(actual, Math.Max(0, at - 60), Math.Min(200, actual.Length - Math.Max(0, at - 60))));
        }

        actual.ShouldBe(expected);

        // And the update reads back: the new objects in a new revision, the old ones kept.
        var updated = PdfDocument.Open(actual);
        updated.Revisions.Count.ShouldBe(document.Revisions.Count + 1);
        updated.GetObject(first).ShouldNotBeNull();
        updated.GetObject(first + 1)!.Value.ShouldBeOfType<PdfArray>();
        updated.RootId.ShouldBe(document.RootId);
        output.WriteLine($"compared; cross-reference stream: {update.DocumentUsesXrefStream}");
    }

    [Fact]
    public void Add_SerializedObject_GivesWhereItsValuesAre()
    {
        var builder = new PdfFileBuilder()
            .Object(1, "<< /Type /Catalog /Pages 2 0 R >>")
            .Object(2, "<< /Type /Pages /Kids [] /Count 0 >>")
            .EndRevision();
        var update = new PdfIncrementalUpdate(PdfDocument.Open(builder.ToArray()));

        var (offset, values) = update.Add(3, new PdfDictionary(("Type", PdfName.Sig), ("ByteRange", PdfNull.Instance)),
            new Dictionary<string, string> { ["ByteRange"] = "[0000000000 0000000000 0000000000 0000000000]" });
        byte[] pdf = update.Finish(4, 1);

        offset.ShouldBe(builder.ToArray().Length);
        var (start, length) = values["ByteRange"];
        Encoding.Latin1.GetString(pdf, (int)start, length).ShouldBe("[0000000000 0000000000 0000000000 0000000000]");
        update.Offsets.ContainsKey(3).ShouldBeTrue();
    }

    [Fact]
    public void Finish_UpdateWithoutIdOrInfo_CarriesThoseOfTheTrailerBefore()
    {
        byte[] pdf = new PdfFileBuilder()
            .Object(1, "<< /Type /Catalog /Pages 2 0 R >>")
            .Object(2, "<< /Type /Pages /Kids [] /Count 0 >>")
            .Object(3, "<< /Producer (first) >>")
            .EndRevision(XrefStyle.Table, new RevisionOptions { TrailerExtra = "/ID [<AA11> <BB22>] /Info 3 0 R" })
            .Object(4, "<< /Producer (second) >>")
            .EndRevision()
            .ToArray();
        var update = new PdfIncrementalUpdate(PdfDocument.Open(pdf));
        update.Add(5, Encoding.Latin1.GetBytes("5 0 obj\n<< >>\nendobj\n"));

        string trailer = Encoding.Latin1.GetString(update.Finish(6, 1, PdfXrefStyle.Table)[pdf.Length..]);

        trailer.ShouldContain("   /ID [<AA11> <BB22>]\n   /Info 3 0 R\n");
        trailer.ShouldContain(PdfStructureParser.FindTrailerId(pdf)!);
        trailer.ShouldContain(PdfStructureParser.FindTrailerInfo(pdf)!);
    }

    [Fact]
    public void Finish_NothingAdded_Throws()
    {
        var builder = new PdfFileBuilder().Object(1, "<< /Type /Catalog >>").EndRevision();

        Should.Throw<InvalidOperationException>(() => new PdfIncrementalUpdate(PdfDocument.Open(builder.ToArray())).Finish(2, 1));
    }

    [Fact]
    public void New_OriginalWithoutFinalLineEnd_GetsALineFeed()
    {
        byte[] pdf = [.. new PdfFileBuilder().Object(1, "<< /Type /Catalog >>").EndRevision().ToArray()[..^1]];

        var update = new PdfIncrementalUpdate(PdfDocument.Open(pdf));

        update.Position.ShouldBe(pdf.Length + 1);
        update.Written[^1].ShouldBe((byte)'\n');
    }
}
