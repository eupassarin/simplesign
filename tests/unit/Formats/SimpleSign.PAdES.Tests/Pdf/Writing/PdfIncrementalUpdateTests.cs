using System.Text;
using Shouldly;
using SimpleSign.PAdES.Pdf.Model;
using SimpleSign.PAdES.Pdf.Writing;
using SimpleSign.PAdES.Tests.Pdf.Parity;
using Xunit;
using Xunit.Abstractions;

namespace SimpleSign.PAdES.Tests.Pdf.Writing;

/// <summary>
/// The incremental update (ADR 0032) writes what the writers before the object model wrote: it was checked byte for byte
/// against their cross-reference builders on every committed PDF and generated one, and each update is now a snapshot
/// (its SHA-256, per framework: zlib compresses differently from .NET 9 on). It reads back with the new objects in a
/// new revision.
/// </summary>
[Trait("Category", "Unit")]
public sealed class PdfIncrementalUpdateTests(ITestOutputHelper output)
{
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
    public void Finish_Fixture_IsItsSnapshot(string fixture) =>
        AssertUpdate("fixture:" + fixture, File.ReadAllBytes(ParityCorpus.Fixtures[fixture]));

    [Theory]
    [MemberData(nameof(GeneratedDocuments))]
    public void Finish_GeneratedDocument_IsItsSnapshot(string name) =>
        AssertUpdate("generated:" + name, ParityCorpus.Generated[name]());

    private void AssertUpdate(string name, byte[] original)
    {
        var document = PdfDocument.Open(original);
        if (document.IsEncrypted || !original.AsSpan().StartsWith("%PDF-"u8) || document.Catalog is null)
        {
            output.WriteLine("skipped: encrypted, not a PDF or no catalog");
            return;
        }

        int first = document.View().NextObjectNumber;
        int root = document.RootId!.Value.Number;
        var update = new PdfIncrementalUpdate(document);
        update.Add(first, Encoding.Latin1.GetBytes($"{first} 0 obj\n<< /Producer (test) >>\nendobj\n"));
        update.Add(first + 1, Encoding.Latin1.GetBytes($"{first + 1} 0 obj\n[1 2 3]\nendobj\n"));
        byte[] actual = update.Finish(first + 2, root);

        // It reads back: the new objects in a new revision, the old ones kept.
        var updated = PdfDocument.Open(actual);
        updated.Revisions.Count.ShouldBe(document.Revisions.Count + 1);
        updated.GetObject(first).ShouldNotBeNull();
        updated.GetObject(first + 1)!.Value.ShouldBeOfType<PdfArray>();
        updated.RootId.ShouldBe(document.RootId);

        Snapshot.MatchCompressed("writing/incremental-update", name, actual);
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

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void DocumentUsesXrefStream_LatestSection_SaysWhichTheUpdateWrites(bool stream)
    {
        var builder = new PdfFileBuilder().Object(1, "<< /Type /Catalog >>")
            .EndRevision(stream ? XrefStyle.Stream : XrefStyle.Table, stream ? new RevisionOptions { XrefStreamNumber = 2 } : null);

        new PdfIncrementalUpdate(PdfDocument.Open(builder.ToArray())).DocumentUsesXrefStream.ShouldBe(stream);
    }

    [Fact]
    public void DocumentUsesXrefStream_NoStartxref_WritesATable()
    {
        byte[] pdf = Encoding.Latin1.GetBytes("%PDF-1.7\n1 0 obj\n<< /Type /Catalog >>\nendobj\ntrailer\n<< /Root 1 0 R >>\n%%EOF\n");

        new PdfIncrementalUpdate(PdfDocument.Open(pdf)).DocumentUsesXrefStream.ShouldBeFalse();
    }
}

