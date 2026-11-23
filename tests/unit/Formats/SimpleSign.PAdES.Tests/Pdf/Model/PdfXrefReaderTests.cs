using System.Text;
using Shouldly;
using SimpleSign.PAdES.Pdf.Model;
using SimpleSign.PAdES.Tests.Pdf.Parity;
using Xunit;

namespace SimpleSign.PAdES.Tests.Pdf.Model;

/// <summary>Reading cross-reference sections (ISO 32000-1 §7.5.4, §7.5.8) and rebuilding them (ADR 0032).</summary>
[Trait("Category", "Unit")]
public sealed class PdfXrefReaderTests
{
    private static PdfFileBuilder ThreeObjects() => new PdfFileBuilder()
        .Object(1, "<< /Type /Catalog /Pages 2 0 R >>")
        .Object(2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
        .Object(3, "<< /Type /Page /Parent 2 0 R >>");

    private static (PdfXrefChain Chain, PdfParseContext Context) Read(byte[] pdf)
    {
        var context = new PdfParseContext();
        return (PdfXrefReader.ReadChain(pdf, context), context);
    }

    [Fact]
    public void ReadChain_Table_ReadsEntriesAndTrailer()
    {
        var builder = ThreeObjects().EndRevision();
        var (chain, context) = Read(builder.ToArray());

        chain.Complete.ShouldBeTrue();
        chain.StartXref.ShouldBe(builder.XrefOffsets[0]);
        var section = chain.Sections.ShouldHaveSingleItem();
        section.Kind.ShouldBe(PdfXrefSectionKind.Table);
        section.Entries[2].ShouldBe(PdfXrefEntry.InUse(builder.ObjectOffsets[(2, 0)], 0));
        section.Entries.ContainsKey(0).ShouldBeFalse();
        section.Trailer.Get(PdfName.Root).ShouldBeOfType<PdfReference>().Id.ShouldBe(new PdfObjectId(1, 0));
        context.Diagnostics.Count.ShouldBe(0);
    }

    [Fact]
    public void ReadChain_CrLfEntries_ReadsEntries()
    {
        var builder = ThreeObjects().EndRevision(options: new RevisionOptions { EntryEnd = "\r\n" });

        Read(builder.ToArray()).Chain.Sections[0].Entries.Count.ShouldBe(3);
    }

    [Fact]
    public void ReadChain_IncrementalUpdates_FollowsPrevNewestFirst()
    {
        var builder = ThreeObjects().EndRevision()
            .Object(3, "<< /Type /Page /Parent 2 0 R /Rotate 90 >>").EndRevision()
            .Object(4, "(new)").EndRevision(XrefStyle.Stream, new RevisionOptions { XrefStreamNumber = 5 });

        var (chain, _) = Read(builder.ToArray());

        chain.Sections.Select(s => s.Offset).ShouldBe(Enumerable.Reverse(builder.XrefOffsets));
        chain.Sections[0].Kind.ShouldBe(PdfXrefSectionKind.Stream);
        chain.Sections[1].Entries.Keys.ShouldBe([3]);
    }

    [Fact]
    public void ReadChain_XrefStreamWithPredictor_ReadsEntries()
    {
        var builder = ThreeObjects().EndRevision(XrefStyle.Stream, new RevisionOptions { XrefStreamNumber = 4, Predictor = true });

        var section = Read(builder.ToArray()).Chain.Sections.ShouldHaveSingleItem();

        section.Kind.ShouldBe(PdfXrefSectionKind.Stream);
        section.Entries[3].ShouldBe(PdfXrefEntry.InUse(builder.ObjectOffsets[(3, 0)], 0));
        section.Entries[4].Offset.ShouldBe(builder.XrefOffsets[0]);
    }

    [Fact]
    public void ReadChain_CompressedObjects_ReadsType2Entries()
    {
        var builder = new PdfFileBuilder()
            .Compressed(1, "<< /Type /Catalog /Pages 2 0 R >>")
            .Compressed(2, "<< /Type /Pages /Kids [] /Count 0 >>")
            .EndRevision(XrefStyle.Stream, new RevisionOptions { XrefStreamNumber = 4, ObjectStreamNumber = 3 });

        var section = Read(builder.ToArray()).Chain.Sections.ShouldHaveSingleItem();

        section.Entries[1].ShouldBe(PdfXrefEntry.Compressed(3, 0));
        section.Entries[2].ShouldBe(PdfXrefEntry.Compressed(3, 1));
    }

    [Fact]
    public void ReadChain_Hybrid_AddsTheXRefStmEntries()
    {
        var builder = new PdfFileBuilder()
            .Object(1, "<< /Type /Catalog /Pages 2 0 R >>")
            .Compressed(2, "<< /Type /Pages /Kids [] /Count 0 >>")
            .EndRevision(XrefStyle.Hybrid, new RevisionOptions { XrefStreamNumber = 4, ObjectStreamNumber = 3 });

        var section = Read(builder.ToArray()).Chain.Sections.ShouldHaveSingleItem();

        section.Kind.ShouldBe(PdfXrefSectionKind.Table);
        section.XrefStream.ShouldNotBeNull();
        section.Entries[1].Type.ShouldBe(PdfXrefEntryType.InUse);
        section.Entries[2].ShouldBe(PdfXrefEntry.Compressed(3, 0));
    }

    [Fact]
    public void ReadChain_FreeEntry_IsKept()
    {
        var builder = ThreeObjects().EndRevision().Free(3, 1).Object(2, "<< /Type /Pages /Kids [] /Count 0 >>").EndRevision();

        Read(builder.ToArray()).Chain.Sections[0].Entries[3].ShouldBe(PdfXrefEntry.Free(1));
    }

    [Fact]
    public void ReadChain_ShiftedSubsection_ReadsFromZero()
    {
        var builder = ThreeObjects().EndRevision(options: new RevisionOptions { ShiftedSubsection = true });

        var (chain, context) = Read(builder.ToArray());

        chain.Sections[0].Entries[1].Offset.ShouldBe(builder.ObjectOffsets[(1, 0)]);
        chain.Sections[0].Entries.ContainsKey(4).ShouldBeFalse();
        context.Diagnostics.Has(PdfRepairKind.XrefSubsectionShifted).ShouldBeTrue();
    }

    [Fact]
    public void ReadChain_PrevLoop_StopsAndRecords()
    {
        var builder = ThreeObjects().EndRevision().Object(3, "<< /Type /Page >>");

        // The update's table starts where the builder is now: its /Prev points at itself.
        builder.EndRevision(options: new RevisionOptions { Prev = builder.Position });
        var (chain, context) = Read(builder.ToArray());

        chain.Sections.ShouldHaveSingleItem().Offset.ShouldBe(builder.XrefOffsets[1]);
        chain.Complete.ShouldBeFalse();
        context.Diagnostics.Has(PdfRepairKind.PrevLoop).ShouldBeTrue();
    }

    [Fact]
    public void ReadChain_StartXrefOffByAFewBytes_FindsTheSectionNearby()
    {
        var builder = ThreeObjects();
        builder.EndRevision(options: new RevisionOptions { OmitStartXref = true });
        builder.Raw($"startxref\n{builder.XrefOffsets[0] - 3}\n%%EOF\n");

        var (chain, context) = Read(builder.ToArray());

        chain.Sections.ShouldHaveSingleItem().Offset.ShouldBe(builder.XrefOffsets[0]);
        context.Diagnostics.Has(PdfRepairKind.XrefOffsetWrong).ShouldBeTrue();
    }

    [Fact]
    public void ReadChain_NoStartXref_ReturnsEmptyIncompleteChain()
    {
        var builder = ThreeObjects().EndRevision(options: new RevisionOptions { OmitStartXref = true });

        var (chain, context) = Read(builder.ToArray());

        chain.StartXref.ShouldBe(-1);
        chain.Sections.ShouldBeEmpty();
        chain.Complete.ShouldBeFalse();
        context.Diagnostics.Has(PdfRepairKind.StartXrefMissing).ShouldBeTrue();
    }

    [Fact]
    public void ReadChain_TooManySections_StopsAtTheLimit()
    {
        var builder = ThreeObjects().EndRevision();
        for (int i = 0; i < 4; i++)
        {
            builder.Object(3, $"<< /Type /Page /N {i} >>").EndRevision();
        }

        var context = new PdfParseContext(new PdfReadLimits { MaxXrefSections = 2 });
        var chain = PdfXrefReader.ReadChain(builder.ToArray(), context);

        chain.Sections.Count.ShouldBe(2);
        chain.Complete.ShouldBeFalse();
        context.Diagnostics.Has(PdfRepairKind.TooManyXrefSections).ShouldBeTrue();
    }

    [Fact]
    public void ReadChain_GarbageAtTheXrefOffset_IsUnreadable()
    {
        byte[] pdf = Encoding.Latin1.GetBytes("%PDF-1.7\nnot a section at all\nstartxref\n9\n%%EOF\n");

        var (chain, context) = Read(pdf);

        chain.Sections.ShouldBeEmpty();
        chain.Complete.ShouldBeFalse();
        context.Diagnostics.Has(PdfRepairKind.XrefSectionUnreadable).ShouldBeTrue();
    }

    [Fact]
    public void Reconstruct_LastHeaderWinsAndTrailerIsFound()
    {
        var builder = ThreeObjects().EndRevision()
            .Object(3, "<< /Type /Page /Rotate 90 >>").EndRevision(options: new RevisionOptions { OmitStartXref = true });
        var context = new PdfParseContext();

        var section = PdfXrefReader.Reconstruct(builder.ToArray(), context);

        section.Kind.ShouldBe(PdfXrefSectionKind.Reconstructed);
        section.Entries[3].Offset.ShouldBe(builder.ObjectOffsets[(3, 0)]);
        section.Trailer.Get(PdfName.Root).ShouldBeOfType<PdfReference>().Id.Number.ShouldBe(1);
        context.Diagnostics.Has(PdfRepairKind.XrefRebuilt).ShouldBeTrue();
    }

    [Fact]
    public void Reconstruct_NoTrailer_UsesTheLastCatalog()
    {
        byte[] pdf = Encoding.Latin1.GetBytes(
            "%PDF-1.4\n7 0 obj\n<< /Type /Catalog /Pages 8 0 R >>\nendobj\n8 0 obj\n<< /Type /Pages /Kids [] /Count 0 >>\nendobj\n");
        var context = new PdfParseContext();

        var section = PdfXrefReader.Reconstruct(pdf, context);

        section.Trailer.Get(PdfName.Root).ShouldBeOfType<PdfReference>().Id.Number.ShouldBe(7);
        section.Trailer.Get(PdfName.Size).ShouldBeOfType<PdfInteger>().Value.ShouldBe(9);
        context.Diagnostics.Has(PdfRepairKind.TrailerMissing).ShouldBeTrue();
    }

    [Fact]
    public void ScanObjectHeaders_SkipsEndobjAndNumbersInsideTokens()
    {
        byte[] data = Encoding.Latin1.GetBytes("1 0 obj (x) endobj\r\n12 3 obj<<>>endobj x5 0 obj 7 0 objx 8 0 obj");

        var headers = PdfXrefReader.ScanObjectHeaders(data, PdfReadLimits.Default);

        headers.Select(h => h.Id).ShouldBe([new PdfObjectId(1, 0), new PdfObjectId(12, 3), new PdfObjectId(8, 0)]);
        headers[1].Offset.ShouldBe(20);
    }
}
