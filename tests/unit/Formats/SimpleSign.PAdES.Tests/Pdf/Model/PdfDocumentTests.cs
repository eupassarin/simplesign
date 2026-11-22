using System.Text;
using Shouldly;
using SimpleSign.PAdES.Pdf.Exceptions;
using SimpleSign.PAdES.Pdf.Model;
using SimpleSign.PAdES.Tests.Pdf.Parity;
using Xunit;

namespace SimpleSign.PAdES.Tests.Pdf.Model;

/// <summary>A document read through its cross-reference, by revision (ADR 0032).</summary>
[Trait("Category", "Unit")]
public sealed class PdfDocumentTests
{
    private static PdfFileBuilder ThreeObjects() => new PdfFileBuilder()
        .Object(1, "<< /Type /Catalog /Pages 2 0 R >>")
        .Object(2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
        .Object(3, "<< /Type /Page /Parent 2 0 R >>");

    private static string? Text(PdfIndirectObject? obj) =>
        obj?.Value is PdfDictionary d && d.Get("Tag") is PdfString s ? s.Text : null;

    [Fact]
    public void Open_SingleRevision_ReadsCatalogAndVersion()
    {
        var builder = ThreeObjects().EndRevision();
        byte[] pdf = builder.ToArray();

        var doc = PdfDocument.Open(pdf);

        doc.Version.ShouldBe("1.7");
        doc.Revisions.ShouldHaveSingleItem().EndOffset.ShouldBe(pdf.Length);
        doc.RootId.ShouldBe(new PdfObjectId(1, 0));
        doc.Catalog.ShouldNotBeNull().Get(PdfName.Type).ShouldBe(PdfName.Of("Catalog"));
        doc.IsReconstructed.ShouldBeFalse();
        doc.IsEncrypted.ShouldBeFalse();
        doc.IsLinearized.ShouldBeFalse();
        doc.NextObjectNumber.ShouldBe(4);
        doc.ObjectNumbers().ShouldBe([1, 2, 3]);
        doc.Diagnostics.Count.ShouldBe(0);
    }

    [Fact]
    public void GetObject_EachRevision_SeesItsOwnVersion()
    {
        var builder = ThreeObjects().EndRevision()
            .Object(3, "<< /Type /Page /Tag (second) >>").EndRevision()
            .Object(3, "<< /Type /Page /Tag (third) >>").EndRevision(XrefStyle.Stream, new RevisionOptions { XrefStreamNumber = 4 });

        var doc = PdfDocument.Open(builder.ToArray());

        doc.Revisions.Count.ShouldBe(3);
        doc.Revisions.Select(r => r.EndOffset).ShouldBe(builder.RevisionEnds);
        Text(doc.GetObject(3, doc.Revisions[0])).ShouldBeNull();
        Text(doc.GetObject(3, doc.Revisions[1])).ShouldBe("second");
        Text(doc.GetObject(3)).ShouldBe("third");
        doc.GetObject(4, doc.Revisions[1]).ShouldBeNull();
        doc.Revisions[2].Previous.ShouldBeSameAs(doc.Revisions[1]);
    }

    [Fact]
    public void GetObject_FreedInAnUpdate_IsNullFromThatRevisionOn()
    {
        var builder = ThreeObjects().EndRevision()
            .Free(3, 1).Object(2, "<< /Type /Pages /Kids [] /Count 0 >>").EndRevision();

        var doc = PdfDocument.Open(builder.ToArray());

        doc.Lookup(3).ShouldBe(PdfXrefEntry.Free(1));
        doc.GetObject(3).ShouldBeNull();
        doc.GetObject(3, doc.Revisions[0]).ShouldNotBeNull();
        doc.ObjectNumbers().ShouldBe([1, 2]);
    }

    [Fact]
    public void GetObject_Compressed_ReadsFromTheObjectStream()
    {
        var builder = new PdfFileBuilder()
            .Compressed(1, "<< /Type /Catalog /Pages 2 0 R >>")
            .Compressed(2, "<< /Type /Pages /Kids [] /Count 0 /Tag (in objstm) >>")
            .EndRevision(XrefStyle.Stream, new RevisionOptions { XrefStreamNumber = 4, ObjectStreamNumber = 3, Predictor = true });

        var doc = PdfDocument.Open(builder.ToArray());

        doc.Catalog.ShouldNotBeNull();
        var pages = doc.GetObject(2).ShouldNotBeNull();
        pages.Id.ShouldBe(new PdfObjectId(2, 0));
        Text(pages).ShouldBe("in objstm");
        doc.GetObject(new PdfObjectId(2, 1)).ShouldBeNull();
        doc.Diagnostics.Count.ShouldBe(0);
    }

    [Fact]
    public void GetObject_Hybrid_FindsTheCompressedObject()
    {
        var builder = new PdfFileBuilder()
            .Object(1, "<< /Type /Catalog /Pages 2 0 R >>")
            .Compressed(2, "<< /Type /Pages /Kids [] /Count 0 /Tag (hidden) >>")
            .EndRevision(XrefStyle.Hybrid, new RevisionOptions { XrefStreamNumber = 4, ObjectStreamNumber = 3 });

        Text(PdfDocument.Open(builder.ToArray()).GetObject(2)).ShouldBe("hidden");
    }

    [Fact]
    public void GetObject_GenerationAboveZero_MatchesTheGeneration()
    {
        var builder = ThreeObjects().Object(4, "<< /Tag (gen two) >>", generation: 2).EndRevision();

        var doc = PdfDocument.Open(builder.ToArray());

        Text(doc.GetObject(new PdfObjectId(4, 2))).ShouldBe("gen two");
        doc.GetObject(new PdfObjectId(4, 0)).ShouldBeNull();
        doc.Resolve(new PdfReference(4, 0)).ShouldBeNull();
        doc.Resolve(new PdfReference(4, 2)).ShouldBeOfType<PdfDictionary>();
    }

    [Fact]
    public void GetObject_OffsetsThatMissTheirObjects_AreFoundByHeader()
    {
        var builder = ThreeObjects().EndRevision(options: new RevisionOptions { OffsetShift = 2 });

        var doc = PdfDocument.Open(builder.ToArray());

        doc.Catalog.ShouldNotBeNull();
        doc.GetObject(3).ShouldNotBeNull().Source.Offset.ShouldBe(builder.ObjectOffsets[(3, 0)]);
        doc.Diagnostics.Has(PdfRepairKind.ObjectOffsetWrong).ShouldBeTrue();
    }

    [Fact]
    public void Open_NoStartXref_RebuildsTheCrossReference()
    {
        var builder = ThreeObjects().EndRevision(options: new RevisionOptions { OmitStartXref = true });

        var doc = PdfDocument.Open(builder.ToArray());

        doc.IsReconstructed.ShouldBeTrue();
        doc.Catalog.ShouldNotBeNull();
        doc.GetObject(3).ShouldNotBeNull();
        doc.Diagnostics.Has(PdfRepairKind.XrefRebuilt).ShouldBeTrue();
    }

    [Fact]
    public void Open_RebuiltWithObjectStream_FindsCompressedObjects()
    {
        var builder = new PdfFileBuilder()
            .Compressed(1, "<< /Type /Catalog /Pages 2 0 R >>")
            .Compressed(2, "<< /Type /Pages /Kids [] /Count 0 /Tag (rebuilt) >>")
            .EndRevision(XrefStyle.Stream, new RevisionOptions { XrefStreamNumber = 4, ObjectStreamNumber = 3, OmitStartXref = true });

        var doc = PdfDocument.Open(builder.ToArray());

        doc.IsReconstructed.ShouldBeTrue();
        doc.RootId.ShouldBe(new PdfObjectId(1, 0));
        Text(doc.GetObject(2)).ShouldBe("rebuilt");
    }

    [Fact]
    public void GetObject_ChainCutShort_FindsOlderObjectsByHeader()
    {
        var builder = ThreeObjects().EndRevision();
        for (int i = 0; i < 3; i++)
        {
            builder.Object(2, $"<< /Type /Pages /Kids [3 0 R] /Count 1 /N {i} >>").EndRevision();
        }

        var doc = PdfDocument.Open(builder.ToArray(), new PdfReadLimits { MaxXrefSections = 2 });

        doc.Revisions.Count.ShouldBe(2);
        doc.GetObject(3).ShouldNotBeNull();
        doc.Catalog.ShouldNotBeNull();
    }

    [Fact]
    public void Open_Linearized_MergesTheFirstPageSectionIntoOneRevision()
    {
        // Two passes: the first-page section's /Prev is the main section's offset, known only once written.
        long main = 1000;
        PdfFileBuilder builder;
        while (true)
        {
            builder = new PdfFileBuilder()
                .Object(10, "<< /Linearized 1 /L 0 >>")
                .Object(1, "<< /Type /Catalog /Pages 2 0 R >>")
                .Object(2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>");
            builder.EndRevision(options: new RevisionOptions { Prev = main, OmitStartXref = true });
            long firstPage = builder.XrefOffsets[0];
            builder.Object(3, "<< /Type /Page /Parent 2 0 R >>")
                .EndRevision(options: new RevisionOptions { NoPrev = true, StartXref = firstPage });
            if (builder.XrefOffsets[1] == main)
            {
                break;
            }

            main = builder.XrefOffsets[1];
        }

        var doc = PdfDocument.Open(builder.ToArray());

        doc.IsLinearized.ShouldBeTrue();
        var revision = doc.Revisions.ShouldHaveSingleItem();
        revision.Sections.Count.ShouldBe(2);
        revision.Trailer.Get(PdfName.Root).ShouldNotBeNull();
        doc.GetObject(3).ShouldNotBeNull();
        doc.Catalog.ShouldNotBeNull();
    }

    [Fact]
    public void GetObject_IndirectLength_IsResolved()
    {
        var builder = new PdfFileBuilder()
            .Object(1, "<< /Type /Catalog /Pages 2 0 R >>")
            .Object(2, "<< /Type /Pages /Kids [] /Count 0 >>")
            .Object(3, "<< /Length 4 0 R >>\nstream\nhello endstream world\nendstream")
            .Object(4, "21")
            .EndRevision();

        var doc = PdfDocument.Open(builder.ToArray());

        var stream = doc.GetObject(3)?.Value.ShouldBeOfType<PdfStream>();
        Encoding.ASCII.GetString(stream!.Encoded.Span).ShouldBe("hello endstream world");
        doc.Diagnostics.Has(PdfRepairKind.StreamLength).ShouldBeFalse();
    }

    [Fact]
    public void GetObject_LengthThatPointsToItself_DoesNotRecurse()
    {
        var builder = new PdfFileBuilder()
            .Object(1, "<< /Type /Catalog /Pages 2 0 R >>")
            .Object(2, "<< /Type /Pages /Kids [] /Count 0 >>")
            .Object(3, "<< /Length 3 0 R >>\nstream\nabc\nendstream")
            .EndRevision();

        var doc = PdfDocument.Open(builder.ToArray());

        var stream = doc.GetObject(3)?.Value.ShouldBeOfType<PdfStream>();
        Encoding.ASCII.GetString(stream!.Encoded.Span).ShouldBe("abc");
    }

    [Fact]
    public void Resolve_TooManyHops_ReturnsNull()
    {
        var builder = ThreeObjects()
            .Object(4, "5 0 R").Object(5, "6 0 R").Object(6, "7 0 R").Object(7, "(end)")
            .EndRevision();

        var doc = PdfDocument.Open(builder.ToArray(), new PdfReadLimits { MaxReferenceHops = 3 });

        doc.Resolve(new PdfReference(5, 0)).ShouldBeOfType<PdfString>();
        doc.Resolve(new PdfReference(4, 0)).ShouldBeNull();
        doc.Diagnostics.Has(PdfRepairKind.ReferenceHopsExceeded).ShouldBeTrue();
    }

    [Fact]
    public void Resolve_ReferenceCycle_ReturnsNull()
    {
        var builder = ThreeObjects().Object(4, "5 0 R").Object(5, "4 0 R").EndRevision();

        PdfDocument.Open(builder.ToArray()).Resolve(new PdfReference(4, 0)).ShouldBeNull();
    }

    [Fact]
    public void GetObject_ObjectStreamsOverBudget_AreNotDecoded()
    {
        var builder = new PdfFileBuilder()
            .Object(1, "<< /Type /Catalog /Pages 2 0 R >>")
            .Compressed(2, "<< /Type /Pages /Kids [] /Count 0 /Pad (" + new string('x', 2000) + ") >>")
            .EndRevision(XrefStyle.Stream, new RevisionOptions { XrefStreamNumber = 4, ObjectStreamNumber = 3 });

        var doc = PdfDocument.Open(builder.ToArray(), new PdfReadLimits { MaxTotalObjectStreamBytes = 100 });

        doc.GetObject(2).ShouldBeNull();
        doc.Diagnostics.Has(PdfRepairKind.ObjectStreamBudgetExceeded).ShouldBeTrue();
    }

    [Fact]
    public void DecodeStream_FlateWithIndirectFilter_Decodes()
    {
        var builder = ThreeObjects()
            .Stream(4, "/Filter 5 0 R", PdfFileBuilder.Zlib(Encoding.ASCII.GetBytes("decoded!")))
            .Object(5, "/FlateDecode")
            .EndRevision();
        var doc = PdfDocument.Open(builder.ToArray());

        var stream = doc.GetObject(4)!.Value.ShouldBeOfType<PdfStream>();

        Encoding.ASCII.GetString(doc.DecodeStream(stream)).ShouldBe("decoded!");
    }

    [Fact]
    public void GetObject_FromManyThreads_GivesTheSameObjects()
    {
        var builder = ThreeObjects();
        for (int i = 4; i < 200; i++)
        {
            builder.Compressed(i, $"<< /N {i} >>");
        }

        var doc = PdfDocument.Open(builder.EndRevision(XrefStyle.Stream, new RevisionOptions { XrefStreamNumber = 201, ObjectStreamNumber = 200 }).ToArray());

        var results = new PdfIndirectObject?[200];
        Parallel.For(1, 200, i => results[i] = doc.GetObject(i));

        for (int i = 4; i < 200; i++)
        {
            results[i].ShouldNotBeNull().Value.ShouldBeOfType<PdfDictionary>().Get("N").ShouldBeOfType<PdfInteger>().Value.ShouldBe(i);
            doc.GetObject(i).ShouldBeSameAs(results[i]);
        }
    }

    [Fact]
    public void Open_Encrypted_IsReported()
    {
        var builder = ThreeObjects().Object(4, "<< /Filter /Standard >>").EndRevision(options: new RevisionOptions { TrailerExtra = "/Encrypt 4 0 R " });

        PdfDocument.Open(builder.ToArray()).IsEncrypted.ShouldBeTrue();
    }

    [Fact]
    public void Open_LargerThanTheLimit_Throws() =>
        Should.Throw<PdfStructureException>(() => PdfDocument.Open(new byte[100], new PdfReadLimits { MaxFileSize = 10 }));

    [Fact]
    public void Open_Garbage_GivesAnEmptyRebuiltDocument()
    {
        var doc = PdfDocument.Open(Encoding.ASCII.GetBytes("this is not a PDF"));

        doc.IsReconstructed.ShouldBeTrue();
        doc.Catalog.ShouldBeNull();
        doc.ObjectNumbers().ShouldBeEmpty();
    }
}
