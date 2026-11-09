using System.Text;
using Shouldly;
using SimpleSign.Core.Validation.Policy;
using SimpleSign.PAdES.Pdf;
using Xunit;

namespace SimpleSign.PAdES.Tests.Pdf;

[Trait("Category", "Unit")]
public sealed class PdfRevisionComparerTests
{
    private const string SignedRevision = """
        %PDF-1.7
        1 0 obj
        << /Type /Catalog /Pages 2 0 R /AcroForm << /Fields [5 0 R 7 0 R] /SigFlags 3 >> >>
        endobj
        2 0 obj
        << /Type /Pages /Kids [3 0 R] /Count 1 >>
        endobj
        3 0 obj
        << /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Annots [5 0 R 7 0 R] >>
        endobj
        4 0 obj
        << /Length 0 >>
        stream

        endstream
        endobj
        5 0 obj
        << /FT /Tx /T (name) /Subtype /Widget /Rect [10 10 100 30] /P 3 0 R >>
        endobj
        6 0 obj
        << /Type /Sig /Filter /Adobe.PPKLite /SubFilter /ETSI.CAdES.detached
           /Reference [<< /Type /SigRef /TransformMethod /FieldMDP /TransformParams << /Type /TransformParams /Action /Include /Fields [(name)] /V /1.2 >> >>] >>
        endobj
        7 0 obj
        << /FT /Sig /T (Sig1) /Subtype /Widget /Rect [0 0 0 0] /V 6 0 R /P 3 0 R /Lock << /Type /SigFieldLock /Action /All >> >>
        endobj
        trailer
        << /Root 1 0 R /Size 8 >>
        %%EOF

        """;

    [Fact]
    public void Compare_NoLaterRevision_NoChanges()
    {
        var changes = Compare(SignedRevision, "");

        changes.SignedPageCount.ShouldBe(1);
        changes.FinalPageCount.ShouldBe(1);
        changes.Undefined.ShouldBeEmpty();
        changes.FieldMdp.ShouldBe(new PdfFieldLock("Include", ["name"]), new LockComparer());
        changes.SigFieldLock!.Action.ShouldBe("All");
    }

    [Fact]
    public void Compare_FieldFilled_FormFillOnLockedField()
    {
        var changes = Compare(SignedRevision, """
            5 0 obj
            << /FT /Tx /T (name) /V (Ann) /Subtype /Widget /Rect [10 10 100 30] /P 3 0 R >>
            endobj
            """);

        changes.FormFills.Count.ShouldBe(1);
        changes.ChangedFields.ShouldBe(["name"]);
        changes.Undefined.ShouldBeEmpty();
        changes.Annotations.ShouldBeEmpty();
        changes.FieldMdp!.Violations(changes.ChangedFields).ShouldBe(["name"]);
    }

    [Fact]
    public void Compare_AnnotationAdded_AnnotationChangeAndOverlap()
    {
        var changes = Compare(SignedRevision, """
            8 0 obj
            << /Type /Annot /Subtype /Text /Rect [50 20 60 40] /Contents (note) >>
            endobj
            3 0 obj
            << /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Annots [5 0 R 7 0 R 8 0 R] >>
            endobj
            """);

        changes.Annotations.Count.ShouldBe(1);
        changes.AnnotationsOverlap.ShouldBeTrue();
        changes.Undefined.ShouldBeEmpty();
    }

    [Fact]
    public void Compare_PageContentReplaced_UndefinedChange()
    {
        var changes = Compare(SignedRevision, """
            9 0 obj
            << /Length 0 >>
            stream

            endstream
            endobj
            3 0 obj
            << /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 9 0 R /Annots [5 0 R 7 0 R] >>
            endobj
            """);

        changes.Undefined.ShouldHaveSingleItem().ShouldContain("Page 1");
    }

    [Fact]
    public void Compare_PageAdded_PageCountsDiffer()
    {
        var changes = Compare(SignedRevision, """
            10 0 obj
            << /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>
            endobj
            2 0 obj
            << /Type /Pages /Kids [3 0 R 10 0 R] /Count 2 >>
            endobj
            """);

        changes.SignedPageCount.ShouldBe(1);
        changes.FinalPageCount.ShouldBe(2);
        changes.Undefined.ShouldBeEmpty();
    }

    [Theory]
    [InlineData("/ETSI.CAdES.detached", 1)]
    [InlineData("/ETSI.RFC3161", 0)]
    public void Compare_SignatureAdded_SignatureChangeUnlessDocumentTimestamp(string subFilter, int signatures)
    {
        var changes = Compare(SignedRevision, $"""
            11 0 obj
            << /Type /Sig /SubFilter {subFilter} /ByteRange [0 0 0 0] /Contents <00> >>
            endobj
            12 0 obj
            << /FT /Sig /T (Sig2) /Subtype /Widget /Rect [0 0 0 0] /V 11 0 R /P 3 0 R >>
            endobj
            3 0 obj
            << /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Annots [5 0 R 7 0 R 12 0 R] >>
            endobj
            1 0 obj
            << /Type /Catalog /Pages 2 0 R /AcroForm << /Fields [5 0 R 7 0 R 12 0 R] /SigFlags 3 >> /DSS 13 0 R >>
            endobj
            13 0 obj
            << /Type /DSS /Certs [14 0 R] >>
            endobj
            14 0 obj
            << /Length 1 >>
            stream
            0
            endstream
            endobj
            """);

        changes.Signatures.Count.ShouldBe(signatures);
        changes.Undefined.ShouldBeEmpty();
        changes.Annotations.ShouldBeEmpty();
        changes.AnnotationsOverlap.ShouldBeFalse();
    }

    [Fact]
    public void Compare_CatalogChanged_UndefinedChange()
    {
        var changes = Compare(SignedRevision, """
            1 0 obj
            << /Type /Catalog /Pages 2 0 R /AcroForm << /Fields [5 0 R 7 0 R] /SigFlags 3 >> /OpenAction [3 0 R /Fit] >>
            endobj
            """);

        changes.Undefined.ShouldHaveSingleItem().ShouldContain("catalog");
    }

    [Fact]
    public void Compare_ChangeInsideObjectStream_IsFound()
    {
        const string objects = "3 0 << /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 9 0 R /Annots [5 0 R 7 0 R] >>";
        string header = "3 0 ";
        var changes = Compare(SignedRevision, $"""
            15 0 obj
            << /Type /ObjStm /N 1 /First {header.Length} /Length {objects.Length} >>
            stream
            {objects}
            endstream
            endobj
            """);

        changes.Undefined.ShouldHaveSingleItem().ShouldContain("Page 1");
    }

    [Fact]
    public void Compare_DocMdpCertified_ReadsLevel()
    {
        string certified = SignedRevision.Replace(
            "/TransformMethod /FieldMDP /TransformParams << /Type /TransformParams /Action /Include /Fields [(name)] /V /1.2 >>",
            "/TransformMethod /DocMDP /TransformParams << /Type /TransformParams /P 2 /V /1.2 >>", StringComparison.Ordinal);

        var changes = Compare(certified, """
            5 0 obj
            << /FT /Tx /T (name) /V (Ann) /Subtype /Widget /Rect [10 10 100 30] /P 3 0 R >>
            endobj
            """);

        changes.DocMdpLevel.ShouldBe(2);
        changes.DocMdpViolations.ShouldBeEmpty();
        changes.FieldMdp.ShouldBeNull();
    }

    private static PdfChangeFacts Compare(string signed, string later)
    {
        byte[] pdf = Encoding.Latin1.GetBytes(signed + later);
        return PdfRevisionComparer.Compare(PdfObjectIndex.Build(pdf), pdf, Encoding.Latin1.GetByteCount(signed), 6);
    }

    private sealed class LockComparer : IEqualityComparer<PdfFieldLock>
    {
        public bool Equals(PdfFieldLock? x, PdfFieldLock? y) => x?.Action == y?.Action && (x?.Fields ?? []).SequenceEqual(y?.Fields ?? []);

        public int GetHashCode(PdfFieldLock obj) => obj.Action.GetHashCode(StringComparison.Ordinal);
    }
}
