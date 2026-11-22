using System.Text;
using Shouldly;
using SimpleSign.PAdES.Pdf.Model;
using SimpleSign.PAdES.Tests.Pdf.Parity;
using Xunit;

namespace SimpleSign.PAdES.Tests.Pdf.Model;

/// <summary>What a revision holds, read through the object model (ADR 0032).</summary>
[Trait("Category", "Unit")]
public sealed class PdfRevisionViewTests
{
    private static PdfRevisionView Latest(PdfFileBuilder builder) => PdfDocument.Open(builder.ToArray()).View();

    private static string Numbers(PdfArray? array) =>
        array is null ? "null" : string.Join(" ", array.Select(item => ((PdfInteger)item).Value));

    [Fact]
    public void Pages_NestedTree_InOrderWithInheritedAttributes()
    {
        var builder = new PdfFileBuilder()
            .Object(1, "<< /Type /Catalog /Pages 2 0 R >>")
            .Object(2, "<< /Type /Pages /Kids [3 0 R 4 0 R] /Count 3 /MediaBox [0 0 612 792] /Rotate 90 /Resources << /Font << >> >> >>")
            .Object(3, "<< /Type /Pages /Parent 2 0 R /Kids [5 0 R 6 0 R] /Count 2 /MediaBox [0 0 100 200] >>")
            .Object(4, "<< /Type /Page /Parent 2 0 R /Rotate 0 >>")
            .Object(5, "<< /Type /Page /Parent 3 0 R >>")
            .Object(6, "<< /Type /Page /Parent 3 0 R /MediaBox [0 0 300 400] /CropBox [10 10 290 390] >>")
            .EndRevision();

        var pages = Latest(builder).Pages;

        pages.Select(p => p.Id!.Value.Number).ShouldBe([5, 6, 4]);
        pages.Select(p => p.Index).ShouldBe([0, 1, 2]);
        Numbers(pages[0].MediaBox).ShouldBe("0 0 100 200");
        Numbers(pages[1].MediaBox).ShouldBe("0 0 300 400");
        Numbers(pages[1].CropBox).ShouldBe("10 10 290 390");
        Numbers(pages[2].MediaBox).ShouldBe("0 0 612 792");
        pages[0].Rotate.ShouldBe(90);
        pages[2].Rotate.ShouldBe(0);
        pages.ShouldAllBe(p => p.Resources != null);
    }

    [Fact]
    public void Pages_KidThatPointsBackToItsAncestor_IsReadOnce()
    {
        var builder = new PdfFileBuilder()
            .Object(1, "<< /Type /Catalog /Pages 2 0 R >>")
            .Object(2, "<< /Type /Pages /Kids [3 0 R 2 0 R] /Count 1 >>")
            .Object(3, "<< /Type /Page /Parent 2 0 R >>")
            .EndRevision();
        var doc = PdfDocument.Open(builder.ToArray());

        doc.View().Pages.ShouldHaveSingleItem();
        doc.Diagnostics.Has(PdfRepairKind.TreeCycle).ShouldBeTrue();
    }

    [Fact]
    public void Pages_DeeperThanTheLimit_AreNotRead()
    {
        var builder = new PdfFileBuilder().Object(1, "<< /Type /Catalog /Pages 2 0 R >>");
        for (int n = 2; n < 12; n++)
        {
            builder.Object(n, $"<< /Type /Pages /Kids [{n + 1} 0 R] /Count 1 >>");
        }

        builder.Object(12, "<< /Type /Page >>").EndRevision();
        var doc = PdfDocument.Open(builder.ToArray(), new PdfReadLimits { MaxTreeDepth = 5 });

        doc.View().Pages.ShouldBeEmpty();
        doc.Diagnostics.Has(PdfRepairKind.TreeTooDeep).ShouldBeTrue();
    }

    [Fact]
    public void Pages_MoreThanTheLimit_StopAtIt()
    {
        var builder = new PdfFileBuilder()
            .Object(1, "<< /Type /Catalog /Pages 2 0 R >>")
            .Object(2, "<< /Type /Pages /Kids [3 0 R 3 0 R 3 0 R] /Count 3 >>")
            .Object(3, "<< /Type /Page >>")
            .Object(4, "<< /Type /Pages /Kids [5 0 R 6 0 R 7 0 R] /Count 3 >>")
            .Object(5, "<< /Type /Page >>").Object(6, "<< /Type /Page >>").Object(7, "<< /Type /Page >>")
            .Root(8).Object(8, "<< /Type /Catalog /Pages 4 0 R >>")
            .EndRevision();
        var doc = PdfDocument.Open(builder.ToArray(), new PdfReadLimits { MaxPages = 2 });

        doc.View().Pages.Count.ShouldBe(2);
        doc.Diagnostics.Has(PdfRepairKind.TooManyPages).ShouldBeTrue();
    }

    private static PdfFileBuilder WithForm(string acroForm, params (int Number, string Body)[] objects)
    {
        var builder = new PdfFileBuilder()
            .Object(1, $"<< /Type /Catalog /Pages 2 0 R /AcroForm {acroForm} >>")
            .Object(2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
            .Object(3, "<< /Type /Page /Parent 2 0 R >>");
        foreach (var (number, body) in objects)
        {
            builder.Object(number, body);
        }

        return builder;
    }

    [Fact]
    public void AcroForm_Inline_HasNoObject()
    {
        var view = Latest(WithForm("<< /Fields [10 0 R] >>", (10, "<< /FT /Tx /T (name) >>")).EndRevision());

        view.AcroForm.ShouldNotBeNull();
        view.AcroFormId.ShouldBeNull();
        view.Fields.ShouldHaveSingleItem().FullName.ShouldBe("name");
    }

    [Fact]
    public void Fields_Tree_FullNamesInheritedTypeWidgetsLockAndSeedValue()
    {
        var view = Latest(WithForm(
            "9 0 R",
            (9, "<< /Fields [10 0 R 14 0 R] >>"),
            (10, "<< /T (form) /FT /Sig /Kids [11 0 R 12 0 R] >>"),
            (11, "<< /T (approval) /Parent 10 0 R /Lock 13 0 R /SV << /Type /SV /Ff 1 >> /Kids [15 0 R] >>"),
            (12, "<< /T (name) /FT /Tx /Parent 10 0 R /Subtype /Widget /Rect [0 0 10 10] >>"),
            (13, "<< /Type /SigFieldLock /Action /All >>"),
            (14, "<< /T (other) /FT /Btn >>"),
            (15, "<< /Subtype /Widget /Parent 11 0 R /Rect [0 0 0 0] >>")).EndRevision());

        view.AcroFormId.ShouldBe(new PdfObjectId(9, 0));
        view.Fields.Select(f => f.FullName).ShouldBe(["form", "form.approval", "form.name", "other"]);
        view.RootFields.Select(f => f.FullName).ShouldBe(["form", "other"]);

        var approval = view.Fields[1];
        approval.IsSignature.ShouldBeTrue();
        approval.PartialName.ShouldBe("approval");
        approval.Parent.ShouldBeSameAs(view.Fields[0]);
        approval.Lock.ShouldNotBeNull().Get("Action").ShouldBe(PdfName.Of("All"));
        approval.SeedValue.ShouldNotBeNull().Get("Ff").ShouldBeOfType<PdfInteger>().Value.ShouldBe(1);
        approval.Widgets.ShouldBe([new PdfObjectId(15, 0)]);

        var name = view.Fields[2];
        name.FieldType.ShouldBe("Tx");
        name.Widgets.ShouldBe([new PdfObjectId(12, 0)]);
        view.Fields[0].Kids.Count.ShouldBe(2);
    }

    private static PdfFileBuilder Signed(string extraCatalog = "", string signatureExtra = "")
    {
        var builder = new PdfFileBuilder()
            .Object(1, $"<< /Type /Catalog /Pages 2 0 R /AcroForm << /Fields [10 0 R 12 0 R] >> {extraCatalog} >>")
            .Object(2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
            .Object(3, "<< /Type /Page /Parent 2 0 R >>")
            .Object(10, "<< /FT /Sig /T (Sig1) /V 11 0 R /Subtype /Widget /Rect [0 0 0 0] >>")
            .Object(11, $"<< /Type /Sig /Filter /Adobe.PPKLite /SubFilter /ETSI.CAdES.detached /ByteRange [0 10 20 30] /Contents <0A0B0C> /Reason (ok) /M (D:20260101000000Z) {signatureExtra} >>")
            .Object(12, "<< /FT /Sig /T (Empty) /Subtype /Widget /Rect [0 0 0 0] >>")
            .Object(13, "<< /Type /DocTimeStamp /SubFilter /ETSI.RFC3161 /ByteRange [0 1 2 3] /Contents <00> >>");
        return builder;
    }

    [Fact]
    public void Signatures_HeldAndOrphan_InFileOrder()
    {
        var view = Latest(Signed().EndRevision());

        view.Signatures.Count.ShouldBe(2);
        var held = view.Signatures[0];
        held.Id.ShouldBe(new PdfObjectId(11, 0));
        held.Field.ShouldNotBeNull().FullName.ShouldBe("Sig1");
        held.ByteRange.ShouldBe([0L, 10, 20, 30]);
        held.Contents.ToArray().ShouldBe([0x0A, 0x0B, 0x0C]);
        held.Name("SubFilter").ShouldBe("ETSI.CAdES.detached");
        held.Text("Reason").ShouldBe("ok");
        held.Text("M").ShouldBe("D:20260101000000Z");
        held.IsDocumentTimestamp.ShouldBeFalse();
        held.IsUsageRights.ShouldBeFalse();

        var orphan = view.Signatures[1];
        orphan.Field.ShouldBeNull();
        orphan.IsDocumentTimestamp.ShouldBeTrue();
        view.Fields.Single(f => f.FullName == "Empty").Value.ShouldBeNull();
    }

    [Fact]
    public void Signatures_UsageRights_IsMarked()
    {
        var view = Latest(Signed(signatureExtra: "/Reference [<< /TransformMethod /UR3 >>]").EndRevision());

        view.Signatures[0].IsUsageRights.ShouldBeTrue();
    }

    [Fact]
    public void CertificationSignature_PermsDocMdp_GivesTheSignatureAndP()
    {
        var view = Latest(Signed(
            "/Perms << /DocMDP 11 0 R >>",
            "/Reference [<< /Type /SigRef /TransformMethod /DocMDP /TransformParams << /Type /TransformParams /P 2 /V /1.2 >> >>]").EndRevision());

        view.CertificationSignature.ShouldNotBeNull().Id.ShouldBe(new PdfObjectId(11, 0));
        view.DocMdpPermissions.ShouldBe(2);
    }

    [Fact]
    public void CertificationSignature_WithoutP_HasNoPermissions()
    {
        var view = Latest(Signed(
            "/Perms << /DocMDP 11 0 R >>",
            "/Reference [<< /TransformMethod /DocMDP /TransformParams << /V /1.2 >> >>]").EndRevision());

        view.CertificationSignature.ShouldNotBeNull();
        view.DocMdpPermissions.ShouldBeNull();
    }

    [Fact]
    public void CertificationSignature_WithoutPerms_IsTheSignatureWithADocMdpReference()
    {
        var view = Latest(Signed(
            signatureExtra: "/Reference [<< /TransformMethod /DocMDP /TransformParams << /P 3 >> >>]").EndRevision());

        view.CertificationSignature.ShouldNotBeNull().Id.ShouldBe(new PdfObjectId(11, 0));
        view.DocMdpPermissions.ShouldBe(3);
    }

    [Fact]
    public void CertificationSignature_None_IsNull()
    {
        var view = Latest(Signed().EndRevision());

        view.CertificationSignature.ShouldBeNull();
        view.DocMdpPermissions.ShouldBeNull();
    }

    [Fact]
    public void View_EachRevision_SeesItsOwnFieldsAndSignatures()
    {
        var builder = WithForm("<< /Fields [10 0 R] >>", (10, "<< /FT /Sig /T (Sig1) /Subtype /Widget /Rect [0 0 0 0] >>")).EndRevision()
            .Object(10, "<< /FT /Sig /T (Sig1) /V 11 0 R /Subtype /Widget /Rect [0 0 0 0] >>")
            .Object(11, "<< /Type /Sig /ByteRange [0 1 2 3] /Contents <01> >>")
            .EndRevision();
        var doc = PdfDocument.Open(builder.ToArray());

        doc.View(doc.Revisions[0]).Signatures.ShouldBeEmpty();
        doc.View(doc.Revisions[0]).Fields.ShouldHaveSingleItem().Value.ShouldBeNull();
        doc.View().Signatures.ShouldHaveSingleItem().Field!.FullName.ShouldBe("Sig1");
        doc.View().ShouldBeSameAs(doc.View(doc.Latest));
        doc.View(doc.Revisions[0]).NextObjectNumber.ShouldBe(11);
        doc.View().NextObjectNumber.ShouldBe(12);
    }

    [Fact]
    public void NameTree_KidsAndNames_InTreeOrder()
    {
        var view = Latest(new PdfFileBuilder()
            .Object(1, "<< /Type /Catalog /Pages 2 0 R /Names << /EmbeddedFiles 5 0 R >> >>")
            .Object(2, "<< /Type /Pages /Kids [] /Count 0 >>")
            .Object(5, "<< /Kids [6 0 R 7 0 R 5 0 R] >>")
            .Object(6, "<< /Names [(a.txt) 8 0 R (b.txt) 8 0 R] /Limits [(a.txt) (b.txt)] >>")
            .Object(7, "<< /Names [(c.txt) 8 0 R] >>")
            .Object(8, "<< /Type /Filespec /F (x) >>")
            .EndRevision());

        view.NameTree("EmbeddedFiles").Select(e => e.Key.Text).ShouldBe(["a.txt", "b.txt", "c.txt"]);
        view.NameTree("Dests").ShouldBeEmpty();
    }

    [Fact]
    public void Dss_FromTheCatalog()
    {
        var view = Latest(new PdfFileBuilder()
            .Object(1, "<< /Type /Catalog /Pages 2 0 R /DSS 4 0 R >>")
            .Object(2, "<< /Type /Pages /Kids [] /Count 0 >>")
            .Stream(3, "", Encoding.ASCII.GetBytes("cert"))
            .Object(4, "<< /Type /DSS /Certs [3 0 R] >>")
            .EndRevision());

        view.Dss.ShouldNotBeNull().Get("Certs").ShouldBeOfType<PdfArray>().Count.ShouldBe(1);
    }
}
