using System.Text;
using Shouldly;
using SimpleSign.PAdES.Pdf;
using SimpleSign.PAdES.Pdf.Enums;
using SimpleSign.PAdES.Pdf.Model;
using SimpleSign.PAdES.Tests.Pdf.Parity;
using SimpleSign.PAdES.Validation;
using SimpleSign.TestHelpers;
using Xunit;

namespace SimpleSign.PAdES.Tests.Validation;

/// <summary>The DSS read through the object model (ADR 0032), and the document facts read with it.</summary>
[Trait("Category", "Unit")]
public sealed class DssReaderTests
{
    private const string Hash1 = "AABBCCDDEEFF00112233445566778899AABBCCDD";
    private const string Hash2 = "00112233445566778899AABBCCDDEEFF00112233";

    private static PdfRevisionView View(PdfFileBuilder builder) => PdfDocument.Open(builder.ToArray()).View();

    private static PdfFileBuilder WithDss(string dss) => new PdfFileBuilder()
        .Object(1, "<< /Type /Catalog /Pages 2 0 R /DSS 20 0 R >>")
        .Object(2, "<< /Type /Pages /Kids [] /Count 0 >>")
        .Object(20, dss)
        .Stream(21, "", [0x30, 0x01])
        .Stream(22, "/Filter /FlateDecode", PdfFileBuilder.Zlib([0x30, 0x02]))
        .Stream(23, "", [0x30, 0x03]);

    [Fact]
    public void Read_ArraysAsReferencesAndIndirectVri_ReadsEverything()
    {
        var view = View(WithDss($"<< /Type /DSS /Certs 30 0 R /OCSPs [22 0 R] /CRLs [23 0 R] /VRI 31 0 R >>")
            .Object(30, "[21 0 R]")
            .Object(31, $"<< /Type /VRI /{Hash1} 32 0 R /{Hash2} << /OCSP [22 0 R] /TU (D:20260101000000Z) >> >>")
            .Object(32, "<< /Cert [21 0 R] /CRL [23 0 R] >>")
            .EndRevision());

        var dss = DssReader.Read(view);

        dss.Present.ShouldBeTrue();
        dss.Keys.ShouldBe(["Type", "Certs", "OCSPs", "CRLs", "VRI"], ignoreOrder: true);
        dss.GlobalCerts.ShouldHaveSingleItem().ShouldBe([0x30, 0x01]);
        dss.GlobalOcsps.ShouldHaveSingleItem().ShouldBe([0x30, 0x02]);
        dss.GlobalCrls.ShouldHaveSingleItem().ShouldBe([0x30, 0x03]);
        dss.VriEntries.Keys.ShouldBe([Hash1, Hash2], ignoreOrder: true);
        dss.VriEntries[Hash1].Certs.ShouldHaveSingleItem().ShouldBe([0x30, 0x01]);
        dss.VriEntries[Hash1].Crls.ShouldHaveSingleItem().ShouldBe([0x30, 0x03]);
        dss.VriEntries[Hash2].Ocsps.ShouldHaveSingleItem().ShouldBe([0x30, 0x02]);
        dss.VriEntries[Hash2].Keys.ShouldBe(["OCSP", "TU"], ignoreOrder: true);
    }

    [Fact]
    public void Read_NoDss_IsEmpty() =>
        DssReader.Read(View(new PdfFileBuilder()
            .Object(1, "<< /Type /Catalog /Pages 2 0 R >>").Object(2, "<< /Type /Pages /Kids [] /Count 0 >>").EndRevision()))
            .Present.ShouldBeFalse();

    [Fact]
    public void ReadExisting_KeepsReferencesOnly()
    {
        var view = View(WithDss($"<< /Type /DSS /Certs 30 0 R /OCSPs [22 0 R] /CRLs [] /VRI << /{Hash1} 32 0 R /{Hash2} << /Cert [21 0 R] >> >> /PBAD_PolicyArtifacts [23 0 R] >>")
            .Object(30, "[21 0 R]")
            .Object(32, "<< /Cert [21 0 R] >>")
            .EndRevision());

        var existing = DssReader.ReadExisting(view);

        existing.CertObjRefs.ShouldBe([21]);
        existing.OcspObjRefs.ShouldBe([22]);
        existing.CrlObjRefs.ShouldBeEmpty();
        existing.VriEntries.ShouldBe(new Dictionary<string, int> { [Hash1] = 32 });
        existing.ExtraArrays["PBAD_PolicyArtifacts"].ShouldBe([23]);
    }

    [Fact]
    public void Summary_CountsAndChecksTheVri()
    {
        var view = View(WithDss($"<< /Type /DSS /Certs [21 0 R 23 0 R] /OCSPs [22 0 R] /VRI << /Type /VRI /{Hash1} << /Cert [21 0 R] /TU (D:20260101000000Z) >> /abc << >> >> >>")
            .EndRevision());

        var info = DssReader.Summary(view).ShouldNotBeNull();

        info.CertificateCount.ShouldBe(2);
        info.OcspResponseCount.ShouldBe(1);
        info.CrlCount.ShouldBe(0);
        info.HasVri.ShouldBeTrue();
        info.VriEntryCount.ShouldBe(2);
        info.VriHasTimestamps.ShouldBeFalse();
        info.VriWarnings.ShouldContain(w => w.Contains("'abc'", StringComparison.Ordinal));
        info.VriWarnings.ShouldContain(w => w.Contains("1 of 2 entries missing /TU", StringComparison.Ordinal));
        info.VriWarnings.ShouldNotContain(w => w.Contains("'Type'", StringComparison.Ordinal));
    }

    [Fact]
    public async Task DetectPdfALevelAsync_CatalogMetadata_IsTheLevel()
    {
        using var stream = new MemoryStream(TestPdfFactory.CreateMinimalPdfA(2, 'U'));

        (await PdfStructureReader.DetectPdfALevelAsync(stream)).ShouldBe(PdfALevel.A2u);
    }

    [Fact]
    public async Task DetectPdfALevelAsync_PdfAidOutsideTheCatalogMetadata_IsNone()
    {
        byte[] pdf = [.. TestPdfFactory.CreateMinimalPdfWithPage(), .. "\n%<pdfaid:part>1</pdfaid:part><pdfaid:conformance>B</pdfaid:conformance>\n"u8];
        using var stream = new MemoryStream(pdf);

        (await PdfStructureReader.DetectPdfALevelAsync(stream)).ShouldBe(PdfALevel.None);
    }

    [Fact]
    public async Task IsEncryptedAsync_EncryptWordInAContentStream_IsFalse()
    {
        byte[] pdf = new PdfFileBuilder()
            .Object(1, "<< /Type /Catalog /Pages 2 0 R >>")
            .Object(2, "<< /Type /Pages /Kids [] /Count 0 >>")
            .Stream(3, "", Encoding.ASCII.GetBytes("BT (Use /Encrypt to protect a file) Tj ET"))
            .EndRevision().ToArray();
        using var stream = new MemoryStream(pdf);

        (await PdfStructureReader.IsEncryptedAsync(stream)).ShouldBeFalse();
    }

    [Theory]
    [InlineData("/Reference [<</TransformMethod/DocMDP/TransformParams<</P 2>>>>]", 2)]
    [InlineData("/Reference [<< /TransformMethod /DocMDP /TransformParams << /P 3 >> >>]", 3)]
    [InlineData("/Reference [<< /TransformMethod /DocMDP /TransformParams << /V /1.2 >> >>]", 1)]
    [InlineData("/Reference [<< /TransformMethod /FieldMDP /TransformParams << /P 2 >> >>]", 0)]
    public async Task GetDocMdpPermissionLevelAsync_CertificationReference_IsItsLevel(string reference, int level)
    {
        byte[] pdf = new PdfFileBuilder()
            .Object(1, "<< /Type /Catalog /Pages 2 0 R /AcroForm << /Fields [10 0 R] >> >>")
            .Object(2, "<< /Type /Pages /Kids [] /Count 0 >>")
            .Object(10, "<< /FT /Sig /T (Cert) /V 11 0 R >>")
            .Object(11, $"<< /Type /Sig /ByteRange [0 1 2 3] /Contents <00> {reference} >>")
            .EndRevision().ToArray();
        using var stream = new MemoryStream(pdf);

        (await PdfStructureReader.GetDocMdpPermissionLevelAsync(stream)).ShouldBe(level);
    }
}
