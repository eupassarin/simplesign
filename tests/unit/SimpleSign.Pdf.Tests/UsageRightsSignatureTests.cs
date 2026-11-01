using Shouldly;
using Xunit;

namespace SimpleSign.Pdf.Tests;

/// <summary>
/// Tests that usage-rights signatures (Adobe Reader Extensions, /TransformMethod /UR3
/// in the /Reference array) are not reported as document signatures, while regular and
/// DocMDP signatures still are.
/// </summary>
[Trait("Category", "Unit")]
public sealed class UsageRightsSignatureTests
{
    private const string SigPrefix = "/Type /Sig /Filter /Adobe.PPKLite /SubFilter /adbe.pkcs7.detached\n";

    /// <summary>
    /// Mirrors the compact signature dictionary written by Adobe Reader Extensions
    /// (XFA/LiveCycle forms): a /Reference array with /TransformMethod /UR3.
    /// </summary>
    private const string UsageRightsBody =
        "/Type/Sig/Filter/Adobe.PPKLite/SubFilter/adbe.pkcs7.detached/Reference[<</Type/SigRef/TransformMethod/UR3/TransformParams<</V/2.2/Type/TransformParams/Document[/FullSave]/Form[/FillIn]>>/Data 3 0 R>>]/Name(Adobe Profile 24 ARES 8.1 Unlimited Comment PunchCard 1272)/Contents <00>/ByteRange [0 100 200 300]";

    [Fact]
    public async Task ReadSignatureFields_UsageRightsOnly_ReturnsNoSignatures()
    {
        var (pdf, _) = PdfTextStringDecodingTests.BuildPdfWithSignatures(UsageRightsBody);

        using var stream = new MemoryStream(pdf);
        var fields = await PdfStructureReader.ReadSignatureFieldsAsync(stream);

        fields.ShouldBeEmpty();
    }

    [Fact]
    public async Task ReadSignatureFields_UsageRightsAndRealSignature_ReportsOnlyRealOne()
    {
        string realBody = SigPrefix + "/Name (Real Signer)\n/Contents <00>\n/ByteRange [0 100 200 300]";
        var (pdf, sigObjNums) = PdfTextStringDecodingTests.BuildPdfWithSignatures(UsageRightsBody, realBody);

        using var stream = new MemoryStream(pdf);
        var fields = await PdfStructureReader.ReadSignatureFieldsAsync(stream);

        fields.Count.ShouldBe(1);
        fields[0].SigDictObjectNumber.ShouldBe(sigObjNums[1]);
        fields[0].SignerName.ShouldBe("Real Signer");
    }

    [Fact]
    public async Task ReadSignatureFields_DocMdpSignature_StillReported()
    {
        string docMdpBody = SigPrefix +
            "/Reference [<< /Type /SigRef /TransformMethod /DocMDP /TransformParams << /Type /TransformParams /P 2 /V /1.2 >> >>]\n" +
            "/Contents <00>\n" +
            "/ByteRange [0 100 200 300]";
        var (pdf, _) = PdfTextStringDecodingTests.BuildPdfWithSignatures(docMdpBody);

        using var stream = new MemoryStream(pdf);
        var fields = await PdfStructureReader.ReadSignatureFieldsAsync(stream);

        fields.Count.ShouldBe(1);
    }
}
