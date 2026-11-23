using System.Reflection;
using System.Text;
using Shouldly;
using SimpleSign.PAdES.Pdf;
using SimpleSign.PAdES.Pdf.Writing;
using SimpleSign.PAdES.Signing;
using Xunit;

namespace SimpleSign.PAdES.Tests.Pdf.Writing;

/// <summary>
/// The patch makes the writers' edits of existing objects (ADR 0032): golden against the text edits they make on an
/// object written with LF line ends, and keeping CRLF, which those edits turned into LF.
/// </summary>
[Trait("Category", "Unit")]
public sealed class PdfDictionaryPatchTests
{
    private static PdfDictionaryPatch Patch(string objectText) => new(Encoding.Latin1.GetBytes(objectText));

    private static string Text(PdfDictionaryPatch patch) => Encoding.Latin1.GetString(patch.ToBytes());

    private const string Catalog = "1 0 obj\n<< /Type /Catalog /Pages 2 0 R\n/Perms << /DocMDP 9 0 R >>\n/OpenAction [3 0 R /Fit] /Lang (pt-BR) /PageMode /UseNone /AcroForm 6 0 R >>\nendobj";

    [Theory]
    [InlineData("/Perms")]
    [InlineData("/OpenAction")]
    [InlineData("/Lang")]
    [InlineData("/PageMode")]
    [InlineData("/AcroForm")]
    [InlineData("/Missing")]
    public void Remove_AnyValueKind_IsRemoveKeyFromDict(string key) =>
        Text(Patch(Catalog).Remove(key[1..])).ShouldBe(PdfStructureParser.RemoveKeyFromDict(Catalog, key));

    [Fact]
    public void Set_AbsentKey_IsInsertIntoDictBeforeTheClose() =>
        Text(Patch(Catalog).Remove("AcroForm").Set("AcroForm", "7 0 R"))
            .ShouldBe(PdfStructureParser.InsertIntoDict(PdfStructureParser.RemoveKeyFromDict(Catalog, "/AcroForm"), "   /AcroForm 7 0 R\n"));

    [Theory]
    [InlineData("4 0 obj\n<< /FT /Sig /T (Sig1) /V /Off /Rect [0 0 0 0] >>\nendobj", "/V", "5 0 R")]
    [InlineData("4 0 obj\n<< /FT /Sig /T (Sig1) /Rect [0 0 0 0] >>\nendobj", "/V", "5 0 R")]
    [InlineData("4 0 obj\n<< /FT /Sig /T (Sig1) /AP << /N 8 0 R >> >>\nendobj", "/AP", "<< /N 12 0 R >>")]
    [InlineData("4 0 obj\n<< /FT /Sig /T (Sig1) /V () /F 4 >>\nendobj", "/V", "5 0 R")]
    public void Set_FieldValue_IsTheSignerSetTopLevelValue(string field, string key, string value)
    {
        string legacy = (string)typeof(PdfSignatureWriter).GetMethod("SetTopLevelValue", BindingFlags.NonPublic | BindingFlags.Static)!
            .Invoke(null, [field, key, value])!;

        Text(Patch(field).Set(key[1..], value)).ShouldBe(legacy);
    }

    [Theory]
    [InlineData("3 0 obj\n<< /Type /Page /Parent 2 0 R /Annots [4 0 R] /MediaBox [0 0 612 792] >>\nendobj")]
    [InlineData("3 0 obj\n<< /Type /Page /Parent 2 0 R /Annots [] >>\nendobj")]
    [InlineData("3 0 obj\n<< /Type /Page /Annots [4 0 R 5 0 R] /Border [0 0 0] >>\nendobj")]
    public void AppendToArray_PageAnnots_IsTheSignerPageUpdate(string page)
    {
        byte[] data = Encoding.Latin1.GetBytes(page);
        int dictStart = page.IndexOf("<<", StringComparison.Ordinal);
        string legacy = Encoding.Latin1.GetString(PdfSignatureWriter.BuildUpdatedPageObject(3, data, dictStart, data.Length, 9));

        var patch = Patch(page);
        patch.AppendToArray(["Annots"], "9 0 R", spaceWhenEmpty: true).ShouldBeTrue();

        (Text(patch) + "\n").ShouldBe(legacy);
    }

    [Theory]
    [InlineData("1 0 obj\n<< /Type /Catalog /Pages 2 0 R /AcroForm << /Fields [4 0 R] /SigFlags 3 /DA (/Helv 0 Tf 0 g) >> >>\nendobj")]
    [InlineData("1 0 obj\n<< /Type /Catalog /Pages 2 0 R /AcroForm << /Fields [] /DR << /Font << /Helv 5 0 R >> >> >> >>\nendobj")]
    [InlineData("1 0 obj\n<< /Type /Catalog /Pages 2 0 R /AcroForm << /SigFlags 3 >> >>\nendobj")]
    public void AppendToArray_InlineAcroFormFields_IsAppendFieldToInlineAcroForm(string catalog)
    {
        var patch = Patch(catalog);

        patch.AppendToArray(["AcroForm", "Fields"], "12 0 R").ShouldBeTrue();

        Text(patch).ShouldBe(PdfStructureParser.AppendFieldToInlineAcroForm(catalog, "12 0 R"));
    }

    [Fact]
    public void AppendToArray_ArrayIsAReference_IsRefused()
    {
        var patch = Patch("3 0 obj\n<< /Type /Page /Annots 7 0 R >>\nendobj");

        patch.AppendToArray(["Annots"], "9 0 R").ShouldBeFalse();
        Text(patch).ShouldBe("3 0 obj\n<< /Type /Page /Annots 7 0 R >>\nendobj");
    }

    [Fact]
    public void Edits_CrLfObject_KeepEveryOtherByte()
    {
        const string page = "3 0 obj\r\n<<\r\n/Type /Page\r\n/Annots [4 0 R]\r\n/Lang (pt)\r\n>>\r\nendobj";

        var patch = Patch(page).Remove("Lang");
        patch.AppendToArray(["Annots"], "9 0 R");
        patch.Set("Tabs", "/S");

        // The writers' text edits turned every CRLF into LF; the patch changes the edited entries only.
        Text(patch).ShouldBe("3 0 obj\r\n<<\r\n/Type /Page\r\n/Annots [4 0 R 9 0 R]\r\n\r\n   /Tabs /S\n>>\r\nendobj");
    }

    [Fact]
    public void Of_DocumentObject_PatchesItsBytes()
    {
        var builder = new Parity.PdfFileBuilder()
            .Object(1, "<< /Type /Catalog /Pages 2 0 R /Lang (en) >>")
            .Object(2, "<< /Type /Pages /Kids [] /Count 0 >>")
            .EndRevision();
        var document = SimpleSign.PAdES.Pdf.Model.PdfDocument.Open(builder.ToArray());

        var patch = PdfDictionaryPatch.Of(document, 1).ShouldNotBeNull();

        patch.Id.Number.ShouldBe(1);
        Text(patch.Set("Lang", "(pt-BR)")).ShouldBe("1 0 obj\n<< /Type /Catalog /Pages 2 0 R /Lang (pt-BR) >>\nendobj");
    }
}
