using System.Text;
using Shouldly;
using SimpleSign.PAdES.Pdf.Writing;
using SimpleSign.PAdES.Tests.Pdf.Parity;
using Xunit;

namespace SimpleSign.PAdES.Tests.Pdf.Writing;

/// <summary>
/// The patch makes the writers' edits of existing objects (ADR 0032): each edit's output was checked against the text
/// edit the writers made before (on an object written with LF line ends) and is now a snapshot; CRLF is kept, which
/// those edits turned into LF.
/// </summary>
[Trait("Category", "Unit")]
public sealed class PdfDictionaryPatchTests
{
    private static PdfDictionaryPatch Patch(string objectText) => new(Encoding.Latin1.GetBytes(objectText));

    private static string Text(PdfDictionaryPatch patch) => Encoding.Latin1.GetString(patch.ToBytes());

    /// <summary>The edit's output is its snapshot: it was the writers' text edit's, byte for byte, when they were replaced.</summary>
    private static void Match(string key, string text) =>
        Snapshot.MatchKey("writing/dictionary-patch.txt", Snapshot.OneLine(key), Snapshot.OneLine(text));

    private const string Catalog = "1 0 obj\n<< /Type /Catalog /Pages 2 0 R\n/Perms << /DocMDP 9 0 R >>\n/OpenAction [3 0 R /Fit] /Lang (pt-BR) /PageMode /UseNone /AcroForm 6 0 R >>\nendobj";

    [Theory]
    [InlineData("/Perms")]
    [InlineData("/OpenAction")]
    [InlineData("/Lang")]
    [InlineData("/PageMode")]
    [InlineData("/AcroForm")]
    [InlineData("/Missing")]
    public void Remove_AnyValueKind_IsItsSnapshot(string key) =>
        Match($"remove{key}", Text(Patch(Catalog).Remove(key[1..])));

    [Fact]
    public void Set_RemovedKey_IsWrittenAgainBeforeTheClose() =>
        Match("remove-then-set/AcroForm", Text(Patch(Catalog).Remove("AcroForm").Set("AcroForm", "7 0 R")));

    [Theory]
    [InlineData("4 0 obj\n<< /FT /Sig /T (Sig1) /V /Off /Rect [0 0 0 0] >>\nendobj", "/V", "5 0 R")]
    [InlineData("4 0 obj\n<< /FT /Sig /T (Sig1) /Rect [0 0 0 0] >>\nendobj", "/V", "5 0 R")]
    [InlineData("4 0 obj\n<< /FT /Sig /T (Sig1) /AP << /N 8 0 R >> >>\nendobj", "/AP", "<< /N 12 0 R >>")]
    [InlineData("4 0 obj\n<< /FT /Sig /T (Sig1) /V () /F 4 >>\nendobj", "/V", "5 0 R")]
    public void Set_FieldValue_IsItsSnapshot(string field, string key, string value) =>
        Match($"set{key}/{field}", Text(Patch(field).Set(key[1..], value)));

    [Theory]
    [InlineData("3 0 obj\n<< /Type /Page /Parent 2 0 R /Annots [4 0 R] /MediaBox [0 0 612 792] >>\nendobj")]
    [InlineData("3 0 obj\n<< /Type /Page /Parent 2 0 R /Annots [] >>\nendobj")]
    [InlineData("3 0 obj\n<< /Type /Page /Annots [4 0 R 5 0 R] /Border [0 0 0] >>\nendobj")]
    public void AppendToArray_PageAnnots_IsItsSnapshot(string page)
    {
        var patch = Patch(page);
        patch.AppendToArray(["Annots"], "9 0 R", spaceWhenEmpty: true).ShouldBeTrue();

        Match($"annots/{page}", Text(patch));
    }

    [Theory]
    [InlineData("1 0 obj\n<< /Type /Catalog /Pages 2 0 R /AcroForm << /Fields [4 0 R] /SigFlags 3 /DA (/Helv 0 Tf 0 g) >> >>\nendobj")]
    [InlineData("1 0 obj\n<< /Type /Catalog /Pages 2 0 R /AcroForm << /Fields [] /DR << /Font << /Helv 5 0 R >> >> >> >>\nendobj")]
    [InlineData("1 0 obj\n<< /Type /Catalog /Pages 2 0 R /AcroForm << /SigFlags 3 >> >>\nendobj")]
    public void AppendToArray_InlineAcroFormFields_IsItsSnapshot(string catalog)
    {
        var patch = Patch(catalog);

        patch.AppendToArray(["AcroForm", "Fields"], "12 0 R").ShouldBeTrue();

        Match($"inline-acroform/{catalog}", Text(patch));
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

    // ── Layouts the scanning editor handled, now the patch's (ported with ADR 0032) ──────────────────────────────

    public static TheoryData<string, string> InlineAcroForms()
    {
        var data = new TheoryData<string, string>();
        data.Add("1 0 obj\n<< /Type /Catalog /AcroForm << /SigFlags 3 /Fields [51 0 R] /DA (/Helv 0 Tf 0 g) >> >>\nendobj\n", "/Fields [51 0 R 62 0 R]");
        data.Add("1 0 obj\n<< /Type /Catalog /AcroForm<< /Fields[51 0 R] /DA (/Helv 0 Tf 0 g) >> >>\nendobj\n", "/Fields[51 0 R 62 0 R]");
        data.Add("1 0 obj\n<<\n/Type /Catalog\n/AcroForm <<\n/SigFlags 3\n/Fields [\n51 0 R\n]\n/DA (/Helv 0 Tf 0 g)\n/DR <<\n/Font <<\n/Helv 52 0 R\n>>\n>>\n>>\n>>\nendobj\n", "51 0 R\n 62 0 R]");
        data.Add("1 0 obj\n<< /Type /Catalog /AcroForm << /Fields [] /DA (/Helv 0 Tf 0 g) >> >>\nendobj\n", "/Fields [62 0 R]");
        data.Add("1 0 obj\n<< /Type /Catalog /AcroForm << /SigFlags 3 /DA (/Helv 0 Tf 0 g) >> >>\nendobj\n", "/Fields [62 0 R]");
        data.Add("1 0 obj\n<< /Type /Catalog /AcroForm << /SigFlags 3 /Fields [51 0 R % ]\n52 0 R] /DA (/Helv 0 Tf 0 g) >> >>\nendobj\n", "52 0 R 62 0 R]");
        return data;
    }

    [Theory]
    [MemberData(nameof(InlineAcroForms))]
    public void AppendToArray_InlineAcroFormLayouts_AppendsTheFieldAndKeepsTheRest(string catalog, string expected)
    {
        var patch = Patch(catalog);

        patch.AppendToArray(["AcroForm", "Fields"], "62 0 R").ShouldBeTrue();

        string text = Text(patch);
        text.ShouldContain(expected);
        text.ShouldContain("/DA (/Helv 0 Tf 0 g)");
    }

    [Theory]
    [InlineData("1 0 obj\n<< /Type /Catalog /AcroForm << /Fields 51 0 R /DA (/Helv 0 Tf 0 g) >> >>\nendobj\n")]
    [InlineData("1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n")]
    public void AppendToArray_FieldsNotAnInlineArray_IsRefusedAndChangesNothing(string catalog)
    {
        var patch = Patch(catalog);

        patch.AppendToArray(["AcroForm", "Fields"], "62 0 R").ShouldBeFalse();

        Text(patch).ShouldBe(catalog);
    }

    [Theory]
    [InlineData("1 0 obj\n<< /Type /Catalog /Pages 2 0 R\n   /AcroForm <<\n      /SigFlags 3\n      /Fields [51 0 R]\n      /DA (/Helv 0 Tf 0 g)\n   >>\n>>\nendobj\n", "AcroForm", "/SigFlags 3")]
    [InlineData("1 0 obj\n<< /Type /Catalog\n   /Perms << /DocMDP 5 0 R\n             /UR3 6 0 R >>\n   /Pages 2 0 R\n>>\nendobj\n", "Perms", "/UR3 6 0 R")]
    [InlineData("1 0 obj\n<< /Type /Catalog /Pages 2 0 R /AcroForm 56 0 R >>\nendobj\n", "AcroForm", "56 0 R")]
    [InlineData("1 0 obj\n<< /Type /Catalog /Foo /Bar /Pages 2 0 R >>\nendobj\n", "Foo", "/Bar")]
    public void Remove_ValueOfAnyLayout_RemovesTheWholeEntry(string catalog, string key, string valuePart)
    {
        string text = Text(Patch(catalog).Remove(key));

        text.ShouldNotContain(valuePart);
        text.ShouldContain("/Type /Catalog");
        text.ShouldContain("/Pages 2 0 R");
    }

    [Fact]
    public void Remove_KeyAlsoInsideALiteralString_RemovesOnlyTheEntry()
    {
        const string catalog = "1 0 obj\n<< /Type /Catalog /Pages 2 0 R /Note (see /AcroForm here) /AcroForm 5 0 R >>\nendobj\n";

        string text = Text(Patch(catalog).Remove("AcroForm"));

        text.ShouldContain("(see /AcroForm here)");
        text.ShouldNotContain("/AcroForm 5 0 R");
    }

    [Fact]
    public void Remove_MissingKey_ChangesNothing()
    {
        const string catalog = "1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n";

        Text(Patch(catalog).Remove("AcroForm")).ShouldBe(catalog);
    }

    [Theory]
    [InlineData("1 0 obj\n<< /DA (a >> b) /DR << /Font << /F 0 R >> >> >>\nendobj")]
    [InlineData("1 0 obj\n<< /Foo 1\n% fake << >>\n/Bar 2 >>\nendobj")]
    public void Set_DictionaryWithDelimitersInStringsOrComments_InsertsBeforeItsOwnClose(string obj)
    {
        string text = Text(Patch(obj).Set("New", "1"));

        text.ShouldEndWith("   /New 1\n>>\nendobj");
        text.ShouldStartWith(obj[..^">>\nendobj".Length]);
    }
}

