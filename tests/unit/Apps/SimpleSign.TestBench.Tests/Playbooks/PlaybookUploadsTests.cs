using System.Text;
using Shouldly;
using SimpleSign.TestBench.Playbooks;

namespace SimpleSign.TestBench.Tests.Playbooks;

[Trait("Category", "Unit")]
public sealed class PlaybookUploadsTests
{
    private static readonly byte[] s_pdf = Encoding.ASCII.GetBytes("%PDF-1.7\n1 0 obj\n<<>>\nendobj\n%%EOF\n");
    private static readonly byte[] s_xml = Encoding.UTF8.GetBytes("﻿  <?xml version=\"1.0\"?><order/>");
    private static readonly byte[] s_cms = [0x30, 0x82, 0x01, 0x00, 0x06, 0x09];

    private static PlaybookInput Input(string? accept) => new() { Id = "theirs", Title = "A signed file", Accept = accept };

    [Theory]
    [InlineData(".pdf", "signed.pdf")]
    [InlineData(".PDF", "signed.pdf")]
    [InlineData(".pdf", "SIGNED.PDF")]
    [InlineData(".xml, .pdf", "signed.pdf")]
    [InlineData("application/pdf", "signed.pdf")]
    public void Refusal_PdfTheInputAccepts_IsNull(string accept, string fileName) =>
        PlaybookUploads.Refusal(Input(accept), fileName, s_pdf).ShouldBeNull();

    [Fact]
    public void Refusal_XmlAndCmsTheInputAccepts_IsNull()
    {
        PlaybookUploads.Refusal(Input(".xml"), "order.xml", s_xml).ShouldBeNull();
        PlaybookUploads.Refusal(Input("text/xml"), "order.xml", s_xml).ShouldBeNull();
        PlaybookUploads.Refusal(Input(".p7s,.p7m"), "data.p7m", s_cms).ShouldBeNull();
        PlaybookUploads.Refusal(Input("application/pkcs7-signature"), "data.p7s", s_cms).ShouldBeNull();
    }

    [Fact]
    public void Refusal_ExtensionTheInputDoesNotAccept_SaysWhatItTakes() =>
        PlaybookUploads.Refusal(Input(".pdf"), "order.xml", s_xml).ShouldNotBeNull().ShouldContain(".pdf");

    [Fact]
    public void Refusal_ContentOtherThanItsExtension_SaysSo() =>
        PlaybookUploads.Refusal(Input(".pdf"), "renamed.pdf", s_xml).ShouldNotBeNull().ShouldContain("not a PDF");

    [Fact]
    public void Refusal_TextNamedP7s_IsNotACmsStructure() =>
        PlaybookUploads.Refusal(Input(".p7s"), "data.p7s", Encoding.ASCII.GetBytes("hello")).ShouldNotBeNull().ShouldContain("CMS");

    [Fact]
    public void Refusal_EmptyFile_IsRefusedEvenWithoutAccept() =>
        PlaybookUploads.Refusal(Input(null), "empty.pdf", []).ShouldNotBeNull().ShouldContain("empty");

    [Fact]
    public void Refusal_NoAccept_TakesAnyNonEmptyFile() =>
        PlaybookUploads.Refusal(Input(null), "notes.txt", Encoding.ASCII.GetBytes("hello")).ShouldBeNull();

    [Fact]
    public void Refusal_MimeTypeItCannotMap_DoesNotJudgeTheNameButStillTheContent()
    {
        PlaybookUploads.Refusal(Input("image/*"), "photo.png", [0x89, 0x50, 0x4E, 0x47]).ShouldBeNull();
        PlaybookUploads.Refusal(Input("image/*"), "fake.pdf", s_xml).ShouldNotBeNull();
    }

    [Theory]
    [InlineData(".pdf", true)]
    [InlineData("application/pdf", true)]
    [InlineData("image/*", true)]
    [InlineData("pdf", false)]
    [InlineData(".", false)]
    [InlineData(".p df", false)]
    [InlineData("/pdf", false)]
    [InlineData("application/", false)]
    public void IsValidToken_GivesWhetherItIsAnExtensionOrAMimeType(string token, bool valid) =>
        PlaybookUploads.IsValidToken(token).ShouldBe(valid);

    [Fact]
    public void Tokens_SplitsAndTrims() =>
        PlaybookUploads.Tokens(" .pdf , application/xml,, ").ShouldBe([".pdf", "application/xml"]);
}
