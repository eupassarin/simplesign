using Shouldly;
using SimpleSign.PAdES.Signing;
using SimpleSign.TestBench.Documents;

namespace SimpleSign.TestBench.Tests;

/// <summary>
/// The sample documents, made by the HtmlToPdf engine: a stamp can be anchored to their signing lines, whether the text
/// is in a standard font (the contract) or an embedded one (the PDF/A-2b terms).
/// </summary>
[Trait("Category", "Unit")]
public sealed class SampleDocumentsTests
{
    [Theory]
    [InlineData("contract", 2)]
    [InlineData("pdfa-2b", 1)]
    public async Task CreateAsync_SigningLines_AnchorAStamp(string id, int lastPage)
    {
        var documents = await SampleDocuments.CreateAsync();
        byte[] pdf = documents.Single(d => d.Id == id).Content;

        var contratante = new SignatureAnchor("Contratante") { OffsetY = 30 }.Locate(pdf);
        var contratada = new SignatureAnchor("Contratada").Locate(pdf);

        contratante.Page.ShouldBe(lastPage);
        contratada.Page.ShouldBe(lastPage);
        contratada.X.ShouldBe(contratante.X, 0.5f);
        contratada.Y.ShouldBeLessThan(contratante.Y - 30);
        new SignatureAnchor("Cláusula 1.").Locate(pdf).Page.ShouldBe(1);
    }
}
