using Shouldly;
using SimpleSign.Integration.Tests.Helpers;
using SimpleSign.PAdES.Inspection;
using Xunit;
using Xunit.Abstractions;

namespace SimpleSign.Integration.Tests;

/// <summary>
/// <see cref="PdfSignatureInspector"/> on real-world PAdES documents from the EU DSS corpus and the ETSI plugtests.
/// See <c>Fixtures/README.md</c> for their origin.
/// </summary>
[Trait("Category", "Integration")]
public sealed class PdfSignatureInspectorCorpusTests(ITestOutputHelper output)
{
    /// <summary>Known-good corpus documents: the inspector finds their signatures.</summary>
    [Theory(DisplayName = "Known-good corpus PDF: the inspector finds its signatures")]
    [InlineData("AD-RB.pdf")]
    [InlineData("dss-1683.pdf")]
    [InlineData("dss-1983.pdf")]
    [InlineData("pades-lt.pdf")]
    [InlineData("signature-p-bg-bor-1.pdf")]
    [InlineData("signature-p-bg-bor-2.pdf")]
    [InlineData("signature-p-de-sci-4.pdf")]
    [InlineData("signature-p-fr-cs-5.pdf")]
    [InlineData("belgian-multi-ocsp.pdf")]
    [InlineData("doc-firmado-B.pdf")]
    [InlineData("doc-firmado-T.pdf")]
    [InlineData("doc-firmado-lt.pdf")]
    [InlineData("signature-p-hu-mic-1.pdf")] // the removed interop suite only asked this one not to throw
    public async Task InspectAsync_KnownGoodCorpusPdf_FindsSignatures(string fixture)
    {
        using var stream = FixturePath.Open(fixture);
        var result = await PdfSignatureInspector.InspectAsync(stream);

        output.WriteLine($"[{fixture}] signatures={result.Signatures.Count}");
        foreach (var sig in result.Signatures)
        {
            output.WriteLine($"  {sig.FieldName}: subFilter={sig.SubFilter} signer={sig.Signer?.Subject}");
        }

        result.Signatures.ShouldNotBeEmpty($"'{fixture}' is a known-good signed PDF");
    }

    /// <summary>Malformed documents: the inspector returns, it never throws.</summary>
    [Theory(DisplayName = "Corpus PDF with a malformed CMS: inspection does not throw")]
    [InlineData("bad-encoded-cms.pdf")]
    public async Task InspectAsync_MalformedCmsCorpusPdf_DoesNotThrow(string fixture)
    {
        using var stream = FixturePath.Open(fixture);

        var ex = await Record.ExceptionAsync(() => PdfSignatureInspector.InspectAsync(stream));

        ex.ShouldBeNull($"the inspector must handle '{fixture}' without throwing");
    }
}
