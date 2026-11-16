using Shouldly;
using SimpleSign.Core.Validation;
using SimpleSign.Integration.Tests.Helpers;
using SimpleSign.PAdES.Validation;
using Xunit;
using Xunit.Abstractions;

namespace SimpleSign.Integration.Tests;

/// <summary>
/// <see cref="PdfSignatureValidator"/> on real-world PAdES documents from the EU DSS corpus and the ETSI plugtests
/// (BG, DE, FR, HU, ES, BE producers), offline. See <c>Fixtures/README.md</c> for their origin.
/// </summary>
[Trait("Category", "Integration")]
public sealed class PdfSignatureValidatorCorpusTests(ITestOutputHelper output)
{
    private static PdfSignatureValidator CreateValidator() =>
        new(EtsiCorpus.OfflineOptions, EtsiCorpus.FailingHttpClient);

    /// <summary>Single-signature documents: the one signature's byte range must verify.</summary>
    [Theory(DisplayName = "Corpus PDF with one signature: every signature is integrity-valid")]
    [InlineData("AD-RB.pdf")] // ETSI plugtest, AdES baseline
    [InlineData("signature-p-bg-bor-1.pdf")] // Bulgarian plugtest
    [InlineData("doc-firmado-T.pdf")] // Spanish B-T
    [InlineData("doc-firmado-lt.pdf")] // Spanish B-LT
    [InlineData("signature-p-hu-mic-1.pdf")] // Hungarian plugtest (the removed interop suite only asked it not to throw)
    public async Task ValidateAsync_SingleSignatureCorpusPdf_EverySignatureIntegrityValid(string fixture)
    {
        var results = await ValidateAsync(fixture);

        results.ShouldNotBeEmpty($"'{fixture}' must have at least one parseable signature");
        results.ShouldAllBe(r => r.IsIntegrityValid, $"'{fixture}' is a single-signature corpus document");
    }

    /// <summary>
    /// Multi-revision documents (document and archive timestamps, DSS updates): the primary signature must verify.
    /// </summary>
    [Theory(DisplayName = "Corpus PDF with several revisions: at least one signature is integrity-valid")]
    [InlineData("dss-1983.pdf")] // CMS signature + DSS update
    [InlineData("pades-lt.pdf")] // signature + document timestamp + DSS update + archive timestamp
    [InlineData("signature-p-bg-bor-2.pdf")] // SHA-512 signature + SHA-1 document timestamp
    [InlineData("signature-p-de-sci-4.pdf")] // German plugtest: signature + archive timestamp
    [InlineData("signature-p-fr-cs-5.pdf")] // French plugtest: signature + 2 archive timestamps
    [InlineData("belgian-multi-ocsp.pdf")] // Belgian PKI: DSS with several OCSP responses
    [InlineData("doc-firmado-B.pdf")] // Spanish B-B + DSS update
    public async Task ValidateAsync_MultiRevisionCorpusPdf_AtLeastOneSignatureIntegrityValid(string fixture)
    {
        var results = await ValidateAsync(fixture);

        results.ShouldNotBeEmpty($"'{fixture}' must have at least one parseable signature");
        results.ShouldContain(r => r.IsIntegrityValid, $"'{fixture}' must have a signature whose byte range verifies");
    }

    /// <summary>Unusual or malformed documents: the validator returns results, it never throws.</summary>
    [Theory(DisplayName = "Corpus PDF the validator may not accept: validation does not throw")]
    [InlineData("dss-1683.pdf")] // EU DSS bug report: SHA-1 signature whose byte range does not verify
    [InlineData("bad-encoded-cms.pdf")] // malformed CMS
    public async Task ValidateAsync_UnusualCorpusPdf_DoesNotThrow(string fixture)
    {
        var ex = await Record.ExceptionAsync(() => ValidateAsync(fixture));

        ex.ShouldBeNull($"the validator must handle '{fixture}' without throwing");
    }

    private async Task<IReadOnlyList<SignatureValidationResult>> ValidateAsync(string fixture)
    {
        using var stream = FixturePath.Open(fixture);
        var results = await CreateValidator().ValidateAsync(stream);

        output.WriteLine($"[{fixture}] {results.Count} result(s):");
        foreach (var r in results)
        {
            output.WriteLine($"  {r.FieldName}: integrity={r.IsIntegrityValid} sig={r.IsSignatureValid} algo={r.DigestAlgorithmName}");
        }

        return results;
    }
}
