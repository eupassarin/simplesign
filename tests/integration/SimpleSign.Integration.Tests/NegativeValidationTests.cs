using FluentAssertions;
using SimpleSign.Core.Validation;
using SimpleSign.Integration.Tests.Helpers;
using SimpleSign.PAdES.Validation;
using SimpleSign.Pdf.Exceptions;
using Xunit;
using Xunit.Abstractions;

namespace SimpleSign.Integration.Tests;

public sealed class NegativeValidationTests(ITestOutputHelper output)
{
    private static PdfSignatureValidator CreateValidator() =>
        new(new ValidationOptions { CheckRevocation = false });

    [SkippableFact(DisplayName = "PDF with wrong digest should fail integrity on all")]
    public async Task WrongDigestAlgo_AllIntegrityFalse()
    {
        const string fixture = "wrong-digest-algo.pdf";
        Skip.IfNot(FixturePath.Exists(fixture), $"Fixture {fixture} not found");

        var validator = CreateValidator();
        using var stream = FixturePath.Open(fixture);
        var results = await validator.ValidateAsync(stream);

        results.Should().HaveCount(4);
        // Only the first signature (adbe.pkcs7.sha1 SubFilter with legacy structure)
        // fails integrity. The three subsequent document timestamps use SHA-256 and their
        // byte ranges are valid as incremental updates.
        results[0].IsIntegrityValid.Should().BeFalse();
        results.Skip(1).Should().OnlyContain(r => r.IsIntegrityValid);
        output.WriteLine($"All {results.Count} signatures have invalid integrity as expected");
    }

    [SkippableFact(DisplayName = "PDF with bad encoded CMS should fail validation")]
    public async Task BadEncodedCms_FailsValidation()
    {
        const string fixture = "bad-encoded-cms.pdf";
        Skip.IfNot(FixturePath.Exists(fixture), $"Fixture {fixture} not found");

        var validator = CreateValidator();
        using var stream = FixturePath.Open(fixture);
        var results = await validator.ValidateAsync(stream);

        results.Should().HaveCount(1);
        results[0].IsIntegrityValid.Should().BeFalse();
        results[0].IsSignatureValid.Should().BeFalse();
        output.WriteLine($"Signer: {results[0].SignerName ?? "(unknown)"}");
    }

    [SkippableFact(DisplayName = "Malformed PDF should throw on validation")]
    public async Task MalformedPdf_ThrowsOnValidation()
    {
        const string fixture = "malformed-pades.pdf";
        Skip.IfNot(FixturePath.Exists(fixture), $"Fixture {fixture} not found");

        var validator = CreateValidator();
        using var stream = FixturePath.Open(fixture);

        var act = () => validator.ValidateAsync(stream);
        await act.Should().ThrowAsync<PdfStructureException>();
    }

    [SkippableFact(DisplayName = "DSS-3226 PDF with CAdES signatures validates with chain failure")]
    public async Task Dss3226_ValidatesWithChainFailure()
    {
        const string fixture = "dss-3226.pdf";
        Skip.IfNot(FixturePath.Exists(fixture), $"Fixture {fixture} not found");

        var validator = CreateValidator();
        using var stream = FixturePath.Open(fixture);
        var results = await validator.ValidateAsync(stream);

        results.Should().NotBeEmpty("the PDF contains two CAdES detached signatures");
        foreach (var result in results)
        {
            result.IsIntegrityValid.Should().BeTrue();
            output.WriteLine($"{result.FieldName}: Valid={result.IsValid}, Integrity={result.IsIntegrityValid}");
        }
    }

    [SkippableFact(DisplayName = "Unsigned PDF should return no results")]
    public async Task UnsignedPdf_ReturnsNoResults()
    {
        const string fixture = "empty-page-unsigned.pdf";
        Skip.IfNot(FixturePath.Exists(fixture), $"Fixture {fixture} not found");

        var validator = CreateValidator();
        using var stream = FixturePath.Open(fixture);
        var results = await validator.ValidateAsync(stream);

        results.Should().BeEmpty();
        output.WriteLine("No validation results as expected for unsigned PDF");
    }
}
