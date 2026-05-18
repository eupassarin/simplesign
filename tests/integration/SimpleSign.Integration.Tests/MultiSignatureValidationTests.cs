using Shouldly;
using SimpleSign.Core.Validation;
using SimpleSign.Integration.Tests.Helpers;
using SimpleSign.PAdES.Validation;
using Xunit;
using Xunit.Abstractions;

namespace SimpleSign.Integration.Tests;

public sealed class MultiSignatureValidationTests(ITestOutputHelper output)
{
    private static PdfSignatureValidator CreateValidator() =>
        new(new ValidationOptions { CheckRevocation = false });

    [SkippableFact(DisplayName = "PDF with 5 signatures and 1 timestamp should return 6 results")]
    public async Task FiveSignaturesAndTimestamp_AllParsed()
    {
        const string fixture = "pades-5sigs-1ts.pdf";
        Skip.IfNot(FixturePath.Exists(fixture), $"Fixture {fixture} not found");

        var validator = CreateValidator();
        using var stream = FixturePath.Open(fixture);
        var results = await validator.ValidateAsync(stream);

        results.Count().ShouldBe(6);
        output.WriteLine($"Signers: {string.Join(", ", results.Select(r => r.SignerName ?? "(unknown)"))}");
    }

    [SkippableFact(DisplayName = "PAdES-LT PDF should contain 4 signatures")]
    public async Task PadesLt_FourSignaturesFound()
    {
        const string fixture = "pades-lt.pdf";
        Skip.IfNot(FixturePath.Exists(fixture), $"Fixture {fixture} not found");

        var validator = CreateValidator();
        using var stream = FixturePath.Open(fixture);
        var results = await validator.ValidateAsync(stream);

        results.Count().ShouldBe(4);
        output.WriteLine($"Signers: {string.Join(", ", results.Select(r => r.SignerName ?? "(unknown)"))}");
    }

    [SkippableFact(DisplayName = "Timestamped and signed PDF should return 2 results")]
    public async Task TimestampedAndSigned_TwoResults()
    {
        const string fixture = "timestamped-and-signed.pdf";
        Skip.IfNot(FixturePath.Exists(fixture), $"Fixture {fixture} not found");

        var validator = CreateValidator();
        using var stream = FixturePath.Open(fixture);
        var results = await validator.ValidateAsync(stream);

        results.Count().ShouldBe(2);
        // Both signatures cover their respective byte ranges correctly.
        // The first signature is not the last (incremental update was added on top),
        // so its byte range not covering the full file is expected and not an integrity failure.
        results[0].IsIntegrityValid.ShouldBeTrue();
        results[1].IsIntegrityValid.ShouldBeTrue();
        output.WriteLine($"Signers: {string.Join(", ", results.Select(r => r.SignerName ?? "(unknown)"))}");
    }
}
