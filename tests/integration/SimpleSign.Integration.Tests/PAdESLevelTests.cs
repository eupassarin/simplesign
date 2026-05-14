using FluentAssertions;
using SimpleSign.Core.Validation;
using SimpleSign.Integration.Tests.Helpers;
using SimpleSign.PAdES.Validation;
using SimpleSign.Pdf;
using Xunit;
using Xunit.Abstractions;

namespace SimpleSign.Integration.Tests;

public sealed class PAdESLevelTests(ITestOutputHelper output)
{
    private static PdfSignatureValidator CreateValidator() =>
        new(new ValidationOptions { CheckRevocation = false });

    [SkippableFact(DisplayName = "PAdES-LTA with DSS dictionary should validate integrity")]
    public async Task PadesLta_HasDssAndValidIntegrity()
    {
        const string fixture = "pades-lta.pdf";
        Skip.IfNot(FixturePath.Exists(fixture), $"Fixture {fixture} not found");

        // Parse signature fields
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        using var parseStream = FixturePath.Open(fixture);
        var fields = await PdfStructureReader.ReadSignatureFieldsAsync(parseStream, cancellationToken: cts.Token);
        fields.Should().NotBeEmpty("PAdES-LTA should contain signatures");
        output.WriteLine($"Fields: {fields.Count}");

        // Check DSS dictionary presence in raw bytes
        var bytes = await FixturePath.ReadBytesAsync(fixture);
        var hasDss = System.Text.Encoding.ASCII.GetString(bytes).Contains("/DSS ");
        hasDss.Should().BeTrue("PAdES-LTA should contain DSS dictionary");

        // Validate
        var validator = CreateValidator();
        using var valStream = FixturePath.Open(fixture);
        var results = await validator.ValidateAsync(valStream);
        results.Should().NotBeNull();
        results.Should().NotBeEmpty();
        results[0].IsIntegrityValid.Should().BeTrue();
        output.WriteLine($"Signers: {string.Join(", ", results.Select(r => r.SignerName ?? "(unknown)"))}");
    }

    [SkippableFact(DisplayName = "PAdES-EPES should parse and validate")]
    public async Task PadesEpes_ParsesAndValidates()
    {
        const string fixture = "pades-epes.pdf";
        Skip.IfNot(FixturePath.Exists(fixture), $"Fixture {fixture} not found");

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        using var parseStream = FixturePath.Open(fixture);
        var fields = await PdfStructureReader.ReadSignatureFieldsAsync(parseStream, cancellationToken: cts.Token);
        fields.Should().NotBeNull();
        output.WriteLine($"Fields: {fields.Count}");

        var validator = CreateValidator();
        using var valStream = FixturePath.Open(fixture);
        var results = await validator.ValidateAsync(valStream);
        results.Should().NotBeNull();
        output.WriteLine($"Results: {results.Count}");
        foreach (var r in results)
            output.WriteLine($"  {r.FieldName}: Integrity={r.IsIntegrityValid}, Sig={r.IsSignatureValid}");
    }

    [SkippableFact(DisplayName = "PAdES-T with timestamp should have at least 1 signature")]
    public async Task PadesT_HasAtLeastOneSignature()
    {
        const string fixture = "doc-firmado-T.pdf";
        Skip.IfNot(FixturePath.Exists(fixture), $"Fixture {fixture} not found");

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        using var stream = FixturePath.Open(fixture);
        var fields = await PdfStructureReader.ReadSignatureFieldsAsync(stream, cancellationToken: cts.Token);

        fields.Should().HaveCountGreaterThanOrEqualTo(1, "PAdES-T should contain at least 1 signature");
        output.WriteLine($"Fields: {string.Join(", ", fields.Select(f => f.FieldName ?? "(none)"))}");
    }

    [SkippableFact(DisplayName = "PAdES-B baseline should validate integrity")]
    public async Task PadesB_ValidatesIntegrity()
    {
        const string fixture = "doc-firmado-B.pdf";
        Skip.IfNot(FixturePath.Exists(fixture), $"Fixture {fixture} not found");

        var validator = CreateValidator();
        using var stream = FixturePath.Open(fixture);
        var results = await validator.ValidateAsync(stream);

        results.Should().NotBeNull();
        results.Should().NotBeEmpty();
        results[0].IsIntegrityValid.Should().BeTrue();
        output.WriteLine($"Signer: {results[0].SignerName ?? "(unknown)"}");
    }

    [SkippableFact(DisplayName = "SHA-512 with LTA should validate integrity")]
    public async Task Sha512Lta_ValidatesIntegrity()
    {
        const string fixture = "sha512-lta.pdf";
        Skip.IfNot(FixturePath.Exists(fixture), $"Fixture {fixture} not found");

        var validator = CreateValidator();
        using var stream = FixturePath.Open(fixture);
        var results = await validator.ValidateAsync(stream);

        results.Should().NotBeNull();
        results.Should().NotBeEmpty();
        results[0].IsIntegrityValid.Should().BeTrue();
        output.WriteLine($"Algorithm: {results[0].DigestAlgorithmName}, Signer: {results[0].SignerName ?? "(unknown)"}");
    }

    [SkippableFact(DisplayName = "Full PAdES-LTV should have DSS and at least 1 signature")]
    public async Task PadesLtvFull_HasDssAndSignatures()
    {
        const string fixture = "pades-ltv-full.pdf";
        Skip.IfNot(FixturePath.Exists(fixture), $"Fixture {fixture} not found");

        // Check DSS
        var bytes = await FixturePath.ReadBytesAsync(fixture);
        var hasDss = System.Text.Encoding.ASCII.GetString(bytes).Contains("/DSS ");
        hasDss.Should().BeTrue("PAdES-LTV should contain DSS dictionary");

        // Parse fields
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        using var stream = FixturePath.Open(fixture);
        var fields = await PdfStructureReader.ReadSignatureFieldsAsync(stream, cancellationToken: cts.Token);
        fields.Should().HaveCountGreaterThanOrEqualTo(1);
        output.WriteLine($"Fields: {fields.Count}, DSS: {hasDss}");
    }

    [SkippableFact(DisplayName = "PAdES-LTV with signing reason should validate")]
    public async Task PadesLtvReason_ValidatesAndContainsReason()
    {
        const string fixture = "pades-ltv-reason.pdf";
        Skip.IfNot(FixturePath.Exists(fixture), $"Fixture {fixture} not found");

        var validator = CreateValidator();
        using var stream = FixturePath.Open(fixture);
        var results = await validator.ValidateAsync(stream);

        results.Should().NotBeNull();
        results.Should().NotBeEmpty();
        output.WriteLine($"Results: {results.Count}");
        foreach (var r in results)
            output.WriteLine($"  {r.FieldName}: Integrity={r.IsIntegrityValid}, Signer={r.SignerName ?? "(unknown)"}");

        // Check reason in raw PDF bytes
        var bytes = await FixturePath.ReadBytesAsync(fixture);
        var pdfText = System.Text.Encoding.Latin1.GetString(bytes);
        pdfText.Should().Contain("/Reason", "PDF with reason should contain /Reason entry in signature dictionary");
    }
}
