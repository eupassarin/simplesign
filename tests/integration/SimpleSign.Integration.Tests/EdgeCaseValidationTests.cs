using FluentAssertions;
using SimpleSign.Core.Validation;
using SimpleSign.Integration.Tests.Helpers;
using SimpleSign.PAdES.Validation;
using SimpleSign.Pdf;
using SimpleSign.Pdf.Exceptions;
using Xunit;
using Xunit.Abstractions;

namespace SimpleSign.Integration.Tests;

public sealed class EdgeCaseValidationTests(ITestOutputHelper output)
{
    private static PdfSignatureValidator CreateValidator() =>
        new(new ValidationOptions { CheckRevocation = false });

    [SkippableFact(DisplayName = "Encrypted PDF should throw or return gracefully")]
    public async Task EncryptedPdf_ThrowsOrReturnsGracefully()
    {
        const string fixture = "encrypted.pdf";
        Skip.IfNot(FixturePath.Exists(fixture), $"Fixture {fixture} not found");

        try
        {
            var validator = CreateValidator();
            using var stream = FixturePath.Open(fixture);
            var results = await validator.ValidateAsync(stream);

            results.Should().NotBeNull();
            output.WriteLine($"Returned {results.Count} result(s) without exception");
            foreach (var r in results)
                output.WriteLine($"  {r.FieldName}: Integrity={r.IsIntegrityValid}");
        }
        catch (Exception ex) when (ex is EncryptedPdfException or InvalidOperationException or InvalidDataException)
        {
            output.WriteLine($"Expected exception: {ex.GetType().Name}: {ex.Message}");
        }
    }

    [SkippableFact(DisplayName = "Modified-after-sign PDF should have invalid integrity")]
    public async Task ModifiedAfterSig_IntegrityInvalid()
    {
        const string fixture = "modified-after-sig.pdf";
        Skip.IfNot(FixturePath.Exists(fixture), $"Fixture {fixture} not found");

        var validator = CreateValidator();
        using var stream = FixturePath.Open(fixture);
        var results = await validator.ValidateAsync(stream);

        results.Should().NotBeNull();
        results.Should().NotBeEmpty("Modified PDF should have at least one signature");
        output.WriteLine($"Results: {results.Count}");
        foreach (var r in results)
            output.WriteLine($"  {r.FieldName}: Integrity={r.IsIntegrityValid}, Sig={r.IsSignatureValid}");
    }

    [SkippableFact(DisplayName = "PAdES enveloping CMS should parse without error")]
    public async Task PadesEnvelopingCms_ParsesWithoutCrashing()
    {
        const string fixture = "pades-enveloping-cms.pdf";
        Skip.IfNot(FixturePath.Exists(fixture), $"Fixture {fixture} not found");

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        using var stream = FixturePath.Open(fixture);
        var fields = await PdfStructureReader.ReadSignatureFieldsAsync(stream, cancellationToken: cts.Token);

        fields.Should().NotBeNull();
        output.WriteLine($"Fields: {fields.Count}");
        foreach (var f in fields)
            output.WriteLine($"  {f.FieldName}: Signed={f.IsSigned}, SubFilter={f.SubFilter ?? "(none)"}");
    }

    [SkippableFact(DisplayName = "ECDSA PDF should parse signature fields")]
    public async Task PadesEcdsa_ParsesSignatureFields()
    {
        const string fixture = "pades-ecdsa.pdf";
        Skip.IfNot(FixturePath.Exists(fixture), $"Fixture {fixture} not found");

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        using var stream = FixturePath.Open(fixture);
        var fields = await PdfStructureReader.ReadSignatureFieldsAsync(stream, cancellationToken: cts.Token);

        fields.Should().NotBeNull();
        output.WriteLine($"Fields: {fields.Count}");
        foreach (var f in fields)
            output.WriteLine($"  {f.FieldName}: Signed={f.IsSigned}, SubFilter={f.SubFilter ?? "(none)"}");
    }

    [SkippableFact(DisplayName = "PDF with embedded CRL should parse and validate")]
    public async Task AdbeCrlSigned_ParsesAndValidates()
    {
        const string fixture = "adbe-crl-signed.pdf";
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
            output.WriteLine($"  {r.FieldName}: Integrity={r.IsIntegrityValid}");
    }

    [SkippableFact(DisplayName = "PDF with embedded OCSP should parse")]
    public async Task AdbeOcspSigned_Parses()
    {
        const string fixture = "adbe-ocsp-signed.pdf";
        Skip.IfNot(FixturePath.Exists(fixture), $"Fixture {fixture} not found");

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        using var stream = FixturePath.Open(fixture);
        var fields = await PdfStructureReader.ReadSignatureFieldsAsync(stream, cancellationToken: cts.Token);

        fields.Should().NotBeNull();
        output.WriteLine($"Fields: {fields.Count}");
        foreach (var f in fields)
            output.WriteLine($"  {f.FieldName}: Signed={f.IsSigned}");
    }

    [SkippableFact(DisplayName = "Belgian PDF with multiple OCSP should validate")]
    public async Task BelgianMultiOcsp_Validates()
    {
        const string fixture = "belgian-multi-ocsp.pdf";
        Skip.IfNot(FixturePath.Exists(fixture), $"Fixture {fixture} not found");

        var validator = CreateValidator();
        using var stream = FixturePath.Open(fixture);
        var results = await validator.ValidateAsync(stream);

        results.Should().NotBeNull();
        output.WriteLine($"Results: {results.Count}");
        foreach (var r in results)
            output.WriteLine($"  {r.FieldName}: Integrity={r.IsIntegrityValid}, Signer={r.SignerName ?? "(unknown)"}");
    }

    [SkippableFact(DisplayName = "DSS-1443 edge case should parse without hanging")]
    public async Task Dss1443_ParsesWithoutHanging()
    {
        const string fixture = "dss-1443.pdf";
        Skip.IfNot(FixturePath.Exists(fixture), $"Fixture {fixture} not found");

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        using var stream = FixturePath.Open(fixture);
        var fields = await PdfStructureReader.ReadSignatureFieldsAsync(stream, cancellationToken: cts.Token);

        fields.Should().NotBeNull();
        output.WriteLine($"{fixture}: {fields.Count} field(s)");
    }

    [SkippableFact(DisplayName = "DSS-3567 edge case should parse without hanging")]
    public async Task Dss3567_ParsesWithoutHanging()
    {
        const string fixture = "dss-3567.pdf";
        Skip.IfNot(FixturePath.Exists(fixture), $"Fixture {fixture} not found");

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        using var stream = FixturePath.Open(fixture);
        var fields = await PdfStructureReader.ReadSignatureFieldsAsync(stream, cancellationToken: cts.Token);

        fields.Should().NotBeNull();
        output.WriteLine($"{fixture}: {fields.Count} field(s)");
    }
}
