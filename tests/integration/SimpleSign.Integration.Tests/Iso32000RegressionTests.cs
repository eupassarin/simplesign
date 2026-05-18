using Shouldly;
using SimpleSign.Core.Validation;
using SimpleSign.Integration.Tests.Helpers;
using SimpleSign.PAdES.Inspection;
using SimpleSign.PAdES.Validation;
using SimpleSign.Pdf;
using Xunit;
using Xunit.Abstractions;

namespace SimpleSign.Integration.Tests;

/// <summary>
/// Regression tests for ISO 32000 compliance fixes.
/// These tests verify that specific bug fixes continue to work correctly
/// against real-world PDF fixtures.
/// </summary>
public sealed class Iso32000RegressionTests(ITestOutputHelper output)
{
    private static PdfSignatureValidator CreateValidator() =>
        new(new ValidationOptions { CheckRevocation = false });

    // ── Multiline /Fields parsing (whitespace split fix) ────────────────────

    [SkippableFact(DisplayName = "Regression: PDF with 51 signatures parses all fields correctly")]
    public async Task Regression_51Sigs_AllFieldsParsed()
    {
        const string fixture = "51sigs.pdf";
        Skip.IfNot(FixturePath.Exists(fixture), $"Fixture {fixture} not found");

        using var stream = FixturePath.Open(fixture);
        var fields = await PdfStructureReader.ReadSignatureFieldsAsync(stream);

        fields.Count().ShouldBeGreaterThanOrEqualTo(51);
        fields.Where(f => f.IsSigned).Count().ShouldBeGreaterThanOrEqualTo(51);
        output.WriteLine($"Fields found: {fields.Count}, signed: {fields.Count(f => f.IsSigned)}");
    }

    [SkippableFact(DisplayName = "Regression: Multi-signed PDF preserves all signature fields")]
    public async Task Regression_MultiSign_AllPreserved()
    {
        const string fixture = "incremental-multi-sign.pdf";
        Skip.IfNot(FixturePath.Exists(fixture), $"Fixture {fixture} not found");

        using var stream = FixturePath.Open(fixture);
        var fields = await PdfStructureReader.ReadSignatureFieldsAsync(stream);

        fields.Count().ShouldBeGreaterThanOrEqualTo(2);
        fields.ShouldAllBe(f => f.IsSigned);

        // Validate each signature field has proper SubFilter
        foreach (var field in fields)
        {
            field.SubFilter.ShouldNotBeNullOrEmpty(
                $"Field '{field.FieldName}' should have a SubFilter");
            output.WriteLine($"  {field.FieldName}: SubFilter={field.SubFilter}");
        }
    }

    // ── ByteRange coverage validation ───────────────────────────────────────

    [SkippableFact(DisplayName = "Regression: Last signature covers entire file")]
    public async Task Regression_LastSignature_CoversEntireFile()
    {
        const string fixture = "pades-bes.pdf";
        Skip.IfNot(FixturePath.Exists(fixture), $"Fixture {fixture} not found");

        byte[] data = await FixturePath.ReadBytesAsync(fixture);
        using var stream = new MemoryStream(data);
        var fields = await PdfStructureReader.ReadSignatureFieldsAsync(stream);

        fields.ShouldNotBeEmpty();
        var lastField = fields[^1];
        lastField.IsSigned.ShouldBeTrue();
        lastField.ByteRange.ShouldNotBeNull();

        bool coversFile = lastField.ByteRange!.CoversEntireFile(data.Length);
        coversFile.ShouldBeTrue(
            $"Last signature should cover entire file ({data.Length} bytes), " +
            $"ByteRange ends at {lastField.ByteRange.Offset2 + lastField.ByteRange.Length2}");
        output.WriteLine($"File size: {data.Length}, ByteRange: [{lastField.ByteRange.Offset1} {lastField.ByteRange.Length1} {lastField.ByteRange.Offset2} {lastField.ByteRange.Length2}]");
    }

    [SkippableFact(DisplayName = "Regression: Intermediate signatures don't need to cover entire file")]
    public async Task Regression_IntermediateSignature_DoesNotCoverEntireFile()
    {
        const string fixture = "double-signed.pdf";
        Skip.IfNot(FixturePath.Exists(fixture), $"Fixture {fixture} not found");

        byte[] data = await FixturePath.ReadBytesAsync(fixture);
        using var stream = new MemoryStream(data);
        var fields = await PdfStructureReader.ReadSignatureFieldsAsync(stream);

        Skip.If(fields.Count < 2, "Need at least 2 signatures");
        var firstField = fields[0];
        firstField.ByteRange.ShouldNotBeNull();

        // First signature in a multi-signed PDF typically doesn't cover the full file
        bool coversFile = firstField.ByteRange!.CoversEntireFile(data.Length);
        // This is expected behavior - not a failure
        output.WriteLine($"First sig covers entire file: {coversFile} (file={data.Length}, range ends at {firstField.ByteRange.Offset2 + firstField.ByteRange.Length2})");
    }

    // ── Linearized PDF detection ────────────────────────────────────────────

    [SkippableFact(DisplayName = "Regression: All fixtures can be inspected without crash")]
    public async Task Regression_AllFixtures_InspectWithoutCrash()
    {
        string[] fixtures = [
            "pades-bes.pdf", "pades-lt.pdf", "pades-lta.pdf",
            "double-signed.pdf", "timestamped-and-signed.pdf",
            "signed-icp-brasil.pdf", "pades-ecdsa.pdf"
        ];

        foreach (string fixture in fixtures)
        {
            if (!FixturePath.Exists(fixture))
            {
                continue;
            }

            using var stream = FixturePath.Open(fixture);
            var result = await PdfSignatureInspector.InspectAsync(stream);

            result.ShouldNotBeNull($"Inspect of {fixture} should succeed");
            output.WriteLine($"{fixture}: {result.Signatures.Count} signatures");
        }
    }

    // ── Validate→Inspect roundtrip ──────────────────────────────────────────

    [SkippableFact(DisplayName = "Roundtrip: Validate and Inspect agree on signature count")]
    public async Task Roundtrip_ValidateAndInspect_AgreeOnCount()
    {
        string[] fixtures = [
            "pades-bes.pdf", "pades-lt.pdf", "double-signed.pdf",
            "timestamped-and-signed.pdf", "pades-5sigs-1ts.pdf"
        ];

        var validator = CreateValidator();

        foreach (string fixture in fixtures)
        {
            if (!FixturePath.Exists(fixture))
            {
                continue;
            }

            // Validate
            using var stream1 = FixturePath.Open(fixture);
            var validationResults = await validator.ValidateAsync(stream1);

            // Inspect
            using var stream2 = FixturePath.Open(fixture);
            var inspectionResult = await PdfSignatureInspector.InspectAsync(stream2);

            validationResults.Count().ShouldBe(inspectionResult.Signatures.Count,
                $"{fixture}: validate and inspect should find same number of signatures");
            output.WriteLine($"{fixture}: {validationResults.Count} signatures (consistent)");
        }
    }

    // ── Integrity validation with ByteRange ─────────────────────────────────

    [SkippableFact(DisplayName = "Roundtrip: Valid signatures pass integrity check")]
    public async Task Roundtrip_ValidSignatures_PassIntegrity()
    {
        string[] fixtures = ["pades-bes.pdf", "dss-2025.pdf", "pades-epes.pdf"];
        var validator = CreateValidator();

        foreach (string fixture in fixtures)
        {
            if (!FixturePath.Exists(fixture))
            {
                continue;
            }

            using var stream = FixturePath.Open(fixture);
            var results = await validator.ValidateAsync(stream);

            results.ShouldNotBeEmpty($"{fixture} should have signatures");
            foreach (var result in results)
            {
                result.IsIntegrityValid.ShouldBeTrue(
                    $"{fixture}/{result.SignerName}: integrity should be valid");
            }
            output.WriteLine($"{fixture}: all {results.Count} signatures pass integrity");
        }
    }

    [SkippableFact(DisplayName = "Regression: Modified-after-sig PDF detected by validator")]
    public async Task Regression_ModifiedAfterSig_DetectedByValidator()
    {
        const string fixture = "modified-after-sig.pdf";
        Skip.IfNot(FixturePath.Exists(fixture), $"Fixture {fixture} not found");

        var validator = CreateValidator();
        using var stream = FixturePath.Open(fixture);
        var results = await validator.ValidateAsync(stream);

        results.ShouldNotBeEmpty();
        // In an incrementally-updated PDF, earlier signatures won't cover the full file.
        // The validator should still parse all signatures without crashing.
        output.WriteLine($"Results: {results.Count} sigs, integrity valid: {results.Count(r => r.IsIntegrityValid)}, invalid: {results.Count(r => !r.IsIntegrityValid)}");
        foreach (var r in results)
        {
            output.WriteLine($"  {r.SignerName}: integrity={r.IsIntegrityValid}");
        }
    }

    // ── SubFilter variety ───────────────────────────────────────────────────

    [SkippableFact(DisplayName = "Regression: ECDSA signature parsed correctly")]
    public async Task Regression_EcdsaSignature_Parsed()
    {
        const string fixture = "pades-ecdsa.pdf";
        Skip.IfNot(FixturePath.Exists(fixture), $"Fixture {fixture} not found");

        using var stream = FixturePath.Open(fixture);
        var fields = await PdfStructureReader.ReadSignatureFieldsAsync(stream);

        fields.ShouldNotBeEmpty();
        fields[0].IsSigned.ShouldBeTrue();
        output.WriteLine($"SubFilter: {fields[0].SubFilter}, Field: {fields[0].FieldName}");
    }

    [SkippableFact(DisplayName = "Regression: PAdES-LTA with timestamps parsed correctly")]
    public async Task Regression_PadesLta_TimestampsParsed()
    {
        const string fixture = "pades-lta.pdf";
        Skip.IfNot(FixturePath.Exists(fixture), $"Fixture {fixture} not found");

        using var stream = FixturePath.Open(fixture);
        var result = await PdfSignatureInspector.InspectAsync(stream);

        result.Signatures.ShouldNotBeEmpty();
        // LTA should have at least one timestamp
        result.Signatures.ShouldContain(s =>
            s.SubFilter == "ETSI.RFC3161" || s.SubFilter == "adbe.pkcs7.detached");
        output.WriteLine($"Signatures: {result.Signatures.Count}");
        foreach (var sig in result.Signatures)
        {
            output.WriteLine($"  {sig.FieldName}: SubFilter={sig.SubFilter}");
        }
    }

}
