using Shouldly;
using SimpleSign.Core.Validation;
using SimpleSign.Integration.Tests.Helpers;
using SimpleSign.PAdES.Validation;
using Xunit;
using Xunit.Abstractions;

namespace SimpleSign.Integration.Tests;

public sealed class SignatureValidationTests(ITestOutputHelper output)
{
    private static PdfSignatureValidator CreateValidator() =>
        new(new ValidationOptions { CheckRevocation = false });

    [SkippableFact(DisplayName = "Valid signature should pass integrity check")]
    public async Task ValidSignature_PassesIntegrityAndSignatureCheck()
    {
        const string fixture = "pades-bes.pdf";
        Skip.IfNot(FixturePath.Exists(fixture), $"Fixture {fixture} not found");

        var validator = CreateValidator();
        using var stream = FixturePath.Open(fixture);
        var results = await validator.ValidateAsync(stream);

        results.Count().ShouldBe(1);
        results[0].IsIntegrityValid.ShouldBeTrue();
        results[0].IsSignatureValid.ShouldBeTrue();
        output.WriteLine($"Signer: {results[0].SignerName}");
    }

    [SkippableFact(DisplayName = "Valid PKCS7 signature should pass checks")]
    public async Task ValidPkcs7Signature_PassesChecks()
    {
        const string fixture = "dss-2025.pdf";
        Skip.IfNot(FixturePath.Exists(fixture), $"Fixture {fixture} not found");

        var validator = CreateValidator();
        using var stream = FixturePath.Open(fixture);
        var results = await validator.ValidateAsync(stream);

        results.Count().ShouldBe(1);
        results[0].IsIntegrityValid.ShouldBeTrue();
        results[0].IsSignatureValid.ShouldBeTrue();
        output.WriteLine($"Signer: {results[0].SignerName}");
    }

    [SkippableFact(DisplayName = "CMS without certificates should fail signature but pass integrity")]
    public async Task NoCertificatesInCms_FailsSignatureButPassesIntegrity()
    {
        const string fixture = "pades-bes-no-certs.pdf";
        Skip.IfNot(FixturePath.Exists(fixture), $"Fixture {fixture} not found");

        var validator = CreateValidator();
        using var stream = FixturePath.Open(fixture);
        var results = await validator.ValidateAsync(stream);

        results.Count().ShouldBe(1);
        results[0].IsIntegrityValid.ShouldBeTrue();
        results[0].IsSignatureValid.ShouldBeFalse();
        output.WriteLine($"Signer: {results[0].SignerName ?? "(unknown)"}");
    }

    [SkippableFact(DisplayName = "Cross-certificate signature should pass integrity")]
    public async Task CrossCertSignature_PassesIntegrity()
    {
        const string fixture = "pades-cross-cert-ocsp.pdf";
        Skip.IfNot(FixturePath.Exists(fixture), $"Fixture {fixture} not found");

        var validator = CreateValidator();
        using var stream = FixturePath.Open(fixture);
        var results = await validator.ValidateAsync(stream);

        results.Count().ShouldBe(1);
        results[0].IsIntegrityValid.ShouldBeTrue();
        results[0].IsSignatureValid.ShouldBeTrue();
        results[0].SignerName!.ShouldContain("Karimi");
        output.WriteLine($"Signer: {results[0].SignerName}");
    }

    [SkippableFact(DisplayName = "Signature with VRI should pass integrity check")]
    public async Task VriSignature_PassesIntegrity()
    {
        const string fixture = "test-with-vri.pdf";
        Skip.IfNot(FixturePath.Exists(fixture), $"Fixture {fixture} not found");

        var validator = CreateValidator();
        using var stream = FixturePath.Open(fixture);
        var results = await validator.ValidateAsync(stream);

        results.Count().ShouldBe(1);
        results[0].IsIntegrityValid.ShouldBeTrue();
        results[0].IsSignatureValid.ShouldBeTrue();
        output.WriteLine($"Signer: {results[0].SignerName}");
    }

}
