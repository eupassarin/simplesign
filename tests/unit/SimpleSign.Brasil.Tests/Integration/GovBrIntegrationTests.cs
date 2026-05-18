using Shouldly;
using SimpleSign.Core.Validation;
using SimpleSign.PAdES;
using SimpleSign.PAdES.Validation;
using SimpleSign.Pdf;
using SimpleSign.TestHelpers;
using Xunit.Abstractions;

namespace SimpleSign.Brasil.Tests.Integration;

/// <summary>
/// Integration tests using a real-world PDF signed via Gov.br (assinatura.gov.br).
/// Gov.br uses ICP-Brasil certificates with SubFilter adbe.pkcs7.detached.
/// </summary>
[Trait("Category", "Integration")]
public sealed class GovBrIntegrationTests(ITestOutputHelper output)
{
    private const string Fixture = "signed-gov-br.pdf";

    private static string FixturePath(string name) =>
        Path.Combine("Integration", "Fixtures", name);

    private static bool FixtureExists(string name) =>
        File.Exists(FixturePath(name));

    [SkippableFact(DisplayName = "Gov.br PDF should contain a single signature")]
    public async Task ReadSignatureFields_GovBrPdf_FindsSingleSignature()
    {
        Skip.IfNot(FixtureExists(Fixture), "Gov.br fixture not available");

        using var stream = File.OpenRead(FixturePath(Fixture));
        var fields = await PdfStructureReader.ReadSignatureFieldsAsync(stream);

        fields.Count().ShouldBe(1);

        var field = fields[0];
        field.IsSigned.ShouldBeTrue();
        field.FieldName.ShouldBe("Signature_144");
        field.SubFilter.ShouldBe("adbe.pkcs7.detached");
        field.ByteRange.ShouldNotBeNull();
        field.ByteRange!.IsValid.ShouldBeTrue();
        output.WriteLine($"Field: {field.FieldName}, SubFilter: {field.SubFilter}");
    }

    [SkippableFact(DisplayName = "Gov.br PDF should have signing date in 2026")]
    public async Task ReadSignatureFields_GovBrPdf_HasSigningTime()
    {
        Skip.IfNot(FixtureExists(Fixture), "Gov.br fixture not available");

        using var stream = File.OpenRead(FixturePath(Fixture));
        var fields = await PdfStructureReader.ReadSignatureFieldsAsync(stream);

        fields.Count().ShouldBe(1);
        fields[0].PdfSigningTime.ShouldNotBeNull();
        fields[0].PdfSigningTime!.Value.Year.ShouldBe(2026);
    }

    [SkippableFact(DisplayName = "Gov.br PDF should have valid integrity")]
    public async Task Validate_GovBrPdf_IntegrityIsValid()
    {
        Skip.IfNot(FixtureExists(Fixture), "Gov.br fixture not available");

        var validator = new PdfSignatureValidator(new ValidationOptions { CheckRevocation = false });
        using var stream = File.OpenRead(FixturePath(Fixture));
        var results = await validator.ValidateAsync(stream);

        results.Count().ShouldBe(1);
        results[0].IsIntegrityValid.ShouldBeTrue();
        results[0].IsSignatureValid.ShouldBeTrue();
        output.WriteLine($"Signer: {results[0].SignerName}");
    }

    [SkippableFact(DisplayName = "Gov.br PDF should contain signer name")]
    public async Task Validate_GovBrPdf_SignerNameIsPopulated()
    {
        Skip.IfNot(FixtureExists(Fixture), "Gov.br fixture not available");

        var validator = new PdfSignatureValidator(new ValidationOptions { CheckRevocation = false });
        using var stream = File.OpenRead(FixturePath(Fixture));
        var results = await validator.ValidateAsync(stream);

        results.Count().ShouldBe(1);
        results[0].SignerName.ShouldNotBeNullOrWhiteSpace();
        results[0].SignerCertificate.ShouldNotBeNull();
        output.WriteLine($"Signer: {results[0].SignerName}, Subject: {results[0].SignerCertificate!.Subject}");
    }

    [SkippableFact(DisplayName = "Gov.br PDF should use SHA-256 algorithm")]
    public async Task Validate_GovBrPdf_UsesSha256()
    {
        Skip.IfNot(FixtureExists(Fixture), "Gov.br fixture not available");

        var validator = new PdfSignatureValidator(new ValidationOptions { CheckRevocation = false });
        using var stream = File.OpenRead(FixturePath(Fixture));
        var results = await validator.ValidateAsync(stream);

        results.Count().ShouldBe(1);
        results[0].DigestAlgorithmOid.ShouldBe("2.16.840.1.101.3.4.2.1", "Gov.br uses SHA-256");
        results[0].SigningTime.ShouldNotBeNull();
    }

    [SkippableFact(DisplayName = "Re-signing Gov.br PDF should produce valid second signature")]
    public async Task SignAndValidate_GovBrPdf_ProducesValidSecondSignature()
    {
        Skip.IfNot(FixtureExists(Fixture), "Gov.br fixture not available");

        using var cert = TestCertificateFactory.CreateSelfSignedCert();
        byte[] pdfBytes = await File.ReadAllBytesAsync(FixturePath(Fixture));

        byte[] signedPdf = await SimpleSigner
            .Document(pdfBytes)
            .WithCertificate(cert)
            .WithFieldName("Sig2")
            .SignAsync();

        var validator = new PdfSignatureValidator(new ValidationOptions { CheckRevocation = false });
        using var stream = new MemoryStream(signedPdf);
        var results = await validator.ValidateAsync(stream);

        results.Count().ShouldBe(2);

        // Original Gov.br signature preserved
        results[0].IsIntegrityValid.ShouldBeTrue();
        results[0].IsSignatureValid.ShouldBeTrue();

        // New signature valid
        results[1].IsIntegrityValid.ShouldBeTrue();
        results[1].IsSignatureValid.ShouldBeTrue();

        output.WriteLine($"Signers: {string.Join(", ", results.Select(r => r.SignerName))}");
    }
}
