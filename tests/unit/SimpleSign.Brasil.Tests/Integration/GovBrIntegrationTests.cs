using FluentAssertions;
using SimpleSign.PAdES;
using SimpleSign.Core.Validation;
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

        fields.Should().HaveCount(1);

        var field = fields[0];
        field.IsSigned.Should().BeTrue();
        field.FieldName.Should().Be("Signature_144");
        field.SubFilter.Should().Be("adbe.pkcs7.detached");
        field.ByteRange.Should().NotBeNull();
        field.ByteRange!.IsValid.Should().BeTrue();
        output.WriteLine($"Field: {field.FieldName}, SubFilter: {field.SubFilter}");
    }

    [SkippableFact(DisplayName = "Gov.br PDF should have signing date in 2026")]
    public async Task ReadSignatureFields_GovBrPdf_HasSigningTime()
    {
        Skip.IfNot(FixtureExists(Fixture), "Gov.br fixture not available");

        using var stream = File.OpenRead(FixturePath(Fixture));
        var fields = await PdfStructureReader.ReadSignatureFieldsAsync(stream);

        fields.Should().ContainSingle();
        fields[0].PdfSigningTime.Should().NotBeNull();
        fields[0].PdfSigningTime!.Value.Year.Should().Be(2026);
    }

    [SkippableFact(DisplayName = "Gov.br PDF should have valid integrity")]
    public async Task Validate_GovBrPdf_IntegrityIsValid()
    {
        Skip.IfNot(FixtureExists(Fixture), "Gov.br fixture not available");

        var validator = new PdfSignatureValidator(new ValidationOptions { CheckRevocation = false });
        using var stream = File.OpenRead(FixturePath(Fixture));
        var results = await validator.ValidateAsync(stream);

        results.Should().ContainSingle();
        results[0].IsIntegrityValid.Should().BeTrue();
        results[0].IsSignatureValid.Should().BeTrue();
        output.WriteLine($"Signer: {results[0].SignerName}");
    }

    [SkippableFact(DisplayName = "Gov.br PDF should contain signer name")]
    public async Task Validate_GovBrPdf_SignerNameIsPopulated()
    {
        Skip.IfNot(FixtureExists(Fixture), "Gov.br fixture not available");

        var validator = new PdfSignatureValidator(new ValidationOptions { CheckRevocation = false });
        using var stream = File.OpenRead(FixturePath(Fixture));
        var results = await validator.ValidateAsync(stream);

        results.Should().ContainSingle();
        results[0].SignerName.Should().NotBeNullOrWhiteSpace();
        results[0].SignerCertificate.Should().NotBeNull();
        output.WriteLine($"Signer: {results[0].SignerName}, Subject: {results[0].SignerCertificate!.Subject}");
    }

    [SkippableFact(DisplayName = "Gov.br PDF should use SHA-256 algorithm")]
    public async Task Validate_GovBrPdf_UsesSha256()
    {
        Skip.IfNot(FixtureExists(Fixture), "Gov.br fixture not available");

        var validator = new PdfSignatureValidator(new ValidationOptions { CheckRevocation = false });
        using var stream = File.OpenRead(FixturePath(Fixture));
        var results = await validator.ValidateAsync(stream);

        results.Should().ContainSingle();
        results[0].DigestAlgorithmOid.Should().Be("2.16.840.1.101.3.4.2.1", "Gov.br uses SHA-256");
        results[0].SigningTime.Should().NotBeNull();
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

        results.Should().HaveCount(2);

        // Original Gov.br signature preserved
        results[0].IsIntegrityValid.Should().BeTrue();
        results[0].IsSignatureValid.Should().BeTrue();

        // New signature valid
        results[1].IsIntegrityValid.Should().BeTrue();
        results[1].IsSignatureValid.Should().BeTrue();

        output.WriteLine($"Signers: {string.Join(", ", results.Select(r => r.SignerName))}");
    }
}
