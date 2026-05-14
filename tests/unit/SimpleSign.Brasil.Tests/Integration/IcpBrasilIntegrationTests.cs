using FluentAssertions;
using SimpleSign.PAdES;
using SimpleSign.Core.Validation;
using SimpleSign.PAdES.Validation;
using SimpleSign.Pdf;
using SimpleSign.TestHelpers;

namespace SimpleSign.Brasil.Tests.Integration;

/// <summary>
/// Integration tests using a real-world PDF signed with ICP-Brasil certificates.
/// </summary>
[Trait("Category", "Integration")]
public sealed class IcpBrasilIntegrationTests
{
    private const string Fixture = "signed-icp-brasil.pdf";

    private static string FixturePath(string name) =>
        Path.Combine("Integration", "Fixtures", name);

    private static bool FixtureExists(string name) =>
        File.Exists(FixturePath(name));

    [SkippableFact(DisplayName = "ICP-Brasil PDF should contain two signatures")]
    public async Task ReadSignatureFields_IcpBrasilPdf_FindsBothSignatures()
    {
        Skip.IfNot(FixtureExists(Fixture), "ICP-Brasil fixture not available");

        using var stream = File.OpenRead(FixturePath(Fixture));
        var fields = await PdfStructureReader.ReadSignatureFieldsAsync(stream);

        fields.Should().HaveCount(2);
        fields.Should().AllSatisfy(f =>
        {
            f.IsSigned.Should().BeTrue();
            f.SubFilter.Should().Be("adbe.pkcs7.detached");
            f.ByteRange.Should().NotBeNull();
            f.ByteRange!.IsValid.Should().BeTrue();
        });
    }

    [SkippableFact(DisplayName = "ICP-Brasil PDF should have signing dates in 2026")]
    public async Task ReadSignatureFields_IcpBrasilPdf_HasCorrectSigningTimes()
    {
        Skip.IfNot(FixtureExists(Fixture), "ICP-Brasil fixture not available");

        using var stream = File.OpenRead(FixturePath(Fixture));
        var fields = await PdfStructureReader.ReadSignatureFieldsAsync(stream);

        fields.Should().HaveCount(2);
        fields[0].PdfSigningTime.Should().NotBeNull();
        fields[0].PdfSigningTime!.Value.Year.Should().Be(2026);
        fields[1].PdfSigningTime.Should().NotBeNull();
        fields[1].PdfSigningTime!.Value.Year.Should().Be(2026);
    }

    [SkippableFact(DisplayName = "ICP-Brasil PDF should have valid integrity and signature")]
    public async Task Validate_IcpBrasilPdf_IntegrityAndSignatureValid()
    {
        Skip.IfNot(FixtureExists(Fixture), "ICP-Brasil fixture not available");

        var validator = new PdfSignatureValidator(new ValidationOptions { CheckRevocation = false });
        using var stream = File.OpenRead(FixturePath(Fixture));
        var results = await validator.ValidateAsync(stream);

        results.Should().HaveCount(2);
        results.Should().AllSatisfy(r =>
        {
            r.IsIntegrityValid.Should().BeTrue();
            r.IsSignatureValid.Should().BeTrue();
        });
    }

    [SkippableFact(DisplayName = "ICP-Brasil PDF should contain CPF in signer names")]
    public async Task Validate_IcpBrasilPdf_SignerNamesContainCpf()
    {
        Skip.IfNot(FixtureExists(Fixture), "ICP-Brasil fixture not available");

        var validator = new PdfSignatureValidator(new ValidationOptions { CheckRevocation = false });
        using var stream = File.OpenRead(FixturePath(Fixture));
        var results = await validator.ValidateAsync(stream);

        results.Should().HaveCount(2);
        results[0].SignerName.Should().Contain(":");
        results[1].SignerName.Should().Contain(":");
    }

    [SkippableFact(DisplayName = "Re-signing ICP-Brasil PDF should produce valid third signature")]
    public async Task SignAndValidate_IcpBrasilPdf_ProducesValidThirdSignature()
    {
        Skip.IfNot(FixtureExists(Fixture), "ICP-Brasil fixture not available");

        using var cert = TestCertificateFactory.CreateSelfSignedCert();
        byte[] pdfBytes = await File.ReadAllBytesAsync(FixturePath(Fixture));

        byte[] signedPdf = await SimpleSigner
            .Document(pdfBytes)
            .WithCertificate(cert)
            .SignAsync();

        var validator = new PdfSignatureValidator(new ValidationOptions { CheckRevocation = false });
        using var stream = new MemoryStream(signedPdf);
        var results = await validator.ValidateAsync(stream);

        results.Should().HaveCountGreaterThanOrEqualTo(3);
        var lastResult = results[^1];
        lastResult.IsIntegrityValid.Should().BeTrue();
        lastResult.IsSignatureValid.Should().BeTrue();
    }

    [SkippableFact(DisplayName = "ICP-Brasil AD-RB PDF should pass integrity check")]
    public async Task AdRbSignature_PassesIntegrity()
    {
        const string fixture = "AD-RB.pdf";
        Skip.IfNot(FixtureExists(fixture), $"Fixture {fixture} not found");

        var validator = new PdfSignatureValidator(new ValidationOptions { CheckRevocation = false });
        using var stream = File.OpenRead(FixturePath(fixture));
        var results = await validator.ValidateAsync(stream);

        results.Should().HaveCountGreaterThanOrEqualTo(2);
        results[0].IsIntegrityValid.Should().BeTrue();
    }
}
