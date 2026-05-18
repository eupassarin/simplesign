using Shouldly;
using SimpleSign.Core.Validation;
using SimpleSign.PAdES;
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

        fields.Count().ShouldBe(2);
        foreach (var f in fields)
        {
            f.IsSigned.ShouldBeTrue();
            f.SubFilter.ShouldBe("adbe.pkcs7.detached");
            f.ByteRange.ShouldNotBeNull();
            f.ByteRange!.IsValid.ShouldBeTrue();
        }
    }

    [SkippableFact(DisplayName = "ICP-Brasil PDF should have signing dates in 2026")]
    public async Task ReadSignatureFields_IcpBrasilPdf_HasCorrectSigningTimes()
    {
        Skip.IfNot(FixtureExists(Fixture), "ICP-Brasil fixture not available");

        using var stream = File.OpenRead(FixturePath(Fixture));
        var fields = await PdfStructureReader.ReadSignatureFieldsAsync(stream);

        fields.Count().ShouldBe(2);
        fields[0].PdfSigningTime.ShouldNotBeNull();
        fields[0].PdfSigningTime!.Value.Year.ShouldBe(2026);
        fields[1].PdfSigningTime.ShouldNotBeNull();
        fields[1].PdfSigningTime!.Value.Year.ShouldBe(2026);
    }

    [SkippableFact(DisplayName = "ICP-Brasil PDF should have valid integrity and signature")]
    public async Task Validate_IcpBrasilPdf_IntegrityAndSignatureValid()
    {
        Skip.IfNot(FixtureExists(Fixture), "ICP-Brasil fixture not available");

        var validator = new PdfSignatureValidator(new ValidationOptions { CheckRevocation = false });
        using var stream = File.OpenRead(FixturePath(Fixture));
        var results = await validator.ValidateAsync(stream);

        results.Count().ShouldBe(2);
        foreach (var r in results)
        {
            r.IsIntegrityValid.ShouldBeTrue();
            r.IsSignatureValid.ShouldBeTrue();
        }
    }

    [SkippableFact(DisplayName = "ICP-Brasil PDF should contain CPF in signer names")]
    public async Task Validate_IcpBrasilPdf_SignerNamesContainCpf()
    {
        Skip.IfNot(FixtureExists(Fixture), "ICP-Brasil fixture not available");

        var validator = new PdfSignatureValidator(new ValidationOptions { CheckRevocation = false });
        using var stream = File.OpenRead(FixturePath(Fixture));
        var results = await validator.ValidateAsync(stream);

        results.Count().ShouldBe(2);
        results[0].SignerName!.ShouldContain(":");
        results[1].SignerName!.ShouldContain(":");
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

        results.Count().ShouldBeGreaterThanOrEqualTo(3);
        var lastResult = results[^1];
        lastResult.IsIntegrityValid.ShouldBeTrue();
        lastResult.IsSignatureValid.ShouldBeTrue();
    }

    [SkippableFact(DisplayName = "ICP-Brasil AD-RB PDF should pass integrity check")]
    public async Task AdRbSignature_PassesIntegrity()
    {
        const string fixture = "AD-RB.pdf";
        Skip.IfNot(FixtureExists(fixture), $"Fixture {fixture} not found");

        var validator = new PdfSignatureValidator(new ValidationOptions { CheckRevocation = false });
        using var stream = File.OpenRead(FixturePath(fixture));
        var results = await validator.ValidateAsync(stream);

        results.Count().ShouldBeGreaterThanOrEqualTo(2);
        results[0].IsIntegrityValid.ShouldBeTrue();
    }
}
