using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Shouldly;
using SimpleSign.Core.Crypto;
using SimpleSign.Core.Signing;
using SimpleSign.Core.Validation;
using SimpleSign.PAdES.Inspection;
using SimpleSign.PAdES.Signing;
using SimpleSign.PAdES.Validation;
using SimpleSign.TestHelpers;
using Xunit;

namespace SimpleSign.PAdES.Tests.Signing;

/// <summary>What <see cref="PadesSignerBuilder.SignWithDetailsAsync"/> reports of the signature it made.</summary>
[Trait("Category", "Unit")]
public sealed class PadesSignerBuilderTests : IDisposable
{
    private readonly X509Certificate2 _cert = CreateRsaCert();

    public void Dispose() => _cert.Dispose();

    [Theory]
    [InlineData(PdfSignatureSubFilter.AdbePkcs7Detached, "adbe.pkcs7.detached")]
    [InlineData(PdfSignatureSubFilter.PbadPades, "PBAD.PAdES")]
    public async Task SignWithDetailsAsync_SubFilterNotEtsiCadesDetached_WarnsItIsNotBaseline(PdfSignatureSubFilter subFilter, string name)
    {
        var result = await PadesSigner.Document(TestPdfFactory.CreateMinimalPdf()).WithCertificate(_cert)
            .WithSubFilter(subFilter).SignWithDetailsAsync();

        // What it holds is still reported; that it is not EN 319 142-1 baseline is the warning.
        result.AchievedLevel.ShouldBe(AdesBaselineLevel.Basic);
        var warning = result.Warnings.Where(w => w.Code == SigningWarningCode.SubFilterNotBaseline).ShouldHaveSingleItem();
        warning.Message.ShouldContain(name);
        warning.Message.ShouldContain("EN 319 142-1");
    }

    [Fact]
    public async Task SignWithDetailsAsync_EtsiCadesDetached_HasNoSubFilterWarning()
    {
        var result = await PadesSigner.Document(TestPdfFactory.CreateMinimalPdf()).WithCertificate(_cert).SignWithDetailsAsync();

        result.Warnings.ShouldNotContain(w => w.Code == SigningWarningCode.SubFilterNotBaseline);
    }

    [Fact]
    public async Task WithSignerRoles_RolesAreSignedAndReadBackByTheValidatorAndTheInspector()
    {
        byte[] signed = await PadesSigner.Document(TestPdfFactory.CreateMinimalPdf()).WithCertificate(_cert)
            .WithSignerRoles(["Diretor", " ", " Testemunha "])
            .SignAsync();

        using var stream = new MemoryStream(signed);
        var results = await new PdfSignatureValidator(new ValidationOptions { CheckRevocation = false, TrustedRoots = [_cert] })
            .ValidateAsync(stream);
        var result = results.ShouldHaveSingleItem();
        result.IsSignatureValid.ShouldBeTrue(string.Join("; ", result.Errors));
        result.ClaimedRoles.ShouldBe(["Diretor", "Testemunha"]);
        stream.Position = 0;
        var inspection = await PdfSignatureInspector.InspectAsync(stream);
        inspection.Signatures.ShouldHaveSingleItem().ClaimedRoles.ShouldBe(["Diretor", "Testemunha"]);
    }

    [Fact]
    public async Task WithSignerRole_ReplacesTheRolesSetBefore_AndWritesOneSignerAttributesV2()
    {
        byte[] signed = await PadesSigner.Document(TestPdfFactory.CreateMinimalPdf()).WithCertificate(_cert)
            .WithSignerRoles(["Diretor"])
            .WithSignerRole("Sócia")
            .SignAsync();

        using var stream = new MemoryStream(signed);
        var signature = (await PdfSignatureInspector.InspectAsync(stream)).Signatures.ShouldHaveSingleItem();
        signature.ClaimedRoles.ShouldBe(["Sócia"]);
        var attribute = CmsAttribute.SignerAttributesV2(["Sócia"]);
        CmsParser.Parse(signature.CmsRawData.ToArray()).SignedAttrs.ShouldNotBeNull()
            .AsSpan().IndexOf(attribute.DerValue).ShouldBeGreaterThan(0);
    }

    [Fact]
    public async Task SignAsync_WithoutRoles_ClaimsNone()
    {
        byte[] signed = await PadesSigner.Document(TestPdfFactory.CreateMinimalPdf()).WithCertificate(_cert).SignAsync();

        using var stream = new MemoryStream(signed);
        (await PdfSignatureInspector.InspectAsync(stream)).Signatures.ShouldHaveSingleItem().ClaimedRoles.ShouldBeEmpty();
        stream.Position = 0;
        var results = await new PdfSignatureValidator(new ValidationOptions { CheckRevocation = false, TrustedRoots = [_cert] })
            .ValidateAsync(stream);
        results.ShouldHaveSingleItem().ClaimedRoles.ShouldBeEmpty();
    }

    private static X509Certificate2 CreateRsaCert()
    {
        using RSA key = RSA.Create(2048);
        var request = new CertificateRequest("CN=SubFilter Test", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.NonRepudiation, critical: false));
        using var cert = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        return CertificateLoader.LoadPkcs12(cert.Export(X509ContentType.Pfx, "export"), "export");
    }
}
