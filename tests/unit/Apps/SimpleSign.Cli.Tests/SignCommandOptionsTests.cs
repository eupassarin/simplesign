using Shouldly;
using SimpleSign.Cli.Rendering;
using SimpleSign.PAdES.Signing;

namespace SimpleSign.Cli.Tests;

[Trait("Category", "Unit")]
public sealed class SignCommandOptionsTests
{
    [Theory]
    [InlineData("SHA256", "SHA256")]
    [InlineData("sha256", "SHA256")]
    [InlineData("SHA384", "SHA384")]
    [InlineData("sha512", "SHA512")]
    [InlineData("unknown", "SHA256")]
    public void ParseHash_ReturnsExpected(string input, string expectedName) =>
        SignCommandOptions.ParseHash(input).Name.ShouldBe(expectedName);

    [Theory]
    [InlineData("no-changes", CertificationLevel.NoChanges)]
    [InlineData("NO-CHANGES", CertificationLevel.NoChanges)]
    [InlineData("form-filling", CertificationLevel.FormFilling)]
    [InlineData("annotations", CertificationLevel.FormFillingAndAnnotations)]
    [InlineData("unknown", CertificationLevel.FormFilling)]
    public void ParseCertificationLevel_ReturnsExpected(string input, CertificationLevel expected) =>
        SignCommandOptions.ParseCertificationLevel(input).ShouldBe(expected);

    [Theory]
    [InlineData("adbe.pkcs7.detached", PdfSignatureSubFilter.AdbePkcs7Detached)]
    [InlineData("adbe_pkcs7_detached", PdfSignatureSubFilter.AdbePkcs7Detached)]
    [InlineData("adbe-pkcs7-detached", PdfSignatureSubFilter.AdbePkcs7Detached)]
    [InlineData("etsi.cades.detached", PdfSignatureSubFilter.EtsiCadesDetached)]
    [InlineData("etsi-cades-detached", PdfSignatureSubFilter.EtsiCadesDetached)]
    [InlineData("unknown", null)]
    public void ParseSubFilter_ReturnsExpected(string input, PdfSignatureSubFilter? expected) =>
        SignCommandOptions.ParseSubFilter(input).ShouldBe(expected);

    [Theory]
    [InlineData("rsa-pkcs1", null)]
    [InlineData("rsa", null)]
    [InlineData("1.2.840.113549.1.1.1", null)]
    [InlineData("rsassa-pss", "1.2.840.113549.1.1.10")]
    [InlineData("pss", "1.2.840.113549.1.1.10")]
    [InlineData("1.2.840.113549.1.1.10", "1.2.840.113549.1.1.10")]
    [InlineData("unknown", null)]
    public void ParseSignatureAlgorithm_ReturnsExpected(string input, string? expected) =>
        SignCommandOptions.ParseSignatureAlgorithm(input).ShouldBe(expected);
}
