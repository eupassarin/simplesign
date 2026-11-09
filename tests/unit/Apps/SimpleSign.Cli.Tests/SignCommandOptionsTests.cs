using Shouldly;
using SimpleSign.Cli.Rendering;
using SimpleSign.Core.Constants;
using SimpleSign.Core.Signing;
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

    [Fact]
    public void ParseSigningTime_IsoWithOffset_KeepsTheInstant() =>
        SignCommandOptions.ParseSigningTime("2026-11-09T10:00:00-03:00").ShouldBe(new DateTimeOffset(2026, 11, 9, 13, 0, 0, TimeSpan.Zero));

    [Theory]
    [InlineData("tomorrow")]
    [InlineData(null)]
    public void ParseSigningTime_NotADate_IsNull(string? value) =>
        SignCommandOptions.ParseSigningTime(value).ShouldBeNull();

    [Fact]
    public void SplitDocumentInfo_KeyAndValue_SplitsAtTheFirstEquals() =>
        SignCommandOptions.SplitDocumentInfo("Title=a=b").ShouldBe(("Title", "a=b"));

    [Theory]
    [InlineData("Title")]
    [InlineData("=value")]
    public void SplitDocumentInfo_NoKey_IsNull(string entry) =>
        SignCommandOptions.SplitDocumentInfo(entry).ShouldBeNull();

    [Theory]
    [InlineData("0A:FF", new byte[] { 0x0A, 0xFF })]
    [InlineData("0a ff", new byte[] { 0x0A, 0xFF })]
    public void ParseHex_HexWithSeparators_ReturnsTheBytes(string value, byte[] expected) =>
        SignCommandOptions.ParseHex(value).ShouldBe(expected);

    [Theory]
    [InlineData("xyz")]
    [InlineData("ABC")]
    [InlineData("")]
    public void ParseHex_NotHex_IsNull(string value) =>
        SignCommandOptions.ParseHex(value).ShouldBeNull();

    [Theory]
    [InlineData("SHA256", Oids.Sha256)]
    [InlineData("sha-384", Oids.Sha384)]
    [InlineData("SHA512", Oids.Sha512)]
    [InlineData("MD5", null)]
    public void PolicyHashOid_ReturnsTheDigestOid(string name, string? expected) =>
        SignCommandOptions.PolicyHashOid(name).ShouldBe(expected);

    [Theory]
    [InlineData("origin", CommitmentType.ProofOfOrigin)]
    [InlineData("Creation", CommitmentType.ProofOfCreation)]
    [InlineData("other", null)]
    public void ParseCommitment_ReturnsTheType(string value, CommitmentType? expected) =>
        SignCommandOptions.ParseCommitment(value).ShouldBe(expected);
}
