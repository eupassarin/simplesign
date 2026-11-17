using System.Text;
using Shouldly;
using SimpleSign.Peru.Iofe.Accredited.Internal;

namespace SimpleSign.Peru.Iofe.Accredited.Tests;

[Trait("Category", "Unit")]
public sealed class IofeModuleDeclarationTests
{
    private static IofeModuleDeclaration Declared(string manufacturer, string model) => new(manufacturer, model, "FIPS 140-2 Level 3", "0000");

    [Theory]
    [InlineData("Thales", "Luna K7", "Thales", "Luna K7", true)]
    [InlineData("thales ", " luna k7", "Thales", "Luna K7", true)]
    [InlineData("Thales", "Luna K7", "SoftHSM project", "SoftHSM v2", false)]
    [InlineData("Thales", "Luna K7", "Thales", "", false)]
    // The driver cuts the model at 16 characters and the manufacturer at 32.
    [InlineData("Utimaco IS GmbH", "CryptoServer Se-Series Gen2", "Utimaco IS GmbH", "CryptoServer Se-", true)]
    [InlineData("Utimaco IS GmbH", "CryptoServer Se-Series Gen2", "Utimaco IS GmbH", "CryptoServer", false)]
    public void Matches_ReportedManufacturerAndModel_AreTheDeclaredOnes(
        string declaredManufacturer, string declaredModel, string reportedManufacturer, string reportedModel, bool expected) =>
        Declared(declaredManufacturer, declaredModel).Matches(reportedManufacturer, reportedModel).ShouldBe(expected);
}

[Trait("Category", "Unit")]
public sealed class IofeFormatsTests
{
    [Theory]
    [InlineData("%PDF-1.7\n1 0 obj", IofeDocumentFormat.Pdf)]
    [InlineData("\n\n%PDF-1.4", IofeDocumentFormat.Pdf)]
    [InlineData("<?xml version=\"1.0\"?><a/>", IofeDocumentFormat.Xml)]
    [InlineData("  \r\n<a/>", IofeDocumentFormat.Xml)]
    [InlineData("-----BEGIN PKCS7-----", IofeDocumentFormat.Cms)]
    public void Detect_FirstBytes_TellTheFormat(string start, IofeDocumentFormat expected) =>
        IofeFormats.Detect(Encoding.ASCII.GetBytes(start)).ShouldBe(expected);

    [Fact]
    public void Detect_XmlWithByteOrderMark_IsXml() =>
        IofeFormats.Detect([0xEF, 0xBB, 0xBF, (byte)'<', (byte)'a', (byte)'/', (byte)'>']).ShouldBe(IofeDocumentFormat.Xml);

    [Fact]
    public void Detect_DerSequence_IsCms() =>
        IofeFormats.Detect([0x30, 0x82, 0x01, 0x00]).ShouldBe(IofeDocumentFormat.Cms);
}
