using System.Text;
using Shouldly;
using SimpleSign.TestBench.Runs;
using SimpleSign.TestBench.Validation;

namespace SimpleSign.TestBench.Tests;

/// <summary>The file tells its own format, so validation asks for no format.</summary>
[Trait("Category", "Unit")]
public sealed class FormatDetectorTests
{
    [Theory]
    [InlineData("%PDF-1.7\n1 0 obj", RunFormats.Pades)]
    [InlineData("<?xml version=\"1.0\"?><doc/>", RunFormats.Xades)]
    [InlineData("  \r\n<doc/>", RunFormats.Xades)]
    [InlineData("-----BEGIN PKCS7-----\nMIIB", RunFormats.Cades)]
    public void Detect_Text_GivesTheFormat(string content, string expected) =>
        FormatDetector.Detect(Encoding.UTF8.GetBytes(content)).ShouldBe(expected);

    [Fact]
    public void Detect_XmlWithByteOrderMark_IsXades() =>
        FormatDetector.Detect([0xEF, 0xBB, 0xBF, (byte)'<', (byte)'a', (byte)'/', (byte)'>']).ShouldBe(RunFormats.Xades);

    [Fact]
    public void Detect_DerSequence_IsCades() =>
        FormatDetector.Detect([0x30, 0x82, 0x01, 0x00, 0x06, 0x09]).ShouldBe(RunFormats.Cades);

    [Theory]
    [InlineData("just some text")]
    [InlineData("")]
    public void Detect_SomethingElse_Throws(string content) =>
        Should.Throw<ArgumentException>(() => FormatDetector.Detect(Encoding.UTF8.GetBytes(content)));

    [Fact]
    public void DetachedReferenceUri_DetachedSignature_IsTheExternalReference()
    {
        const string Xml = """
            <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo>
              <ds:Reference URI="order.xml"/><ds:Reference URI="#SignedProperties-1"/>
            </ds:SignedInfo></ds:Signature>
            """;

        FormatDetector.DetachedReferenceUri(Encoding.UTF8.GetBytes(Xml)).ShouldBe("order.xml");
    }

    [Theory]
    [InlineData("<doc><ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><ds:SignedInfo><ds:Reference URI=\"\"/></ds:SignedInfo></ds:Signature></doc>")]
    [InlineData("not xml")]
    public void DetachedReferenceUri_NoExternalReference_IsNull(string xml) =>
        FormatDetector.DetachedReferenceUri(Encoding.UTF8.GetBytes(xml)).ShouldBeNull();
}
