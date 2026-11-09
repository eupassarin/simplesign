using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Xml;
using Microsoft.Extensions.Logging.Abstractions;
using Shouldly;
using SimpleSign.Core.Validation;
using SimpleSign.TestHelpers;
using SimpleSign.XAdES.Internal;
using Xunit;

namespace SimpleSign.XAdES.Tests;

/// <summary>The embedded XML Signature, XAdES and TS 119 612 schemas (StructuralValidation, TLStructure).</summary>
[Trait("Category", "Unit")]
public sealed class XmlSchemasTests
{
    private const string Ds = "http://www.w3.org/2000/09/xmldsig#";
    private const string Xades = "http://uri.etsi.org/01903/v1.3.2#";
    private static readonly byte[] s_xml = Encoding.UTF8.GetBytes("<?xml version=\"1.0\" encoding=\"UTF-8\"?><p:order xmlns:p=\"urn:example:order\"><p:item>1</p:item></p:order>");
    private static readonly X509Certificate2 s_cert = TestCertificateFactory.CreateSelfSignedCert("CN=XAdES Schema, O=Tests");

    [Fact]
    public void Validate_SignatureFromTheBuilder_IsValid()
    {
        var errors = XmlSchemas.Validate(SignatureOf(Sign()));

        errors.ShouldBeEmpty(string.Join(" | ", errors));
    }

    [Fact]
    public void Validate_UnknownXadesElement_ReportsIt()
    {
        var doc = Load(Sign());
        var qualifying = (XmlElement)doc.GetElementsByTagName("QualifyingProperties", Xades)[0]!;
        qualifying.AppendChild(doc.CreateElement("xades", "Bogus", Xades));

        XmlSchemas.Validate(SignatureOf(doc)).ShouldNotBeEmpty();
    }

    [Fact]
    public void Validate_NotATrustedList_ReportsIt()
    {
        var doc = new XmlDocument();
        doc.LoadXml("<TrustServiceStatusList xmlns=\"http://uri.etsi.org/02231/v2#\" TSLTag=\"http://uri.etsi.org/19612/TSLTag\"><Unexpected/></TrustServiceStatusList>");

        XmlSchemas.Validate(doc.DocumentElement!).ShouldNotBeEmpty();
    }

    [Fact]
    public void Validator_UnknownXadesElement_StructuralValidationWarns()
    {
        var doc = Load(Sign());
        var qualifying = (XmlElement)doc.GetElementsByTagName("QualifyingProperties", Xades)[0]!;
        qualifying.AppendChild(doc.CreateElement("xades", "Bogus", Xades));
        byte[] tampered = Encoding.UTF8.GetBytes(doc.OuterXml);

        var valid = new XadesSignatureValidator(new ValidationOptions { CheckRevocation = false }).Validate(Sign(), [s_cert]);
        var invalid = new XadesSignatureValidator(new ValidationOptions { CheckRevocation = false }).Validate(tampered, [s_cert]);

        valid.Constraints.ShouldContain(c => c.Id == "SignatureConstraints/StructuralValidation" && c.Status == ConstraintStatus.Passed);
        invalid.IsSignatureValid.ShouldBeTrue(string.Join("; ", invalid.Errors));
        invalid.Constraints.ShouldContain(c => c.Id == "SignatureConstraints/StructuralValidation" && c.Status == ConstraintStatus.Warning
            && c.Message.Contains("Bogus", StringComparison.Ordinal));
    }

    private static byte[] Sign() => XadesSignatureBuilder.BuildSignature(
        s_xml, s_cert, HashAlgorithmName.SHA256, DateTimeOffset.UtcNow, extraCertificates: null, commitmentType: null,
        signaturePolicy: null, XadesSigningCertificateForm.V2, "1.2.840.113549.1.1.11", XadesForm.Enveloped,
        signerRoles: null, dataObjectFormat: null, productionPlace: null, dataObjectsTimeStamp: null, additionalReferences: null, NullLogger.Instance);

    private static XmlDocument Load(byte[] xml)
    {
        var doc = new XmlDocument { PreserveWhitespace = true };
        doc.Load(new MemoryStream(xml));
        return doc;
    }

    private static XmlElement SignatureOf(byte[] xml) => SignatureOf(Load(xml));

    private static XmlElement SignatureOf(XmlDocument doc) => (XmlElement)doc.GetElementsByTagName("Signature", Ds)[0]!;
}
