using System.Formats.Asn1;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Xml;
using Shouldly;
using SimpleSign.Core.Constants;
using SimpleSign.Core.Signing;
using SimpleSign.TestHelpers;
using Xunit;

namespace SimpleSign.XAdES.Tests;

/// <summary>SignerRoleV2 (ETSI EN 319 132-1 §5.2.6): claimed roles, attribute certificates and signed assertions.</summary>
[Trait("Category", "Unit")]
public sealed class XadesSignerRoleTests
{
    private const string XadesNs = "http://uri.etsi.org/01903/v1.3.2#";
    private const string Assertion =
        "<saml:Assertion xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"a1\"><saml:Subject>Diretor</saml:Subject></saml:Assertion>";

    private static readonly byte[] s_xml = Encoding.UTF8.GetBytes("<?xml version=\"1.0\" encoding=\"UTF-8\"?><doc>roles</doc>");
    private static readonly X509Certificate2 s_cert = TestCertificateFactory.CreateSelfSignedCert("CN=XAdES Roles, O=Tests");
    // Stands for an attribute certificate: the library embeds any single DER SEQUENCE without reading it.
    private static readonly byte[] s_attributeCertificate = Der(w => w.WriteOctetString([1, 2, 3]));

    [Fact]
    public async Task SignAsync_ClaimedRoles_UseSignerRoleV2()
    {
        byte[] signed = await XadesSigner.Document(s_xml).WithCertificate(s_cert).WithSignerRoles(["Diretor", " ", "Procurador"]).SignAsync();

        var (properties, ns) = SignedSignatureProperties(signed);
        // EN 319 132-1 obsoletes SignerRole: it shall not be incorporated into the signature.
        properties.SelectSingleNode("xades:SignerRole", ns).ShouldBeNull();
        properties.SelectNodes("xades:SignerRoleV2/xades:ClaimedRoles/xades:ClaimedRole", ns)!.OfType<XmlElement>().Select(e => e.InnerText)
            .ShouldBe(["Diretor", "Procurador"]);
        new XadesSignatureValidator().Validate(signed, [s_cert]).ClaimedRoles.ShouldBe(["Diretor", "Procurador"]);
    }

    [Fact]
    public async Task SignAsync_Xades132Form_KeepsTheLegacySignerRole()
    {
        byte[] signed = await XadesSigner.Document(s_xml).WithCertificate(s_cert)
            .WithSigningCertificateForm(XadesSigningCertificateForm.V1).WithSignerRole("Diretor").SignAsync();

        var (properties, ns) = SignedSignatureProperties(signed);
        properties.SelectSingleNode("xades:SignerRoleV2", ns).ShouldBeNull();
        properties.SelectSingleNode("xades:SignerRole/xades:ClaimedRoles/xades:ClaimedRole", ns)!.InnerText.ShouldBe("Diretor");
        new XadesSignatureValidator().Validate(signed, [s_cert]).ClaimedRoles.ShouldBe(["Diretor"]);
    }

    [Fact]
    public async Task SignAsync_AllThreeKinds_AreWrittenInSchemaOrderAndReadBack()
    {
        byte[] signed = await XadesSigner.Document(s_xml).WithCertificate(s_cert)
            .WithSignedAssertions([Assertion])
            .WithAttributeCertificates([s_attributeCertificate])
            .WithSignerRole("Diretor")
            .SignAsync();

        var (properties, ns) = SignedSignatureProperties(signed);
        var signerRole = properties.SelectSingleNode("xades:SignerRoleV2", ns).ShouldBeOfType<XmlElement>();
        signerRole.ChildNodes.OfType<XmlElement>().Select(e => e.LocalName).ShouldBe(["ClaimedRoles", "CertifiedRolesV2", "SignedAssertions"]);
        Convert.FromBase64String(signerRole.SelectSingleNode("xades:CertifiedRolesV2/xades:CertifiedRole/xades:X509AttributeCertificate", ns)!.InnerText)
            .ShouldBe(s_attributeCertificate);
        var assertion = signerRole.SelectSingleNode("xades:SignedAssertions/xades:SignedAssertion/*", ns).ShouldBeOfType<XmlElement>();
        assertion.LocalName.ShouldBe("Assertion");
        assertion.NamespaceURI.ShouldBe("urn:oasis:names:tc:SAML:2.0:assertion");

        var result = new XadesSignatureValidator().Validate(signed, [s_cert]);
        result.IsValid.ShouldBeTrue(string.Join("; ", result.Errors));
        result.ClaimedRoles.ShouldBe(["Diretor"]);
        result.AttributeCertificates.ShouldHaveSingleItem().ToArray().ShouldBe(s_attributeCertificate);
        result.SignedAssertions.ShouldHaveSingleItem().ShouldContain("saml:Subject");
    }

    [Fact]
    public async Task SignAsync_OnlyAttributeCertificates_WritesNoClaimedRoles()
    {
        byte[] signed = await XadesSigner.Document(s_xml).WithCertificate(s_cert).WithAttributeCertificates([s_attributeCertificate]).SignAsync();

        var (properties, ns) = SignedSignatureProperties(signed);
        properties.SelectSingleNode("xades:SignerRoleV2", ns)!.ChildNodes.OfType<XmlElement>().Select(e => e.LocalName).ShouldBe(["CertifiedRolesV2"]);
    }

    [Fact]
    public async Task SignAsync_ExternalSignerWithSignedAssertion_Validates()
    {
        byte[] signed = await XadesSigner.Document(s_xml)
            .WithExternalSigner(s_cert, new DelegatingExternalSigner(data =>
            {
                using var rsa = s_cert.GetRSAPrivateKey()!;
                return Task.FromResult(rsa.SignData(data, System.Security.Cryptography.HashAlgorithmName.SHA256, System.Security.Cryptography.RSASignaturePadding.Pkcs1));
            }))
            .WithSignatureAlgorithm("1.2.840.113549.1.1.11")
            .WithSignedAssertions([Assertion])
            .SignAsync();

        var result = new XadesSignatureValidator().Validate(signed, [s_cert]);
        result.IsValid.ShouldBeTrue(string.Join("; ", result.Errors));
        result.SignedAssertions.ShouldHaveSingleItem();
    }

    [Fact]
    public async Task SignAsync_Xades132FormWithAttributeCertificates_Throws()
    {
        var builder = XadesSigner.Document(s_xml).WithCertificate(s_cert)
            .WithSigningCertificateForm(XadesSigningCertificateForm.V1).WithAttributeCertificates([s_attributeCertificate]);

        var exception = await Should.ThrowAsync<SigningException>(() => builder.SignAsync());

        exception.Message.ShouldContain("SignerRoleV2");
    }

    [Fact]
    public void WithAttributeCertificates_NotASingleDerSequence_Throws()
    {
        Should.Throw<ArgumentException>(() => XadesSigner.Document(s_xml).WithAttributeCertificates([new byte[] { 0x04, 0x01, 0x00 }]));
        Should.Throw<ArgumentException>(() => XadesSigner.Document(s_xml).WithAttributeCertificates([(byte[])[.. s_attributeCertificate, 0x00]]));
    }

    [Theory]
    [InlineData("not xml")]
    [InlineData("<a><b></a>")]
    [InlineData("")]
    public void WithSignedAssertions_NotWellFormedXml_Throws(string assertion) =>
        Should.Throw<ArgumentException>(() => XadesSigner.Document(s_xml).WithSignedAssertions([assertion]));

    private static byte[] Der(Action<AsnWriter> content)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSequence())
        {
            content(writer);
        }

        return writer.Encode();
    }

    private static (XmlNode Properties, XmlNamespaceManager Ns) SignedSignatureProperties(byte[] signed)
    {
        var doc = new XmlDocument { PreserveWhitespace = true };
        using var stream = new MemoryStream(signed);
        doc.Load(stream);
        var ns = new XmlNamespaceManager(doc.NameTable);
        ns.AddNamespace("ds", XmlDSigUrls.DsNamespace);
        ns.AddNamespace("xades", XadesNs);
        return (doc.SelectSingleNode("//xades:SignedSignatureProperties", ns)!, ns);
    }
}
