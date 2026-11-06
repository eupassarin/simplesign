using System.Security.Cryptography.X509Certificates;
using System.Xml;
using Shouldly;
using SimpleSign.Core.Constants;
using SimpleSign.Core.Validation;
using SimpleSign.TestHelpers;
using SimpleSign.XAdES.Constants;
using Xunit;

namespace SimpleSign.XAdES.Tests;

/// <summary>SigningCertificate (XAdES 1.3.2, v1) as the ICP-Brasil XML policies require, and SigningCertificateV2.</summary>
[Trait("Category", "Unit")]
public sealed class XadesSigningCertificateFormTests
{
    private static readonly X509Certificate2 s_cert = TestCertificateFactory.CreateSelfSignedCert("CN=XAdES V1 Test, O=Tests");
    private static readonly byte[] s_xml = "<?xml version=\"1.0\"?><doc><id>1</id></doc>"u8.ToArray();

    [Fact]
    public async Task WithSigningCertificateForm_V1_WritesSigningCertificateWithIssuerSerial()
    {
        byte[] signed = await XadesSigner.Document(s_xml).WithCertificate(s_cert)
            .WithSigningCertificateForm(XadesSigningCertificateForm.V1).SignAsync();

        var (doc, ns) = Load(signed);
        doc.SelectSingleNode("//xades:SigningCertificateV2", ns).ShouldBeNull();
        var cert = doc.SelectSingleNode("//xades:SignedSignatureProperties/xades:SigningCertificate/xades:Cert", ns).ShouldBeOfType<XmlElement>();
        cert.SelectSingleNode("xades:IssuerSerial/ds:X509IssuerName", ns)!.InnerText.ShouldBe(s_cert.IssuerName.Name);
        cert.SelectSingleNode("xades:IssuerSerial/ds:X509SerialNumber", ns)!.InnerText
            .ShouldBe(new System.Numerics.BigInteger(s_cert.GetSerialNumber(), isUnsigned: true).ToString(System.Globalization.CultureInfo.InvariantCulture));
    }

    [Fact]
    public async Task Validate_V1Signature_ResolvesSignerAndIsValid()
    {
        byte[] signed = await XadesSigner.Document(s_xml).WithCertificate(s_cert)
            .WithSigningCertificateForm(XadesSigningCertificateForm.V1).SignAsync();

        var result = new XadesSignatureValidator(new ValidationOptions { CheckRevocation = false }).Validate(signed, trustAnchors: [s_cert]);

        result.IsValid.ShouldBeTrue(string.Join("; ", result.Errors));
        result.SignerCertificate.ShouldNotBeNull().Thumbprint.ShouldBe(s_cert.Thumbprint);
    }

    [Fact]
    public async Task Default_WritesSigningCertificateV2Only()
    {
        byte[] signed = await XadesSigner.Document(s_xml).WithCertificate(s_cert).SignAsync();

        var (doc, ns) = Load(signed);
        doc.SelectSingleNode("//xades:SigningCertificateV2", ns).ShouldNotBeNull();
        doc.SelectSingleNode("//xades:SignedSignatureProperties/xades:SigningCertificate", ns).ShouldBeNull();
    }

    private static (XmlDocument Doc, XmlNamespaceManager Ns) Load(byte[] xml)
    {
        var doc = new XmlDocument { PreserveWhitespace = true, XmlResolver = null };
        using var stream = new MemoryStream(xml);
        using var reader = XmlReader.Create(stream, new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit });
        doc.Load(reader);
        var ns = new XmlNamespaceManager(doc.NameTable);
        ns.AddNamespace("ds", XmlDSigUrls.DsNamespace);
        ns.AddNamespace("xades", XadesUris.XadesNamespace);
        return (doc, ns);
    }
}
