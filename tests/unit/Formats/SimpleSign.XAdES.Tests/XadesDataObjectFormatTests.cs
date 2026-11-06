using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Xml;
using Shouldly;
using SimpleSign.Core.Constants;
using SimpleSign.Core.Signing;
using SimpleSign.TestHelpers;
using Xunit;

namespace SimpleSign.XAdES.Tests;

/// <summary>
/// The DataObjectFormat of the signed document: ETSI EN 319 132-1 §6.3 asks for one for each signed
/// data object, so the signer writes it unless the XAdES 1.3.2 form is in use.
/// </summary>
[Trait("Category", "Unit")]
public sealed class XadesDataObjectFormatTests
{
    private const string XadesNs = "http://uri.etsi.org/01903/v1.3.2#";
    private static readonly byte[] s_xml = Encoding.UTF8.GetBytes("<?xml version=\"1.0\" encoding=\"UTF-8\"?><order><item>1</item></order>");
    private static readonly X509Certificate2 s_cert = TestCertificateFactory.CreateSelfSignedCert("CN=XAdES Format, O=Tests");

    [Theory]
    [InlineData(XadesForm.Enveloped)]
    [InlineData(XadesForm.Enveloping)]
    [InlineData(XadesForm.Detached)]
    public async Task SignAsync_ByDefault_DescribesTheDocumentAsXml(XadesForm form)
    {
        var builder = XadesSigner.Document(s_xml).WithCertificate(s_cert).WithForm(form);

        byte[] signed = await (form == XadesForm.Detached ? builder.WithDataUri("order.xml") : builder).SignAsync();

        var (signature, ns) = Signature(signed);
        var formats = signature.SelectNodes(".//xades:SignedDataObjectProperties/xades:DataObjectFormat", ns)!.OfType<XmlElement>().ToList();
        formats.Count.ShouldBe(1);
        formats[0].SelectSingleNode("xades:MimeType", ns)!.InnerText.ShouldBe("text/xml");
        string referenceId = formats[0].GetAttribute("ObjectReference").TrimStart('#');
        referenceId.ShouldNotBeNullOrEmpty();
        var reference = signature.SelectSingleNode($"ds:SignedInfo/ds:Reference[@Id='{referenceId}']", ns).ShouldBeOfType<XmlElement>();
        reference.GetAttribute("Type").ShouldBeEmpty("the format points to the document, not to the SignedProperties");

        var result = new XadesSignatureValidator().Validate(signed, [s_cert], form == XadesForm.Detached ? s_xml : null);
        result.IsValid.ShouldBeTrue(string.Join("; ", result.Errors));
    }

    [Fact]
    public async Task SignAsync_WithTheUsersFormat_KeepsItAndPointsItToTheDocument()
    {
        byte[] signed = await XadesSigner.Document(s_xml).WithCertificate(s_cert)
            .WithDataObjectFormat(new DataObjectFormat { MimeType = "application/xml" })
            .SignAsync();

        var (signature, ns) = Signature(signed);
        var format = signature.SelectNodes(".//xades:DataObjectFormat", ns)!.OfType<XmlElement>().ShouldHaveSingleItem();
        format.SelectSingleNode("xades:MimeType", ns)!.InnerText.ShouldBe("application/xml");
        string referenceId = format.GetAttribute("ObjectReference").TrimStart('#');
        signature.SelectSingleNode($"ds:SignedInfo/ds:Reference[@Id='{referenceId}'][@URI='']", ns).ShouldNotBeNull();
    }

    [Fact]
    public async Task SignAsync_WithThe132Form_LeavesTheDocumentReferenceAsItWas()
    {
        byte[] signed = await XadesSigner.Document(s_xml).WithCertificate(s_cert)
            .WithSigningCertificateForm(XadesSigningCertificateForm.V1)
            .SignAsync();

        var (signature, ns) = Signature(signed);
        ((XmlElement)signature.SelectSingleNode("ds:SignedInfo/ds:Reference[@URI='']", ns)!).HasAttribute("Id").ShouldBeFalse();
        signature.SelectSingleNode(".//xades:DataObjectFormat", ns).ShouldBeNull();
        signature.SelectSingleNode(".//xades:SignedDataObjectProperties", ns).ShouldBeNull();
    }

    [Fact]
    public async Task SignAsync_ExternalSigner_BothPassesAgreeOnTheDocumentReference()
    {
        // The signature is assembled twice with an external key: the Id the format points to cannot be random.
        byte[] signed = await XadesSigner.Document(s_xml)
            .WithExternalSigner(s_cert, new DelegatingExternalSigner(data =>
            {
                using var rsa = s_cert.GetRSAPrivateKey()!;
                return Task.FromResult(rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
            }))
            .WithSignatureAlgorithm("1.2.840.113549.1.1.11")
            .SignAsync();

        var (signature, ns) = Signature(signed);
        string referenceId = ((XmlElement)signature.SelectSingleNode(".//xades:DataObjectFormat", ns)!).GetAttribute("ObjectReference").TrimStart('#');
        signature.SelectSingleNode($"ds:SignedInfo/ds:Reference[@Id='{referenceId}']", ns).ShouldNotBeNull();
        var result = new XadesSignatureValidator().Validate(signed, trustAnchors: [s_cert]);
        result.IsValid.ShouldBeTrue(string.Join("; ", result.Errors));
    }

    [Fact]
    public async Task CounterSign_SignsNoDataObject_HasNoDataObjectFormat()
    {
        byte[] signed = await XadesSigner.Document(s_xml).WithCertificate(s_cert).SignAsync();

        byte[] countersigned = await XadesSigner.CounterSign(signed).WithCertificate(s_cert).SignAsync();

        var (signature, ns) = Signature(countersigned);
        signature.SelectNodes(".//xades:CounterSignature//xades:DataObjectFormat", ns)!.Count.ShouldBe(0);
        signature.SelectNodes(".//xades:DataObjectFormat", ns)!.Count.ShouldBe(1);
    }

    private static (XmlElement Signature, XmlNamespaceManager Ns) Signature(byte[] signed)
    {
        var doc = new XmlDocument { PreserveWhitespace = true };
        using var stream = new MemoryStream(signed);
        doc.Load(stream);
        var ns = new XmlNamespaceManager(doc.NameTable);
        ns.AddNamespace("ds", XmlDSigUrls.DsNamespace);
        ns.AddNamespace("xades", XadesNs);
        return ((XmlElement)doc.SelectSingleNode("//ds:Signature", ns)!, ns);
    }
}
