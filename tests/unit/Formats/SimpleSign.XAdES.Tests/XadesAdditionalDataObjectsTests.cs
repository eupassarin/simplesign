using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Xml;
using Shouldly;
using SimpleSign.Core.Constants;
using SimpleSign.Core.Crypto;
using SimpleSign.Core.Http;
using SimpleSign.Core.Signing;
using SimpleSign.TestHelpers;
using Xunit;

namespace SimpleSign.XAdES.Tests;

/// <summary>Data objects signed together with the document: one more ds:Reference each (W3C XMLDSig Core 1.1 §4.4.3).</summary>
[Trait("Category", "Unit")]
public sealed class XadesAdditionalDataObjectsTests : IDisposable
{
    private const string XadesNs = "http://uri.etsi.org/01903/v1.3.2#";
    private const string Base64Transform = "http://www.w3.org/2000/09/xmldsig#base64";
    private static readonly byte[] s_xml = Encoding.UTF8.GetBytes("<?xml version=\"1.0\" encoding=\"UTF-8\"?><order><item>1</item></order>");
    private static readonly byte[] s_attachment = [0x25, 0x50, 0x44, 0x46, 0x00, 0xFF, 0x10, 0x80];
    private static readonly byte[] s_terms = Encoding.UTF8.GetBytes("Termos e condições\n");
    private static readonly X509Certificate2 s_cert = TestCertificateFactory.CreateSelfSignedCert("CN=XAdES Objects, O=Tests");

    private readonly HttpClient _tsaHttp = new(new MockHttpHandler(async request =>
    {
        byte[] requestBytes = await request.Content!.ReadAsByteArrayAsync();
        var response = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new ByteArrayContent(TimestampTestResponseBuilder.CreateForRequest(requestBytes)),
        };
        response.Content.Headers.ContentType = new MediaTypeHeaderValue("application/timestamp-reply");
        return response;
    }));

    public void Dispose() => _tsaHttp.Dispose();

    private TimestampOptions Tsa => new(new Uri("http://mock-tsa.example.com"), new SingleClientProvider(_tsaHttp));

    [Theory]
    [InlineData(XadesForm.Enveloped)]
    [InlineData(XadesForm.Enveloping)]
    public async Task SignAsync_EmbeddedDataObject_IsCarriedInABase64ObjectAndValidatesOnItsOwn(XadesForm form)
    {
        byte[] signed = await XadesSigner.Document(s_xml).WithCertificate(s_cert).WithForm(form)
            .WithAdditionalDataObject(XadesDataObject.Embedded(s_attachment, "application/pdf"))
            .SignAsync();

        var (signature, ns) = Signature(signed);
        var references = signature.SelectNodes("ds:SignedInfo/ds:Reference", ns)!.OfType<XmlElement>().ToList();
        references.Count.ShouldBe(3);
        references[2].GetAttribute("Type").ShouldBe("http://uri.etsi.org/01903#SignedProperties");
        var reference = references[1];
        reference.SelectNodes("ds:Transforms/ds:Transform", ns)!.OfType<XmlElement>().Select(t => t.GetAttribute("Algorithm")).ShouldBe([Base64Transform]);
        Convert.FromBase64String(reference.SelectSingleNode("ds:DigestValue", ns)!.InnerText).ShouldBe(SHA256.HashData(s_attachment));

        var dataObject = signature.SelectSingleNode($"ds:Object[@Id='{reference.GetAttribute("URI")[1..]}']", ns).ShouldBeOfType<XmlElement>();
        dataObject.GetAttribute("Encoding").ShouldBe(Base64Transform);
        Convert.FromBase64String(dataObject.InnerText).ShouldBe(s_attachment);

        var format = signature.SelectSingleNode($".//xades:DataObjectFormat[@ObjectReference='#{reference.GetAttribute("Id")}']", ns).ShouldBeOfType<XmlElement>();
        format.SelectSingleNode("xades:MimeType", ns)!.InnerText.ShouldBe("application/pdf");

        // Everything the signature needs is in the document.
        var result = new XadesSignatureValidator().Validate(signed, [s_cert]);
        result.IsValid.ShouldBeTrue(string.Join("; ", result.Errors));
    }

    [Fact]
    public async Task SignAsync_AdditionalDataObjects_EverySignedDataObjectHasItsDataObjectFormat()
    {
        // ETSI EN 319 132-1 §6.3: one DataObjectFormat for each signed data object except SignedProperties.
        // EU DSS reports XAdES-BES instead of XAdES-BASELINE-B when one is missing.
        byte[] signed = await XadesSigner.Document(s_xml).WithCertificate(s_cert)
            .WithAdditionalDataObject(XadesDataObject.Embedded(s_attachment))
            .WithAdditionalDataObject(XadesDataObject.External("termos.txt", s_terms, "text/plain"))
            .SignAsync();

        var (signature, ns) = Signature(signed);
        var dataReferences = signature.SelectNodes("ds:SignedInfo/ds:Reference[not(@Type)]", ns)!.OfType<XmlElement>().ToList();
        dataReferences.Count.ShouldBe(3);
        var formats = signature.SelectNodes(".//xades:SignedDataObjectProperties/xades:DataObjectFormat", ns)!.OfType<XmlElement>()
            .ToDictionary(f => f.GetAttribute("ObjectReference"), f => f.SelectSingleNode("xades:MimeType", ns)!.InnerText);
        formats.Keys.ShouldBe(dataReferences.Select(r => "#" + r.GetAttribute("Id")), ignoreOrder: true);
        formats["#" + dataReferences[0].GetAttribute("Id")].ShouldBe("text/xml");                 // the document
        formats["#" + dataReferences[1].GetAttribute("Id")].ShouldBe("application/octet-stream"); // type not given
        formats["#" + dataReferences[2].GetAttribute("Id")].ShouldBe("text/plain");
    }

    [Fact]
    public async Task SignAsync_AdditionalDataObjectsWithTheUsersDataObjectFormat_KeepsItForTheDocument()
    {
        byte[] signed = await XadesSigner.Document(s_xml).WithCertificate(s_cert)
            .WithDataObjectFormat(new DataObjectFormat { MimeType = "application/xml" })
            .WithAdditionalDataObject(XadesDataObject.Embedded(s_attachment))
            .SignAsync();

        var (signature, ns) = Signature(signed);
        string documentReferenceId = ((XmlElement)signature.SelectSingleNode("ds:SignedInfo/ds:Reference[@URI='']", ns)!).GetAttribute("Id");
        signature.SelectSingleNode($".//xades:DataObjectFormat[@ObjectReference='#{documentReferenceId}']/xades:MimeType", ns)!.InnerText.ShouldBe("application/xml");
        new XadesSignatureValidator().Validate(signed, [s_cert]).IsValid.ShouldBeTrue();
    }

    [Fact]
    public async Task Validate_EmbeddedDataObjectAltered_IsInvalid()
    {
        byte[] signed = await XadesSigner.Document(s_xml).WithCertificate(s_cert)
            .WithAdditionalDataObject(XadesDataObject.Embedded(s_attachment))
            .SignAsync();
        string altered = Encoding.UTF8.GetString(signed).Replace(
            Convert.ToBase64String(s_attachment), Convert.ToBase64String([.. s_attachment, 0x01]), StringComparison.Ordinal);

        new XadesSignatureValidator().Validate(Encoding.UTF8.GetBytes(altered), [s_cert]).IsValid.ShouldBeFalse();
    }

    [Fact]
    public async Task SignAsync_ExternalDataObject_IsReferencedByUriAndNeedsItsDataToValidate()
    {
        byte[] signed = await XadesSigner.Document(s_xml).WithCertificate(s_cert)
            .WithAdditionalDataObject(XadesDataObject.External("termos.txt", s_terms, "text/plain"))
            .SignAsync();

        var (signature, ns) = Signature(signed);
        var reference = signature.SelectSingleNode("ds:SignedInfo/ds:Reference[@URI='termos.txt']", ns).ShouldBeOfType<XmlElement>();
        reference.SelectSingleNode("ds:Transforms", ns).ShouldBeNull();
        Convert.FromBase64String(reference.SelectSingleNode("ds:DigestValue", ns)!.InnerText).ShouldBe(SHA256.HashData(s_terms));
        signature.SelectNodes("ds:Object", ns)!.Count.ShouldBe(1); // only the qualifying properties

        var validator = new XadesSignatureValidator();
        var withData = validator.Validate(signed, [s_cert], new Dictionary<string, byte[]> { ["termos.txt"] = s_terms });
        withData.IsValid.ShouldBeTrue(string.Join("; ", withData.Errors));
        validator.Validate(signed, [s_cert], new Dictionary<string, byte[]> { ["termos.txt"] = "outro texto"u8.ToArray() }).IsValid.ShouldBeFalse();
        validator.Validate(signed, [s_cert]).IsValid.ShouldBeFalse();
    }

    [Fact]
    public async Task SignAsync_DetachedDocumentWithExternalDataObject_ValidatesWithBothByUri()
    {
        byte[] signed = await XadesSigner.Document(s_xml).WithCertificate(s_cert)
            .WithForm(XadesForm.Detached).WithDataUri("order.xml")
            .WithAdditionalDataObject(XadesDataObject.External("termos.txt", s_terms))
            .WithAdditionalDataObject(XadesDataObject.Embedded(s_attachment))
            .SignAsync();

        var result = new XadesSignatureValidator().Validate(signed, [s_cert],
            new Dictionary<string, byte[]> { ["order.xml"] = s_xml, ["termos.txt"] = s_terms });

        result.IsValid.ShouldBeTrue(string.Join("; ", result.Errors));
    }

    [Fact]
    public async Task SignAsync_ExternalSignerWithDataObjects_Validates()
    {
        byte[] signed = await XadesSigner.Document(s_xml)
            .WithExternalSigner(s_cert, new DelegatingExternalSigner(data =>
            {
                using var rsa = s_cert.GetRSAPrivateKey()!;
                return Task.FromResult(rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
            }))
            .WithSignatureAlgorithm("1.2.840.113549.1.1.11")
            .WithAdditionalDataObject(XadesDataObject.Embedded(s_attachment, "application/pdf"))
            .WithAdditionalDataObject(XadesDataObject.External("termos.txt", s_terms))
            .SignAsync();

        var result = new XadesSignatureValidator().Validate(signed, [s_cert], new Dictionary<string, byte[]> { ["termos.txt"] = s_terms });

        result.IsValid.ShouldBeTrue(string.Join("; ", result.Errors));
    }

    [Fact]
    public async Task SignAsync_DataObjectsTimestamp_CoversTheDocumentAndEveryDataObjectInOrder()
    {
        byte[] signed = await XadesSigner.Document(s_xml).WithCertificate(s_cert)
            .WithAdditionalDataObject(XadesDataObject.Embedded(s_attachment))
            .WithAdditionalDataObject(XadesDataObject.External("termos.txt", s_terms))
            .WithDataObjectsTimestamp(Tsa)
            .SignAsync();

        var (signature, ns) = Signature(signed);
        byte[] token = Convert.FromBase64String(signature.SelectSingleNode(".//xades:AllDataObjectsTimeStamp/xades:EncapsulatedTimeStamp", ns)!.InnerText);
        // The enveloped document reference digests the exclusive canonical form of the document without signatures.
        byte[] document = "<order><item>1</item></order>"u8.ToArray();
        TimestampToken.Verify(token, [.. document, .. s_attachment, .. s_terms]).IsImprintValid.ShouldBeTrue();

        var result = new XadesSignatureValidator().Validate(signed, [s_cert], new Dictionary<string, byte[]> { ["termos.txt"] = s_terms });
        result.IsValid.ShouldBeTrue(string.Join("; ", result.Errors));
        result.HasValidDataObjectsTimeStamp.ShouldBe(true);
    }

    [Fact]
    public void WithAdditionalDataObject_SameExternalUriTwice_Throws()
    {
        var builder = XadesSigner.Document(s_xml).WithAdditionalDataObject(XadesDataObject.External("a.txt", s_terms));

        Should.Throw<ArgumentException>(() => builder.WithAdditionalDataObject(XadesDataObject.External("a.txt", s_attachment)));
    }

    [Fact]
    public async Task SignAsync_ExternalDataObjectWithTheDetachedDataUri_Throws()
    {
        var builder = XadesSigner.Document(s_xml).WithCertificate(s_cert).WithForm(XadesForm.Detached).WithDataUri("order.xml")
            .WithAdditionalDataObject(XadesDataObject.External("order.xml", s_terms));

        await Should.ThrowAsync<SigningException>(() => builder.SignAsync());
    }

    [Fact]
    public async Task CounterSign_WithAdditionalDataObject_Throws()
    {
        byte[] signed = await XadesSigner.Document(s_xml).WithCertificate(s_cert).SignAsync();
        var builder = XadesSigner.CounterSign(signed).WithCertificate(s_cert).WithAdditionalDataObject(XadesDataObject.Embedded(s_attachment));

        await Should.ThrowAsync<SigningException>(() => builder.SignAsync());
    }

    [Theory]
    [InlineData("")]
    [InlineData("#fragment")]
    public void External_UriEmptyOrSameDocument_Throws(string uri) =>
        Should.Throw<ArgumentException>(() => XadesDataObject.External(uri, s_terms));

    [Fact]
    public void Embedded_EmptyContent_Throws() =>
        Should.Throw<ArgumentException>(() => XadesDataObject.Embedded(ReadOnlyMemory<byte>.Empty));

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
