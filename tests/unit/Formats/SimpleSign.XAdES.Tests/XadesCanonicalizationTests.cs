using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Xml;
using Shouldly;
using SimpleSign.Core.Constants;
using SimpleSign.Core.Signing;
using SimpleSign.TestHelpers;
using Xunit;

namespace SimpleSign.XAdES.Tests;

/// <summary>
/// The canonicalization choice of SignedInfo and of the references. Inclusive canonicalization
/// depends on the namespaces around the signed parts, so what the builder signs is checked against
/// the canonical form .NET computes for the same nodes inside the finished document.
/// </summary>
[Trait("Category", "Unit")]
public sealed class XadesCanonicalizationTests
{
    private const string ExclusiveUri = "http://www.w3.org/2001/10/xml-exc-c14n#";
    private const string InclusiveUri = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";

    // The root declares namespaces the signature never uses: inclusive canonicalization renders
    // all of them on SignedInfo and SignedProperties, exclusive does not. It has no xml: attribute
    // because .NET's node-set canonicalization, the oracle below, repeats an inherited xml:
    // attribute on every element instead of only on the apex (Canonical XML 1.0 §2.4); that
    // inheritance is checked against a hand-written canonical form instead.
    private const string Document =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" +
        "<p:order xmlns:p=\"urn:example:order\" xmlns:unused=\"urn:example:unused\" " +
        "xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">" +
        "<!-- a comment --><p:item xsi:nil=\"false\">café</p:item></p:order>";

    private static readonly byte[] s_xml = Encoding.UTF8.GetBytes(Document);
    private static readonly X509Certificate2 s_cert = TestCertificateFactory.CreateSelfSignedCert("CN=XAdES C14N, O=Tests");

    [Fact]
    public void CanonicalizeElement_Inclusive_GivesTheApexItsAncestorsNamespacesAndXmlAttributes()
    {
        var doc = new XmlDocument { PreserveWhitespace = true };
        doc.LoadXml("<a xmlns:x=\"urn:x\" xml:lang=\"en\"><b xmlns=\"urn:b\" xmlns:x=\"urn:x2\"><c><d/></c></b></a>");
        var c = (XmlElement)doc.DocumentElement!.FirstChild!.FirstChild!;

        string inclusive = Encoding.UTF8.GetString(XadesSignatureBuilder.CanonicalizeElement(c, XmlDSigUrls.C14N));
        string exclusive = Encoding.UTF8.GetString(XadesSignatureBuilder.CanonicalizeElement(c, XmlDSigUrls.ExcC14N));

        // The nearest declaration of x wins, and the default namespace comes from b.
        inclusive.ShouldBe("<c xmlns=\"urn:b\" xmlns:x=\"urn:x2\" xml:lang=\"en\"><d></d></c>");
        exclusive.ShouldBe("<c xmlns=\"urn:b\"><d></d></c>");
    }

    [Fact]
    public void CanonicalizeElement_Inclusive_DoesNotGiveANoNamespaceElementTheAncestorsDefault()
    {
        var doc = new XmlDocument { PreserveWhitespace = true };
        doc.LoadXml("<a xmlns=\"urn:a\"><b xmlns=\"\"><c/></b></a>");
        var c = (XmlElement)doc.DocumentElement!.FirstChild!.FirstChild!;

        Encoding.UTF8.GetString(XadesSignatureBuilder.CanonicalizeElement(c, XmlDSigUrls.C14N)).ShouldBe("<c></c>");
    }

    [Theory]
    [InlineData(XadesForm.Enveloped)]
    [InlineData(XadesForm.Enveloping)]
    [InlineData(XadesForm.Detached)]
    public async Task SignAsync_Inclusive_DeclaresTheAlgorithmAndValidates(XadesForm form)
    {
        byte[] signed = await Builder(form).WithCanonicalization(XadesCanonicalization.Inclusive).SignAsync();

        var (signature, ns) = Signature(signed);
        Algorithm(signature, "ds:SignedInfo/ds:CanonicalizationMethod", ns).ShouldBe(InclusiveUri);
        foreach (XmlElement reference in signature.SelectNodes("ds:SignedInfo/ds:Reference", ns)!)
        {
            Algorithm(reference, "ds:Transforms/ds:Transform[last()]", ns).ShouldBe(InclusiveUri);
        }

        var result = new XadesSignatureValidator().Validate(signed, [s_cert], form == XadesForm.Detached ? s_xml : null);
        result.IsValid.ShouldBeTrue(string.Join("; ", result.Errors));
    }

    [Theory]
    [InlineData(XadesForm.Enveloped, false)]
    [InlineData(XadesForm.Enveloped, true)]
    [InlineData(XadesForm.Enveloping, false)]
    [InlineData(XadesForm.Enveloping, true)]
    [InlineData(XadesForm.Detached, false)]
    [InlineData(XadesForm.Detached, true)]
    public async Task SignAsync_Inclusive_SignsTheCanonicalFormOfTheNodesInTheirDocument(XadesForm form, bool externalSigner)
    {
        var builder = externalSigner
            ? XadesSigner.Document(s_xml)
                .WithExternalSigner(s_cert, new DelegatingExternalSigner(data =>
                {
                    using var rsa = s_cert.GetRSAPrivateKey()!;
                    return Task.FromResult(rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
                }))
                .WithSignatureAlgorithm("1.2.840.113549.1.1.11")
            : XadesSigner.Document(s_xml).WithCertificate(s_cert);
        builder = builder.WithForm(form).WithCanonicalization(XadesCanonicalization.Inclusive);

        byte[] signed = await (form == XadesForm.Detached ? builder.WithDataUri("order.xml") : builder).SignAsync();

        var (signature, ns) = Signature(signed);

        // SignedInfo: the signature value is over its canonical form inside the finished document.
        var signedInfo = (XmlElement)signature.SelectSingleNode("ds:SignedInfo", ns)!;
        byte[] signedInfoOctets = CanonicalizeInPlace(SubtreeWithoutComments(signedInfo));
        Encoding.UTF8.GetString(XadesSignatureBuilder.CanonicalizeElement(signedInfo, XmlDSigUrls.C14N))
            .ShouldBe(Encoding.UTF8.GetString(signedInfoOctets));
        byte[] signatureValue = Convert.FromBase64String(signature.SelectSingleNode("ds:SignatureValue", ns)!.InnerText);
        using (var rsa = s_cert.GetRSAPublicKey()!)
        {
            rsa.VerifyData(signedInfoOctets, signatureValue, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1).ShouldBeTrue();
        }

        // SignedProperties: the reference digest is over its canonical form inside the finished document.
        var propertiesReference = (XmlElement)signature.SelectSingleNode("ds:SignedInfo/ds:Reference[@Type]", ns)!;
        string propertiesId = propertiesReference.GetAttribute("URI")[1..];
        var signedProperties = (XmlElement)signature.SelectSingleNode($".//*[@Id='{propertiesId}']")!;
        Digest(propertiesReference, ns).ShouldBe(SHA256.HashData(CanonicalizeInPlace(SubtreeWithoutComments(signedProperties))));

        if (form == XadesForm.Enveloped)
        {
            // The document reference: every node outside ds:Signature, comments excluded.
            Encoding.UTF8.GetString(signedInfoOctets).ShouldContain("xmlns:unused=\"urn:example:unused\"");
            var documentReference = (XmlElement)signature.SelectSingleNode("ds:SignedInfo/ds:Reference[@URI='']", ns)!;
            var outsideSignature = signature.OwnerDocument.SelectNodes(
                "(//. | //@* | //namespace::*)[not(ancestor-or-self::ds:Signature)][not(self::comment())]", ns)!;
            Digest(documentReference, ns).ShouldBe(SHA256.HashData(CanonicalizeInPlace(outsideSignature)));
        }
    }

    [Fact]
    public async Task SignAsync_Default_KeepsExclusiveCanonicalization()
    {
        byte[] signed = await Builder(XadesForm.Enveloped).SignAsync();

        var (signature, ns) = Signature(signed);
        Algorithm(signature, "ds:SignedInfo/ds:CanonicalizationMethod", ns).ShouldBe(ExclusiveUri);
        Algorithm(signature, "ds:SignedInfo/ds:Reference[@Type]/ds:Transforms/ds:Transform[last()]", ns).ShouldBe(ExclusiveUri);
        new XadesSignatureValidator().Validate(signed, [s_cert]).IsValid.ShouldBeTrue();
    }

    [Fact]
    public async Task Validate_InclusiveSignatureMovedUnderAnotherNamespaceContext_IsInvalid()
    {
        byte[] signed = await Builder(XadesForm.Enveloped).WithCanonicalization(XadesCanonicalization.Inclusive).SignAsync();

        // Inclusive canonicalization signs the namespace context: dropping a declaration the
        // signature never uses must still break it, which proves the validator reads the context.
        string tampered = Encoding.UTF8.GetString(signed).Replace(" xmlns:unused=\"urn:example:unused\"", "", StringComparison.Ordinal);
        tampered.ShouldNotBe(Encoding.UTF8.GetString(signed));

        new XadesSignatureValidator().Validate(Encoding.UTF8.GetBytes(tampered), [s_cert]).IsValid.ShouldBeFalse();
    }

    [Fact]
    public async Task Validate_ExclusiveSignature_SurvivesTheSameChange()
    {
        byte[] signed = await Builder(XadesForm.Enveloping).SignAsync();

        // Wrapping an enveloping signature changes the namespaces around it and nothing it signs.
        string wrapped = Encoding.UTF8.GetString(signed);
        wrapped = wrapped[wrapped.IndexOf("<Signature", StringComparison.Ordinal)..];
        wrapped = "<w:wrapper xmlns:w=\"urn:example:wrapper\">" + wrapped + "</w:wrapper>";

        var result = new XadesSignatureValidator().Validate(Encoding.UTF8.GetBytes(wrapped), [s_cert]);
        result.IsValid.ShouldBeTrue(string.Join("; ", result.Errors));
    }

    [Fact]
    public void WithCanonicalization_UndefinedValue_Throws() =>
        Should.Throw<ArgumentOutOfRangeException>(() => XadesSigner.Document(s_xml).WithCanonicalization((XadesCanonicalization)42));

    private static XadesSignerBuilder Builder(XadesForm form)
    {
        var builder = XadesSigner.Document(s_xml).WithCertificate(s_cert).WithForm(form);
        return form == XadesForm.Detached ? builder.WithDataUri("order.xml") : builder;
    }

    private static (XmlElement Signature, XmlNamespaceManager Ns) Signature(byte[] signed)
    {
        var doc = new XmlDocument { PreserveWhitespace = true };
        using var stream = new MemoryStream(signed);
        doc.Load(stream);
        var ns = new XmlNamespaceManager(doc.NameTable);
        ns.AddNamespace("ds", "http://www.w3.org/2000/09/xmldsig#");
        return ((XmlElement)doc.SelectSingleNode("//ds:Signature", ns)!, ns);
    }

    private static string Algorithm(XmlElement context, string xpath, XmlNamespaceManager ns) =>
        ((XmlElement)context.SelectSingleNode(xpath, ns)!).GetAttribute("Algorithm");

    private static byte[] Digest(XmlElement reference, XmlNamespaceManager ns) =>
        Convert.FromBase64String(reference.SelectSingleNode("ds:DigestValue", ns)!.InnerText);

    /// <summary>The node-set of an element as a same-document reference selects it: the subtree, without comments.</summary>
    private static XmlNodeList SubtreeWithoutComments(XmlElement element) =>
        element.SelectNodes("descendant-or-self::node()[not(self::comment())] | descendant-or-self::*/@* | descendant-or-self::*/namespace::*")!;

    /// <summary>Canonical XML 1.0 of a node-set that stays in its document, so the ancestors' context applies.</summary>
    private static byte[] CanonicalizeInPlace(XmlNodeList nodes)
    {
        var transform = new XmlDsigC14NTransform();
        transform.LoadInput(nodes);
        using var output = (Stream)transform.GetOutput(typeof(Stream));
        using var buffer = new MemoryStream();
        output.CopyTo(buffer);
        return buffer.ToArray();
    }
}
