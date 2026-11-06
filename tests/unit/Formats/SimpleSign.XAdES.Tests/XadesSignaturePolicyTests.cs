using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Xml;
using Shouldly;
using SimpleSign.Core.Constants;
using SimpleSign.Core.Crypto;
using SimpleSign.Core.Validation;
using SimpleSign.TestHelpers;
using SimpleSign.XAdES.Constants;
using Xunit;

namespace SimpleSign.XAdES.Tests;

/// <summary>SignaturePolicyIdentifier written by <see cref="XadesSignerBuilder"/> and read by <see cref="XadesSignatureValidator"/>.</summary>
[Trait("Category", "Unit")]
public sealed class XadesSignaturePolicyTests
{
    private const string PolicyOid = "2.16.76.1.7.1.6.2.5";
    private const string PolicyUri = "http://politicas.icpbrasil.gov.br/PA_AD_RB_v2_5.xml";
    private static readonly X509Certificate2 s_cert = TestCertificateFactory.CreateSelfSignedCert("CN=XAdES Policy Test, O=Tests");
    private static readonly byte[] s_xml = "<?xml version=\"1.0\"?><doc><id>1</id></doc>"u8.ToArray();
    private static readonly byte[] s_policyHash = SHA256.HashData("policy"u8);

    [Fact]
    public async Task WithSignaturePolicy_Reference_WritesOidUrnAndPolicyHash()
    {
        byte[] signed = await XadesSigner.Document(s_xml).WithCertificate(s_cert)
            .WithSignaturePolicy(new SignaturePolicyReference(PolicyOid, Oids.Sha256, s_policyHash, PolicyUri))
            .SignAsync();

        var (doc, ns) = Load(signed);
        var policyId = doc.SelectSingleNode("//xades:SignaturePolicyId", ns).ShouldBeOfType<XmlElement>();
        var identifier = policyId.SelectSingleNode("xades:SigPolicyId/xades:Identifier", ns).ShouldBeOfType<XmlElement>();
        identifier.GetAttribute("Qualifier").ShouldBe("OIDAsURN");
        identifier.InnerText.ShouldBe("urn:oid:" + PolicyOid);
        policyId.SelectSingleNode("xades:SigPolicyHash/ds:DigestMethod", ns).ShouldBeOfType<XmlElement>()
            .GetAttribute("Algorithm").ShouldBe(XmlDSigUrls.Sha256Digest);
        policyId.SelectSingleNode("xades:SigPolicyHash/ds:DigestValue", ns)!.InnerText.ShouldBe(Convert.ToBase64String(s_policyHash));
        policyId.SelectSingleNode("xades:SigPolicyQualifiers/xades:SigPolicyQualifier/xades:SPURI", ns)!.InnerText.ShouldBe(PolicyUri);
    }

    [Fact]
    public async Task Validate_SignatureWithPolicyReference_ExposesPolicy()
    {
        byte[] signed = await XadesSigner.Document(s_xml).WithCertificate(s_cert)
            .WithSignaturePolicy(new SignaturePolicyReference(PolicyOid, Oids.Sha1, SHA1.HashData("policy"u8), PolicyUri))
            .SignAsync();

        var result = new XadesSignatureValidator(new ValidationOptions { CheckRevocation = false }).Validate(signed, trustAnchors: [s_cert]);

        result.IsValid.ShouldBeTrue(string.Join("; ", result.Errors));
        var policy = result.SignaturePolicy.ShouldNotBeNull();
        policy.Oid.ShouldBe(PolicyOid);
        policy.HashAlgorithmOid.ShouldBe(Oids.Sha1);
        policy.Hash.ToArray().ShouldBe(SHA1.HashData("policy"u8));
        policy.Uri.ShouldBe(PolicyUri);
    }

    [Fact]
    public async Task Validate_LegacyPolicyOid_ExposesPlainOid()
    {
        byte[] signed = await XadesSigner.Document(s_xml).WithCertificate(s_cert).WithSignaturePolicy("1.2.3.4").SignAsync();

        var result = new XadesSignatureValidator(new ValidationOptions { CheckRevocation = false }).Validate(signed, trustAnchors: [s_cert]);

        var policy = result.SignaturePolicy.ShouldNotBeNull();
        policy.Oid.ShouldBe("1.2.3.4");
        policy.Hash.IsEmpty.ShouldBeTrue();
        policy.Uri.ShouldBeNull();
    }

    [Fact]
    public async Task Validate_NoPolicy_SignaturePolicyIsNull()
    {
        byte[] signed = await XadesSigner.Document(s_xml).WithCertificate(s_cert).SignAsync();

        var result = new XadesSignatureValidator(new ValidationOptions { CheckRevocation = false }).Validate(signed, trustAnchors: [s_cert]);

        result.SignaturePolicy.ShouldBeNull();
    }

    [Fact]
    public void WithSignaturePolicy_UnsupportedHashAlgorithm_ThrowsOnSign()
    {
        var builder = XadesSigner.Document(s_xml).WithCertificate(s_cert)
            .WithSignaturePolicy(new SignaturePolicyReference(PolicyOid, "1.2.3", s_policyHash));

        Should.Throw<Core.Signing.SigningException>(() => builder.SignAsync());
    }

    [Fact]
    public async Task WithSignaturePolicyStore_Document_WritesTheV141PropertyAndTheValidatorReadsIt()
    {
        byte[] policyDocument = "a signature policy document"u8.ToArray();
        var policy = new SignaturePolicyReference(PolicyOid, Oids.Sha256, SHA256.HashData(policyDocument), PolicyUri);

        byte[] signed = await XadesSigner.Document(s_xml).WithCertificate(s_cert)
            .WithSignaturePolicy(policy)
            .WithSignaturePolicyStore(SignaturePolicyStore.FromDocument("1.2.3.4.5.1", policyDocument))
            .SignAsync();

        var (doc, ns) = Load(signed);
        ns.AddNamespace("xades141", XadesUris.Xades141Namespace);
        var store = doc.SelectSingleNode("//xades:UnsignedSignatureProperties/xades141:SignaturePolicyStore", ns).ShouldBeOfType<XmlElement>();
        store.ChildNodes.OfType<XmlElement>().Select(e => (e.LocalName, e.NamespaceURI)).ShouldBe(
        [
            ("SPDocSpecification", XadesUris.Xades141Namespace),
            ("SignaturePolicyDocument", XadesUris.Xades141Namespace),
        ]);
        var identifier = store.SelectSingleNode("xades141:SPDocSpecification/xades:Identifier", ns).ShouldBeOfType<XmlElement>();
        identifier.GetAttribute("Qualifier").ShouldBe("OIDAsURN");
        identifier.InnerText.ShouldBe("urn:oid:1.2.3.4.5.1");
        store.SelectSingleNode("xades141:SignaturePolicyDocument", ns)!.InnerText.ShouldBe(Convert.ToBase64String(policyDocument));

        var result = new XadesSignatureValidator().Validate(signed, [s_cert]);
        result.IsValid.ShouldBeTrue(string.Join("; ", result.Errors));
        var read = result.SignaturePolicyStore.ShouldNotBeNull();
        read.Specification.ShouldBe("1.2.3.4.5.1");
        read.Document.ToArray().ShouldBe(policyDocument);
        read.MatchesHash(result.SignaturePolicy.ShouldNotBeNull()).ShouldBeTrue();
    }

    [Fact]
    public async Task WithSignaturePolicyStore_LocalUri_WritesTheUriAndAPlainSpecification()
    {
        byte[] signed = await XadesSigner.Document(s_xml).WithCertificate(s_cert)
            .WithSignaturePolicy(new SignaturePolicyReference(PolicyOid, Oids.Sha256, s_policyHash, PolicyUri))
            .WithSignaturePolicyStore(SignaturePolicyStore.FromLocalUri("https://example.com/policy-syntax", "file:///policies/pa.xml"))
            .SignAsync();

        var (doc, ns) = Load(signed);
        ns.AddNamespace("xades141", XadesUris.Xades141Namespace);
        var identifier = doc.SelectSingleNode("//xades141:SignaturePolicyStore/xades141:SPDocSpecification/xades:Identifier", ns).ShouldBeOfType<XmlElement>();
        identifier.HasAttribute("Qualifier").ShouldBeFalse();
        identifier.InnerText.ShouldBe("https://example.com/policy-syntax");
        doc.SelectSingleNode("//xades141:SignaturePolicyStore/xades141:SigPolDocLocalURI", ns)!.InnerText.ShouldBe("file:///policies/pa.xml");
        doc.SelectSingleNode("//xades141:SignaturePolicyStore/xades141:SignaturePolicyDocument", ns).ShouldBeNull();

        var read = new XadesSignatureValidator().Validate(signed, [s_cert]).SignaturePolicyStore.ShouldNotBeNull();
        read.LocalUri.ShouldBe("file:///policies/pa.xml");
        read.SpecificationIsOid.ShouldBeFalse();
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task WithSignaturePolicyStore_WithoutThePolicyHash_Throws(bool policyWithoutHash)
    {
        // The hash in the signed SignaturePolicyIdentifier is what protects the unsigned store (§6.3).
        var builder = XadesSigner.Document(s_xml).WithCertificate(s_cert)
            .WithSignaturePolicyStore(SignaturePolicyStore.FromDocument("1.2.3", "policy"u8.ToArray()));
        builder = policyWithoutHash ? builder.WithSignaturePolicy(PolicyOid, PolicyUri) : builder;

        var exception = await Should.ThrowAsync<SimpleSign.Core.Signing.SigningException>(() => builder.SignAsync());

        exception.Message.ShouldContain("SignaturePolicyStore");
    }

    [Fact]
    public async Task Validate_SignatureWithoutStore_HasNoSignaturePolicyStore()
    {
        byte[] signed = await XadesSigner.Document(s_xml).WithCertificate(s_cert).SignAsync();

        new XadesSignatureValidator().Validate(signed, [s_cert]).SignaturePolicyStore.ShouldBeNull();
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
