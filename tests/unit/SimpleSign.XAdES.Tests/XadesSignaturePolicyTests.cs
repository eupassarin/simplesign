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
