using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Xml;
using Shouldly;
using SimpleSign.Core.Policies;
using SimpleSign.Core.Signing;
using SimpleSign.XAdES;

namespace SimpleSign.Brazil.Fiscal.Tests;

/// <summary>
/// Fiscal XML signed by layout, cross-checked with .NET's SignedXml. The certificates are test ones outside ICP-Brasil,
/// so the signatures are made under the layout's policy without the ICP-Brasil chain and revocation checks.
/// </summary>
[Trait("Category", "Unit")]
public sealed class FiscalXmlSignerTests : IDisposable
{
    private const string NfeKey = "NFe35260711222333000181550010000000071123456780";
    private readonly X509Certificate2 _eCnpj = CreateECnpj("11222333000181");

    public void Dispose() => _eCnpj.Dispose();

    /// <summary>The layout's policy without the checks only a real ICP-Brasil certificate passes (chain to its roots, revocation).</summary>
    private static SigningPolicy Offline(FiscalDocumentProfile layout) => layout.SigningPolicy
        .With("SigningCertificate/ProspectiveCertificateChain", new PolicyConstraint(ConstraintLevel.Ignore))
        .With("SigningCertificate/NotRevoked", new PolicyConstraint(ConstraintLevel.Ignore))
        .With("SigningCertificate/RevocationDataAvailable", new PolicyConstraint(ConstraintLevel.Ignore))
        .With("CACertificate/NotRevoked", new PolicyConstraint(ConstraintLevel.Ignore))
        .With("CACertificate/RevocationDataAvailable", new PolicyConstraint(ConstraintLevel.Ignore));

    private static XmlDsigSignerBuilder Signer(string xml, FiscalDocumentProfile layout) =>
        FiscalXmlSigner.Document(Utf8(xml), layout).WithSigningPolicy(Offline(layout));

    private static string Nfe(string key = NfeKey) =>
        $"<NFe xmlns=\"http://www.portalfiscal.inf.br/nfe\"><infNFe versao=\"4.00\" Id=\"{key}\"><ide><cUF>35</cUF><natOp>VENDA</natOp></ide><emit><CNPJ>11222333000181</CNPJ><xNome>EMPRESA &amp; CIA LTDA</xNome></emit></infNFe></NFe>";

    private static byte[] Utf8(string s) => Encoding.UTF8.GetBytes(s);

    [Fact]
    public async Task Document_NFe_SignsInfNFeWithRsaSha1AfterIt()
    {
        byte[] signed = await Signer(Nfe(), FiscalDocumentProfile.NFe).WithCertificate(_eCnpj).SignAsync();

        var doc = Load(signed);
        var ns = new XmlNamespaceManager(doc.NameTable);
        ns.AddNamespace("ds", "http://www.w3.org/2000/09/xmldsig#");
        ns.AddNamespace("nfe", "http://www.portalfiscal.inf.br/nfe");
        doc.SelectSingleNode("/nfe:NFe/ds:Signature", ns)!.PreviousSibling!.LocalName.ShouldBe("infNFe");
        doc.SelectSingleNode("//ds:SignatureMethod/@Algorithm", ns)!.Value.ShouldBe("http://www.w3.org/2000/09/xmldsig#rsa-sha1");
        var result = FiscalXmlValidator.VerifySignatures(signed, FiscalDocumentProfile.NFe);
        result.IsValid.ShouldBeTrue(string.Join("; ", result.Signatures.SelectMany(s => s.Errors)));
        result.Signatures[0].Cnpj.ShouldBe("11222333000181");
        CheckWithSignedXml(signed).ShouldBeTrue();
    }

    [Theory]
    [InlineData("evento", "<envEvento xmlns=\"http://www.portalfiscal.inf.br/nfe\"><evento versao=\"1.00\"><infEvento Id=\"ID1101113526071122233300018155001000000007112345678001\"><tpEvento>110111</tpEvento></infEvento></evento></envEvento>")]
    [InlineData("inutilizacao", "<inutNFe xmlns=\"http://www.portalfiscal.inf.br/nfe\" versao=\"4.00\"><infInut Id=\"ID35261122233300018155001000000001000000010\"><tpAmb>2</tpAmb></infInut></inutNFe>")]
    [InlineData("cte", "<CTe xmlns=\"http://www.portalfiscal.inf.br/cte\"><infCte versao=\"4.00\" Id=\"CTe35260711222333000181570010000000071123456780\"><ide><cUF>35</cUF></ide></infCte></CTe>")]
    [InlineData("mdfe", "<MDFe xmlns=\"http://www.portalfiscal.inf.br/mdfe\"><infMDFe versao=\"3.00\" Id=\"MDFe35260711222333000181580010000000071123456780\"><ide><cUF>35</cUF></ide></infMDFe></MDFe>")]
    [InlineData("nfse", "<DPS xmlns=\"http://www.sped.fazenda.gov.br/nfse\" versao=\"1.00\"><infDPS Id=\"DPS355030721122233300018100001000000000000001\"><tpAmb>2</tpAmb></infDPS></DPS>")]
    [InlineData("esocial", "<eSocial xmlns=\"http://www.esocial.gov.br/schema/evt/evtInfoEmpregador/v_S_01_03_00\"><evtInfoEmpregador Id=\"ID1112223330000002026110510000000000001\"><ideEvento><tpAmb>2</tpAmb></ideEvento></evtInfoEmpregador></eSocial>")]
    [InlineData("reinf", "<Reinf xmlns=\"http://www.reinf.esocial.gov.br/schemas/evtInfoContribuinte/v2_01_02\"><evtInfoContri id=\"ID1112223330000002026110510000000000001\"><ideEvento><tpAmb>2</tpAmb></ideEvento></evtInfoContri></Reinf>")]
    public async Task Document_EveryLayout_RoundTripsAndFollowsTheLayout(string name, string xml)
    {
        var layout = FiscalDocumentProfile.ByName[name];

        byte[] signed = await Signer(xml, layout).WithCertificate(_eCnpj).SignAsync();

        var result = FiscalXmlValidator.VerifySignatures(signed, layout);
        result.IsValid.ShouldBeTrue(string.Join("; ", result.Signatures.SelectMany(s => s.Errors)));
        result.Signatures[0].Signature.HashAlgorithm.ShouldBe(layout.HashAlgorithm.Name);
        CheckWithSignedXml(signed).ShouldBeTrue();
    }

    [Fact]
    public async Task VerifySignatures_AnotherLayout_ReportsIt()
    {
        byte[] signed = await Signer(Nfe(), FiscalDocumentProfile.NFe).WithCertificate(_eCnpj).SignAsync();

        var result = FiscalXmlValidator.VerifySignatures(signed, FiscalDocumentProfile.ESocial);

        result.IsValid.ShouldBeFalse();
        result.Signatures[0].Signature.IsValid.ShouldBeTrue();
        result.Signatures[0].LayoutErrors.Count.ShouldBe(2, "another element, another hash");
    }

    [Fact]
    public async Task SignAllAsync_Batch_SignsEveryNFe()
    {
        static string Nested(string nfe) => nfe.Replace(" xmlns=\"http://www.portalfiscal.inf.br/nfe\"", string.Empty, StringComparison.Ordinal);
        string batch = $"<enviNFe xmlns=\"http://www.portalfiscal.inf.br/nfe\" versao=\"4.00\"><idLote>1</idLote>{Nested(Nfe())}{Nested(Nfe(NfeKey[..^1] + "1"))}</enviNFe>";

        byte[] signed = await Signer(batch, FiscalDocumentProfile.NFe).WithCertificate(_eCnpj).SignAllAsync();

        var result = FiscalXmlValidator.VerifySignatures(signed, FiscalDocumentProfile.NFe);
        result.Signatures.Count.ShouldBe(2);
        result.IsValid.ShouldBeTrue();
    }

    [Fact]
    public async Task Deferred_PrepareAndComplete_ProducesAValidNFe()
    {
        byte[] key = RandomNumberGenerator.GetBytes(32);
        using var publicCertificate = X509CertificateLoader.LoadCertificate(_eCnpj.RawData);

        var prepared = await FiscalXmlSigner.Deferred(Utf8(Nfe()), FiscalDocumentProfile.NFe)
            .WithSigningPolicy(Offline(FiscalDocumentProfile.NFe)).WithCertificate(publicCertificate).WithSessionIntegrityKey(key).PrepareAsync();
        using var rsa = _eCnpj.GetRSAPrivateKey()!;
        byte[] signed = await XmlDsigDeferredSigner.Resume(prepared.SessionData, key)
            .CompleteAsync(rsa.SignData(prepared.DataToSign, HashAlgorithmName.SHA1, RSASignaturePadding.Pkcs1));

        prepared.DigestAlgorithm.ShouldBe("SHA1");
        FiscalXmlValidator.VerifySignatures(signed, FiscalDocumentProfile.NFe).IsValid.ShouldBeTrue();
    }

    [Fact]
    public async Task Document_TestCertificateUnderTheIcpBrasilPolicy_IsRefused()
    {
        var builder = FiscalXmlSigner.Document(Utf8(Nfe()), FiscalDocumentProfile.NFe).WithCertificate(_eCnpj);

        await Should.ThrowAsync<SigningException>(() => builder.SignAsync());
    }

    [Fact]
    public async Task ValidateAsync_TestCertificate_ChainIsNotIcpBrasil()
    {
        byte[] signed = await Signer(Nfe(), FiscalDocumentProfile.NFe).WithCertificate(_eCnpj).SignAsync();

        var result = await new FiscalXmlValidator().ValidateAsync(signed, FiscalDocumentProfile.NFe, checkRevocation: false);

        result.Signatures[0].Signature.IsDigestValid.ShouldBeTrue();
        result.Signatures[0].Signature.IsChainValid.ShouldBe(false);
        result.IsValid.ShouldBeFalse();
    }

    [Fact]
    public void SefazPolicy_AcceptsSha1ForTheSignatureOnly()
    {
        string json = FiscalPolicies.Sefaz.ToJson();

        json.ShouldContain("\"SHA1\"");
        FiscalDocumentProfile.NFe.SigningPolicy.ShouldBeSameAs(FiscalPolicies.Sefaz);
        FiscalDocumentProfile.ESocial.SigningPolicy.ShouldNotBeSameAs(FiscalPolicies.Sefaz);
    }

    [Fact]
    public async Task SefazPolicy_CaCertificateSignedWithSha1_IsRefused()
    {
        using var rootKey = RSA.Create(2048);
        using var root = new CertificateRequest("CN=Test Root", rootKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)
            .AddCa().CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(2));
        using var caKey = RSA.Create(2048);
        // .NET no longer signs certificates with SHA-1: a generator of our own writes sha1WithRSAEncryption.
        using var caPublic = new CertificateRequest("CN=Test CA SHA-1", caKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)
            .AddCa().Create(root.SubjectName, new Sha1RsaGenerator(rootKey), DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1), [1]);
        using var ca = caPublic.CopyWithPrivateKey(caKey);
        using var leafKey = RSA.Create(2048);
        var leafRequest = new CertificateRequest("CN=EMPRESA:11222333000181", leafKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        leafRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.NonRepudiation, true));
        using var leafPublic = leafRequest.Create(ca, DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddMonths(6), [2]);
        using var leaf = leafPublic.CopyWithPrivateKey(leafKey);

        var ex = await Should.ThrowAsync<SigningException>(() => Signer(Nfe(), FiscalDocumentProfile.NFe).WithCertificate(leaf, [caPublic, root]).SignAsync());

        ex.Reason.ShouldBe(SigningErrorReason.AlgorithmNotPermitted);
        ex.Message.ShouldContain("Test CA SHA-1");
    }

    /// <summary>Independent check with System.Security.Cryptography.Xml.SignedXml (every signature).</summary>
    private static bool CheckWithSignedXml(byte[] signed)
    {
        var doc = Load(signed);
        var signatures = doc.GetElementsByTagName("Signature", "http://www.w3.org/2000/09/xmldsig#").Cast<XmlElement>().ToList();
        foreach (var element in signatures)
        {
            var signedXml = new IdAwareSignedXml(doc);
            signedXml.LoadXml(element);
            if (!signedXml.CheckSignature())
            {
                return false;
            }
        }

        return signatures.Count > 0;
    }

    /// <summary>SignedXml that also resolves the lowercase <c>id</c> attribute used by EFD-Reinf.</summary>
    private sealed class IdAwareSignedXml(XmlDocument doc) : SignedXml(doc)
    {
        public override XmlElement? GetIdElement(XmlDocument? document, string idValue) =>
            base.GetIdElement(document, idValue)
            ?? document?.SelectSingleNode($"//*[@id='{idValue}']") as XmlElement;
    }

    private static XmlDocument Load(byte[] xml)
    {
        var doc = new XmlDocument { PreserveWhitespace = true, XmlResolver = null };
        doc.LoadXml(Encoding.UTF8.GetString(xml));
        return doc;
    }

    /// <summary>A self-signed RSA certificate shaped like an e-CNPJ (SAN otherName 2.16.76.1.3.3, digitalSignature).</summary>
    private static X509Certificate2 CreateECnpj(string cnpj)
    {
        var w = new AsnWriter(AsnEncodingRules.DER);
        using (w.PushSequence())
        {
            using (w.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0, isConstructed: true)))
            {
                w.WriteObjectIdentifier("2.16.76.1.3.3");
                using (w.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0, isConstructed: true)))
                {
                    w.WriteOctetString(Encoding.ASCII.GetBytes(cnpj));
                }
            }
        }

        using var key = RSA.Create(2048);
        var request = new CertificateRequest("CN=EMPRESA EXEMPLO LTDA:11222333000181, O=ICP-Brasil Test", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509Extension("2.5.29.17", w.Encode(), critical: false));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.NonRepudiation, true));
        return request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
    }
}

/// <summary>Signs certificates with sha1WithRSAEncryption, which CertificateRequest refuses.</summary>
internal sealed class Sha1RsaGenerator(RSA key) : X509SignatureGenerator
{
    public override byte[] GetSignatureAlgorithmIdentifier(HashAlgorithmName hashAlgorithm) =>
        Convert.FromHexString("300d06092a864886f70d0101050500");

#pragma warning disable CA5350 // a CA certificate signed with SHA-1, which the policy must refuse
    public override byte[] SignData(byte[] data, HashAlgorithmName hashAlgorithm) =>
        key.SignData(data, HashAlgorithmName.SHA1, RSASignaturePadding.Pkcs1);
#pragma warning restore CA5350

    protected override PublicKey BuildPublicKey() => CreateForRSA(key, RSASignaturePadding.Pkcs1).PublicKey;
}

internal static class CertificateRequestExtensions
{
    public static CertificateRequest AddCa(this CertificateRequest request)
    {
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
        return request;
    }
}
