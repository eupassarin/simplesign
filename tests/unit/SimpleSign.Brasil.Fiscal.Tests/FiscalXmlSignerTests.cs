using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Xml;
using Shouldly;
using SimpleSign.Core.Signing;

namespace SimpleSign.Brasil.Fiscal.Tests;

/// <summary>Fiscal XML signing and validation, cross-checked with .NET's SignedXml.</summary>
[Trait("Category", "Unit")]
public sealed class FiscalXmlSignerTests : IDisposable
{
    private const string NfeKey = "NFe35260711222333000181550010000000071123456780";
    private readonly X509Certificate2 _eCnpj = CreateECnpj("11222333000181");

    public void Dispose() => _eCnpj.Dispose();

    private static string Nfe(string key = NfeKey, string name = "EMPRESA &amp; CIA LTDA") =>
        $"<NFe xmlns=\"http://www.portalfiscal.inf.br/nfe\"><infNFe versao=\"4.00\" Id=\"{key}\"><ide><cUF>35</cUF><natOp>VENDA</natOp></ide><emit><CNPJ>11222333000181</CNPJ><xNome>{name}</xNome></emit></infNFe></NFe>";

    private static byte[] Utf8(string s) => Encoding.UTF8.GetBytes(s);

    [Fact]
    public void Sign_NFe_FollowsTheLayout()
    {
        byte[] signed = FiscalXmlSigner.Sign(Utf8(Nfe()), FiscalDocumentProfile.NFe, _eCnpj);

        var doc = Load(signed);
        var ns = Ns(doc);
        var signature = (XmlElement)doc.SelectSingleNode("/nfe:NFe/ds:Signature", ns)!;
        signature.PreviousSibling!.LocalName.ShouldBe("infNFe");
        signature.Prefix.ShouldBeEmpty("SEFAZ expects the default namespace, no ds: prefix");
        signature.SelectSingleNode("ds:SignedInfo/ds:Reference/@URI", ns)!.Value.ShouldBe("#" + NfeKey);
        signature.SelectSingleNode("ds:SignedInfo/ds:CanonicalizationMethod/@Algorithm", ns)!.Value.ShouldBe("http://www.w3.org/TR/2001/REC-xml-c14n-20010315");
        signature.SelectSingleNode("ds:SignedInfo/ds:SignatureMethod/@Algorithm", ns)!.Value.ShouldBe("http://www.w3.org/2000/09/xmldsig#rsa-sha1");
        signature.SelectSingleNode("ds:SignedInfo/ds:Reference/ds:DigestMethod/@Algorithm", ns)!.Value.ShouldBe("http://www.w3.org/2000/09/xmldsig#sha1");
        signature.SelectNodes("ds:SignedInfo/ds:Reference/ds:Transforms/ds:Transform/@Algorithm", ns)!.Cast<XmlAttribute>().Select(a => a.Value)
            .ShouldBe(["http://www.w3.org/2000/09/xmldsig#enveloped-signature", "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"]);
        signature.SelectNodes("ds:KeyInfo/ds:X509Data/ds:X509Certificate", ns)!.Count.ShouldBe(1);
        Encoding.UTF8.GetString(signed).ShouldNotContain("\n", customMessage: "no reformatting");
    }

    [Fact]
    public void Sign_NFe_VerifiesWithOurValidatorAndWithSignedXml()
    {
        byte[] signed = FiscalXmlSigner.Sign(Utf8(Nfe()), FiscalDocumentProfile.NFe, _eCnpj);

        var result = FiscalXmlValidator.VerifySignatures(signed);
        result.IsValid.ShouldBeTrue(string.Join("; ", result.Signatures.SelectMany(s => s.Errors)));
        result.Signatures[0].Cnpj.ShouldBe("11222333000181");
        result.Signatures[0].SignedElement.ShouldBe("infNFe");
        CheckWithSignedXml(signed).ShouldBeTrue();
    }

    [Fact]
    public void Validate_ChangedAfterSigning_DigestFails()
    {
        string signed = Encoding.UTF8.GetString(FiscalXmlSigner.Sign(Utf8(Nfe()), FiscalDocumentProfile.NFe, _eCnpj));
        byte[] tampered = Utf8(signed.Replace("VENDA", "DOACAO", StringComparison.Ordinal));

        var result = FiscalXmlValidator.VerifySignatures(tampered);

        result.IsValid.ShouldBeFalse();
        result.Signatures[0].IsDigestValid.ShouldBeFalse();
    }

    [Fact]
    public void SignAll_Batch_SignsEveryNFe()
    {
        string batch = $"<enviNFe xmlns=\"http://www.portalfiscal.inf.br/nfe\" versao=\"4.00\"><idLote>1</idLote><indSinc>1</indSinc>"
            + Nfe().Replace("<NFe xmlns=\"http://www.portalfiscal.inf.br/nfe\">", "<NFe>", StringComparison.Ordinal)
            + Nfe(NfeKey[..^1] + "1").Replace("<NFe xmlns=\"http://www.portalfiscal.inf.br/nfe\">", "<NFe>", StringComparison.Ordinal)
            + "</enviNFe>";

        Should.Throw<ArgumentException>(() => FiscalXmlSigner.Sign(Utf8(batch), FiscalDocumentProfile.NFe, _eCnpj));
        byte[] signed = FiscalXmlSigner.SignAll(Utf8(batch), FiscalDocumentProfile.NFe, _eCnpj);

        var result = FiscalXmlValidator.VerifySignatures(signed);
        result.Signatures.Count.ShouldBe(2);
        result.IsValid.ShouldBeTrue(string.Join("; ", result.Signatures.SelectMany(s => s.Errors)));
        // Already signed: nothing is added.
        FiscalXmlValidator.VerifySignatures(FiscalXmlSigner.SignAll(signed, FiscalDocumentProfile.NFe, _eCnpj)).Signatures.Count.ShouldBe(2);
    }

    [Fact]
    public void Sign_ElementId_SignsOnlyThatElement()
    {
        string batch = $"<enviNFe xmlns=\"http://www.portalfiscal.inf.br/nfe\">{Nfe().Replace(" xmlns=\"http://www.portalfiscal.inf.br/nfe\"", "", StringComparison.Ordinal)}{Nfe(NfeKey[..^1] + "1").Replace(" xmlns=\"http://www.portalfiscal.inf.br/nfe\"", "", StringComparison.Ordinal)}</enviNFe>";

        byte[] signed = FiscalXmlSigner.Sign(Utf8(batch), FiscalDocumentProfile.NFe, _eCnpj, elementId: NfeKey);

        var result = FiscalXmlValidator.VerifySignatures(signed);
        result.Signatures.ShouldHaveSingleItem().ReferenceUri.ShouldBe("#" + NfeKey);
    }

    [Fact]
    public void Sign_ESocial_WholeDocumentLastChildSha256()
    {
        string xml = "<eSocial xmlns=\"http://www.esocial.gov.br/schema/evt/evtInfoEmpregador/v_S_01_03_00\"><evtInfoEmpregador Id=\"ID1112223330000002026110510000000000001\"><ideEvento><tpAmb>2</tpAmb></ideEvento></evtInfoEmpregador></eSocial>";

        byte[] signed = FiscalXmlSigner.Sign(Utf8(xml), FiscalDocumentProfile.ESocial, _eCnpj);

        var doc = Load(signed);
        var ns = Ns(doc);
        doc.DocumentElement!.LastChild!.LocalName.ShouldBe("Signature");
        doc.SelectSingleNode("//ds:Reference/@URI", ns)!.Value.ShouldBeEmpty();
        doc.SelectSingleNode("//ds:SignatureMethod/@Algorithm", ns)!.Value.ShouldBe("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256");
        FiscalXmlValidator.VerifySignatures(signed).IsValid.ShouldBeTrue();
        CheckWithSignedXml(signed).ShouldBeTrue();
    }

    [Fact]
    public void Sign_Reinf_EventByLowercaseId()
    {
        string xml = "<Reinf xmlns=\"http://www.reinf.esocial.gov.br/schemas/evtInfoContribuinte/v2_01_02\"><evtInfoContri id=\"ID1112223330000002026110510000000000001\"><ideEvento><tpAmb>2</tpAmb></ideEvento></evtInfoContri></Reinf>";

        byte[] signed = FiscalXmlSigner.Sign(Utf8(xml), FiscalDocumentProfile.Reinf, _eCnpj);

        var doc = Load(signed);
        var ns = Ns(doc);
        doc.DocumentElement!.LastChild!.LocalName.ShouldBe("Signature");
        doc.SelectSingleNode("//ds:Reference/@URI", ns)!.Value.ShouldBe("#ID1112223330000002026110510000000000001");
        FiscalXmlValidator.VerifySignatures(signed).IsValid.ShouldBeTrue();
        CheckWithSignedXml(signed).ShouldBeTrue();
    }

    [Theory]
    [InlineData("evento", "<envEvento xmlns=\"http://www.portalfiscal.inf.br/nfe\"><evento versao=\"1.00\"><infEvento Id=\"ID1101113526071122233300018155001000000007112345678001\"><tpEvento>110111</tpEvento></infEvento></evento></envEvento>")]
    [InlineData("cte", "<CTe xmlns=\"http://www.portalfiscal.inf.br/cte\"><infCte versao=\"4.00\" Id=\"CTe35260711222333000181570010000000071123456780\"><ide><cUF>35</cUF></ide></infCte></CTe>")]
    [InlineData("mdfe", "<MDFe xmlns=\"http://www.portalfiscal.inf.br/mdfe\"><infMDFe versao=\"3.00\" Id=\"MDFe35260711222333000181580010000000071123456780\"><ide><cUF>35</cUF></ide></infMDFe></MDFe>")]
    [InlineData("nfse", "<DPS xmlns=\"http://www.sped.fazenda.gov.br/nfse\" versao=\"1.00\"><infDPS Id=\"DPS355030721122233300018100001000000000000001\"><tpAmb>2</tpAmb></infDPS></DPS>")]
    public void Sign_OtherLayouts_RoundTrip(string profile, string xml)
    {
        byte[] signed = FiscalXmlSigner.Sign(Utf8(xml), FiscalDocumentProfile.ByName[profile], _eCnpj);

        FiscalXmlValidator.VerifySignatures(signed).IsValid.ShouldBeTrue();
        CheckWithSignedXml(signed).ShouldBeTrue();
    }

    [Fact]
    public void Validate_DuplicateId_IsRejected()
    {
        string signed = Encoding.UTF8.GetString(FiscalXmlSigner.Sign(Utf8(Nfe()), FiscalDocumentProfile.NFe, _eCnpj));
        // Signature wrapping: a second element with the same Id.
        byte[] wrapped = Utf8(signed.Replace("</NFe>", $"<infNFe Id=\"{NfeKey}\"><ide><natOp>FALSA</natOp></ide></infNFe></NFe>", StringComparison.Ordinal));

        var result = FiscalXmlValidator.VerifySignatures(wrapped);

        result.IsValid.ShouldBeFalse();
        result.Signatures[0].Errors.ShouldContain(e => e.Contains("share the Id", StringComparison.Ordinal));
    }

    [Fact]
    public async Task SignAsync_ExternalSigner_ProducesTheSameValidSignature()
    {
        var signer = new KeySigner(_eCnpj);

        byte[] signed = await FiscalXmlSigner.SignAsync(Utf8(Nfe()), FiscalDocumentProfile.NFe, _eCnpj, signer);

        signer.Kind.ShouldBe(ExternalSigningPayloadKind.XmlCanonicalizedSignedInfo);
        FiscalXmlValidator.VerifySignatures(signed).IsValid.ShouldBeTrue();
        CheckWithSignedXml(signed).ShouldBeTrue();
    }

    [Fact]
    public async Task ValidateAsync_NonIcpCertificate_ChainIsInvalid()
    {
        byte[] signed = FiscalXmlSigner.Sign(Utf8(Nfe()), FiscalDocumentProfile.NFe, _eCnpj);
        var offline = new HttpClient(new SimpleSign.TestHelpers.MockHttpHandler(_ =>
            Task.FromResult(new HttpResponseMessage(System.Net.HttpStatusCode.ServiceUnavailable))));

        var result = await new FiscalXmlValidator(offline).ValidateAsync(signed, checkRevocation: false);

        result.Signatures[0].IsDigestValid.ShouldBeTrue();
        result.Signatures[0].IsChainValid.ShouldBe(false);
        result.IsValid.ShouldBeFalse();
    }

    [Fact]
    public void VerifySignatures_Unsigned_ReportsNoSignature() =>
        FiscalXmlValidator.VerifySignatures(Utf8(Nfe())).Errors.ShouldContain(e => e.Contains("no XMLDSig", StringComparison.Ordinal));

    private sealed class KeySigner(X509Certificate2 certificate) : IExternalSigner
    {
        public ExternalSigningPayloadKind? Kind { get; private set; }

        public ValueTask<ReadOnlyMemory<byte>> SignAsync(ExternalSigningRequest request, CancellationToken cancellationToken)
        {
            Kind = request.PayloadKind;
            using var rsa = certificate.GetRSAPrivateKey()!;
            return ValueTask.FromResult<ReadOnlyMemory<byte>>(rsa.SignData(request.DataToSign.Span, request.HashAlgorithm, RSASignaturePadding.Pkcs1));
        }
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
        var doc = new XmlDocument { PreserveWhitespace = true };
        doc.LoadXml(Encoding.UTF8.GetString(xml));
        return doc;
    }

    private static XmlNamespaceManager Ns(XmlDocument doc)
    {
        var ns = new XmlNamespaceManager(doc.NameTable);
        ns.AddNamespace("ds", "http://www.w3.org/2000/09/xmldsig#");
        ns.AddNamespace("nfe", "http://www.portalfiscal.inf.br/nfe");
        return ns;
    }

    /// <summary>A self-signed RSA certificate shaped like an e-CNPJ (SAN 2.16.76.1.3.3).</summary>
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
        var req = new CertificateRequest("CN=EMPRESA EXEMPLO LTDA:11222333000181, O=ICP-Brasil Test", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        req.CertificateExtensions.Add(new X509Extension("2.5.29.17", w.Encode(), critical: false));
        return req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
    }
}
