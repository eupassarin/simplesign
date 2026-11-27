using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Xml;
using Shouldly;
using SimpleSign.Core.Policies;
using SimpleSign.Core.Signing;
using SimpleSign.TestHelpers;
using Xunit;

namespace SimpleSign.XAdES.Tests;

/// <summary>Plain enveloped XML-DSig signatures (the fiscal layouts), cross-checked with .NET's SignedXml.</summary>
[Trait("Category", "Unit")]
public sealed class XmlDsigSignerTests : IDisposable
{
    private const string NfeKey = "NFe35260711222333000181550010000000071123456780";
    private const string Ds = "http://www.w3.org/2000/09/xmldsig#";

    /// <summary>The default policy with SHA-1 accepted for the signature digest, as the fiscal profiles do.</summary>
    internal static readonly SigningPolicy Sha1Allowed = SigningPolicy.Default.With(
        "Cryptographic/AcceptableDigestAlgo",
        new PolicyConstraint(null) { Algorithms = [new("SHA1"), new("SHA256"), new("SHA384"), new("SHA512")] });

    private readonly X509Certificate2 _rsa = TestCertificateFactory.CreateSelfSignedCert("CN=EMPRESA EXEMPLO LTDA:11222333000181, O=Tests");
    private readonly X509Certificate2 _ecdsa = TestCertificateFactory.CreateEcdsaCert(subject: "CN=XML-DSig ECDSA, O=Tests");

    public void Dispose()
    {
        _rsa.Dispose();
        _ecdsa.Dispose();
    }

    internal static string Nfe(string key = NfeKey, string name = "EMPRESA &amp; CIA LTDA") =>
        $"<NFe xmlns=\"http://www.portalfiscal.inf.br/nfe\"><infNFe versao=\"4.00\" Id=\"{key}\"><ide><cUF>35</cUF><natOp>VENDA</natOp></ide><emit><CNPJ>11222333000181</CNPJ><xNome>{name}</xNome></emit></infNFe></NFe>";

    private static byte[] Utf8(string s) => Encoding.UTF8.GetBytes(s);

    private XmlDsigSignerBuilder NfeSigner(string xml) =>
        XmlDsigSigner.Document(Utf8(xml)).WithSignedElement("infNFe").WithHashAlgorithm(HashAlgorithmName.SHA1)
            .WithSigningPolicy(Sha1Allowed).WithCertificate(_rsa);

    [Fact]
    public async Task SignAsync_NFe_FollowsTheLayout()
    {
        byte[] signed = await NfeSigner(Nfe()).SignAsync();

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
        signature.SelectSingleNode("ds:Object", ns).ShouldBeNull("no XAdES qualifying properties");
        Encoding.UTF8.GetString(signed).ShouldNotContain("\n", customMessage: "no reformatting");
    }

    [Fact]
    public async Task SignAsync_NFe_VerifiesWithTheValidatorAndWithSignedXml()
    {
        byte[] signed = await NfeSigner(Nfe()).SignAsync();

        var result = XmlDsigValidator.VerifySignatures(signed);
        result.IsValid.ShouldBeTrue(string.Join("; ", result.Signatures.SelectMany(s => s.Errors)));
        result.Signatures[0].SignedElement.ShouldBe("infNFe");
        result.Signatures[0].HashAlgorithm.ShouldBe("SHA1");
        CheckWithSignedXml(signed).ShouldBeTrue();
    }

    [Fact]
    public async Task SignAsync_Sha1UnderTheDefaultPolicy_IsRefused()
    {
        var builder = XmlDsigSigner.Document(Utf8(Nfe())).WithSignedElement("infNFe").WithHashAlgorithm(HashAlgorithmName.SHA1).WithCertificate(_rsa);

        var ex = await Should.ThrowAsync<SigningException>(() => builder.SignAsync());

        ex.Reason.ShouldBe(SigningErrorReason.AlgorithmNotPermitted);
    }

    [Fact]
    public async Task Validate_ChangedAfterSigning_DigestFails()
    {
        string signed = Encoding.UTF8.GetString(await NfeSigner(Nfe()).SignAsync());

        var result = XmlDsigValidator.VerifySignatures(Utf8(signed.Replace("VENDA", "DOACAO", StringComparison.Ordinal)));

        result.IsValid.ShouldBeFalse();
        result.Signatures[0].IsDigestValid.ShouldBeFalse();
    }

    [Fact]
    public async Task SignAllAsync_Batch_SignsEveryNFeOnce()
    {
        string batch = "<enviNFe xmlns=\"http://www.portalfiscal.inf.br/nfe\" versao=\"4.00\"><idLote>1</idLote>"
            + Nested(Nfe()) + Nested(Nfe(NfeKey[..^1] + "1")) + "</enviNFe>";

        await Should.ThrowAsync<ArgumentException>(() => NfeSigner(batch).SignAsync());
        byte[] signed = await NfeSigner(batch).SignAllAsync();

        var result = XmlDsigValidator.VerifySignatures(signed);
        result.Signatures.Count.ShouldBe(2);
        result.IsValid.ShouldBeTrue(string.Join("; ", result.Signatures.SelectMany(s => s.Errors)));
        CheckWithSignedXml(signed).ShouldBeTrue();
        byte[] again = await XmlDsigSigner.Document(signed).WithSignedElement("infNFe").WithHashAlgorithm(HashAlgorithmName.SHA1)
            .WithSigningPolicy(Sha1Allowed).WithCertificate(_rsa).SignAllAsync();
        again.ShouldBe(signed, "already signed: nothing is added");
    }

    [Fact]
    public async Task SignAsync_ElementId_SignsOnlyThatElement()
    {
        string batch = $"<enviNFe xmlns=\"http://www.portalfiscal.inf.br/nfe\">{Nested(Nfe())}{Nested(Nfe(NfeKey[..^1] + "1"))}</enviNFe>";

        byte[] signed = await NfeSigner(batch).WithElementId(NfeKey).SignAsync();

        XmlDsigValidator.VerifySignatures(signed).Signatures.ShouldHaveSingleItem().ReferenceUri.ShouldBe("#" + NfeKey);
    }

    [Fact]
    public async Task SignAsync_WholeDocument_LastChildOfRootSha256()
    {
        string xml = "<eSocial xmlns=\"http://www.esocial.gov.br/schema/evt/evtInfoEmpregador/v_S_01_03_00\"><evtInfoEmpregador Id=\"ID1112223330000002026110510000000000001\"><ideEvento><tpAmb>2</tpAmb></ideEvento></evtInfoEmpregador></eSocial>";

        byte[] signed = await XmlDsigSigner.Document(Utf8(xml)).WithCertificate(_rsa).SignAsync();

        var doc = Load(signed);
        var ns = Ns(doc);
        doc.DocumentElement!.LastChild!.LocalName.ShouldBe("Signature");
        doc.SelectSingleNode("//ds:Reference/@URI", ns)!.Value.ShouldBeEmpty();
        doc.SelectSingleNode("//ds:SignatureMethod/@Algorithm", ns)!.Value.ShouldBe("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256");
        XmlDsigValidator.VerifySignatures(signed).IsValid.ShouldBeTrue();
        CheckWithSignedXml(signed).ShouldBeTrue();
    }

    [Fact]
    public async Task SignAsync_AnyElementByLowercaseIdAtTheEndOfTheRoot_RoundTrips()
    {
        string xml = "<Reinf xmlns=\"http://www.reinf.esocial.gov.br/schemas/evtInfoContribuinte/v2_01_02\"><evtInfoContri id=\"ID1112223330000002026110510000000000001\"><ideEvento><tpAmb>2</tpAmb></ideEvento></evtInfoContri></Reinf>";

        byte[] signed = await XmlDsigSigner.Document(Utf8(xml)).WithSignedElement("*", "id").WithPlacement(XmlDsigPlacement.LastChildOfRoot)
            .WithCertificate(_rsa).SignAsync();

        var doc = Load(signed);
        doc.DocumentElement!.LastChild!.LocalName.ShouldBe("Signature");
        doc.SelectSingleNode("//ds:Reference/@URI", Ns(doc))!.Value.ShouldBe("#ID1112223330000002026110510000000000001");
        XmlDsigValidator.VerifySignatures(signed).IsValid.ShouldBeTrue();
        CheckWithSignedXml(signed).ShouldBeTrue();
    }

    [Fact]
    public async Task SignAsync_Ecdsa_RoundTrips()
    {
        byte[] signed = await XmlDsigSigner.Document(Utf8(Nfe())).WithSignedElement("infNFe").WithCertificate(_ecdsa).SignAsync();

        // SignedXml has no ECDSA SignatureDescription out of the box: the r || s value is checked by the validator only.
        XmlDsigValidator.VerifySignatures(signed).IsValid.ShouldBeTrue();
    }

    [Fact]
    public async Task Validate_DuplicateId_IsRefused()
    {
        string signed = Encoding.UTF8.GetString(await NfeSigner(Nfe()).SignAsync());
        // Signature wrapping: a second element with the same Id.
        byte[] wrapped = Utf8(signed.Replace("</NFe>", $"<infNFe Id=\"{NfeKey}\"><ide><natOp>FALSA</natOp></ide></infNFe></NFe>", StringComparison.Ordinal));

        var result = XmlDsigValidator.VerifySignatures(wrapped);

        result.IsValid.ShouldBeFalse();
        result.Signatures[0].Errors.ShouldContain(e => e.Contains("share the Id", StringComparison.Ordinal));
    }

    [Fact]
    public async Task SignAsync_DuplicateId_IsRefused()
    {
        string xml = Nfe().Replace("</NFe>", $"<infNFe Id=\"{NfeKey}\"/></NFe>", StringComparison.Ordinal);

        await Should.ThrowAsync<ArgumentException>(() => NfeSigner(xml).WithElementId(NfeKey).SignAsync());
    }

    [Fact]
    public async Task SignAsync_ExternalSigner_ReceivesTheSignedInfoAndProducesAValidSignature()
    {
        var signer = new KeySigner(_rsa);

        byte[] signed = await XmlDsigSigner.Document(Utf8(Nfe())).WithSignedElement("infNFe").WithHashAlgorithm(HashAlgorithmName.SHA1)
            .WithSigningPolicy(Sha1Allowed).WithExternalSigner(RemoteKey(_rsa), signer).SignAsync();

        signer.Kind.ShouldBe(ExternalSigningPayloadKind.XmlCanonicalizedSignedInfo);
        signer.Hash.ShouldBe(HashAlgorithmName.SHA1);
        XmlDsigValidator.VerifySignatures(signed).IsValid.ShouldBeTrue();
        CheckWithSignedXml(signed).ShouldBeTrue();
    }

    [Fact]
    public async Task SignAsync_AuditSink_RecordsTheSignature()
    {
        var sink = new ListSink();

        await NfeSigner(Nfe()).WithAuditSink(sink).WithOperationId("nfe-1").SignAsync();

        var record = sink.Events.ShouldHaveSingleItem();
        record.Format.ShouldBe("XMLDSig");
        record.Signed.ShouldBeTrue();
        record.OperationId.ShouldBe("nfe-1");
    }

    [Fact]
    public void VerifySignatures_Unsigned_ReportsNoSignature() =>
        XmlDsigValidator.VerifySignatures(Utf8(Nfe())).Errors.ShouldContain(e => e.Contains("no XML-DSig signature", StringComparison.Ordinal));

    [Fact]
    public async Task Load_Dtd_IsRefused()
    {
        byte[] xml = Utf8("<!DOCTYPE NFe [<!ENTITY x \"y\">]>" + Nfe());

        await Should.ThrowAsync<ArgumentException>(() => NfeSigner(Encoding.UTF8.GetString(xml)).SignAsync());
    }

    private static string Nested(string nfe) =>
        nfe.Replace(" xmlns=\"http://www.portalfiscal.inf.br/nfe\"", string.Empty, StringComparison.Ordinal);

    internal static X509Certificate2 RemoteKey(X509Certificate2 certificate) =>
        X509CertificateLoader.LoadCertificate(certificate.RawData);

    internal sealed class KeySigner(X509Certificate2 certificate) : IExternalSigner
    {
        public ExternalSigningPayloadKind? Kind { get; private set; }

        public HashAlgorithmName? Hash { get; private set; }

        public ValueTask<ReadOnlyMemory<byte>> SignAsync(ExternalSigningRequest request, CancellationToken cancellationToken)
        {
            Kind = request.PayloadKind;
            Hash = request.HashAlgorithm;
            using var rsa = certificate.GetRSAPrivateKey()!;
            return ValueTask.FromResult<ReadOnlyMemory<byte>>(rsa.SignData(request.DataToSign.Span, request.HashAlgorithm, RSASignaturePadding.Pkcs1));
        }
    }

    private sealed class ListSink : ISignatureAuditSink
    {
        public List<SignatureAuditEvent> Events { get; } = [];

        public ValueTask RecordAsync(SignatureAuditEvent auditEvent, CancellationToken cancellationToken)
        {
            Events.Add(auditEvent);
            return ValueTask.CompletedTask;
        }
    }

    /// <summary>Independent check with System.Security.Cryptography.Xml.SignedXml (every signature).</summary>
    internal static bool CheckWithSignedXml(byte[] signed)
    {
        var doc = Load(signed);
        var signatures = doc.GetElementsByTagName("Signature", Ds).Cast<XmlElement>().ToList();
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

    private static XmlNamespaceManager Ns(XmlDocument doc)
    {
        var ns = new XmlNamespaceManager(doc.NameTable);
        ns.AddNamespace("ds", Ds);
        ns.AddNamespace("nfe", "http://www.portalfiscal.inf.br/nfe");
        return ns;
    }
}
