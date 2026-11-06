using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using SimpleSign.Brazil.Fiscal;
using SimpleSign.TestBench.Documents;
using SimpleSign.TestBench.Sandbox;
using SimpleSign.XAdES;

namespace SimpleSign.TestBench.Xml;

/// <summary>
/// A file for the XML page: an XML to sign (with the mode and profile it suits) or a validation
/// case (signed XML, its data when detached, and the expected verdict).
/// </summary>
public sealed record XmlSample(
    string Id,
    string Kind,
    XmlMode Mode,
    string? Profile,
    string FileId,
    string FileName,
    string? DataId,
    string Title,
    string Description,
    string? ExpectedIndication,
    string? ExpectedCheck);

internal sealed class XmlSampleStore
{
    public IReadOnlyList<XmlSample> Samples { get; set; } = [];
}

/// <summary>Synthetic documents (fictitious keys, CNPJ 11.222.333/0001-81) and signed cases built at startup.</summary>
internal static class XmlSamples
{
    private const string Cnpj = "11222333000181";

    public static async Task<IReadOnlyList<XmlSample>> CreateAsync(SandboxEnvironment sandbox, DocumentStore documents, CancellationToken cancellationToken = default)
    {
        var pki = sandbox.Pki;
        var maria = pki.Signer("rsa-2048").Certificate;
        var company = pki.Signer("company").Certificate;
        string key = "35261111222333000181550010000042171000042170";
        var files = new (string Id, XmlMode Mode, string? Profile, string Name, string Xml, string Title, string Description)[]
        {
            ("order", XmlMode.Xades, null, "pedido.xml", Order(), "Purchase order", "A generic XML document: sign it enveloped, detached or enveloping."),
            ("nfe", XmlMode.Fiscal, "nfe", "nfe.xml",
                $"<NFe xmlns=\"http://www.portalfiscal.inf.br/nfe\"><infNFe Id=\"NFe{key}\" versao=\"4.00\"><ide><cUF>35</cUF><nNF>4217</nNF><dhEmi>2026-11-05T10:00:00-03:00</dhEmi></ide><emit><CNPJ>{Cnpj}</CNPJ><xNome>Empresa Exemplo Ltda</xNome></emit><total><ICMSTot><vNF>1530.75</vNF></ICMSTot></total></infNFe></NFe>",
                "NF-e 4.00", "One electronic invoice: infNFe@Id is signed with RSA-SHA1 (MOC)."),
            ("nfe-batch", XmlMode.Fiscal, "nfe", "enviNFe.xml",
                $"<enviNFe xmlns=\"http://www.portalfiscal.inf.br/nfe\" versao=\"4.00\"><idLote>1</idLote><indSinc>1</indSinc>"
                + $"<NFe><infNFe Id=\"NFe{key}\" versao=\"4.00\"><ide><nNF>4217</nNF></ide><emit><CNPJ>{Cnpj}</CNPJ></emit></infNFe></NFe>"
                + $"<NFe><infNFe Id=\"NFe{key[..^4]}4218\" versao=\"4.00\"><ide><nNF>4218</nNF></ide><emit><CNPJ>{Cnpj}</CNPJ></emit></infNFe></NFe></enviNFe>",
                "NF-e batch (enviNFe)", "Two NF-e in one batch: choose the Id to sign or sign all (FiscalXmlSigner.SignAll)."),
            ("evento", XmlMode.Fiscal, "evento", "evento.xml",
                $"<evento xmlns=\"http://www.portalfiscal.inf.br/nfe\" versao=\"1.00\"><infEvento Id=\"ID110111{key}01\"><cOrgao>35</cOrgao><CNPJ>{Cnpj}</CNPJ><chNFe>{key}</chNFe><tpEvento>110111</tpEvento><detEvento versao=\"1.00\"><descEvento>Cancelamento</descEvento><xJust>Pedido cancelado pelo cliente</xJust></detEvento></infEvento></evento>",
                "NF-e event (cancellation)", "infEvento@Id, RSA-SHA1."),
            ("inutilizacao", XmlMode.Fiscal, "inutilizacao", "inutNFe.xml",
                $"<inutNFe xmlns=\"http://www.portalfiscal.inf.br/nfe\" versao=\"4.00\"><infInut Id=\"ID35261122233300018155001000004300000004310\"><tpAmb>2</tpAmb><xServ>INUTILIZAR</xServ><CNPJ>{Cnpj}</CNPJ><nNFIni>4300</nNFIni><nNFFin>4310</nNFFin><xJust>Falha de sistema na numeracao</xJust></infInut></inutNFe>",
                "Number voiding (inutilização)", "infInut@Id, RSA-SHA1."),
            ("cte", XmlMode.Fiscal, "cte", "cte.xml",
                $"<CTe xmlns=\"http://www.portalfiscal.inf.br/cte\"><infCte Id=\"CTe35261111222333000181570010000000011000000011\" versao=\"4.00\"><ide><nCT>1</nCT></ide><emit><CNPJ>{Cnpj}</CNPJ></emit></infCte></CTe>",
                "CT-e 4.00", "Transport document: infCte@Id, RSA-SHA1."),
            ("mdfe", XmlMode.Fiscal, "mdfe", "mdfe.xml",
                $"<MDFe xmlns=\"http://www.portalfiscal.inf.br/mdfe\"><infMDFe Id=\"MDFe35261111222333000181580010000000011000000011\" versao=\"3.00\"><ide><nMDF>1</nMDF></ide><emit><CNPJ>{Cnpj}</CNPJ></emit></infMDFe></MDFe>",
                "MDF-e 3.00", "Cargo manifest: infMDFe@Id, RSA-SHA1."),
            ("nfse", XmlMode.Fiscal, "nfse", "dps.xml",
                $"<DPS xmlns=\"http://www.sped.fazenda.gov.br/nfse\" versao=\"1.00\"><infDPS Id=\"DPS355030811122233300018100001000000000000001\"><tpAmb>2</tpAmb><prest><CNPJ>{Cnpj}</CNPJ></prest><serv><cServ><xDescServ>Consultoria</xDescServ></cServ></serv></infDPS></DPS>",
                "NFS-e DPS (Padrão Nacional)", "infDPS@Id, RSA-SHA256."),
            ("esocial", XmlMode.Fiscal, "esocial", "esocial.xml",
                $"<eSocial xmlns=\"http://www.esocial.gov.br/schema/evt/evtInfoEmpregador/v_S_01_02_00\"><evtInfoEmpregador Id=\"ID1112223330001812026110510000000001\"><ideEvento><tpAmb>2</tpAmb></ideEvento><ideEmpregador><tpInsc>1</tpInsc><nrInsc>11222333</nrInsc></ideEmpregador></evtInfoEmpregador></eSocial>",
                "eSocial S-1000", "The whole document (URI=\"\"), RSA-SHA256, Signature as the last child of eSocial."),
            ("reinf", XmlMode.Fiscal, "reinf", "reinf.xml",
                $"<Reinf xmlns=\"http://www.reinf.esocial.gov.br/schemas/evtInfoContribuinte/v2_01_02\"><evtInfoContri id=\"ID1112223330001812026110510000000001\"><ideEvento><tpAmb>2</tpAmb></ideEvento><ideContri><tpInsc>1</tpInsc><nrInsc>11222333</nrInsc></ideContri></evtInfoContri></Reinf>",
                "EFD-Reinf R-1000", "The event by its lowercase id attribute, RSA-SHA256."),
        };

        var samples = new List<XmlSample>();
        var ids = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var f in files)
        {
            var stored = documents.AddPinned(f.Name, Encoding.UTF8.GetBytes(f.Xml));
            ids[f.Id] = stored.Id;
            samples.Add(new XmlSample(f.Id, "data", f.Mode, f.Profile, stored.Id, f.Name, null, f.Title, f.Description, null, null));
        }

        // Validation cases.
        byte[] order = Encoding.UTF8.GetBytes(Order());
        byte[] enveloped = await XadesSigner.Document(order).WithCertificate(maria, pki.Chain).WithHttpClientProvider(sandbox.Network).SignAsync(cancellationToken);
        byte[] detached = await XadesSigner.Document(order).WithCertificate(maria, pki.Chain).WithHttpClientProvider(sandbox.Network)
            .WithForm(XadesForm.Detached).WithDataUri("pedido.xml").SignAsync(cancellationToken);
        byte[] nfe = FiscalXmlSigner.Sign(documents.Get(ids["nfe"]).Content, FiscalDocumentProfile.NFe, company);
        byte[] nfeChanged = Replace(nfe, "<vNF>1530.75</vNF>", "<vNF>9530.75</vNF>");
        byte[] tampered = TamperSignatureValue(enveloped);
        using var outsiderKey = RSA.Create(2048);
        var request = new CertificateRequest("CN=Assinante Fora da Cadeia, O=Outside, C=BR", outsiderKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.NonRepudiation, true));
        using var outsider = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        byte[] untrusted = await XadesSigner.Document(order).WithCertificate(outsider).SignAsync(cancellationToken);

        XmlSample Case(string id, XmlMode mode, string name, byte[] content, string? dataId, string title, string description, string indication, string check) =>
            new(id, "validation", mode, null, documents.AddPinned(name, content).Id, name, dataId, title, description, indication, check);

        samples.AddRange(
        [
            Case("v-xades", XmlMode.Xades, "pedido-assinado.xml", enveloped, null, "Valid XAdES (control)", "Enveloped XAdES B-B: every check passes.", "Valid", "—"),
            Case("v-detached", XmlMode.Xades, "pedido-signature.xml", detached, ids["order"], "Valid detached XAdES", "The signature and the data it references (pedido.xml) as two files.", "Valid", "—"),
            Case("v-nfe", XmlMode.Fiscal, "nfe-assinada.xml", nfe, null, "Signed NF-e", "Signed with the sandbox e-CNPJ: digest and signature pass, the CNPJ is read from the certificate.", "Valid", "—"),
            Case("v-nfe-changed", XmlMode.Fiscal, "nfe-alterada.xml", nfeChanged, null, "NF-e changed after signing", "The invoice total was changed after signing: the reference digest no longer matches.", "Invalid", "digest"),
            Case("v-tampered", XmlMode.Xades, "valor-alterado.xml", tampered, null, "Signature value changed", "One character of the SignatureValue was changed: the RSA verification fails.", "Invalid", "signature"),
            Case("v-untrusted", XmlMode.Xades, "raiz-desconhecida.xml", untrusted, null, "Root outside the trust anchors", "Signed with a self-signed certificate that no trusted root vouches for.", "Indeterminate", "chain"),
        ]);
        return samples;
    }

    private static string Order() =>
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<pedido xmlns=\"urn:simplesign:testbench:pedido\" numero=\"4217\">\n"
        + "  <cliente cnpj=\"11222333000181\">Empresa Exemplo Ltda</cliente>\n"
        + "  <item quantidade=\"3\" valor=\"510.25\">Licença SimpleSign</item>\n"
        + "  <total moeda=\"BRL\">1530.75</total>\n</pedido>\n";

    private static byte[] Replace(byte[] xml, string from, string to)
    {
        string text = Encoding.UTF8.GetString(xml);
        if (!text.Contains(from, StringComparison.Ordinal))
        {
            throw new InvalidOperationException($"'{from}' not found in the sample.");
        }

        return Encoding.UTF8.GetBytes(text.Replace(from, to, StringComparison.Ordinal));
    }

    /// <summary>Changes one base64 character in the middle of the first SignatureValue.</summary>
    private static byte[] TamperSignatureValue(byte[] xml)
    {
        string text = Encoding.UTF8.GetString(xml);
        int start = text.IndexOf("SignatureValue", StringComparison.Ordinal);
        start = text.IndexOf('>', start) + 1;
        int end = text.IndexOf('<', start);
        int index = start + ((end - start) / 2);
        char replacement = text[index] == 'A' ? 'B' : 'A';
        return Encoding.UTF8.GetBytes(string.Concat(text.AsSpan(0, index), replacement.ToString(), text.AsSpan(index + 1)));
    }
}
