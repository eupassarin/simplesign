using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using SimpleSign.TestBench.Documents;
using SimpleSign.TestBench.Sandbox;
using SimpleSign.XAdES;

namespace SimpleSign.TestBench.Xml;

/// <summary>
/// A file for the XML page: an XML to sign or a validation case (signed XML, its data when
/// detached, and the expected verdict).
/// </summary>
public sealed record XmlSample(
    string Id,
    string Kind,
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

/// <summary>A synthetic document and the signed cases built from it at startup.</summary>
internal static class XmlSamples
{
    /// <summary>A synthetic document of each fiscal family: an NF-e, an event, a CT-e and an eSocial event.</summary>
    internal static IEnumerable<(string Id, string File, string Title, string Description, string Xml)> FiscalSamples() =>
    [
        ("nfe", "nfe.xml", "NF-e", "A synthetic NF-e 4.00 (infNFe by its Id): sign it with the Fiscal XML type and the NF-e layout.",
            "<NFe xmlns=\"http://www.portalfiscal.inf.br/nfe\"><infNFe versao=\"4.00\" Id=\"NFe35261111222333000181550010000000071123456780\">"
            + "<ide><cUF>35</cUF><natOp>VENDA</natOp><mod>55</mod><serie>1</serie><nNF>7</nNF><tpAmb>2</tpAmb></ide>"
            + "<emit><CNPJ>11222333000181</CNPJ><xNome>EMPRESA EXEMPLO LTDA</xNome></emit>"
            + "<total><ICMSTot><vNF>1530.75</vNF></ICMSTot></total></infNFe></NFe>"),
        ("nfe-evento", "evento.xml", "NF-e event", "A synthetic cancellation event (infEvento by its Id): the Event layout.",
            "<envEvento xmlns=\"http://www.portalfiscal.inf.br/nfe\" versao=\"1.00\"><idLote>1</idLote><evento versao=\"1.00\">"
            + "<infEvento Id=\"ID1101113526111122233300018155001000000007112345678001\"><cOrgao>35</cOrgao><tpAmb>2</tpAmb>"
            + "<CNPJ>11222333000181</CNPJ><tpEvento>110111</tpEvento><nSeqEvento>1</nSeqEvento></infEvento></evento></envEvento>"),
        ("cte", "cte.xml", "CT-e", "A synthetic CT-e 4.00 (infCte by its Id): the CT-e layout.",
            "<CTe xmlns=\"http://www.portalfiscal.inf.br/cte\"><infCte versao=\"4.00\" Id=\"CTe35261111222333000181570010000000071123456780\">"
            + "<ide><cUF>35</cUF><tpAmb>2</tpAmb></ide><emit><CNPJ>11222333000181</CNPJ></emit></infCte></CTe>"),
        ("esocial", "esocial.xml", "eSocial event", "A synthetic eSocial S-1000 (the whole document is signed): the eSocial layout.",
            "<eSocial xmlns=\"http://www.esocial.gov.br/schema/evt/evtInfoEmpregador/v_S_01_03_00\">"
            + "<evtInfoEmpregador Id=\"ID1112223330000002026111110000000000001\"><ideEvento><tpAmb>2</tpAmb><procEmi>1</procEmi></ideEvento>"
            + "<ideEmpregador><tpInsc>1</tpInsc><nrInsc>11222333</nrInsc></ideEmpregador></evtInfoEmpregador></eSocial>"),
    ];

    public static async Task<IReadOnlyList<XmlSample>> CreateAsync(SandboxEnvironment sandbox, DocumentStore documents, CancellationToken cancellationToken = default)
    {
        var orderFile = documents.AddPinned("pedido.xml", Encoding.UTF8.GetBytes(Order()));
        var samples = new List<XmlSample>
        {
            new("order", "data", orderFile.Id, "pedido.xml", null, "Purchase order", "A generic XML document: sign it enveloped, detached or enveloping.", null, null),
        };

        // Fiscal layouts (signature type Fiscal XML): synthetic documents of each family, not valid against the SEFAZ schemas.
        foreach (var (id, file, title, description, xml) in FiscalSamples())
        {
            samples.Add(new(id, "data", documents.AddPinned(file, Encoding.UTF8.GetBytes(xml)).Id, file, null, title, description, null, null));
        }

        // The validation cases need a signer: they come from the connected Sandbox.
        if (sandbox.Current is not { } connection)
        {
            return samples;
        }

        var chain = connection.Chain;
        var maria = connection.Signer("rsa-2048").Certificate;
        byte[] order = Encoding.UTF8.GetBytes(Order());
        byte[] enveloped = await XadesSigner.Document(order).WithCertificate(maria, chain).WithHttpClientProvider(sandbox).SignAsync(cancellationToken);
        byte[] detached = await XadesSigner.Document(order).WithCertificate(maria, chain).WithHttpClientProvider(sandbox)
            .WithForm(XadesForm.Detached).WithDataUri("pedido.xml").SignAsync(cancellationToken);
        byte[] changed = Replace(enveloped, "<total moeda=\"BRL\">1530.75</total>", "<total moeda=\"BRL\">9530.75</total>");
        byte[] tampered = TamperSignatureValue(enveloped);
        using var outsiderKey = RSA.Create(2048);
        var request = new CertificateRequest("CN=Assinante Fora da Cadeia, O=Outside, C=BR", outsiderKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.NonRepudiation, true));
        using var outsider = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        byte[] untrusted = await XadesSigner.Document(order).WithCertificate(outsider).SignAsync(cancellationToken);

        XmlSample Case(string id, string name, byte[] content, string? dataId, string title, string description, string indication, string check) =>
            new(id, "validation", documents.AddPinned(name, content).Id, name, dataId, title, description, indication, check);

        samples.AddRange(
        [
            Case("v-xades", "pedido-assinado.xml", enveloped, null, "Valid XAdES (control)", "Enveloped XAdES B-B: every check passes.", "Valid", "—"),
            Case("v-detached", "pedido-signature.xml", detached, orderFile.Id, "Valid detached XAdES", "The signature and the data it references (pedido.xml) as two files.", "Valid", "—"),
            Case("v-changed", "pedido-alterado.xml", changed, null, "Document changed after signing", "The order total was changed after signing: the reference digest no longer matches.", "Invalid", "signature"),
            Case("v-tampered", "valor-alterado.xml", tampered, null, "Signature value changed", "One character of the SignatureValue was changed: the RSA verification fails.", "Invalid", "signature"),
            Case("v-untrusted", "raiz-desconhecida.xml", untrusted, null, "Root outside the trust anchors", "Signed with a self-signed certificate that no trusted root vouches for.", "Indeterminate", "chain"),
        ]);
        return samples;
    }

    private static string Order() =>
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<pedido xmlns=\"urn:simplesign:testbench:pedido\" numero=\"4217\">\n"
        + "  <cliente id=\"C-1001\">Empresa Exemplo Ltda</cliente>\n"
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
