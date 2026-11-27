using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using SimpleSign.Core.Policies;
using SimpleSign.XAdES;

namespace SimpleSign.Brazil.Fiscal.Tests;

/// <summary>
/// What the fiscal tests share: a test e-CNPJ outside ICP-Brasil, the layout's policy without the checks only an
/// ICP-Brasil chain passes, and the eSocial / EFD-Reinf events and batches (<c>envioLoteEventos</c>).
/// </summary>
internal static class FiscalTestSigning
{
    internal const string ESocialEventId = "ID1112223330000002026110510000000000001";
    internal const string ESocialEventId2 = "ID1112223330000002026110510000000000002";

    internal static byte[] Utf8(string s) => Encoding.UTF8.GetBytes(s);

    /// <summary>The layout's policy without the checks only a real ICP-Brasil certificate passes (chain to its roots, revocation).</summary>
    internal static SigningPolicy Offline(FiscalDocumentProfile layout) => layout.SigningPolicy
        .With("SigningCertificate/ProspectiveCertificateChain", new PolicyConstraint(ConstraintLevel.Ignore))
        .With("SigningCertificate/NotRevoked", new PolicyConstraint(ConstraintLevel.Ignore))
        .With("SigningCertificate/RevocationDataAvailable", new PolicyConstraint(ConstraintLevel.Ignore))
        .With("CACertificate/NotRevoked", new PolicyConstraint(ConstraintLevel.Ignore))
        .With("CACertificate/RevocationDataAvailable", new PolicyConstraint(ConstraintLevel.Ignore));

    internal static XmlDsigSignerBuilder Signer(string xml, FiscalDocumentProfile layout) =>
        FiscalXmlSigner.Document(Utf8(xml), layout).WithSigningPolicy(Offline(layout));

    /// <summary>The XML of <paramref name="xml"/> signed alone, as <paramref name="layout"/> requires.</summary>
    internal static async Task<string> SignedAsync(string xml, FiscalDocumentProfile layout, X509Certificate2 certificate) =>
        Encoding.UTF8.GetString(await Signer(xml, layout).WithCertificate(certificate).SignAsync());

    internal static string ESocialEvent(string id, string tpAmb = "2") =>
        $"<eSocial xmlns=\"http://www.esocial.gov.br/schema/evt/evtInfoEmpregador/v_S_01_03_00\"><evtInfoEmpregador Id=\"{id}\"><ideEvento><tpAmb>{tpAmb}</tpAmb></ideEvento></evtInfoEmpregador></eSocial>";

    internal static string ReinfEvent(string id) =>
        $"<Reinf xmlns=\"http://www.reinf.esocial.gov.br/schemas/evtInfoContribuinte/v2_01_02\"><evtInfoContri id=\"{id}\"><ideEvento><tpAmb>2</tpAmb></ideEvento></evtInfoContri></Reinf>";

    /// <summary>An eSocial batch: each event (already signed, or not) inside its <c>evento</c>.</summary>
    internal static string ESocialBatch(params (string Id, string Xml)[] events) =>
        "<eSocial xmlns=\"http://www.esocial.gov.br/schema/lote/eventos/envio/v1_1_1\"><envioLoteEventos grupo=\"1\">"
        + "<ideEmpregador><tpInsc>1</tpInsc><nrInsc>11222333</nrInsc></ideEmpregador>"
        + "<ideTransmissor><tpInsc>1</tpInsc><nrInsc>11222333000181</nrInsc></ideTransmissor>"
        + $"<eventos>{Events(events)}</eventos></envioLoteEventos></eSocial>";

    /// <summary>An EFD-Reinf batch: each event inside its <c>evento</c>, whose Id is the event's.</summary>
    internal static string ReinfBatch(params (string Id, string Xml)[] events) =>
        "<Reinf xmlns=\"http://www.reinf.esocial.gov.br/schemas/envioLoteEventosAssincrono/v1_00_00\"><envioLoteEventos>"
        + "<ideContribuinte><tpInsc>1</tpInsc><nrInsc>11222333</nrInsc></ideContribuinte>"
        + $"<eventos>{Events(events)}</eventos></envioLoteEventos></Reinf>";

    private static string Events((string Id, string Xml)[] events) =>
        string.Concat(events.Select(e => $"<evento Id=\"{e.Id}\">{e.Xml}</evento>"));

    /// <summary>A self-signed RSA certificate shaped like an e-CNPJ (SAN otherName 2.16.76.1.3.3, digitalSignature).</summary>
    internal static X509Certificate2 CreateECnpj(string cnpj)
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
