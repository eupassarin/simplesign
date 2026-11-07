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
    public static async Task<IReadOnlyList<XmlSample>> CreateAsync(SandboxEnvironment sandbox, DocumentStore documents, CancellationToken cancellationToken = default)
    {
        var pki = sandbox.Pki;
        var maria = pki.Signer("rsa-2048").Certificate;
        var orderFile = documents.AddPinned("pedido.xml", Encoding.UTF8.GetBytes(Order()));
        var samples = new List<XmlSample>
        {
            new("order", "data", orderFile.Id, "pedido.xml", null, "Purchase order", "A generic XML document: sign it enveloped, detached or enveloping.", null, null),
        };

        // Validation cases.
        byte[] order = Encoding.UTF8.GetBytes(Order());
        byte[] enveloped = await XadesSigner.Document(order).WithCertificate(maria, pki.Chain).WithHttpClientProvider(sandbox.Network).SignAsync(cancellationToken);
        byte[] detached = await XadesSigner.Document(order).WithCertificate(maria, pki.Chain).WithHttpClientProvider(sandbox.Network)
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
