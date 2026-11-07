using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using SimpleSign.CAdES;
using SimpleSign.Core.Crypto;
using SimpleSign.Core.Signing;
using SimpleSign.TestBench.Documents;
using SimpleSign.TestBench.Sandbox;

namespace SimpleSign.TestBench.Cades;

/// <summary>
/// A file for the CAdES page: data to sign, a signature to co-sign or countersign, or a
/// validation case (signature plus the data it should be checked against) with its expected verdict.
/// </summary>
public sealed record CadesSample(
    string Id,
    string Kind,
    string FileId,
    string FileName,
    string? DataId,
    string Title,
    string Description,
    string? ExpectedIndication,
    string? ExpectedCheck);

/// <summary>The CAdES samples, created at startup.</summary>
internal sealed class CadesSampleStore
{
    public IReadOnlyList<CadesSample> Samples { get; set; } = [];
}

/// <summary>Builds the CAdES samples with the sandbox PKI.</summary>
internal static class CadesSamples
{
    public static async Task<IReadOnlyList<CadesSample>> CreateAsync(SandboxEnvironment sandbox, DocumentStore documents, CancellationToken cancellationToken = default)
    {
        byte[] text = Encoding.UTF8.GetBytes(
            "Contrato de prestação de serviços — SimpleSign TestBench\n\n"
            + "As partes acordam que este documento foi assinado digitalmente em CAdES (RFC 5652 / ETSI EN 319 122).\n"
            + "Qualquer alteração de um único byte invalida a assinatura.\n");
        byte[] json = Encoding.UTF8.GetBytes("{\n  \"pedido\": 4217,\n  \"cliente\": \"Empresa Exemplo Ltda\",\n  \"valor\": 1530.75,\n  \"moeda\": \"BRL\"\n}\n");
        byte[] pdf = documents.Get(DocumentStore.SampleKey("contract")).Content;
        string textId = documents.AddPinned("contrato.txt", text).Id;
        CadesSample Data(string id, string name, byte[] content, string title, string description) =>
            new(id, "data", id == "text" ? textId : documents.AddPinned(name, content).Id, name, null, title, description, null, null);
        CadesSample[] data =
        [
            Data("text", "contrato.txt", text, "Text contract", "A short UTF-8 text: any file can be signed in CAdES."),
            Data("json", "pedido.json", json, "JSON order", "Structured data, as signed by APIs."),
            Data("pdf", "contrato.pdf", pdf, "PDF as a file", "A PDF signed as opaque bytes (CAdES), not inside the PDF (that is PAdES)."),
        ];

        // The signed samples need a signer: they come from the connected Sandbox.
        if (sandbox.Current is not { } connection)
        {
            return data;
        }

        var chain = connection.Chain;
        var maria = connection.Signer("rsa-2048").Certificate;
        var joao = connection.Signer("rsa-3072").Certificate;
        var ana = connection.Signer("rsa-4096").Certificate;

        Task<byte[]> Sign(byte[] data, X509Certificate2 signer, IReadOnlyList<X509Certificate2> chain, CadesContentType type) =>
            CadesSigner.Document(data).WithCertificate(signer, chain).WithHttpClientProvider(sandbox)
                .WithContentType(type).WithCommitmentType(CommitmentType.ProofOfApproval).SignAsync(cancellationToken);

        byte[] detached = await Sign(text, maria, chain, CadesContentType.Detached);
        byte[] enveloped = await Sign(text, maria, chain, CadesContentType.Enveloped);
        byte[] cosigned = await CadesSigner.CoSign(enveloped).WithCertificate(joao, chain).WithHttpClientProvider(sandbox).SignAsync(cancellationToken);
        byte[] countersigned = await CadesSigner.CounterSign(cosigned, 0).WithCertificate(ana, chain).WithHttpClientProvider(sandbox)
            .WithLevel(AdesBaselineProfile.Timestamped(new TimestampOptions(connection.TsaUri, sandbox))).SignAsync(cancellationToken);

        byte[] changedText = (byte[])text.Clone();
        changedText[^2] = (byte)'!';
        byte[] tampered = (byte[])detached.Clone();
        FlipSignatureValue(tampered);

        using var outsiderKey = RSA.Create(2048);
        var request = new CertificateRequest("CN=Assinante Fora da Cadeia, O=Outside, C=BR", outsiderKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.NonRepudiation, true));
        using var outsider = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        byte[] untrusted = await Sign(text, outsider, [], CadesContentType.Detached);

        string changedId = documents.AddPinned("contrato-alterado.txt", changedText).Id;
        CadesSample Signature(string id, string name, byte[] content, string? dataId, string title, string description, string? indication = null, string? check = null) =>
            new(id, indication is null ? "signature" : "validation", documents.AddPinned(name, content).Id, name, dataId, title, description, indication, check);

        return
        [
            .. data,
            Signature("detached", "contrato.txt.p7s", detached, textId, "Detached signature (.p7s)",
                "Maria's signature of the text contract; the content stays outside. Co-sign it (with the same data) or countersign it."),
            Signature("enveloped", "contrato.txt.p7m", enveloped, null, "Enveloped signature (.p7m)",
                "Maria's signature with the text inside. Co-sign or countersign it without the data."),
            Signature("v-valid", "assinado.p7s", detached, textId, "Valid detached (control)",
                "The .p7s with its data: every check passes.", "Valid", "—"),
            Signature("v-tree", "cossinado-contrassinado.p7m", countersigned, null, "Two signers and a countersignature",
                "Maria and João sign the same content (co-signature); Ana countersigns Maria's signature with a timestamp.", "Valid", "—"),
            Signature("v-changed-data", "assinado.p7s", detached, changedId, "Data changed",
                "The .p7s checked against a copy of the text with one character changed: the message digest no longer matches.", "Invalid", "integrity"),
            Signature("v-tampered", "valor-alterado.p7s", tampered, textId, "Signature value changed",
                "One byte of the signature value was changed: the RSA verification fails.", "Invalid", "signature"),
            Signature("v-untrusted", "raiz-desconhecida.p7s", untrusted, textId, "Root outside the trust anchors",
                "Signed with a self-signed certificate that no trusted root vouches for.", "Indeterminate", "chain"),
        ];
    }

    /// <summary>Flips one byte in the middle of the first signer's signature value.</summary>
    private static void FlipSignatureValue(byte[] cms)
    {
        byte[] signature = CmsParser.ParseAll(cms).Signers[0].Signature!;
        int index = cms.AsSpan().IndexOf(signature);
        cms[index + (signature.Length / 2)] ^= 0x01;
    }
}
