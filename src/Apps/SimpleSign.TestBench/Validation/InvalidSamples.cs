using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using SimpleSign.Core.Signing;
using SimpleSign.PAdES;
using SimpleSign.TestBench.Documents;
using SimpleSign.TestBench.Sandbox;

namespace SimpleSign.TestBench.Validation;

/// <summary>The validation samples, created at startup.</summary>
internal sealed class ValidationSampleStore
{
    public IReadOnlyList<ValidationSample> Samples { get; set; } = [];
}

/// <summary>A sample for the Validation page: what it is and what the validator should say.</summary>
public sealed record ValidationSample(string Id, string FileId, string Title, string Description, string ExpectedIndication, string ExpectedCheck);

/// <summary>
/// Signed PDFs built at startup with the sandbox, each one broken in one specific way (plus a
/// valid control), so every failure of the validation report can be seen.
/// </summary>
internal static class InvalidSamples
{
    public static async Task<IReadOnlyList<ValidationSample>> CreateAsync(SandboxEnvironment sandbox, DocumentStore documents, CancellationToken cancellationToken = default)
    {
        byte[] contract = documents.Get(DocumentStore.SampleKey("contract")).Content;
        var pki = sandbox.Pki;
        var maria = pki.Signer("rsa-2048").Certificate;

        async Task<byte[]> Sign(X509Certificate2 certificate, IReadOnlyList<X509Certificate2> chain, AdesBaselineProfile profile) =>
            await PadesSigner.Document(contract)
                .WithCertificate(certificate, chain)
                .WithHttpClientProvider(sandbox.Network)
                .WithFieldName("Assinatura")
                .WithLevel(profile)
                .SignAsync(cancellationToken);

        var tsa = new TimestampOptions(SandboxPki.TsaUri, sandbox.Network);
        var ltv = new LongTermValidationOptions(sandbox.Network);
        byte[] valid = await Sign(maria, pki.Chain, AdesBaselineProfile.LongTerm(tsa, ltv));
        byte[] basic = await Sign(maria, pki.Chain, AdesBaselineProfile.Basic());

        byte[] tamperedContent = (byte[])basic.Clone();
        Patch(tamperedContent, "SimpleSign TestBench", "SimpleSign TestBanch");

        byte[] tamperedCms = (byte[])basic.Clone();
        FlipInsideContents(tamperedCms);

        byte[] appended = [.. basic, .. Encoding.ASCII.GetBytes("\n% An unsigned change appended after the signature.\n")];

        byte[] revoked = await Sign(pki.Signer("revoked").Certificate, pki.Chain, AdesBaselineProfile.Basic());
        // The library refuses to sign with a certificate that is not valid now, so the "expired"
        // sample is signed with a certificate that lives a few seconds and has expired by validation time.
        var shortLived = pki.IssueShortLived("CN=Certificado de Vida Curta, OU=Sandbox, O=SimpleSign TestBench, C=BR", TimeSpan.FromSeconds(3));
        byte[] expired = await Sign(shortLived, pki.Chain, AdesBaselineProfile.Basic());
        await Task.Delay(TimeSpan.FromSeconds(3.5), cancellationToken);

        using var outsiderKey = RSA.Create(2048);
        var outsiderRequest = new CertificateRequest("CN=Assinante Fora da Cadeia, O=Outside, C=BR", outsiderKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        outsiderRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.NonRepudiation, true));
        using var outsider = outsiderRequest.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        byte[] untrustedRoot = await Sign(outsider, [], AdesBaselineProfile.Basic());

        byte[] untrustedTsa = await Sign(maria, pki.Chain, AdesBaselineProfile.Timestamped(new TimestampOptions(SandboxPki.UntrustedTsaUri, sandbox.Network)));

        ValidationSample Add(string id, string fileName, byte[] content, string title, string description, string indication, string check) =>
            new(id, documents.AddPinned(fileName, content).Id, title, description, indication, check);

        return
        [
            Add("valid", "valido-b-lt.pdf", valid, "Valid B-LT (control)", "Signed by the sandbox signer with timestamp and LTV data: every check passes.", "Valid", "—"),
            Add("tampered-content", "conteudo-alterado.pdf", tamperedContent, "Content changed after signing", "One byte of the signed range (the Author entry) was changed: the ByteRange digest no longer matches.", "Invalid", "integrity"),
            Add("tampered-cms", "cms-alterado.pdf", tamperedCms, "Signature value changed", "One hex digit inside /Contents was changed: the CMS no longer verifies.", "Invalid", "signature"),
            Add("appended", "alterado-depois.pdf", appended, "Bytes appended after signing", "The file grew after the signature with no new revision: the signature still verifies, and the validator reports that the ByteRange does not cover the whole file.", "Valid", "coverage"),
            Add("revoked", "revogado.pdf", revoked, "Revoked signer", "The signer is in the intermediate CA's CRL, fetched by the validator. (The library refuses to build B-LT for a revoked signer.)", "Invalid", "revocation"),
            Add("expired", "expirado.pdf", expired, "Expired signer", "Signed while the certificate was valid; it has expired since, and a B-B signature has no timestamp to prove when it was made.", "Indeterminate", "chain"),
            Add("untrusted-root", "raiz-desconhecida.pdf", untrustedRoot, "Root outside the trust anchors", "Signed with a self-signed certificate that no trusted root vouches for.", "Indeterminate", "chain"),
            Add("untrusted-tsa", "tsa-desconhecida.pdf", untrustedTsa, "Untrusted TSA", "The signature timestamp comes from a TSA under an unknown CA. The validator keeps the signature Valid and reports the untrusted TSA chain as a warning.", "Valid", "timestamp"),
        ];
    }

    private static void Patch(byte[] pdf, string from, string to)
    {
        int index = pdf.AsSpan().IndexOf(Encoding.ASCII.GetBytes(from));
        if (index < 0)
        {
            throw new InvalidOperationException($"'{from}' not found in the sample.");
        }

        Encoding.ASCII.GetBytes(to).CopyTo(pdf, index);
    }

    /// <summary>Changes one hex digit about a third into the signature's /Contents (inside the CMS, not the zero padding).</summary>
    private static void FlipInsideContents(byte[] pdf)
    {
        int contents = pdf.AsSpan().LastIndexOf("/Contents <"u8);
        int start = contents + "/Contents <".Length;
        int end = pdf.AsSpan(start).IndexOf((byte)'>') + start;
        int used = end;
        while (used > start && pdf[used - 1] == (byte)'0')
        {
            used--;
        }

        int index = start + ((used - start) * 2 / 3);
        pdf[index] = pdf[index] == (byte)'A' ? (byte)'B' : (byte)'A';
    }
}
