using SimpleSign.PAdES;
using SimpleSign.TestBench.Credentials;
using SimpleSign.TestBench.Documents;
using SimpleSign.TestBench.Sandbox;

namespace SimpleSign.TestBench.Signing;

/// <summary>
/// Renders the stamp for the live preview: signs a throwaway copy (B-B, no network) with the
/// chosen field and appearance, so pdf.js shows exactly what the library draws.
/// </summary>
internal sealed class PreviewService(SandboxEnvironment sandbox, DocumentStore documents, CredentialStore credentials, CredentialFactory factory)
{
    private CredentialHandle? _previewSigner;

    public async Task<string> RenderAsync(SigningOptions options, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(options);
        var document = documents.Get(options.DocumentId ?? throw new ArgumentException("Choose a document first."));
        // A local credential previews with the real holder name; tokens and cloud signers would prompt, so use the sandbox one.
        var signer = credentials.TryGet(options.CredentialId, out var chosen) && chosen!.External is null
            ? chosen
            : _previewSigner ??= factory.OpenSandbox(new SandboxCredentialRequest("rsa-2048"));
        var preview = options with
        {
            Environment = EnvironmentMode.Sandbox,
            Kind = SignatureKind.Baseline,
            Level = BaselineLevel.BB,
            Mode = RunMode.Sign,
            SubFilter = SubFilterChoice.EtsiCadesDetached,
            Padding = RsaPadding.Pkcs1,
            Hash = HashChoice.Sha256,
            PreservePdfA = false,
            Certification = CertificationChoice.None,
            UseSignerDetails = false,
            Health = new HealthChoice(),
            DocumentInfo = [],
            Appearance = options.Appearance with { Visible = true },
        };
        var plan = new SigningPlan(preview, signer, sandbox, documents);
        var builder = PadesSigner.Document(document.Content)
            .WithCertificate(signer.Certificate, signer.Chain)
            .WithHttpClientProvider(sandbox.Network)
            .WithFieldOptions(plan.Field)
            .WithLevel(plan.Profile!);
        if (preview.SigningTime is { } time)
        {
            builder = builder.WithSigningTime(time);
        }

        byte[] signed = await builder.SignAsync(cancellationToken);
        return documents.Add("preview.pdf", signed).Id;
    }
}
