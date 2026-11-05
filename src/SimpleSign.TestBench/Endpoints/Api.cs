using System.Security.Cryptography;
using SimpleSign.Brasil.IcpBrasil;
using SimpleSign.Brasil.Signing;
using SimpleSign.PAdES;
using SimpleSign.TestBench.Credentials;
using SimpleSign.TestBench.Documents;
using SimpleSign.TestBench.Matrix;
using SimpleSign.TestBench.Sandbox;
using SimpleSign.TestBench.Signing;

namespace SimpleSign.TestBench.Endpoints;

public sealed record SandboxSignerView(string Id, string Title, string Description, string KeyType, bool IsUsable, string? Problem, string Holder, string NotAfter);

public sealed record EnvironmentView(
    IReadOnlyList<SandboxSignerView> Signers,
    string TsaUrl,
    string AuthenticatedTsaUrl,
    string TsaUser,
    string TsaPassword,
    string PscUrl,
    string PscCpf,
    string PscOtp,
    string CscUrl,
    string CscPin,
    string CscOtp,
    IReadOnlyList<CscCredentialSummary> CscCredentials,
    string Runtime,
    bool Sha3Supported,
    string Version);

public sealed record OptionsResponse(OptionsReport Report, DocumentFacts? Document, CredentialFacts? Credential);

public sealed record IcpVersionView(
    string Oid, string Version, string NotBefore, string NotAfter, string? RevokedAt, bool InForce, bool IsAutomatic,
    string? Disabled, IReadOnlyList<string> AcceptedRoots, IReadOnlyList<string> Requirements, string Uri);

public sealed record UploadView(string Id, string FileName, long Size);

public sealed record ValidateRequest(string FileId, EnvironmentMode Environment);

internal static class Api
{
    public static void Map(WebApplication app)
    {
        var api = app.MapGroup("/api");

        api.MapGet("/env", (SandboxEnvironment sandbox) => new EnvironmentView(
            [.. sandbox.Pki.Signers.Select(s => new SandboxSignerView(s.Id, s.Title, s.Description, s.KeyType.ToString(), s.IsUsable, s.Problem,
                s.Certificate.GetNameInfo(System.Security.Cryptography.X509Certificates.X509NameType.SimpleName, false),
                s.Certificate.NotAfter.ToString("yyyy-MM-dd", System.Globalization.CultureInfo.InvariantCulture)))],
            SandboxPki.TsaUri.AbsoluteUri, SandboxPki.AuthenticatedTsaUri.AbsoluteUri, SandboxPki.TsaUser, SandboxPki.TsaPassword,
            SandboxPsc.BaseUri.AbsoluteUri, sandbox.Psc.Cpf, SandboxPsc.Otp,
            SandboxCsc.BaseUri.AbsoluteUri, SandboxCsc.Pin, SandboxCsc.Otp,
            [.. sandbox.Csc.Credentials.Select(c => new CscCredentialSummary(c.Id, c.Description, c.AuthMode, c.Scal, c.MultiSign, c.Algorithms, true))],
            System.Runtime.InteropServices.RuntimeInformation.FrameworkDescription + " · " + System.Runtime.InteropServices.RuntimeInformation.OSDescription,
            SHA3_256.IsSupported,
            typeof(PadesSigner).Assembly.GetName().Version?.ToString(3) ?? "?"));

        api.MapGet("/sandbox/log", (SandboxEnvironment sandbox) => sandbox.Network.Log.Reverse().Take(100));
        api.MapGet("/catalog", () => OptionCatalog.All);

        // Documents and uploads
        api.MapGet("/documents/samples", async (DocumentStore store, CancellationToken ct) =>
        {
            var result = new List<object>();
            foreach (var sample in store.Samples)
            {
                var facts = await store.FactsAsync(DocumentStore.SampleKey(sample.Id), ct);
                result.Add(new { sample.Id, sample.Title, sample.Description, Facts = facts });
            }

            return result;
        });
        api.MapPost("/documents", async (HttpRequest request, DocumentStore store, CancellationToken ct) =>
        {
            var file = await ReadUploadAsync(request, store, ct);
            return file is null ? Results.BadRequest(new { error = "Send the PDF as multipart/form-data (field 'file')." }) : Results.Ok(await store.FactsAsync(file.Id, ct));
        }).DisableAntiforgery();
        api.MapPost("/uploads", async (HttpRequest request, DocumentStore store, CancellationToken ct) =>
        {
            var file = await ReadUploadAsync(request, store, ct);
            return file is null ? Results.BadRequest(new { error = "Send the file as multipart/form-data (field 'file')." }) : Results.Ok(new UploadView(file.Id, file.FileName, file.Content.Length));
        }).DisableAntiforgery();
        api.MapGet("/documents/{id}/facts", async (string id, DocumentStore store, CancellationToken ct) => await store.FactsAsync(id, ct));
        api.MapGet("/files/{id}", (string id, bool? download, DocumentStore store) =>
        {
            if (!store.TryGet(id, out var file))
            {
                return Results.NotFound();
            }

            return download == true
                ? Results.File(file!.Content, "application/pdf", file.FileName)
                : Results.File(file!.Content, "application/pdf");
        });

        // Credentials
        var credentials = api.MapGroup("/credentials");
        credentials.MapPost("/sandbox", (SandboxCredentialRequest body, CredentialFactory factory, CredentialStore store) =>
            Open(store, () => factory.OpenSandbox(body)));
        credentials.MapPost("/pfx", (PfxCredentialRequest body, CredentialFactory factory, CredentialStore store) =>
            Open(store, () => factory.OpenPfx(body)));
        credentials.MapGet("/store", () => CredentialFactory.ListStore());
        credentials.MapPost("/store", (StoreCredentialRequest body, CredentialStore store) => Open(store, () => CredentialFactory.OpenStore(body)));
        credentials.MapGet("/pkcs11", async (CancellationToken ct) => await CredentialFactory.ListTokensAsync(ct));
        credentials.MapPost("/pkcs11", (Pkcs11CredentialRequest body, CredentialStore store) => Open(store, () => CredentialFactory.OpenPkcs11(body)));
        credentials.MapPost("/psc", async (PscCredentialRequest body, EnvironmentMode? environment, CredentialFactory factory, CredentialStore store, CancellationToken ct) =>
            await OpenAsync(store, () => factory.OpenPscAsync(body, environment ?? EnvironmentMode.Sandbox, ct)));
        credentials.MapPost("/csc/list", async (CscCredentialListRequest body, EnvironmentMode? environment, CredentialFactory factory, CancellationToken ct) =>
        {
            try
            {
                return Results.Ok(await factory.ListCscAsync(body, environment ?? EnvironmentMode.Sandbox, ct));
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                return Results.BadRequest(new { error = ex.Message });
            }
        });
        credentials.MapPost("/csc", async (CscCredentialRequest body, EnvironmentMode? environment, CredentialFactory factory, CredentialStore store, CancellationToken ct) =>
            await OpenAsync(store, () => factory.OpenCscAsync(body, environment ?? EnvironmentMode.Sandbox, ct)));
        credentials.MapDelete("/{id}", (string id, CredentialStore store) =>
        {
            store.Remove(id);
            return Results.NoContent();
        });

        // Options, ICP versions, signing, validation
        api.MapPost("/options", async (SigningOptions options, DocumentStore documents, CredentialStore store, CancellationToken ct) =>
        {
            DocumentFacts? document = options.DocumentId is { } id && documents.TryGet(id, out _) ? await documents.FactsAsync(id, ct) : null;
            store.TryGet(options.CredentialId, out var credential);
            return new OptionsResponse(Compatibility.Evaluate(options, document, credential?.Facts), document, credential?.Facts);
        });
        api.MapGet("/icp/versions", (IcpPolicyKind policy, string? credentialId, CredentialStore store) => IcpVersions(policy, credentialId, store));
        api.MapPost("/sign", async (SigningOptions options, SigningRunner runner, CancellationToken ct) => await runner.RunAsync(options, ct));
        api.MapPost("/preview", async (SigningOptions options, PreviewService preview, CancellationToken ct) =>
        {
            try
            {
                return Results.Ok(new { fileId = await preview.RenderAsync(options, ct) });
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                return Results.BadRequest(new { error = ex.Message });
            }
        });
        api.MapPost("/validate", async (ValidateRequest body, SigningRunner runner, DocumentStore documents, CancellationToken ct) =>
            await runner.ValidateAsync(documents.Get(body.FileId).Content, body.Environment, ct));

        // Run matrix
        api.MapGet("/matrix/cases", (MatrixRunner matrix) => matrix.Cases());
        api.MapPost("/matrix/run", async (MatrixRunRequest body, MatrixRunner matrix, CancellationToken ct) => await matrix.RunAsync(body, ct));

        api.MapFallback(() => Results.NotFound(new { error = "Unknown API route." }));
    }

    private static IResult Open(CredentialStore store, Func<CredentialHandle> open)
    {
        try
        {
            return Results.Ok(store.Add(open()).Facts);
        }
        catch (Exception ex) when (ex is CryptographicException or ArgumentException or KeyNotFoundException or InvalidOperationException
            or SimpleSign.Signers.Pkcs11.Pkcs11Exception or DllNotFoundException or IOException or UnauthorizedAccessException)
        {
            return Results.BadRequest(new { error = ex.Message });
        }
    }

    private static async Task<IResult> OpenAsync(CredentialStore store, Func<Task<CredentialHandle>> open)
    {
        try
        {
            return Results.Ok(store.Add(await open()).Facts);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return Results.BadRequest(new { error = ex.Message });
        }
    }

    private static async Task<StoredFile?> ReadUploadAsync(HttpRequest request, DocumentStore store, CancellationToken ct)
    {
        if (!request.HasFormContentType)
        {
            return null;
        }

        var form = await request.ReadFormAsync(ct);
        var upload = form.Files.GetFile("file");
        if (upload is null || upload.Length == 0 || upload.Length > 50 * 1024 * 1024)
        {
            return null;
        }

        using var memory = new MemoryStream();
        await upload.CopyToAsync(memory, ct);
        return store.Add(upload.FileName, memory.ToArray());
    }

    private static IReadOnlyList<IcpVersionView> IcpVersions(IcpPolicyKind kind, string? credentialId, CredentialStore store)
    {
        var policy = kind switch
        {
            IcpPolicyKind.AdRb => IcpBrasilPolicy.AdRb,
            IcpPolicyKind.AdRt => IcpBrasilPolicy.AdRt,
            IcpPolicyKind.AdRc => IcpBrasilPolicy.AdRc,
            _ => IcpBrasilPolicy.AdRa,
        };
        store.TryGet(credentialId, out var credential);
        string? automatic = null;
        try
        {
            var builder = PadesSigner.Document([]);
            if (credential is not null)
            {
                builder = credential.External is { } external
                    ? builder.WithExternalSigner(credential.Certificate, external, credential.Chain)
                    : builder.WithCertificate(credential.Certificate, credential.Chain);
            }

            automatic = builder.ResolveIcpBrasilPolicy(policy).Oid;
        }
        catch (Exception ex) when (ex is IcpBrasilPolicyException or InvalidOperationException or ArgumentException)
        {
            // No version accepts the signer's root: every version is listed, none marked automatic.
        }

        var now = DateTimeOffset.UtcNow;
        string[] requirements = policy switch
        {
            IcpBrasilPolicy.AdRb => ["Signature dictionary /Filter /PBAD_PAdES /SubFilter /PBAD.PAdES (2.16.76.1.8.1)", "signature-policy-identifier with the PA hash", "signing-certificate-v2"],
            IcpBrasilPolicy.AdRt => ["Everything in AD-RB", "signature-time-stamp from an ICP-Brasil ACT"],
            IcpBrasilPolicy.AdRc => ["Everything in AD-RT", "DSS with Certs and CRLs or OCSPs, and a VRI entry for the signature (2.16.76.1.8.2)", "A later document timestamp /ETSI.RFC3161 (2.16.76.1.8.3)"],
            _ => ["Everything in AD-RC", "DSS arrays PBAD_PolicyArtifacts, PBAD_LpaArtifacts, PBAD_LpaSignatures and the matching VRI entries"],
        };
        return [.. IcpBrasilSignaturePolicies.All
            .Where(p => p.Info.Format == IcpBrasilPolicyFormat.Pades && p.Info.Policy == policy)
            .OrderByDescending(p => p.NotBefore)
            .Select(p =>
            {
                IcpBrasilSignaturePolicies.TryGetRules(p.Oid, out var rules);
                bool inForce = p.IsValidAt(now);
                string? disabled = !inForce
                    ? p.RevokedAt is { } revoked && revoked <= now ? $"Revoked by the ITI on {revoked:yyyy-MM-dd}." : $"Signing period {p.NotBefore:yyyy-MM-dd} – {p.NotAfter:yyyy-MM-dd} is over."
                    : null;
                if (disabled is null && credential is { Facts.ChainsToIcpBrasil: true } && automatic is not null && rules is not null
                    && credential.Chain.LastOrDefault() is { } root && !rules.AcceptsRoot(root))
                {
                    disabled = "This version does not accept the signer's AC Raiz.";
                }

                return new IcpVersionView(p.Oid, p.Info.Version ?? "?", p.NotBefore.ToString("yyyy-MM-dd", System.Globalization.CultureInfo.InvariantCulture),
                    p.NotAfter.ToString("yyyy-MM-dd", System.Globalization.CultureInfo.InvariantCulture), p.RevokedAt?.ToString("yyyy-MM-dd", System.Globalization.CultureInfo.InvariantCulture),
                    inForce, p.Oid == automatic, disabled,
                    rules?.TrustAnchorSubjects ?? [], requirements, p.Uri);
            })];
    }
}
