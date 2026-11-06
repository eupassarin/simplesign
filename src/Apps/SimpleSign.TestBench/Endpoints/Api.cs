using System.Security.Cryptography;
using SimpleSign.Brazil.IcpBrasil;
using SimpleSign.PAdES;
using SimpleSign.TestBench.Cades;
using SimpleSign.TestBench.Credentials;
using SimpleSign.TestBench.Documents;
using SimpleSign.TestBench.Localization;
using SimpleSign.TestBench.Matrix;
using SimpleSign.TestBench.Sandbox;
using SimpleSign.TestBench.Signing;
using SimpleSign.TestBench.Validation;
using SimpleSign.TestBench.Xml;

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

public sealed record IcpVersionView(
    string Oid, string Version, string NotBefore, string NotAfter, string? RevokedAt, bool InForce, bool IsAutomatic,
    string? Disabled, IReadOnlyList<string> AcceptedRoots, IReadOnlyList<string> Requirements, string Uri);

public sealed record UploadView(string Id, string FileName, long Size);

public sealed record InspectRequest(string FileId);

internal static class Api
{
    public static void Map(WebApplication app)
    {
        var api = app.MapGroup("/api");

        api.MapGet("/env", (SandboxEnvironment sandbox) => new EnvironmentView(
            [.. sandbox.Pki.Signers.Select(s => new SandboxSignerView(s.Id, L.T(s.Title), L.T(s.Description), s.KeyType.ToString(), s.IsUsable, s.Problem is null ? null : L.T(s.Problem),
                s.Certificate.GetNameInfo(System.Security.Cryptography.X509Certificates.X509NameType.SimpleName, false),
                s.Certificate.NotAfter.ToString("yyyy-MM-dd", System.Globalization.CultureInfo.InvariantCulture)))],
            SandboxPki.TsaUri.AbsoluteUri, SandboxPki.AuthenticatedTsaUri.AbsoluteUri, SandboxPki.TsaUser, SandboxPki.TsaPassword,
            SandboxPsc.BaseUri.AbsoluteUri, sandbox.Psc.Cpf, SandboxPsc.Otp,
            SandboxCsc.BaseUri.AbsoluteUri, SandboxCsc.Pin, SandboxCsc.Otp,
            [.. sandbox.Csc.Credentials.Select(c => new CscCredentialSummary(c.Id, L.T(c.Description), c.AuthMode, c.Scal, c.MultiSign, c.Algorithms, true))],
            System.Runtime.InteropServices.RuntimeInformation.FrameworkDescription + " · " + System.Runtime.InteropServices.RuntimeInformation.OSDescription,
            SHA3_256.IsSupported,
            typeof(PadesSigner).Assembly.GetName().Version?.ToString(3) ?? "?"));

        api.MapGet("/sandbox/log", (SandboxEnvironment sandbox) => sandbox.Network.Log.Reverse().Take(100));
        api.MapGet("/catalog", () => OptionCatalog.Localized());

        // Documents and uploads
        api.MapGet("/documents/samples", async (DocumentStore store, CancellationToken ct) =>
        {
            var result = new List<object>();
            foreach (var sample in store.Samples)
            {
                var facts = await store.FactsAsync(DocumentStore.SampleKey(sample.Id), ct);
                result.Add(new { sample.Id, Title = L.T(sample.Title), Description = L.T(sample.Description), Facts = facts with { Title = L.T(facts.Title) } });
            }

            return result;
        });
        api.MapPost("/documents", async (HttpRequest request, DocumentStore store, CancellationToken ct) =>
        {
            var file = await ReadUploadAsync(request, store, ct);
            return file is null ? Results.BadRequest(new { error = L.T("Send the PDF as multipart/form-data (field 'file').") }) : Results.Ok(await store.FactsAsync(file.Id, ct));
        }).DisableAntiforgery();
        api.MapPost("/uploads", async (HttpRequest request, DocumentStore store, CancellationToken ct) =>
        {
            var file = await ReadUploadAsync(request, store, ct);
            return file is null ? Results.BadRequest(new { error = L.T("Send the file as multipart/form-data (field 'file').") }) : Results.Ok(new UploadView(file.Id, file.FileName, file.Content.Length));
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
        credentials.MapPost("/psc/browser", async (PscCredentialRequest body, EnvironmentMode? environment, CredentialFactory factory, CredentialStore store, CancellationToken ct) =>
            await OpenAsync(store, () => factory.OpenPscBrowserAsync(body, environment ?? EnvironmentMode.Sandbox, ct)));
        credentials.MapPost("/psc/password", async (PscCredentialRequest body, EnvironmentMode? environment, CredentialFactory factory, CredentialStore store, CancellationToken ct) =>
            await OpenAsync(store, () => factory.OpenPscPasswordAsync(body, environment ?? EnvironmentMode.Sandbox, ct)));
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

        // ICP-Brasil policy versions and the stamp preview (options, rules and signing: RunApi)
        api.MapGet("/icp/versions", (IcpPolicyKind policy, string? credentialId, CredentialStore store) => IcpVersions(policy, credentialId, store));
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
        // Validation area
        api.MapGet("/validation/samples", (ValidationSampleStore samples) => samples.Samples.Select(s => s with { Title = L.T(s.Title), Description = L.T(s.Description) }));
        api.MapPost("/validation/bulk", async (BulkRequest body, InspectionService inspection, CancellationToken ct) => await inspection.BulkAsync(body, ct));
        api.MapPost("/inspect", async (InspectRequest body, InspectionService inspection, CancellationToken ct) => await inspection.InspectAsync(body.FileId, ct));
        api.MapGet("/files/{id}/cms/{field}", async (string id, string field, InspectionService inspection, CancellationToken ct) =>
            await inspection.CmsAsync(id, field, ct) is { } cms
                ? Results.File(cms, "application/pkcs7-signature", $"{field}.p7s")
                : Results.NotFound());

        // Run matrix
        // CAdES
        var cades = api.MapGroup("/cades");
        cades.MapGet("/samples", (CadesSampleStore samples) => samples.Samples.Select(s => s with { Title = L.T(s.Title), Description = L.T(s.Description) }));
        cades.MapPost("/inspect", (InspectRequest body, DocumentStore documents) =>
        {
            var file = documents.Get(body.FileId);
            return CadesInspector.Inspect(body.FileId, file.FileName, file.Content);
        });

        // XML: XAdES and fiscal XML-DSig
        var xml = api.MapGroup("/xml");
        xml.MapGet("/samples", (XmlSampleStore samples) => samples.Samples.Select(s => s with { Title = L.T(s.Title), Description = L.T(s.Description) }));

        api.MapGet("/matrix/cases", (string? format, MatrixRunner matrix, CadesMatrix cadesMatrix, XmlMatrix xmlMatrix) =>
            format switch { "cades" => cadesMatrix.Cases(), "xml" => xmlMatrix.Cases(), _ => matrix.Cases() });
        api.MapPost("/matrix/run", async (MatrixRunRequest body, MatrixRunner matrix, CadesMatrix cadesMatrix, XmlMatrix xmlMatrix, CancellationToken ct) =>
            body.Format switch
            {
                "cades" => await cadesMatrix.RunAsync(body, ct),
                "xml" => await xmlMatrix.RunAsync(body, ct),
                _ => await matrix.RunAsync(body, ct),
            });

        RunApi.Map(api);

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
            IcpBrasilPolicy.AdRb => [L.T("Signature dictionary /Filter /PBAD_PAdES /SubFilter /PBAD.PAdES (2.16.76.1.8.1)"), L.T("signature-policy-identifier with the PA hash"), L.T("signing-certificate-v2")],
            IcpBrasilPolicy.AdRt => [L.T("Everything in AD-RB"), L.T("signature-time-stamp from an ICP-Brasil ACT")],
            IcpBrasilPolicy.AdRc => [L.T("Everything in AD-RT"), L.T("DSS with Certs and CRLs or OCSPs, and a VRI entry for the signature (2.16.76.1.8.2)"), L.T("A later document timestamp /ETSI.RFC3161 (2.16.76.1.8.3)")],
            _ => [L.T("Everything in AD-RC"), L.T("DSS arrays PBAD_PolicyArtifacts, PBAD_LpaArtifacts, PBAD_LpaSignatures and the matching VRI entries")],
        };
        return [.. IcpBrasilSignaturePolicies.All
            .Where(p => p.Info.Format == IcpBrasilPolicyFormat.Pades && p.Info.Policy == policy)
            .OrderByDescending(p => p.NotBefore)
            .Select(p =>
            {
                IcpBrasilSignaturePolicies.TryGetRules(p.Oid, out var rules);
                bool inForce = p.IsValidAt(now);
                string? disabled = !inForce
                    ? p.RevokedAt is { } revoked && revoked <= now ? L.T("Revoked by the ITI on {0:yyyy-MM-dd}.", revoked) : L.T("Signing period {0:yyyy-MM-dd} – {1:yyyy-MM-dd} is over.", p.NotBefore, p.NotAfter)
                    : null;
                if (disabled is null && credential is { Facts.ChainsToIcpBrasil: true } && automatic is not null && rules is not null
                    && credential.Chain.LastOrDefault() is { } root && !rules.AcceptsRoot(root))
                {
                    disabled = L.T("This version does not accept the signer's AC Raiz.");
                }

                return new IcpVersionView(p.Oid, p.Info.Version ?? "?", p.NotBefore.ToString("yyyy-MM-dd", System.Globalization.CultureInfo.InvariantCulture),
                    p.NotAfter.ToString("yyyy-MM-dd", System.Globalization.CultureInfo.InvariantCulture), p.RevokedAt?.ToString("yyyy-MM-dd", System.Globalization.CultureInfo.InvariantCulture),
                    inForce, p.Oid == automatic, disabled,
                    rules?.TrustAnchorSubjects ?? [], requirements, p.Uri);
            })];
    }
}
