using System.Security.Cryptography;
using SimpleSign.PAdES;
using SimpleSign.TestBench.Cades;
using SimpleSign.TestBench.Credentials;
using SimpleSign.TestBench.Documents;
using SimpleSign.TestBench.Localization;
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
    string CscUrl,
    string CscPin,
    string CscOtp,
    IReadOnlyList<CscCredentialSummary> CscCredentials,
    string Runtime,
    bool Sha3Supported,
    string Version);

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

        // Validation area
        api.MapGet("/validation/samples", (ValidationSampleStore samples) => samples.Samples.Select(s => s with { Title = L.T(s.Title), Description = L.T(s.Description) }));
        api.MapPost("/validation/bulk", async (BulkRequest body, InspectionService inspection, CancellationToken ct) => await inspection.BulkAsync(body, ct));
        api.MapPost("/inspect", async (InspectRequest body, InspectionService inspection, CancellationToken ct) => await inspection.InspectAsync(body.FileId, ct));
        api.MapGet("/files/{id}/cms/{field}", async (string id, string field, InspectionService inspection, CancellationToken ct) =>
            await inspection.CmsAsync(id, field, ct) is { } cms
                ? Results.File(cms, "application/pkcs7-signature", $"{field}.p7s")
                : Results.NotFound());

        // CAdES
        var cades = api.MapGroup("/cades");
        cades.MapGet("/samples", (CadesSampleStore samples) => samples.Samples.Select(s => s with { Title = L.T(s.Title), Description = L.T(s.Description) }));
        cades.MapPost("/inspect", (InspectRequest body, DocumentStore documents) =>
        {
            var file = documents.Get(body.FileId);
            return CadesInspector.Inspect(body.FileId, file.FileName, file.Content);
        });

        // XML: XAdES
        var xml = api.MapGroup("/xml");
        xml.MapGet("/samples", (XmlSampleStore samples) => samples.Samples.Select(s => s with { Title = L.T(s.Title), Description = L.T(s.Description) }));

        RunApi.Map(api);
        SandboxApi.Map(api);
        EnvironmentApi.Map(api);

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
}
