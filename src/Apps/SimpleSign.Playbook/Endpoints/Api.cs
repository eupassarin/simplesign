using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Text.Json.Serialization;
using SimpleSign.Playbook.Model;
using SimpleSign.Playbook.Runs;
using SimpleSign.Playbook.Workspaces;

namespace SimpleSign.Playbook.Endpoints;

public sealed record SettingsView(string? CliCommand, IReadOnlyList<string> CliPrefix, string ResolvedProgram, IReadOnlyList<string> ResolvedPrefix);

public sealed record SettingsRequest(string? CliCommand, List<string>? CliPrefix);

public sealed record CliCheck(bool Ok, string CommandLine, string Output);

public sealed record SampleView(string Id, string Name, string? Description);

public sealed record WorkspacesView(string? Current, IReadOnlyList<string> Recent, IReadOnlyList<SampleView> Samples, string DefaultFolder);

public sealed record OpenRequest(string Path);

public sealed record CreateRequest(string Path, string? Name, string? Sample);

public sealed record CertificateView(string Subject, string Issuer, DateTimeOffset NotBefore, DateTimeOffset NotAfter, bool HasPrivateKey, string KeyAlgorithm, string Thumbprint);

public sealed record AssetView(string Path, long Bytes, DateTimeOffset Modified, CertificateView? Certificate, string? CertificateProblem);

public sealed record WorkspaceView(
    string Path,
    string PlaybookText,
    PlaybookDefinition? Playbook,
    IReadOnlyList<PlaybookIssue> Issues,
    IReadOnlyList<AssetView> Assets,
    IReadOnlyList<string> SecretKeys,
    IReadOnlyList<RunListItem> Runs,
    string? ActiveRunId);

public sealed record PlaybookTextRequest(string Text);

public sealed record PlaybookCheck(PlaybookDefinition? Playbook, IReadOnlyList<PlaybookIssue> Issues);

public sealed record SecretRequest(string? Value);

public sealed record SandboxStatus(bool Ok, string Url, SandboxSummary? Info, IReadOnlyList<SandboxCertificateSummary> Certificates, string? Error);

public sealed record RunRequest(List<string>? Selection);

public sealed record RunStarted(string? Id);

public sealed record DecisionRequest(string Status, string? Note);

public sealed record ErrorView(string Error);

/// <summary>The app's API (127.0.0.1 only).</summary>
internal static class Api
{
    public static void Map(WebApplication app)
    {
        var api = app.MapGroup("/api");

        // ── Settings: how to start the CLI on this machine ─────────────────────
        api.MapGet("/settings", (AppSettingsStore store) => View(store));
        api.MapPut("/settings", (SettingsRequest body, AppSettingsStore store) =>
        {
            var current = store.Read();
            store.Write(current with
            {
                CliCommand = string.IsNullOrWhiteSpace(body.CliCommand) ? null : body.CliCommand.Trim(),
                CliPrefix = body.CliPrefix?.Where(a => !string.IsNullOrWhiteSpace(a)).ToList() ?? [],
            });
            return View(store);
        });
        api.MapPost("/settings/check", async (AppSettingsStore store, IProcessRunner processes, CancellationToken ct) =>
        {
            var (program, prefix) = store.ResolveCli();
            string line = PlaybookRunner.CommandLine(program, [.. prefix, "version"]);
            try
            {
                var result = await processes.RunAsync(
                    new ProcessCommand(program, [.. prefix, "version"], Environment.CurrentDirectory, TimeSpan.FromSeconds(60)), null, ct);
                return new CliCheck(result.ExitCode == 0, line, (result.Stdout + result.Stderr).Trim());
            }
            catch (System.ComponentModel.Win32Exception ex)
            {
                return new CliCheck(false, line, ex.Message);
            }
        });

        // ── Workspaces ──────────────────────────────────────────────────────
        api.MapGet("/workspaces", (WorkspaceState state, AppSettingsStore store) =>
            new WorkspacesView(state.Current?.Directory, store.Read().RecentWorkspaces, Samples(), DefaultFolder()));
        api.MapPost("/workspaces/open", (OpenRequest body, WorkspaceState state, RunService runs) =>
            Guard(() => Workspace(state.Open(Expand(body.Path)), runs)));
        api.MapPost("/workspaces/create", (CreateRequest body, WorkspaceState state, RunService runs) => Guard(() =>
        {
            string? sample = body.Sample is { Length: > 0 } id ? SampleFolder(id) ?? throw new ArgumentException($"Unknown sample '{id}'.") : null;
            string path = Expand(body.Path);
            string name = string.IsNullOrWhiteSpace(body.Name) ? Path.GetFileName(path.TrimEnd(Path.DirectorySeparatorChar)) : body.Name;
            return Workspace(state.Create(path, name, sample), runs);
        }));

        // ── The open workspace ─────────────────────────────────────────────
        var workspace = api.MapGroup("/workspace");
        workspace.MapGet("", (WorkspaceState state, RunService runs) => Guard(() => Workspace(state.Require(), runs)));
        workspace.MapPut("/playbook", (PlaybookTextRequest body, WorkspaceState state, RunService runs) => Guard(() =>
        {
            var current = state.Require();
            current.SavePlaybookText(body.Text);
            return Workspace(current, runs);
        }));
        workspace.MapPost("/playbook/check", (PlaybookTextRequest body, WorkspaceState state) => Guard(() =>
        {
            var current = state.Require();
            var (playbook, issues) = PlaybookValidator.Parse(body.Text);
            return new PlaybookCheck(playbook, playbook is null ? issues : PlaybookValidator.Validate(playbook, current.Directory));
        }));
        workspace.MapPost("/assets", async (HttpRequest request, WorkspaceState state, RunService runs, CancellationToken ct) =>
        {
            if (!request.HasFormContentType)
            {
                return Results.BadRequest(new ErrorView("Send the files as multipart/form-data."));
            }

            var current = state.Current;
            if (current is null)
            {
                return Results.BadRequest(new ErrorView("No workspace is open."));
            }

            var form = await request.ReadFormAsync(ct);
            foreach (var file in form.Files)
            {
                using var buffer = new MemoryStream();
                await file.CopyToAsync(buffer, ct);
                current.SaveAsset(file.FileName, buffer.ToArray());
            }

            return Results.Ok(Workspace(current, runs));
        }).DisableAntiforgery();
        workspace.MapDelete("/assets", (string path, WorkspaceState state, RunService runs) => Guard(() =>
        {
            var current = state.Require();
            current.DeleteAsset(path);
            return Workspace(current, runs);
        }));
        workspace.MapPut("/secrets/{key}", (string key, SecretRequest body, WorkspaceState state, RunService runs) => Guard(() =>
        {
            if (!PlaybookValidator.IsId(key))
            {
                throw new ArgumentException("A secret key uses letters, digits, '-' and '_' only.");
            }

            var current = state.Require();
            current.SetSecret(key, string.IsNullOrEmpty(body.Value) ? null : body.Value);
            return Workspace(current, runs);
        }));

        // ── The Sandbox of the playbook ───────────────────────────────────
        api.MapGet("/sandbox", async (string url, Func<Uri, ISandboxClient> factory, CancellationToken ct) =>
        {
            if (!Uri.TryCreate(url, UriKind.Absolute, out var uri) || uri.Scheme is not ("http" or "https"))
            {
                return new SandboxStatus(false, url, null, [], "Not an http(s) URL.");
            }

            var client = factory(uri);
            try
            {
                var info = await client.InfoAsync(ct);
                var pki = await client.PkiAsync(ct);
                return new SandboxStatus(true, client.Url.AbsoluteUri, info, pki.Certificates, null);
            }
            catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or JsonException or InvalidOperationException)
            {
                return new SandboxStatus(false, client.Url.AbsoluteUri, null, [], ex.Message);
            }
            finally
            {
                (client as IDisposable)?.Dispose();
            }
        });

        // ── Runs ─────────────────────────────────────────────────────────
        var runs = api.MapGroup("/runs");
        runs.MapGet("", (WorkspaceState state) => Guard(() => RunStore.List(state.Require().RunsPath)));
        runs.MapPost("", (RunRequest body, WorkspaceState state, RunService service) => Guard(() =>
        {
            var active = service.Start(state.Require(), body.Selection is { Count: > 0 } selection ? selection : null);
            return new RunStarted(active.Id);
        }));
        runs.MapDelete("/active", (RunService service) => service.Cancel() ? Results.NoContent() : Results.NotFound());
        runs.MapGet("/active/events", async (RunService service, HttpContext context) =>
        {
            if (service.Active is not { } active)
            {
                context.Response.StatusCode = StatusCodes.Status404NotFound;
                return;
            }

            // Server-sent events, replayed from the start for late readers, until the run ends.
            context.Response.ContentType = "text/event-stream";
            context.Response.Headers.CacheControl = "no-store";
            context.Response.Headers["X-Accel-Buffering"] = "no";
            var ct = context.RequestAborted;
            int sent = 0;
            try
            {
                while (!ct.IsCancellationRequested)
                {
                    var (events, changed, finished) = active.Read(sent);
                    foreach (string runEvent in events)
                    {
                        await context.Response.WriteAsync($"data: {runEvent}\n\n", ct);
                    }

                    sent += events.Count;
                    await context.Response.Body.FlushAsync(ct);
                    if (finished)
                    {
                        return;
                    }

                    await changed.WaitAsync(ct);
                }
            }
            catch (OperationCanceledException)
            {
                // The browser closed the stream.
            }
        });
        runs.MapGet("/{id}", (string id, WorkspaceState state) => Guard(() =>
            RunStore.Load(RunStore.Folder(state.Require().RunsPath, id)) ?? throw new FileNotFoundException($"No run '{id}'.")));
        runs.MapPost("/{id}/steps/{stepId}/decision", (string id, string stepId, DecisionRequest body, RunService service) =>
            service.Active is { } active && active.Id == id && active.Decide(stepId, new ManualDecision(body.Status, body.Note))
                ? Results.NoContent()
                : Results.NotFound(new ErrorView("That step is not waiting for a decision.")));
        runs.MapPost("/{id}/steps/{stepId}/attachments", async (string id, string stepId, HttpRequest request, WorkspaceState state, CancellationToken ct) =>
        {
            if (!request.HasFormContentType || state.Current is not { } current)
            {
                return Results.BadRequest(new ErrorView("Send the files as multipart/form-data, with a workspace open."));
            }

            var form = await request.ReadFormAsync(ct);
            var saved = new List<string>();
            foreach (var file in form.Files)
            {
                using var buffer = new MemoryStream();
                await file.CopyToAsync(buffer, ct);
                saved.Add(RunService.Attach(current, id, stepId, file.FileName, buffer.ToArray()));
            }

            return Results.Ok(saved);
        }).DisableAntiforgery();
        runs.MapGet("/{id}/zip", (string id, WorkspaceState state) => Guard(() =>
        {
            string folder = RunStore.Folder(state.Require().RunsPath, id);
            return Directory.Exists(folder)
                ? Results.File(RunStore.Zip(folder), "application/zip", $"run-{id}.zip")
                : Results.NotFound();
        }));
        runs.MapGet("/{id}/files/{**path}", (string id, string path, bool? download, WorkspaceState state) => Guard(() =>
        {
            string folder = RunStore.Folder(state.Require().RunsPath, id);
            if (RunStore.FileOf(folder, path) is not { } file)
            {
                return Results.NotFound();
            }

            string type = Path.GetExtension(file).ToLowerInvariant() switch
            {
                ".md" or ".txt" or ".pem" => "text/plain; charset=utf-8",
                ".json" => "application/json",
                ".html" => "text/html; charset=utf-8",
                ".pdf" => "application/pdf",
                ".png" => "image/png",
                ".jpg" or ".jpeg" => "image/jpeg",
                ".xml" => "application/xml",
                _ => "application/octet-stream",
            };
            return Results.File(file, type, download == true ? Path.GetFileName(file) : null);
        }));
    }

    /// <summary>Runs <paramref name="action"/>; a bad request, a missing workspace or file gives a 400/404 with the reason.</summary>
    private static IResult Guard<T>(Func<T> action)
    {
        try
        {
            var result = action();
            return result as IResult ?? Results.Ok(result);
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException or IOException or UnauthorizedAccessException or JsonException)
        {
            return ex is FileNotFoundException or DirectoryNotFoundException
                ? Results.NotFound(new ErrorView(ex.Message))
                : Results.BadRequest(new ErrorView(ex.Message));
        }
    }

    private static SettingsView View(AppSettingsStore store)
    {
        var settings = store.Read();
        var (program, prefix) = store.ResolveCli();
        return new SettingsView(settings.CliCommand, settings.CliPrefix, program, prefix);
    }

    private static WorkspaceView Workspace(Workspace workspace, RunService runs)
    {
        var (playbook, issues) = workspace.LoadPlaybook();
        var secrets = workspace.ReadSecrets();
        return new WorkspaceView(
            workspace.Directory,
            workspace.ReadPlaybookText(),
            playbook,
            issues,
            [.. workspace.Assets().Select(a => Asset(workspace, a, playbook, secrets))],
            [.. secrets.Keys.Order(StringComparer.Ordinal)],
            RunStore.List(workspace.RunsPath),
            runs.Active is { IsFinished: false } active && active.Workspace == workspace.Directory ? active.Id : null);
    }

    /// <summary>An asset, with its certificate when it is one (a PKCS#12 is opened with its secret, when the playbook names one).</summary>
    private static AssetView Asset(Workspace workspace, AssetFile file, PlaybookDefinition? playbook, Dictionary<string, string> secrets)
    {
        string extension = Path.GetExtension(file.Path).ToLowerInvariant();
        if (extension is not (".pfx" or ".p12" or ".cer" or ".crt" or ".pem" or ".der"))
        {
            return new AssetView(file.Path, file.Bytes, file.Modified, null, null);
        }

        try
        {
            byte[] content = File.ReadAllBytes(workspace.Resolve(file.Path));
            X509Certificate2 certificate;
            if (extension is ".pfx" or ".p12")
            {
                string? key = playbook?.Assets.FirstOrDefault(a => a.File == file.Path)?.Secret;
                if (key is null || !secrets.TryGetValue(key, out string? password))
                {
                    return new AssetView(file.Path, file.Bytes, file.Modified, null, "A PKCS#12: name its secret in the playbook and set the password to read it.");
                }

                var collection = X509CertificateLoader.LoadPkcs12Collection(content, password, X509KeyStorageFlags.EphemeralKeySet);
                certificate = collection.FirstOrDefault(c => c.HasPrivateKey) ?? collection[0];
            }
            else
            {
                certificate = extension == ".pem" ? X509Certificate2.CreateFromPem(System.Text.Encoding.ASCII.GetString(content)) : X509CertificateLoader.LoadCertificate(content);
            }

            using (certificate)
            {
                return new AssetView(file.Path, file.Bytes, file.Modified, new CertificateView(
                    certificate.Subject, certificate.Issuer, certificate.NotBefore.ToUniversalTime(), certificate.NotAfter.ToUniversalTime(),
                    certificate.HasPrivateKey, certificate.PublicKey.Oid.FriendlyName ?? certificate.PublicKey.Oid.Value ?? "?", certificate.Thumbprint), null);
            }
        }
        catch (CryptographicException ex)
        {
            return new AssetView(file.Path, file.Bytes, file.Modified, null, ex.Message);
        }
    }

    /// <summary>The playbooks shipped with the app (Samples/ID/playbook.json).</summary>
    private static IReadOnlyList<SampleView> Samples()
    {
        string root = Path.Combine(AppContext.BaseDirectory, "Samples");
        if (!Directory.Exists(root))
        {
            return [];
        }

        var samples = new List<SampleView>();
        foreach (string folder in Directory.EnumerateDirectories(root))
        {
            var (playbook, _) = PlaybookValidator.Parse(File.ReadAllText(Path.Combine(folder, Workspaces.Workspace.PlaybookFile)));
            if (playbook is not null)
            {
                samples.Add(new SampleView(Path.GetFileName(folder), playbook.Name, playbook.Description));
            }
        }

        return samples;
    }

    private static string? SampleFolder(string id) =>
        PlaybookValidator.IsId(id) && Directory.Exists(Path.Combine(AppContext.BaseDirectory, "Samples", id))
            ? Path.Combine(AppContext.BaseDirectory, "Samples", id)
            : null;

    /// <summary>Where new workspaces go by default: Documents/SimpleSign Playbooks.</summary>
    private static string DefaultFolder() =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments), "SimpleSign Playbooks");

    /// <summary>Expands a leading ~ to the home folder.</summary>
    private static string Expand(string path) =>
        string.IsNullOrWhiteSpace(path)
            ? throw new ArgumentException("Give a folder.")
            : path.StartsWith('~') ? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), path.TrimStart('~').TrimStart('/', '\\')) : path;
}

[JsonSourceGenerationOptions(JsonSerializerDefaults.Web)]
[JsonSerializable(typeof(SettingsView))]
[JsonSerializable(typeof(SettingsRequest))]
[JsonSerializable(typeof(CliCheck))]
[JsonSerializable(typeof(WorkspacesView))]
[JsonSerializable(typeof(OpenRequest))]
[JsonSerializable(typeof(CreateRequest))]
[JsonSerializable(typeof(WorkspaceView))]
[JsonSerializable(typeof(PlaybookTextRequest))]
[JsonSerializable(typeof(PlaybookCheck))]
[JsonSerializable(typeof(SecretRequest))]
[JsonSerializable(typeof(SandboxStatus))]
[JsonSerializable(typeof(RunRequest))]
[JsonSerializable(typeof(RunStarted))]
[JsonSerializable(typeof(DecisionRequest))]
[JsonSerializable(typeof(ErrorView))]
[JsonSerializable(typeof(RunRecord))]
[JsonSerializable(typeof(IReadOnlyList<RunListItem>))]
[JsonSerializable(typeof(List<string>))]
internal sealed partial class ApiJson : JsonSerializerContext;
