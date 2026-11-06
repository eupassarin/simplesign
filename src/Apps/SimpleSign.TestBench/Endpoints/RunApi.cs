using System.Text.Json;
using SimpleSign.TestBench.Cades;
using SimpleSign.TestBench.Credentials;
using SimpleSign.TestBench.CrossValidation;
using SimpleSign.TestBench.Documents;
using SimpleSign.TestBench.Localization;
using SimpleSign.TestBench.Matrix;
using SimpleSign.TestBench.Runs;
using SimpleSign.TestBench.Sandbox;
using SimpleSign.TestBench.Schema;
using SimpleSign.TestBench.Signing;
using SimpleSign.TestBench.Xml;

namespace SimpleSign.TestBench.Endpoints;

/// <summary>The options of one format, as the workbench sends them.</summary>
public sealed record WorkbenchOptionsRequest(string Format, JsonElement Options);

/// <summary>The rules applied to a format's options, in the same shape for the three formats.</summary>
public sealed record WorkbenchOptionsResponse(
    string Format,
    IReadOnlyDictionary<string, OptionState> States,
    IReadOnlyList<OptionIssue> Issues,
    bool CanSign,
    string EffectiveLevel,
    object Effective,
    DocumentFacts? Document,
    CredentialFacts? Credential,
    object? Inputs);

public sealed record RunStarted(string Id);

public sealed record DssValidateRequest(string FileId, string? DataId);

public sealed record MatrixDone(int Total, long Ms, int UncoverablePairs);

/// <summary>What the matrix stream sends: one finished case, then the totals.</summary>
public sealed record MatrixEvent(string Type, MatrixCaseResult? Case, MatrixDone? Done);

/// <summary>The workbench API: the option schema, the rules, runs with a live log, and DSS cross-validation.</summary>
internal static class RunApi
{
    public static void Map(RouteGroupBuilder api)
    {
        api.MapGet("/schema", () => OptionSchema.Localized());

        api.MapPost("/workbench/options", async (WorkbenchOptionsRequest body, DocumentStore documents, CredentialStore credentials,
            CadesRunner cades, XmlRunner xml, CancellationToken ct) =>
        {
            try
            {
                return Results.Ok(await EvaluateAsync(body, documents, credentials, cades, xml, ct));
            }
            catch (JsonException ex)
            {
                return Results.BadRequest(new { error = ex.Message });
            }
        });

        var runs = api.MapGroup("/runs");
        runs.MapGet("", (RunService service) => service.History());
        runs.MapPost("", (RunRequest body, RunService service) =>
        {
            try
            {
                return Results.Ok(new RunStarted(service.Start(body).Id));
            }
            catch (ArgumentException ex)
            {
                return Results.BadRequest(new { error = ex.Message });
            }
        });
        runs.MapGet("/{id}", (string id, RunService service) =>
            service.Find(id) is { } run
                ? run.Result is { } result ? Results.Ok(result) : Results.Accepted()
                : Results.NotFound());
        runs.MapGet("/{id}/events", async (string id, RunService service, HttpContext context) =>
        {
            if (service.Find(id) is not { } run)
            {
                context.Response.StatusCode = StatusCodes.Status404NotFound;
                return;
            }

            // Server-sent events: one "data:" line per event, replayed from the start for late readers.
            context.Response.ContentType = "text/event-stream";
            context.Response.Headers.CacheControl = "no-store";
            context.Response.Headers["X-Accel-Buffering"] = "no";
            var ct = context.RequestAborted;
            int sent = 0;
            try
            {
                while (!ct.IsCancellationRequested)
                {
                    var (events, changed) = run.Read(sent);
                    foreach (var runEvent in events)
                    {
                        await context.Response.WriteAsync($"data: {JsonSerializer.Serialize(runEvent, WorkbenchJson.Options)}\n\n", ct);
                    }

                    sent += events.Count;
                    await context.Response.Body.FlushAsync(ct);
                    if (events.Any(e => e.Run is not null))
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

        // The run matrix, one case at a time: the page shows progress and can stop by closing the stream.
        api.MapGet("/matrix/stream", async (string? format, string? group, MatrixRunner pades, CadesMatrix cades, XmlMatrix xml, HttpContext context) =>
        {
            string name = format ?? "pades";
            var cases = (name switch { "cades" => cades.Cases(), "xml" => xml.Cases(), _ => pades.Cases() })
                .Where(c => group is null or "all" || c.Group == group).ToList();
            context.Response.ContentType = "text/event-stream";
            context.Response.Headers.CacheControl = "no-store";
            var ct = context.RequestAborted;
            var watch = System.Diagnostics.Stopwatch.StartNew();
            int uncoverable = 0;
            try
            {
                foreach (var matrixCase in cases)
                {
                    var request = new MatrixRunRequest(CaseId: matrixCase.Id, Format: name);
                    var result = name switch
                    {
                        "cades" => await cades.RunAsync(request, ct),
                        "xml" => await xml.RunAsync(request, ct),
                        _ => await pades.RunAsync(request, ct),
                    };
                    uncoverable = result.UncoverablePairs;
                    await context.Response.WriteAsync($"data: {JsonSerializer.Serialize(new MatrixEvent("case", result.Cases.Single(), null), WorkbenchJson.Options)}\n\n", ct);
                    await context.Response.Body.FlushAsync(ct);
                }

                var done = new MatrixEvent("done", null, new MatrixDone(cases.Count, watch.ElapsedMilliseconds, uncoverable));
                await context.Response.WriteAsync($"data: {JsonSerializer.Serialize(done, WorkbenchJson.Options)}\n\n", ct);
            }
            catch (OperationCanceledException)
            {
                // The page stopped the matrix.
            }
        });

        var dss = api.MapGroup("/dss");
        dss.MapGet("/settings", (DssClient client) => client.Settings);
        dss.MapPut("/settings", (DssSettings body, DssClient client) =>
        {
            if (!Uri.TryCreate(body.Url, UriKind.Absolute, out var uri) || uri.Scheme is not ("http" or "https"))
            {
                return Results.BadRequest(new { error = L.T("The DSS address must be an http or https URL.") });
            }

            client.Settings = body;
            return Results.Ok(client.Settings);
        });
        dss.MapGet("/status", async (DssClient client, CancellationToken ct) => await client.StatusAsync(ct));
        dss.MapPost("/validate", async (DssValidateRequest body, DssClient client, DocumentStore documents, CancellationToken ct) =>
            documents.TryGet(body.FileId, out _)
                ? Results.Ok(await client.ValidateAsync(body.FileId, body.DataId, null, ct))
                : Results.NotFound());

        // The sandbox root, so an external validator (DSS) can be told to trust the sandbox PKI.
        api.MapGet("/sandbox/root.pem", (SandboxEnvironment sandbox) =>
            Results.Text(sandbox.Pki.Root.ExportCertificatePem() + "\n", "application/x-pem-file"));
        api.MapGet("/sandbox/chain.pem", (SandboxEnvironment sandbox) =>
            Results.Text(string.Join("\n", new[] { sandbox.Pki.Root }.Concat(sandbox.Pki.Chain).DistinctBy(c => c.Thumbprint).Select(c => c.ExportCertificatePem())) + "\n", "application/x-pem-file"));
    }

    internal static async Task<WorkbenchOptionsResponse> EvaluateAsync(WorkbenchOptionsRequest body, DocumentStore documents, CredentialStore credentials,
        CadesRunner cades, XmlRunner xml, CancellationToken cancellationToken)
    {
        var json = WorkbenchJson.Options;
        switch (body.Format)
        {
            case RunFormats.Cades:
                {
                    var options = body.Options.Deserialize<CadesOptions>(json) ?? new CadesOptions();
                    credentials.TryGet(options.CredentialId, out var credential);
                    var inputs = cades.Inputs(options);
                    var report = CadesCompatibility.Evaluate(options, inputs, credential?.Facts);
                    return new(body.Format, report.Options, report.Issues, report.CanSign, report.EffectiveLevel, report.Effective, null, credential?.Facts, inputs);
                }

            case RunFormats.Xades:
                {
                    var options = body.Options.Deserialize<XmlOptions>(json) ?? new XmlOptions();
                    credentials.TryGet(options.CredentialId, out var credential);
                    var facts = xml.Facts(options.DataId);
                    var report = XmlCompatibility.Evaluate(options, facts, credential?.Facts);
                    return new(body.Format, report.Options, report.Issues, report.CanSign, report.EffectiveLevel, report.Effective, null, credential?.Facts, facts);
                }

            default:
                {
                    var options = body.Options.Deserialize<SigningOptions>(json) ?? new SigningOptions();
                    DocumentFacts? document = options.DocumentId is { } id && documents.TryGet(id, out _) ? await documents.FactsAsync(id, cancellationToken) : null;
                    credentials.TryGet(options.CredentialId, out var credential);
                    var report = Compatibility.Evaluate(options, document, credential?.Facts);
                    return new(RunFormats.Pades, report.Options, report.Issues, report.CanSign, report.EffectiveLevel, report.Effective, document, credential?.Facts, null);
                }
        }
    }
}
