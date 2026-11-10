using System.Text.Json;
using SimpleSign.TestBench.Cades;
using SimpleSign.TestBench.Credentials;
using SimpleSign.TestBench.CrossValidation;
using SimpleSign.TestBench.Documents;
using SimpleSign.TestBench.Localization;
using SimpleSign.TestBench.Runs;
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

/// <summary>A file to validate with DSS, with the data of a detached signature and the uploaded validation policy (null: the default).</summary>
public sealed record DssValidateRequest(string FileId, string? DataId, string? PolicyId = null);

/// <summary>A file to try validation with, and the indication it should get (null: no expectation).</summary>
public sealed record SampleView(string Format, string Id, string FileId, string FileName, string? DataId, string Title, string Description, string? ExpectedIndication);

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
            catch (Exception ex) when (ex is ArgumentException or JsonException)
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

        // Every validation sample of the three formats, with the verdict each one should get.
        api.MapGet("/validation/samples/all", (Validation.ValidationSampleStore pdf, CadesSampleStore cadesSamples, XmlSampleStore xmlSamples, DocumentStore documents) =>
            pdf.Samples.Select(s => new SampleView(RunFormats.Pades, s.Id, s.FileId, documents.TryGet(s.FileId, out var f) ? f!.FileName : s.Id, null, L.T(s.Title), L.T(s.Description), s.ExpectedIndication))
                .Concat(cadesSamples.Samples.Where(s => s.Kind != "data")
                    .Select(s => new SampleView(RunFormats.Cades, s.Id, s.FileId, s.FileName, s.DataId, L.T(s.Title), L.T(s.Description), s.ExpectedIndication)))
                .Concat(xmlSamples.Samples.Where(s => s.Kind == "validation")
                    .Select(s => new SampleView(RunFormats.Xades, s.Id, s.FileId, s.FileName, s.DataId, L.T(s.Title), L.T(s.Description), s.ExpectedIndication))));

        // A stored validation report (SimpleSign's or DSS's JSON), read for the report viewer.
        api.MapGet("/reports/{id}", (string id, DocumentStore documents) =>
        {
            if (!documents.TryGet(id, out var file))
            {
                return Results.NotFound();
            }

            try
            {
                return Reports.ReportReader.Read(System.Text.Encoding.UTF8.GetString(file!.Content)) is { } report
                    ? Results.Ok(report)
                    : Results.BadRequest(new { error = L.T("This file is not a SimpleSign or DSS validation report.") });
            }
            catch (JsonException ex)
            {
                return Results.BadRequest(new { error = L.T("This file is not a SimpleSign or DSS validation report.") + " " + ex.Message });
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
                ? Results.Ok(await client.ValidateAsync(body.FileId, body.DataId, null, ct, policy: PolicyUploads.Validation(body.PolicyId, documents)))
                : Results.NotFound());
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
                    var report = CadesCompatibility.Evaluate(options, inputs, credential?.Facts, cades.SandboxConnected, PolicyUploads.Signing(options.SigningPolicyId, documents));
                    return new(body.Format, report.Options, report.Issues, report.CanSign, report.EffectiveLevel, report.Effective, null, credential?.Facts, inputs);
                }

            case RunFormats.Xades:
                {
                    var options = body.Options.Deserialize<XmlOptions>(json) ?? new XmlOptions();
                    credentials.TryGet(options.CredentialId, out var credential);
                    var facts = xml.Facts(options.DataId);
                    var report = XmlCompatibility.Evaluate(options, facts, credential?.Facts, xml.SandboxConnected, PolicyUploads.Signing(options.SigningPolicyId, documents));
                    return new(body.Format, report.Options, report.Issues, report.CanSign, report.EffectiveLevel, report.Effective, null, credential?.Facts, facts);
                }

            default:
                {
                    var options = body.Options.Deserialize<SigningOptions>(json) ?? new SigningOptions();
                    DocumentFacts? document = options.DocumentId is { } id && documents.TryGet(id, out _) ? await documents.FactsAsync(id, cancellationToken) : null;
                    credentials.TryGet(options.CredentialId, out var credential);
                    var report = Compatibility.Evaluate(options, document, credential?.Facts, xml.SandboxConnected, PolicyUploads.Signing(options.SigningPolicyId, documents));
                    return new(RunFormats.Pades, report.Options, report.Issues, report.CanSign, report.EffectiveLevel, report.Effective, document, credential?.Facts, null);
                }
        }
    }
}
