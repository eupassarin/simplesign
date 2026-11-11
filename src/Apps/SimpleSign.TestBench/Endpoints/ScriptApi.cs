using SimpleSign.TestBench.Documents;
using SimpleSign.TestBench.Runs;
using SimpleSign.TestBench.Scripts;

namespace SimpleSign.TestBench.Endpoints;

/// <summary>A script to load: its JSON text.</summary>
public sealed record ScriptLoadRequest(string Json);

/// <summary>The loaded script and its problems.</summary>
public sealed record ScriptLoaded(CertificationScript? Script, IReadOnlyList<ScriptIssue> Issues, bool CanRun);

/// <summary>A sample script bundled with the TestBench.</summary>
public sealed record ScriptSample(string Id, string Title, string? Authority);

/// <summary>The certification scripts: load and check one, run it, decide its manual steps, export the evidence.</summary>
internal static class ScriptApi
{
    public static void Map(RouteGroupBuilder api)
    {
        var script = api.MapGroup("/script");
        script.MapGet("/schema", () => Results.Text(ScriptSchema.Json(), "application/schema+json"));
        script.MapGet("/options", () => Results.Text(ScriptSchema.OptionsMarkdown(), "text/markdown; charset=utf-8"));
        script.MapGet("/samples", () => ScriptSamples.All.Select(s => new ScriptSample(s.Id, s.Title, s.Authority)));
        script.MapPost("/samples/{id}", (string id, ScriptRunner runner) =>
            ScriptSamples.Json(id) is { } json ? Results.Ok(Loaded(runner.Load(json))) : Results.NotFound());
        script.MapPost("/load", (ScriptLoadRequest body, ScriptRunner runner) => Loaded(runner.Load(body.Json)));
        script.MapGet("/loaded", (ScriptRunner runner) =>
            runner.Loaded is { } check ? Results.Ok(Loaded(check)) : Results.NoContent());
        script.MapGet("/loaded/json", (ScriptRunner runner) =>
            runner.LoadedJson is { } json ? Results.Text(json, "application/json") : Results.NoContent());

        script.MapGet("/runs", (ScriptRunner runner) => runner.History());
        script.MapPost("/runs", (ScriptRunRequest body, ScriptRunner runner) =>
        {
            try
            {
                return Results.Ok(runner.Start(body).View());
            }
            catch (InvalidOperationException ex)
            {
                return Results.Conflict(new { error = ex.Message });
            }
        });
        script.MapGet("/runs/{id}", (string id, ScriptRunner runner) =>
            runner.Get(id) is { } run ? Results.Ok(run.View()) : Results.NotFound());
        script.MapPost("/runs/{id}/cancel", (string id, ScriptRunner runner) =>
        {
            runner.Cancel(id);
            return Results.NoContent();
        });
        script.MapPost("/runs/{id}/steps/{stepId}/decision", (string id, string stepId, ScriptDecision body, ScriptRunner runner) =>
        {
            try
            {
                runner.Decide(id, stepId, body);
                return Results.NoContent();
            }
            catch (KeyNotFoundException ex)
            {
                return Results.NotFound(new { error = ex.Message });
            }
        });
        script.MapGet("/runs/{id}/evidence.html", (string id, ScriptRunner runner, DocumentStore documents) =>
            runner.Get(id) is { } run ? Results.Content(ScriptEvidence.Html(run, documents), "text/html; charset=utf-8") : Results.NotFound());
        script.MapGet("/runs/{id}/evidence.zip", (string id, ScriptRunner runner, DocumentStore documents, RunService runs) =>
            runner.Get(id) is { } run
                ? Results.File(ScriptEvidence.Zip(run, documents, runs), "application/zip", $"evidence-{run.Script.Id}-{run.Id}.zip")
                : Results.NotFound());
    }

    private static ScriptLoaded Loaded(ScriptCheck check) => new(check.Script, check.Issues, check.CanRun);
}
