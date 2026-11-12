using SimpleSign.TestBench.Documents;
using SimpleSign.TestBench.Playbooks;
using SimpleSign.TestBench.Runs;
using SimpleSign.TestBench.Sandbox;

namespace SimpleSign.TestBench.Endpoints;

/// <summary>A playbook to load: its JSON text.</summary>
public sealed record PlaybookLoadRequest(string Json);

/// <summary>The loaded playbook and its problems.</summary>
public sealed record PlaybookLoaded(Playbook? Playbook, IReadOnlyList<PlaybookIssue> Issues, bool CanRun);

/// <summary>A playbook bundled with the TestBench.</summary>
public sealed record PlaybookSample(string Id, string Title, string? Description);

/// <summary>The playbooks: load and check one, preview and run its steps, export the evidence.</summary>
internal static class PlaybookApi
{
    public static void Map(RouteGroupBuilder api)
    {
        var playbook = api.MapGroup("/playbook");
        playbook.MapGet("/schema", () => Results.Text(PlaybookSchema.Json(), "application/schema+json"));
        playbook.MapGet("/options", () => Results.Text(PlaybookSchema.OptionsMarkdown(), "text/markdown; charset=utf-8"));
        playbook.MapGet("/sandbox", (SandboxEnvironment sandbox) => sandbox.Current is { } current
            ? PlaybookSchema.SandboxReference(current.Signers.Select(x => (x.Id, x.Title)), current.Certificates)
            : PlaybookSchema.SandboxReference(null, null));
        playbook.MapGet("/samples", () => PlaybookSamples.All.Select(s => new PlaybookSample(s.Id, s.Title, s.Description)));
        playbook.MapPost("/samples/{id}", (string id, PlaybookRunner runner) => Guard(() =>
            PlaybookSamples.Json(id) is { } json ? Results.Ok(Loaded(runner.Load(json))) : Results.NotFound()));
        playbook.MapPost("/load", (PlaybookLoadRequest body, PlaybookRunner runner) => Guard(() => Results.Ok(Loaded(runner.Load(body.Json)))));
        playbook.MapGet("/loaded", (PlaybookRunner runner) =>
            runner.Loaded is { } check ? Results.Ok(Loaded(check)) : Results.NoContent());
        playbook.MapGet("/loaded/json", (PlaybookRunner runner) =>
            runner.LoadedJson is { } json ? Results.Text(json, "application/json") : Results.NoContent());

        playbook.MapGet("/state", (PlaybookRunner runner) => runner.State());
        playbook.MapPost("/run", (PlaybookRunRequest body, PlaybookRunner runner) => Guard(() =>
        {
            _ = runner.Start(body);
            return Results.Ok(runner.State());
        }));
        playbook.MapDelete("/results", (PlaybookRunner runner) => Guard(() => Results.Ok(runner.Clear(null))));
        playbook.MapDelete("/results/{stepId}", (string stepId, PlaybookRunner runner) => Guard(() => Results.Ok(runner.Clear(stepId))));
        playbook.MapPost("/cancel", (PlaybookRunner runner) =>
        {
            runner.Cancel();
            return Results.NoContent();
        });
        playbook.MapGet("/steps/{id}/preview", async (string id, string? engine, PlaybookRunner runner, CancellationToken cancellationToken) =>
        {
            try
            {
                return Results.Ok(await runner.PreviewAsync(id, engine, cancellationToken));
            }
            catch (KeyNotFoundException ex)
            {
                return Results.NotFound(new { error = ex.Message });
            }
        });
        playbook.MapGet("/evidence.html", (PlaybookRunner runner, DocumentStore documents) =>
            runner.Session is { } session ? Results.Content(PlaybookEvidence.Html(session, documents), "text/html; charset=utf-8") : Results.NotFound());
        playbook.MapGet("/evidence.zip", (PlaybookRunner runner, DocumentStore documents, RunService runs) =>
            runner.Session is { } session
                ? Results.File(PlaybookEvidence.Zip(session, documents, runs), "application/zip",
                    $"evidence-{session.Playbook.Id}-{DateTimeOffset.Now:yyyyMMdd-HHmmss}.zip")
                : Results.NotFound());
    }

    private static IResult Guard(Func<IResult> action)
    {
        try
        {
            return action();
        }
        catch (InvalidOperationException ex)
        {
            return Results.Conflict(new { error = ex.Message });
        }
        catch (ArgumentException ex)
        {
            return Results.BadRequest(new { error = ex.Message });
        }
        catch (KeyNotFoundException ex)
        {
            return Results.NotFound(new { error = ex.Message });
        }
    }

    private static PlaybookLoaded Loaded(PlaybookCheck check) => new(check.Playbook, check.Issues, check.CanRun);
}
