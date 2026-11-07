using System.Globalization;
using System.Net;
using System.Text;

namespace SimpleSign.Playbook.Runs;

/// <summary>A run written for people: report.md and report.html in the run folder.</summary>
public static class RunReport
{
    public static void Write(string runFolder, RunRecord run)
    {
        System.IO.File.WriteAllText(Path.Combine(runFolder, "report.md"), Markdown(run));
        System.IO.File.WriteAllText(Path.Combine(runFolder, "report.html"), Html(run));
    }

    private static string Time(DateTimeOffset? value) =>
        value?.ToString("yyyy-MM-dd HH:mm:ss zzz", CultureInfo.InvariantCulture) ?? "—";

    public static string Markdown(RunRecord run)
    {
        ArgumentNullException.ThrowIfNull(run);
        var md = new StringBuilder();
        void Line(string text = "") => md.Append(text).Append('\n');
        static string Cell(string? text) => (text ?? "—").Replace("|", "\\|", StringComparison.Ordinal).Replace("\n", " ", StringComparison.Ordinal);
        var summary = run.Summary;

        Line($"# {run.PlaybookName} — run {run.Id}");
        Line();
        Line($"- **Result:** {run.Status} ({summary.Passed} passed, {summary.Failed} failed, {summary.Errors} errors, {summary.Skipped} skipped, {summary.Total} steps)");
        Line($"- **Started:** {Time(run.StartedAt)}; **finished:** {Time(run.FinishedAt)}");
        Line($"- **Machine:** {run.Machine} ({run.User})");
        Line($"- **CLI:** `{run.Cli}` — {run.CliVersion ?? "—"}");
        if (run.Sandbox is { } sandbox)
        {
            Line($"- **Sandbox:** '{sandbox.Name}' {sandbox.Version} at {sandbox.Url} — root {sandbox.RootSubject} (SHA-1 {sandbox.RootThumbprint})");
        }

        Line($"- **Playbook SHA-256:** `{run.PlaybookHash}`");
        if (run.Error is not null)
        {
            Line();
            Line($"> **The run stopped:** {run.Error}");
        }

        Line();
        Line("| Step | Section | Result | Time |");
        Line("|---|---|---|---|");
        foreach (var step in run.Steps)
        {
            Line($"| {Cell(step.Title)} (`{step.StepId}`) | {Cell(step.SectionTitle)} | {step.Status} | {(step.DurationMs is { } ms ? $"{ms} ms" : "—")} |");
        }

        foreach (var group in run.Steps.Where(s => s.Status != RunStatus.Skipped).GroupBy(s => s.SectionTitle))
        {
            Line();
            Line($"## {group.Key}");
            foreach (var step in group)
            {
                Line();
                Line($"### {step.Title} — {step.Status}");
                if (step.Description is not null)
                {
                    Line();
                    Line(step.Description);
                }

                Line();
                foreach (string action in step.Actions)
                {
                    Line($"- {action}");
                }

                if (step.Command is not null)
                {
                    Line($"- Command (exit {(step.TimedOut ? "timeout" : step.ExitCode?.ToString(CultureInfo.InvariantCulture) ?? "—")}):");
                    Line();
                    Line("```");
                    Line(step.Command);
                    Line("```");
                }

                if (step.Checks.Count > 0)
                {
                    Line();
                    Line("| Check | Expected | Found | |");
                    Line("|---|---|---|---|");
                    foreach (var check in step.Checks)
                    {
                        Line($"| {Cell(check.Name)} | {Cell(check.Expected)} | {Cell(check.Actual)} | {(check.Passed ? "✓" : "✗")} |");
                    }
                }

                if (step.SandboxRequests.Count > 0)
                {
                    Line();
                    Line("Sandbox requests:");
                    Line();
                    Line("```");
                    foreach (var request in step.SandboxRequests)
                    {
                        Line($"{request.Time:HH:mm:ss.fff}  {request.Service,-5} {request.Method} {request.Path} → {request.Status}{(request.Fault is null ? "" : $" (failure: {request.Fault})")}");
                    }

                    Line("```");
                }

                if (step.Error is not null)
                {
                    Line();
                    Line($"> Error: {step.Error}");
                }

                if (step.Note is not null)
                {
                    Line();
                    Line($"> Note: {step.Note}");
                }

                if (step.Files.Count + step.Attachments.Count > 0)
                {
                    Line();
                    Line("Files: " + string.Join(", ", step.Files.Concat(step.Attachments).Select(f => $"`{f}`")));
                }
            }
        }

        return md.ToString();
    }

    /// <summary>The same report as a self-contained HTML page (printable, opens without the app).</summary>
    public static string Html(RunRecord run)
    {
        ArgumentNullException.ThrowIfNull(run);
        static string E(string? text) => WebUtility.HtmlEncode(text ?? "—");
        string Badge(string status) => $"<span class=\"badge {status}\">{E(status)}</span>";
        var html = new StringBuilder();
        var summary = run.Summary;
        html.Append("<!DOCTYPE html><html><head><meta charset=\"utf-8\"><title>").Append(E(run.PlaybookName)).Append(" — ").Append(E(run.Id)).Append("</title><style>")
            .Append("body{font:14px/1.5 system-ui,sans-serif;margin:2rem auto;max-width:1100px;padding:0 1rem;color:#18181b}")
            .Append("h1{font-size:1.5rem}h2{font-size:1.2rem;margin-top:2rem;border-bottom:1px solid #e4e4e7}h3{font-size:1rem;margin-top:1.5rem}")
            .Append("table{border-collapse:collapse;width:100%;margin:.5rem 0}td,th{border:1px solid #e4e4e7;padding:4px 8px;text-align:left;vertical-align:top}")
            .Append("pre{background:#f4f4f5;padding:8px;overflow:auto;white-space:pre-wrap}code{font-size:12px}")
            .Append(".badge{border-radius:4px;padding:1px 6px;font-size:12px}.passed{background:#dcfce7}.failed,.error{background:#fee2e2}.skipped,.cancelled{background:#f4f4f5}.waiting{background:#fef9c3}")
            .Append("dl{display:grid;grid-template-columns:max-content 1fr;gap:2px 12px}dt{color:#71717a}</style></head><body>");
        html.Append("<h1>").Append(E(run.PlaybookName)).Append("</h1><dl>")
            .Append("<dt>Run</dt><dd>").Append(E(run.Id)).Append(' ').Append(Badge(run.Status)).Append("</dd>")
            .Append("<dt>Steps</dt><dd>").Append(CultureInfo.InvariantCulture, $"{summary.Passed} passed, {summary.Failed} failed, {summary.Errors} errors, {summary.Skipped} skipped, {summary.Total} in all").Append("</dd>")
            .Append("<dt>Started</dt><dd>").Append(E(Time(run.StartedAt))).Append("</dd><dt>Finished</dt><dd>").Append(E(Time(run.FinishedAt))).Append("</dd>")
            .Append("<dt>Machine</dt><dd>").Append(E($"{run.Machine} ({run.User})")).Append("</dd>")
            .Append("<dt>CLI</dt><dd><code>").Append(E(run.Cli)).Append("</code> ").Append(E(run.CliVersion)).Append("</dd>");
        if (run.Sandbox is { } sandbox)
        {
            html.Append("<dt>Sandbox</dt><dd>").Append(E($"'{sandbox.Name}' {sandbox.Version} at {sandbox.Url} — {sandbox.RootSubject} (SHA-1 {sandbox.RootThumbprint})")).Append("</dd>");
        }

        html.Append("<dt>Playbook SHA-256</dt><dd><code>").Append(E(run.PlaybookHash)).Append("</code></dd></dl>");
        if (run.Error is not null)
        {
            html.Append("<p><strong>The run stopped:</strong> ").Append(E(run.Error)).Append("</p>");
        }

        html.Append("<table><tr><th>Step</th><th>Section</th><th>Result</th><th>Time</th></tr>");
        foreach (var step in run.Steps)
        {
            html.Append("<tr><td>").Append(E(step.Title)).Append(" <code>").Append(E(step.StepId)).Append("</code></td><td>").Append(E(step.SectionTitle))
                .Append("</td><td>").Append(Badge(step.Status)).Append("</td><td>").Append(step.DurationMs is { } ms ? $"{ms} ms" : "—").Append("</td></tr>");
        }

        html.Append("</table>");
        foreach (var group in run.Steps.Where(s => s.Status != RunStatus.Skipped).GroupBy(s => s.SectionTitle))
        {
            html.Append("<h2>").Append(E(group.Key)).Append("</h2>");
            foreach (var step in group)
            {
                html.Append("<h3>").Append(E(step.Title)).Append(' ').Append(Badge(step.Status)).Append("</h3>");
                if (step.Description is not null)
                {
                    html.Append("<p>").Append(E(step.Description)).Append("</p>");
                }

                if (step.Actions.Count > 0)
                {
                    html.Append("<ul>");
                    foreach (string action in step.Actions)
                    {
                        html.Append("<li>").Append(E(action)).Append("</li>");
                    }

                    html.Append("</ul>");
                }

                if (step.Command is not null)
                {
                    html.Append("<pre>").Append(E(step.Command)).Append("</pre><p>Exit: ")
                        .Append(E(step.TimedOut ? "timeout" : step.ExitCode?.ToString(CultureInfo.InvariantCulture))).Append("</p>");
                }

                if (step.Checks.Count > 0)
                {
                    html.Append("<table><tr><th>Check</th><th>Expected</th><th>Found</th><th></th></tr>");
                    foreach (var check in step.Checks)
                    {
                        html.Append("<tr><td>").Append(E(check.Name)).Append("</td><td>").Append(E(check.Expected)).Append("</td><td>").Append(E(check.Actual))
                            .Append("</td><td>").Append(check.Passed ? "✓" : "✗").Append("</td></tr>");
                    }

                    html.Append("</table>");
                }

                if (step.SandboxRequests.Count > 0)
                {
                    html.Append("<pre>");
                    foreach (var request in step.SandboxRequests)
                    {
                        html.Append(E($"{request.Time:HH:mm:ss.fff}  {request.Service,-5} {request.Method} {request.Path} → {request.Status}{(request.Fault is null ? "" : $" (failure: {request.Fault})")}")).Append('\n');
                    }

                    html.Append("</pre>");
                }

                if (step.Error is not null)
                {
                    html.Append("<p><strong>Error:</strong> ").Append(E(step.Error)).Append("</p>");
                }

                if (step.Note is not null)
                {
                    html.Append("<p><strong>Note:</strong> ").Append(E(step.Note)).Append("</p>");
                }

                foreach (string attachment in step.Attachments.Where(a => a.EndsWith(".png", StringComparison.OrdinalIgnoreCase) || a.EndsWith(".jpg", StringComparison.OrdinalIgnoreCase)))
                {
                    html.Append("<p><img style=\"max-width:100%\" src=\"").Append(E(attachment)).Append("\"></p>");
                }
            }
        }

        html.Append("</body></html>");
        return html.ToString();
    }
}
