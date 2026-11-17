using System.Globalization;
using System.IO.Compression;
using System.Net;
using System.Text;
using System.Text.Json;
using SimpleSign.TestBench.Documents;
using SimpleSign.TestBench.Runs;

namespace SimpleSign.TestBench.Playbooks;

/// <summary>
/// The evidence of a playbook: an HTML page with the steps by section (tags, what was expected and found per engine,
/// links to the files) and a summary by tag, and a zip with that page, the playbook, the results and every file it
/// links to. Built from the latest result of each step.
/// </summary>
internal static class PlaybookEvidence
{
    private static readonly JsonSerializerOptions s_indented = new(WorkbenchJson.Options) { WriteIndented = true };

    /// <summary>The evidence page.</summary>
    public static string Html(PlaybookSession session, DocumentStore documents)
    {
        var view = session.View();
        var playbook = session.Playbook;
        var html = new StringBuilder();
        html.Append("<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n<title>")
            .Append(E(playbook.Title)).Append("</title>\n<style>")
            .Append("body{font-family:system-ui,sans-serif;margin:24px auto;max-width:1100px;padding:0 16px;color:#1b1b1b;background:#fff}")
            .Append("table{border-collapse:collapse;width:100%;margin:8px 0 24px}td,th{border:1px solid #ccc;padding:6px 8px;text-align:left;vertical-align:top;font-size:.92em}")
            .Append("th{background:#f4f4f4}.passed{color:#11663a;font-weight:700}.failed{color:#a51d1d;font-weight:700}.pending,.running,.skipped{color:#8a5a00}")
            .Append(".tag{display:inline-block;border:1px solid #bbb;border-radius:10px;padding:0 6px;margin:0 3px 2px 0;font-size:.85em}h2{margin-top:36px}")
            .Append("</style>\n</head>\n<body>\n");
        html.Append("<h1>").Append(E(playbook.Title)).Append("</h1>\n");
        if (playbook.Description is { } description)
        {
            html.Append("<p>").Append(E(description)).Append("</p>\n");
        }

        html.Append("<table>\n");
        Row(html, "Playbook", playbook.Id);
        Row(html, "Exported", DateTimeOffset.Now.ToString("yyyy-MM-dd HH:mm:ss zzz", CultureInfo.InvariantCulture));
        Row(html, "Summary", string.Join(" · ", view.Steps.GroupBy(s => s.Status).Select(g => $"{g.Key}: {g.Count()}")));
        Row(html, "EU DSS differs", Steps(view.Steps.Where(s => s.Result?.Runs.Any(r => r.DssAgrees == false) == true)));
        Row(html, "Library ≠ CLI", Steps(view.Steps.Where(s => s.Result?.EngineDifferences.Count > 0)));
        html.Append("</table>\n");

        if (view.Inputs.Count > 0)
        {
            html.Append("<h2>Inputs</h2>\n<table>\n<tr><th>Input</th><th>File</th><th>SHA-256</th></tr>\n");
            foreach (var input in view.Inputs)
            {
                html.Append("<tr><td><b>").Append(E(input.Id)).Append("</b> — ").Append(E(input.Title)).Append("</td><td>");
                if (input.File is { } file)
                {
                    html.Append("<a href=\"").Append(E(InputPath(input.Id, file.FileName))).Append("\">").Append(E(file.FileName)).Append("</a> (")
                        .Append(file.Size.ToString("N0", CultureInfo.InvariantCulture)).Append(" bytes, uploaded ")
                        .Append(E(file.At.ToString("yyyy-MM-dd HH:mm:ss zzz", CultureInfo.InvariantCulture))).Append(")</td><td><code>")
                        .Append(E(file.Sha256)).Append("</code></td></tr>\n");
                }
                else
                {
                    html.Append("<span class=\"skipped\">not uploaded</span></td><td>—</td></tr>\n");
                }
            }

            html.Append("</table>\n");
        }

        var tags = view.Steps.SelectMany(s => s.Tags.Select(t => (Tag: t, Step: s))).GroupBy(x => x.Tag, StringComparer.Ordinal).ToList();
        if (tags.Count > 0)
        {
            html.Append("<h2>By tag</h2>\n<table>\n<tr><th>Tag</th><th>Result</th><th>Steps</th></tr>\n");
            foreach (var tag in tags)
            {
                var steps = tag.Select(x => x.Step).ToList();
                string status = steps.Any(s => s.Status == PlaybookStatuses.Failed) ? PlaybookStatuses.Failed
                    : steps.All(s => s.Status == PlaybookStatuses.Passed) ? PlaybookStatuses.Passed : PlaybookStatuses.Pending;
                html.Append("<tr><td><b>").Append(E(tag.Key)).Append("</b></td><td class=\"").Append(status).Append("\">").Append(status).Append("</td><td>")
                    .Append(string.Join("<br>", steps.Select(s => $"<a href=\"#{E(s.StepId)}\">{E(s.StepId)}</a> <span class=\"{s.Status}\">{s.Status}</span>")))
                    .Append("</td></tr>\n");
            }

            html.Append("</table>\n");
        }

        foreach (var section in playbook.Sections)
        {
            html.Append("<h2>").Append(E(section.Title)).Append("</h2>\n");
            if (section.Description is { } sectionDescription)
            {
                html.Append("<p>").Append(E(sectionDescription)).Append("</p>\n");
            }

            foreach (var definition in section.Steps)
            {
                var step = view.Steps.First(s => s.StepId == definition.Id);
                html.Append("<h3 id=\"").Append(E(step.StepId)).Append("\">").Append(E(step.StepId)).Append(" — ").Append(E(step.Title))
                    .Append(" <span class=\"").Append(step.Status).Append("\">(").Append(step.Status).Append(")</span></h3>\n");
                if (step.Tags.Count > 0)
                {
                    html.Append("<p>").Append(string.Concat(step.Tags.Select(t => $"<span class=\"tag\">{E(t)}</span>"))).Append("</p>\n");
                }

                if (definition.Description is { } stepDescription)
                {
                    html.Append("<p>").Append(E(stepDescription)).Append("</p>\n");
                }

                if (PlaybookRunner.StepProfile(playbook, definition) is { } profile)
                {
                    html.Append("<p><b>Profile:</b> ").Append(E(profile)).Append("</p>\n");
                }

                if (step.Result is not { } result)
                {
                    html.Append("<p class=\"pending\">Not run.</p>\n");
                    continue;
                }

                html.Append("<p>Run ").Append(E(result.At.ToString("yyyy-MM-dd HH:mm:ss zzz", CultureInfo.InvariantCulture))).Append(" · ")
                    .Append(result.Ms).Append(" ms</p>\n");
                if (result.Message is { } message)
                {
                    html.Append("<p class=\"").Append(result.Status == PlaybookStatuses.Skipped ? "skipped" : "failed").Append("\">").Append(E(message)).Append("</p>\n");
                }

                if (result.EngineDifferences.Count > 0)
                {
                    html.Append("<p class=\"failed\">The library and the CLI reached different verdicts.</p>\n<table>\n<tr><th>Field</th><th>Library</th><th>CLI</th></tr>\n");
                    foreach (var difference in result.EngineDifferences)
                    {
                        html.Append("<tr><td>").Append(E(difference.What)).Append("</td><td>").Append(E(difference.Library ?? "—"))
                            .Append("</td><td>").Append(E(difference.Cli ?? "—")).Append("</td></tr>\n");
                    }

                    html.Append("</table>\n");
                }

                foreach (var engineRun in result.Runs)
                {
                    EngineRun(html, step.StepId, engineRun, documents);
                }
            }
        }

        html.Append("</body>\n</html>\n");
        return html.ToString();
    }

    private static void EngineRun(StringBuilder html, string stepId, PlaybookEngineRun engineRun, DocumentStore documents)
    {
        html.Append("<p><b>Engine:</b> ").Append(E(engineRun.Engine)).Append(" · run ").Append(E(engineRun.RunId)).Append(" · ")
            .Append(engineRun.Ms).Append(" ms</p>\n<table>\n<tr><th>Check</th><th>Expected</th><th>Found</th></tr>\n");
        foreach (var check in engineRun.Checks)
        {
            html.Append("<tr><td>").Append(E(check.What)).Append("</td><td>").Append(E(check.Expected)).Append("</td><td class=\"")
                .Append(check.Passed ? "passed" : "failed").Append("\">").Append(E(check.Found)).Append("</td></tr>\n");
        }

        html.Append("</table>\n<p><b>Evidence:</b> ");
        var links = new List<string>();
        string folder = Folder(stepId, engineRun.Engine);
        if (engineRun.OutputId is { } output && documents.TryGet(output, out var signed))
        {
            links.Add($"<a href=\"{folder}/{E(signed!.FileName)}\">Signed file</a>");
        }

        if (engineRun.ReportId is not null)
        {
            links.Add($"<a href=\"{folder}/report.json\">Validation report</a>");
        }

        if (engineRun.EtsiReportId is not null)
        {
            links.Add($"<a href=\"{folder}/etsi-report.xml\">ETSI report (XML)</a>");
        }

        links.Add($"<a href=\"{folder}/run.json\">Log</a>");
        if (engineRun.DssAgrees is { } agrees)
        {
            links.Add($"EU DSS agrees: {(agrees ? "✓" : "✗")}");
        }
        else if (engineRun.DssError is { } dssError)
        {
            links.Add($"EU DSS: unavailable ({WebUtility.HtmlEncode(dssError)})");
        }

        html.Append(string.Join(" · ", links)).Append("</p>\n");
    }

    /// <summary>The zip of the evidence: the page, the playbook, the results and every file the page links to.</summary>
    public static byte[] Zip(PlaybookSession session, DocumentStore documents, RunService runs)
    {
        using var buffer = new MemoryStream();
        var written = new HashSet<string>(StringComparer.Ordinal); // a Create-mode archive cannot list its entries
        var view = session.View();
        using (var zip = new ZipArchive(buffer, ZipArchiveMode.Create, leaveOpen: true))
        {
            Add(zip, written, "evidence.html", Encoding.UTF8.GetBytes(Html(session, documents)));
            Add(zip, written, "playbook.json", Encoding.UTF8.GetBytes(session.Json));
            Add(zip, written, "results.json", JsonSerializer.SerializeToUtf8Bytes(view, s_indented));
            foreach (var input in view.Inputs)
            {
                if (input.File is { } file && documents.TryGet(file.FileId, out var uploaded))
                {
                    Add(zip, written, InputPath(input.Id, file.FileName), uploaded!.Content);
                }
            }

            foreach (var step in view.Steps)
            {
                foreach (var engineRun in step.Result?.Runs ?? [])
                {
                    string folder = Folder(step.StepId, engineRun.Engine);
                    if (engineRun.OutputId is { } output && documents.TryGet(output, out var signed))
                    {
                        Add(zip, written, $"{folder}/{signed!.FileName}", signed.Content);
                    }

                    if (engineRun.ReportId is { } report && documents.TryGet(report, out var reportFile))
                    {
                        Add(zip, written, $"{folder}/report.json", reportFile!.Content);
                    }

                    if (engineRun.EtsiReportId is { } etsi && documents.TryGet(etsi, out var etsiFile))
                    {
                        Add(zip, written, $"{folder}/etsi-report.xml", etsiFile!.Content);
                    }

                    if (runs.Find(engineRun.RunId)?.Result is { } result)
                    {
                        Add(zip, written, $"{folder}/run.json", JsonSerializer.SerializeToUtf8Bytes(result, s_indented));
                    }
                }
            }
        }

        return buffer.ToArray();
    }

    private static string Folder(string stepId, string engine) => $"steps/{Safe(stepId)}/{engine}";

    private static string InputPath(string inputId, string fileName) => $"inputs/{Safe(inputId)}/{Safe(fileName)}";

    private static string Safe(string name) => string.Concat(name.Select(c => char.IsLetterOrDigit(c) || c is '-' or '_' or '.' ? c : '_'));

    private static void Add(ZipArchive zip, HashSet<string> written, string path, byte[] content)
    {
        if (!written.Add(path))
        {
            return;
        }

        var entry = zip.CreateEntry(path, CompressionLevel.Optimal);
        using var stream = entry.Open();
        stream.Write(content);
    }

    /// <summary>How many steps, and which: <c>2: v-tsl-expired, v-tsl-wrong-signer</c>, or <c>0</c>.</summary>
    private static string Steps(IEnumerable<PlaybookStepView> steps)
    {
        var ids = steps.Select(s => s.StepId).ToList();
        return ids.Count == 0 ? "0" : $"{ids.Count}: {string.Join(", ", ids)}";
    }

    private static void Row(StringBuilder html, string name, string value) =>
        html.Append("<tr><th>").Append(E(name)).Append("</th><td>").Append(E(value)).Append("</td></tr>\n");

    private static string E(string text) => WebUtility.HtmlEncode(text);
}
