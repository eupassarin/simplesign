using System.Globalization;
using System.IO.Compression;
using System.Net;
using System.Text;
using System.Text.Json;
using SimpleSign.TestBench.Documents;
using SimpleSign.TestBench.Runs;

namespace SimpleSign.TestBench.Scripts;

/// <summary>
/// The evidence package of a script run: an HTML page in the script's language with the matrix requirement → steps →
/// outcome → evidence, and a zip with that page, the script, the run, and per step the files, reports, logs and
/// attachments it links to.
/// </summary>
internal static class ScriptEvidence
{
    private static readonly JsonSerializerOptions s_indented = new(WorkbenchJson.Options) { WriteIndented = true };

    private static readonly Dictionary<string, Dictionary<string, string>> s_labels = new(StringComparer.Ordinal)
    {
        ["en"] = new(StringComparer.Ordinal)
        {
            ["matrix"] = "Requirements and evidence",
            ["requirement"] = "Requirement",
            ["group"] = "Group",
            ["status"] = "Result",
            ["steps"] = "Steps",
            ["evidence"] = "Evidence",
            ["run"] = "Run",
            ["date"] = "Date",
            ["engine"] = "Engine",
            ["expected"] = "Expected",
            ["found"] = "Found",
            ["check"] = "Check",
            ["note"] = "Note",
            ["attachments"] = "Attachments",
            ["justification"] = "Not applicable",
            ["summary"] = "Summary",
            ["passed"] = "passed",
            ["failed"] = "failed",
            ["pending"] = "pending",
            ["waiting"] = "waiting",
            ["skipped"] = "skipped",
            ["notApplicable"] = "not applicable",
            ["running"] = "running",
            ["signed"] = "Signed file",
            ["report"] = "Validation report",
            ["etsi"] = "ETSI report (XML)",
            ["log"] = "Log",
            ["dss"] = "EU DSS agrees",
            ["authority"] = "Authority",
            ["standard"] = "Standard",
        },
        ["pt"] = new(StringComparer.Ordinal)
        {
            ["matrix"] = "Requisitos e evidências",
            ["requirement"] = "Requisito",
            ["group"] = "Grupo",
            ["status"] = "Resultado",
            ["steps"] = "Passos",
            ["evidence"] = "Evidência",
            ["run"] = "Execução",
            ["date"] = "Data",
            ["engine"] = "Motor",
            ["expected"] = "Esperado",
            ["found"] = "Encontrado",
            ["check"] = "Verificação",
            ["note"] = "Observação",
            ["attachments"] = "Anexos",
            ["justification"] = "Não aplicável",
            ["summary"] = "Resumo",
            ["passed"] = "aprovado",
            ["failed"] = "reprovado",
            ["pending"] = "pendente",
            ["waiting"] = "aguardando",
            ["skipped"] = "ignorado",
            ["notApplicable"] = "não aplicável",
            ["running"] = "em execução",
            ["signed"] = "Arquivo assinado",
            ["report"] = "Relatório de validação",
            ["etsi"] = "Relatório ETSI (XML)",
            ["log"] = "Log",
            ["dss"] = "EU DSS concorda",
            ["authority"] = "Órgão",
            ["standard"] = "Norma",
        },
        ["es"] = new(StringComparer.Ordinal)
        {
            ["matrix"] = "Matriz de requisitos y evidencias",
            ["requirement"] = "Requisito",
            ["group"] = "Grupo",
            ["status"] = "Resultado",
            ["steps"] = "Pasos",
            ["evidence"] = "Evidencia",
            ["run"] = "Ejecución",
            ["date"] = "Fecha",
            ["engine"] = "Motor",
            ["expected"] = "Esperado",
            ["found"] = "Obtenido",
            ["check"] = "Verificación",
            ["note"] = "Observación",
            ["attachments"] = "Anexos",
            ["justification"] = "No aplicable",
            ["summary"] = "Resumen",
            ["passed"] = "conforme",
            ["failed"] = "no conforme",
            ["pending"] = "pendiente",
            ["waiting"] = "en espera",
            ["skipped"] = "omitido",
            ["notApplicable"] = "no aplicable",
            ["running"] = "en ejecución",
            ["signed"] = "Archivo firmado",
            ["report"] = "Informe de verificación",
            ["etsi"] = "Informe ETSI (XML)",
            ["log"] = "Registro",
            ["dss"] = "EU DSS coincide",
            ["authority"] = "Autoridad",
            ["standard"] = "Norma",
        },
    };

    /// <summary>The evidence page of a run.</summary>
    public static string Html(ScriptRun run, DocumentStore documents)
    {
        var view = run.View();
        var script = run.Script;
        string language = s_labels.ContainsKey(script.Language) ? script.Language : "en";
        var t = s_labels[language];
        string Status(string status) => t.TryGetValue(status, out string? text) ? text : status;

        var html = new StringBuilder();
        html.Append("<!DOCTYPE html>\n<html lang=\"").Append(language).Append("\">\n<head>\n<meta charset=\"utf-8\">\n<title>")
            .Append(E(script.Title)).Append("</title>\n<style>")
            .Append("body{font-family:system-ui,sans-serif;margin:24px auto;max-width:1100px;padding:0 16px;color:#1b1b1b;background:#fff}")
            .Append("table{border-collapse:collapse;width:100%;margin:8px 0 24px}td,th{border:1px solid #ccc;padding:6px 8px;text-align:left;vertical-align:top;font-size:.92em}")
            .Append("th{background:#f4f4f4}.passed{color:#11663a;font-weight:700}.failed{color:#a51d1d;font-weight:700}")
            .Append(".pending,.waiting,.skipped{color:#8a5a00}.notApplicable{color:#555}h2{margin-top:36px}code{font-size:.9em}")
            .Append("</style>\n</head>\n<body>\n");
        html.Append("<h1>").Append(E(script.Title)).Append("</h1>\n<table>\n");
        Row(html, t["authority"], script.Authority ?? "—");
        Row(html, t["standard"], script.Standard ?? "—");
        Row(html, t["run"], view.Id);
        Row(html, t["date"], view.StartedAt.ToString("yyyy-MM-dd HH:mm:ss zzz", CultureInfo.InvariantCulture));
        Row(html, t["summary"], string.Join(" · ", view.Requirements.GroupBy(r => r.Status).Select(g => $"{Status(g.Key)}: {g.Count()}")));
        html.Append("</table>\n");

        html.Append("<h2>").Append(E(t["matrix"])).Append("</h2>\n<table>\n<tr><th>").Append(E(t["requirement"])).Append("</th><th>")
            .Append(E(t["group"])).Append("</th><th>").Append(E(t["status"])).Append("</th><th>").Append(E(t["steps"])).Append("</th></tr>\n");
        foreach (var requirement in view.Requirements)
        {
            html.Append("<tr><td><b>").Append(E(requirement.Id)).Append("</b><br>").Append(E(requirement.Text)).Append("</td><td>")
                .Append(E(requirement.Group ?? "")).Append("</td><td class=\"").Append(requirement.Status).Append("\">").Append(E(Status(requirement.Status)))
                .Append("</td><td>");
            if (!requirement.Applies)
            {
                html.Append(E(t["justification"])).Append(": ").Append(E(requirement.Justification ?? ""));
            }
            else
            {
                html.Append(string.Join("<br>", requirement.Steps.Select(s => $"<a href=\"#{E(s)}\">{E(s)}</a>")));
            }

            html.Append("</td></tr>\n");
        }

        html.Append("</table>\n");
        foreach (var step in view.Steps)
        {
            var definition = script.AllSteps().First(s => s.Step.Id == step.StepId).Step;
            html.Append("<h2 id=\"").Append(E(step.StepId)).Append("\">").Append(E(step.StepId)).Append(" — ").Append(E(step.Title))
                .Append(" <span class=\"").Append(step.Status).Append("\">(").Append(E(Status(step.Status))).Append(")</span></h2>\n");
            if (definition.Description is { } description)
            {
                html.Append("<p>").Append(E(description)).Append("</p>\n");
            }

            if (definition.Manual is { } manual)
            {
                html.Append("<p>").Append(E(manual.Instructions)).Append("</p>\n");
            }

            if (step.Message is { } message)
            {
                html.Append("<p class=\"failed\">").Append(E(message)).Append("</p>\n");
            }

            foreach (var engineRun in step.Runs)
            {
                html.Append("<p><b>").Append(E(t["engine"])).Append(":</b> ").Append(E(engineRun.Engine)).Append(" · ")
                    .Append(E(t["run"])).Append(' ').Append(E(engineRun.RunId)).Append(" · ").Append(engineRun.Ms).Append(" ms</p>\n<table>\n<tr><th>")
                    .Append(E(t["check"])).Append("</th><th>").Append(E(t["expected"])).Append("</th><th>").Append(E(t["found"])).Append("</th></tr>\n");
                foreach (var check in engineRun.Checks)
                {
                    html.Append("<tr><td>").Append(E(check.What)).Append("</td><td>").Append(E(check.Expected)).Append("</td><td class=\"")
                        .Append(check.Passed ? "passed" : "failed").Append("\">").Append(E(check.Found)).Append("</td></tr>\n");
                }

                html.Append("</table>\n<p><b>").Append(E(t["evidence"])).Append(":</b> ");
                var links = new List<string>();
                string folder = Folder(step.StepId, engineRun.Engine);
                if (engineRun.OutputId is { } output && documents.TryGet(output, out var signed))
                {
                    links.Add($"<a href=\"{folder}/{E(signed!.FileName)}\">{E(t["signed"])}</a>");
                }

                if (engineRun.ReportId is not null)
                {
                    links.Add($"<a href=\"{folder}/report.json\">{E(t["report"])}</a>");
                }

                if (engineRun.EtsiReportId is not null)
                {
                    links.Add($"<a href=\"{folder}/etsi-report.xml\">{E(t["etsi"])}</a>");
                }

                links.Add($"<a href=\"{folder}/run.json\">{E(t["log"])}</a>");
                if (engineRun.DssAgrees is { } agrees)
                {
                    links.Add($"{E(t["dss"])}: {(agrees ? "✓" : "✗")}");
                }

                html.Append(string.Join(" · ", links)).Append("</p>\n");
            }

            if (step.Note is { } note)
            {
                html.Append("<p><b>").Append(E(t["note"])).Append(":</b> ").Append(E(note)).Append("</p>\n");
            }

            if (step.Attachments.Count > 0)
            {
                html.Append("<p><b>").Append(E(t["attachments"])).Append(":</b> ")
                    .Append(string.Join(" · ", step.Attachments.Select(a => $"<a href=\"{Folder(step.StepId, "manual")}/{E(a.FileName)}\">{E(a.FileName)}</a>")))
                    .Append("</p>\n");
            }
        }

        html.Append("</body>\n</html>\n");
        return html.ToString();
    }

    /// <summary>The zip of the evidence: the page, the script, the run and every file the page links to.</summary>
    public static byte[] Zip(ScriptRun run, DocumentStore documents, RunService runs)
    {
        using var buffer = new MemoryStream();
        var written = new HashSet<string>(StringComparer.Ordinal); // a Create-mode archive cannot list its entries
        using (var zip = new ZipArchive(buffer, ZipArchiveMode.Create, leaveOpen: true))
        {
            Add(zip, written, "evidence.html", Encoding.UTF8.GetBytes(Html(run, documents)));
            Add(zip, written, "script.json", Encoding.UTF8.GetBytes(run.Json));
            Add(zip, written, "run.json", JsonSerializer.SerializeToUtf8Bytes(run.View(), s_indented));
            foreach (var step in run.View().Steps)
            {
                foreach (var engineRun in step.Runs)
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

                foreach (var attachment in step.Attachments)
                {
                    if (documents.TryGet(attachment.Id, out var file))
                    {
                        Add(zip, written, $"{Folder(step.StepId, "manual")}/{attachment.FileName}", file!.Content);
                    }
                }
            }
        }

        return buffer.ToArray();
    }

    private static string Folder(string stepId, string engine) => $"steps/{Safe(stepId)}/{engine}";

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

    private static void Row(StringBuilder html, string name, string value) =>
        html.Append("<tr><th>").Append(E(name)).Append("</th><td>").Append(E(value)).Append("</td></tr>\n");

    private static string E(string text) => WebUtility.HtmlEncode(text);
}
