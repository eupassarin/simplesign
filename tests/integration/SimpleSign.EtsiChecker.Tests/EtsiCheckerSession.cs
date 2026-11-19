using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using SimpleSign.TestHelpers;
using Xunit;

namespace SimpleSign.EtsiChecker.Tests;

/// <summary>
/// One sign-in to the checker for the tests of a class, and what they leave behind:
/// <list type="bullet">
/// <item><see cref="EtsiChecker.EvidenceDirectory"/> (committed): <c>&lt;sample&gt;/&lt;signature&gt;.xml</c>, the
/// checker's raw report of each signature; <c>results.json</c>, the outcome of every sample checked so far; and
/// <c>summary.md</c>, a table made from it.</item>
/// <item><see cref="EtsiChecker.ArtifactsDirectory"/> (not committed): each signed sample and every document of its
/// report.</item>
/// </list>
/// A run of some samples only updates theirs in <c>results.json</c>.
/// </summary>
public sealed class EtsiCheckerSession : IAsyncLifetime, IDisposable
{
    private static readonly JsonSerializerOptions Indented = new() { WriteIndented = true };

    private readonly HttpClient _http = new() { BaseAddress = EtsiChecker.BaseAddress, Timeout = TimeSpan.FromMinutes(5) };
    private readonly Dictionary<string, JsonObject> _results = [];
    private EtsiCheckerClient? _client;
    private string? _commit;

    /// <summary>The client, signed in with <paramref name="user"/> on first use.</summary>
    public EtsiCheckerClient Client(string user, string password) => _client ??= new EtsiCheckerClient(_http, user, password);

    /// <summary>Keeps what the checker said of <paramref name="sample"/>.</summary>
    /// <param name="sample">The sample.</param>
    /// <param name="signed">The file sent.</param>
    /// <param name="upload">The checker's answer.</param>
    /// <param name="known">The failures accepted as known issues.</param>
    public async Task RecordAsync(EtsiSample sample, byte[] signed, EtsiCheckerUpload upload, IReadOnlyCollection<EtsiFinding> known)
    {
        ArgumentNullException.ThrowIfNull(sample);
        ArgumentNullException.ThrowIfNull(upload);
        var report = upload.Report;

        string evidence = Path.Combine(EtsiChecker.EvidenceDirectory, sample.Id);
        if (Directory.Exists(evidence))
        {
            Directory.Delete(evidence, recursive: true);
        }

        Directory.CreateDirectory(evidence);
        foreach (var (signature, xml) in report.Signatures)
        {
            await File.WriteAllTextAsync(Path.Combine(evidence, signature + ".xml"), xml);
        }

        string artifacts = Path.Combine(EtsiChecker.ArtifactsDirectory, sample.Id);
        Directory.CreateDirectory(artifacts);
        await File.WriteAllBytesAsync(Path.Combine(artifacts, sample.FileName), signed);
        foreach (var (path, content) in upload.Documents)
        {
            string target = Path.GetFullPath(Path.Combine(artifacts, path));
            if (target.StartsWith(Path.GetFullPath(artifacts) + Path.DirectorySeparatorChar, StringComparison.Ordinal))
            {
                Directory.CreateDirectory(Path.GetDirectoryName(target)!);
                await File.WriteAllBytesAsync(target, content);
            }
        }

        _commit ??= await CommitAsync();
        int unexpected = report.Failures.Count(f => !known.Contains(f));
        _results[sample.Id] = new JsonObject
        {
            ["format"] = sample.Format.ToString().ToUpperInvariant(),
            ["level"] = sample.Level.ToString(),
            ["description"] = sample.Description,
            ["checkedAt"] = DateTimeOffset.UtcNow.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture),
            ["commit"] = _commit,
            ["specification"] = EtsiCheckerClient.Specification(sample.Format),
            ["signatures"] = report.Signatures.Count,
            ["passed"] = report.Successes,
            ["verdict"] = unexpected > 0 ? "fail" : known.Count > 0 ? "known-issues" : "pass",
            ["failures"] = Findings(report.Failures, known),
            ["warnings"] = Findings(report.Warnings, known),
        };
    }

    /// <inheritdoc/>
    public Task InitializeAsync() => Task.CompletedTask;

    /// <inheritdoc/>
    public async Task DisposeAsync()
    {
        if (_results.Count == 0)
        {
            return;
        }

        string path = Path.Combine(EtsiChecker.EvidenceDirectory, "results.json");
        var all = File.Exists(path) ? JsonNode.Parse(await File.ReadAllTextAsync(path))!.AsObject() : [];
        foreach (var (id, result) in _results)
        {
            all[id] = result;
        }

        // In the corpus's order; samples no longer in it are dropped.
        var ordered = new JsonObject();
        foreach (var sample in EtsiCorpus.Samples.Where(s => all.ContainsKey(s.Id)))
        {
            ordered[sample.Id] = all[sample.Id]!.DeepClone();
        }

        await File.WriteAllTextAsync(path, ordered.ToJsonString(Indented) + "\n");
        await File.WriteAllTextAsync(Path.Combine(EtsiChecker.EvidenceDirectory, "summary.md"), Summary(ordered));
    }

    /// <inheritdoc/>
    public void Dispose() => _http.Dispose();

    /// <summary>The table of <c>summary.md</c>.</summary>
    public static string Summary(JsonObject results)
    {
        ArgumentNullException.ThrowIfNull(results);
        var text = new StringBuilder();
        text.Append("# ETSI Signatures Conformance Checker: results\n\n")
            .Append("Written by `SimpleSign.EtsiChecker.Tests` from `results.json`; see [README.md](README.md). ")
            .Append("Each sample was checked against the baseline profile of its format (EN 319 142-1, EN 319 122-1, EN 319 132-1). ")
            .Append("*Failures* are the checker's failures nobody expects; *Expected* are those `known-issues.json` lists, ")
            .Append("such as the SubFilter of a sample made not to be baseline.\n\n")
            .Append("| Sample | Format | Level | How it was made | Signatures | Checks passed | Failures | Expected | Warnings | Result | Checked |\n")
            .Append("|---|---|---|---|---|---|---|---|---|---|---|\n");
        foreach (var (id, node) in results)
        {
            var r = node!.AsObject();
            string verdict = (string?)r["verdict"] switch
            {
                "pass" => "✅",
                "known-issues" => "✅ expected",
                _ => "❌",
            };
            var failures = r["failures"]!.AsArray();
            int expected = failures.Count(f => f!["known"]!.GetValue<bool>());
            text.Append(CultureInfo.InvariantCulture,
                $"| [{id}]({id}/) | {r["format"]} | {r["level"]} | {r["description"]} | {r["signatures"]} | {r["passed"]} | {failures.Count - expected} | {expected} | {r["warnings"]!.AsArray().Count} | {verdict} | {r["checkedAt"]} ({r["commit"]}) |\n");
        }

        var findings = results.SelectMany(r => r.Value!["failures"]!.AsArray().Concat(r.Value!["warnings"]!.AsArray())
            .Select(f => (Sample: r.Key, Finding: f!.AsObject()))).ToList();
        if (findings.Count > 0)
        {
            text.Append("\n## Failures and warnings\n\n");
            foreach (var (sample, finding) in findings)
            {
                text.Append(CultureInfo.InvariantCulture,
                    $"- **{sample}**, {finding["signature"]}: `{finding["element"]}` `{finding["check"]}`{(finding["known"]!.GetValue<bool>() ? " (expected)" : "")}");
                if ((string?)finding["path"] is { Length: > 0 } where)
                {
                    text.Append(CultureInfo.InvariantCulture, $" at `{where}`");
                }

                text.Append(CultureInfo.InvariantCulture, $": {finding["message"]}\n");
            }
        }

        return text.ToString();
    }

    private static JsonArray Findings(IEnumerable<EtsiFinding> findings, IReadOnlyCollection<EtsiFinding> known) =>
        [.. findings.Select(f => (JsonNode)new JsonObject
        {
            ["signature"] = f.Signature,
            ["element"] = f.Element,
            ["check"] = f.Check,
            ["path"] = f.Path,
            ["message"] = f.Message,
            ["known"] = known.Contains(f),
        })];

    private static async Task<string> CommitAsync()
    {
        try
        {
            var git = await ExternalProcess.RunAsync("git", ["-C", RepositoryPaths.Root, "rev-parse", "--short", "HEAD"]);
            return git.ExitCode == 0 ? git.Stdout.Trim() : "unknown";
        }
        catch (System.ComponentModel.Win32Exception)
        {
            return "unknown";
        }
    }
}
