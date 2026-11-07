using System.Globalization;
using System.Text;
using System.Text.Json;
using SimpleSign.TestBench.Credentials;
using SimpleSign.TestBench.Sandbox;

namespace SimpleSign.TestBench.Runs;

/// <summary>The certificate a run used, as the evidence names it.</summary>
internal sealed record EvidenceCertificate(string Holder, string Subject, string Issuer, string Source, string NotBefore, string NotAfter);

/// <summary>The Sandbox a run used, as the evidence names it.</summary>
internal sealed record EvidenceSandbox(string Name, string Url, string RootSubject, string RootThumbprint);

/// <summary>
/// A run written as evidence for a certification file: when, with what (environment, certificate,
/// options), what came out (the refusal and its reason, or the signature and the verdicts), and
/// every network request it made (CRL, OCSP, TSA, AIA, CSC), from the run's own log.
/// </summary>
internal sealed record EvidenceReport(
    string RunId,
    string Kind,
    string Format,
    DateTimeOffset StartedAt,
    DateTimeOffset GeneratedAt,
    string TestBenchVersion,
    string Runtime,
    EvidenceSandbox? Sandbox,
    EvidenceCertificate? Certificate,
    string? SigningPolicy,
    string? Timestamp,
    string? RequestedLevel,
    string? AchievedLevel,
    bool Success,
    string? ErrorType,
    string? Error,
    string? Overall,
    IReadOnlyList<RunVerdict> Verdicts,
    IReadOnlyList<string> Network,
    IReadOnlyList<string> Warnings,
    IReadOnlyList<string> LibraryWarnings,
    JsonElement Options)
{
    /// <summary>Builds the evidence of a finished run.</summary>
    public static EvidenceReport From(RunView run, SandboxEnvironment sandbox, CredentialStore credentials, string version)
    {
        ArgumentNullException.ThrowIfNull(run);
        ArgumentNullException.ThrowIfNull(sandbox);
        ArgumentNullException.ThrowIfNull(credentials);
        string? Text(string property) =>
            run.Options.ValueKind == JsonValueKind.Object && run.Options.TryGetProperty(property, out var value) && value.ValueKind == JsonValueKind.String ? value.GetString() : null;
        string? timestamp = run.Options.ValueKind == JsonValueKind.Object && run.Options.TryGetProperty("timestamp", out var tsa) && tsa.ValueKind == JsonValueKind.Object
            ? (tsa.TryGetProperty("provider", out var p) ? p.GetString() : null) + (tsa.TryGetProperty("url", out var u) && u.ValueKind == JsonValueKind.String ? $" ({u.GetString()})" : "")
            : null;
        EvidenceCertificate? certificate = null;
        if (Text("credentialId") is { } id && credentials.TryGet(id, out var handle) && handle is not null)
        {
            var facts = handle.Facts;
            certificate = new EvidenceCertificate(facts.Holder, facts.Subject, facts.Issuer, facts.Source, facts.NotBefore, facts.NotAfter);
        }

        return new EvidenceReport(
            run.Id,
            run.Kind,
            run.Format,
            run.StartedAt,
            DateTimeOffset.UtcNow,
            version,
            System.Runtime.InteropServices.RuntimeInformation.FrameworkDescription + " · " + System.Runtime.InteropServices.RuntimeInformation.OSDescription,
            sandbox.Current is { } c ? new EvidenceSandbox(c.Info.Name, c.Url.AbsoluteUri, c.Info.RootSubject, c.Info.RootThumbprint) : null,
            certificate,
            Text("signingPolicy"),
            timestamp,
            run.RequestedLevel,
            run.AchievedLevel,
            run.Success,
            run.ErrorType,
            run.Error,
            run.Overall,
            run.Validation,
            [.. run.Logs.Where(l => l.Source == "network").Select(l => $"+{l.Ms} ms  {l.Message}")],
            run.Warnings,
            [.. run.Logs.Where(l => l.Source != "network" && l.Level is "Warning" or "Error" or "Critical").Select(l => $"+{l.Ms} ms  [{l.Level}] {l.Message}")],
            run.Options);
    }

    /// <summary>The evidence as Markdown, to attach to a certification file.</summary>
    public string ToMarkdown()
    {
        var md = new StringBuilder();
        void Line(string text) => md.Append(text).Append('\n');
        string Time(DateTimeOffset value) => value.UtcDateTime.ToString("yyyy-MM-dd HH:mm:ss 'UTC'", CultureInfo.InvariantCulture);
        static string Cell(string? text) => (text ?? "—").Replace("|", "\\|", StringComparison.Ordinal).Replace("\n", " ", StringComparison.Ordinal);

        Line($"# Evidence — {Kind} run {RunId}");
        Line("");
        Line($"- **Run started:** {Time(StartedAt)}");
        Line($"- **Report generated:** {Time(GeneratedAt)}");
        Line($"- **Application:** SimpleSign TestBench {TestBenchVersion} ({Runtime})");
        Line($"- **Format:** {Format.ToUpperInvariant()}");
        Line(Sandbox is null
            ? "- **Test environment:** none (real network only)"
            : $"- **Test environment:** SimpleSign Sandbox '{Sandbox.Name}' at {Sandbox.Url} — root {Sandbox.RootSubject} (SHA-1 {Sandbox.RootThumbprint})");
        if (Certificate is { } c)
        {
            Line($"- **Certificate:** {c.Holder} — {c.Subject}");
            Line($"  - issuer: {c.Issuer}; valid {c.NotBefore} → {c.NotAfter}; source: {c.Source}");
        }

        if (SigningPolicy is not null)
        {
            Line($"- **Signing policy:** {SigningPolicy}");
        }

        if (Timestamp is not null)
        {
            Line($"- **TSA:** {Timestamp}");
        }

        if (RequestedLevel is not null)
        {
            Line($"- **Requested level:** {RequestedLevel}");
        }

        Line("");
        Line("## Outcome");
        Line("");
        if (Success)
        {
            Line(Kind == RunKinds.Validate ? $"Validated: **{Overall ?? "—"}**." : $"Signed{(AchievedLevel is null ? "" : $" at **{AchievedLevel}**")}{(Overall is null ? "" : $"; validation: **{Overall}**")}.");
        }
        else
        {
            Line($"**Refused** — {ErrorType ?? "error"}");
            Line("");
            Line($"> {Error}");
        }

        if (Verdicts.Count > 0)
        {
            Line("");
            Line("## Verdicts");
            Line("");
            Line("| Signature | Signer | Indication | Sub-indication | Checks that did not pass |");
            Line("|---|---|---|---|---|");
            foreach (var v in Verdicts)
            {
                string failed = string.Join("; ", v.Checks.Where(k => k.Status is "fail" or "warn").Select(k => $"{k.Name}: {k.Status}{(k.Detail is null ? "" : $" ({k.Detail})")}"));
                Line($"| {Cell(v.Label)} | {Cell(v.Signer)} | {Cell(v.Indication)} | {Cell(v.SubIndication)} | {Cell(failed.Length == 0 ? null : failed)} |");
            }
        }

        Line("");
        Line("## Network requests");
        Line("");
        if (Network.Count == 0)
        {
            Line("None.");
        }
        else
        {
            Line("```");
            foreach (string request in Network)
            {
                Line(request);
            }

            Line("```");
        }

        if (Warnings.Count > 0 || LibraryWarnings.Count > 0)
        {
            Line("");
            Line("## Warnings");
            Line("");
            foreach (string warning in Warnings)
            {
                Line($"- {warning}");
            }

            foreach (string warning in LibraryWarnings)
            {
                Line($"- {warning}");
            }
        }

        Line("");
        Line("## Options");
        Line("");
        Line("```json");
        Line(JsonSerializer.Serialize(Options, s_indented));
        Line("```");
        return md.ToString();
    }

    private static readonly JsonSerializerOptions s_indented = new() { WriteIndented = true };
}
