using System.Text;
using System.Text.Json;
using SimpleSign.Core.Signing;
using SimpleSign.TestBench.Runs;
using SimpleSign.TestBench.Sandbox;

namespace SimpleSign.TestBench.Scripts;

/// <summary>A problem of a script, at a JSON path; an error stops the run, a warning does not.</summary>
public sealed record ScriptIssue(string Path, string Message, bool IsError = true);

/// <summary>A script read from a file, with what is wrong with it.</summary>
public sealed record ScriptCheck(CertificationScript? Script, IReadOnlyList<ScriptIssue> Issues)
{
    /// <summary>Whether the script can run.</summary>
    public bool CanRun => Script is not null && !Issues.Any(i => i.IsError);
}

/// <summary>Reads a certification script and checks everything that can be checked before running it.</summary>
internal static class ScriptValidator
{
    private static readonly JsonSerializerOptions s_read = new(WorkbenchJson.Options) { ReadCommentHandling = JsonCommentHandling.Skip, AllowTrailingCommas = true };

    /// <summary>Reads <paramref name="json"/> and checks it.</summary>
    /// <param name="json">The script file.</param>
    /// <param name="sandbox">The connected Sandbox, to check the signer and certificate ids; null to skip.</param>
    public static ScriptCheck Check(string json, SandboxConnection? sandbox)
    {
        CertificationScript? script;
        try
        {
            script = JsonSerializer.Deserialize<CertificationScript>(json, s_read);
        }
        catch (JsonException ex)
        {
            return new(null, [new(ex.Path ?? "$", $"Not a certification script: {ex.Message}")]);
        }

        return script is null ? new(null, [new("$", "The file is empty.")]) : new(script, Validate(script, sandbox));
    }

    /// <summary>The problems of a script.</summary>
    public static IReadOnlyList<ScriptIssue> Validate(CertificationScript script, SandboxConnection? sandbox)
    {
        var issues = new List<ScriptIssue>();
        void Error(string path, string message) => issues.Add(new(path, message));
        void Warn(string path, string message) => issues.Add(new(path, message, IsError: false));

        if (script.Schema != 1)
        {
            Error("$.schema", $"Unknown schema {script.Schema}: this TestBench reads schema 1.");
        }

        if (string.IsNullOrWhiteSpace(script.Id))
        {
            Error("$.id", "The script needs an id.");
        }

        if (string.IsNullOrWhiteSpace(script.Title))
        {
            Error("$.title", "The script needs a title.");
        }

        if (!ScriptEngines.All.Contains(script.Defaults.Engine))
        {
            Error("$.defaults.engine", $"Unknown engine '{script.Defaults.Engine}': use library, cli or both.");
        }

        if (!RunFormats.All.Contains(script.Defaults.Format))
        {
            Error("$.defaults.format", $"Unknown format '{script.Defaults.Format}': use pades, cades or xades.");
        }

        var requirementIds = new HashSet<string>(StringComparer.Ordinal);
        for (int i = 0; i < script.Requirements.Count; i++)
        {
            var requirement = script.Requirements[i];
            string at = $"$.requirements[{i}]";
            if (string.IsNullOrWhiteSpace(requirement.Id) || !requirementIds.Add(requirement.Id))
            {
                Error(at + ".id", $"Requirement id '{requirement.Id}' is empty or repeated.");
            }

            if (!requirement.Applies && string.IsNullOrWhiteSpace(requirement.Justification))
            {
                Error(at + ".justification", $"Requirement '{requirement.Id}' does not apply: say why (justification).");
            }
        }

        var covered = new HashSet<string>(StringComparer.Ordinal);
        var stepIds = new HashSet<string>(StringComparer.Ordinal);
        var sectionIds = new HashSet<string>(StringComparer.Ordinal);
        for (int s = 0; s < script.Sections.Count; s++)
        {
            var section = script.Sections[s];
            if (string.IsNullOrWhiteSpace(section.Id) || !sectionIds.Add(section.Id))
            {
                Error($"$.sections[{s}].id", $"Section id '{section.Id}' is empty or repeated.");
            }

            for (int n = 0; n < section.Steps.Count; n++)
            {
                var step = section.Steps[n];
                string at = $"$.sections[{s}].steps[{n}]";
                if (string.IsNullOrWhiteSpace(step.Id) || !stepIds.Add(step.Id))
                {
                    Error(at + ".id", $"Step id '{step.Id}' is empty or repeated.");
                }

                CheckStep(step, at, script, requirementIds, stepIds, sandbox, Error, Warn);
                covered.UnionWith(step.Requirements);
            }
        }

        foreach (var requirement in script.Requirements.Where(r => r.Applies && !covered.Contains(r.Id)))
        {
            Warn("$.requirements", $"Requirement '{requirement.Id}' applies but no step shows it.");
        }

        return issues;
    }

    private static void CheckStep(
        ScriptStep step, string at, CertificationScript script, HashSet<string> requirementIds, HashSet<string> earlierSteps,
        SandboxConnection? sandbox, Action<string, string> error, Action<string, string> warn)
    {
        if (!ScriptStepKinds.All.Contains(step.Kind))
        {
            error(at + ".kind", $"Unknown kind '{step.Kind}': use sign, validate or manual.");
            return;
        }

        foreach (string id in step.Requirements.Where(r => !requirementIds.Contains(r)))
        {
            error(at + ".requirements", $"Requirement '{id}' is not in the requirements list.");
        }

        if (step.Requirements.Count == 0)
        {
            warn(at + ".requirements", $"Step '{step.Id}' shows no requirement.");
        }

        if (step.Kind == ScriptStepKinds.Manual)
        {
            if (string.IsNullOrWhiteSpace(step.Manual?.Instructions))
            {
                error(at + ".manual.instructions", "A manual step needs instructions.");
            }

            return;
        }

        if (step.Format is { } format && !RunFormats.All.Contains(format))
        {
            error(at + ".format", $"Unknown format '{format}': use pades, cades or xades.");
        }

        if (step.Engine is { } engine && !ScriptEngines.All.Contains(engine))
        {
            error(at + ".engine", $"Unknown engine '{engine}': use library, cli or both.");
        }

        if (step.Expect is null)
        {
            error(at + ".expect", "Say what the run must show (expect).");
        }
        else
        {
            CheckExpectation(step.Expect, at + ".expect", error);
        }

        if (step.Sandbox is { } box)
        {
            CheckEnum<CrlFault>(box.Crl, at + ".sandbox.crl", error);
            CheckEnum<OcspFault>(box.Ocsp, at + ".sandbox.ocsp", error);
            CheckEnum<TsaFault>(box.Tsa, at + ".sandbox.tsa", error);
            CheckEnum<TlFault>(box.TrustedList, at + ".sandbox.trustedList", error);
            if (sandbox is not null)
            {
                foreach (string id in box.Revoke.Where(id => sandbox.Certificates.All(c => c.Id != id)))
                {
                    error(at + ".sandbox.revoke", $"The Sandbox has no certificate '{id}'.");
                }
            }
        }

        if (step.Kind == ScriptStepKinds.Validate
            && (step.Options is not { ValueKind: JsonValueKind.Object } options || !options.TryGetProperty("fileId", out _)))
        {
            error(at + ".options.fileId", "A validation needs options.fileId (step:ID or sample:ID).");
        }

        foreach (var (path, value) in Strings(step.Options, at + ".options").Concat(Strings(script.Defaults.Options, "$.defaults.options")))
        {
            if (value.StartsWith("sandbox:", StringComparison.Ordinal) && sandbox is not null
                && sandbox.Signers.All(s => s.Id != value["sandbox:".Length..]))
            {
                error(path, $"The Sandbox has no signer '{value["sandbox:".Length..]}'.");
            }
            else if (value.StartsWith("step:", StringComparison.Ordinal)
                && (!earlierSteps.Contains(value["step:".Length..]) || value["step:".Length..] == step.Id))
            {
                error(path, $"'{value}' names no earlier step.");
            }
        }
    }

    private static void CheckExpectation(ScriptExpectation expect, string at, Action<string, string> error)
    {
        if (expect.Outcome is { } outcome && !ScriptOutcomes.All.Contains(outcome))
        {
            error(at + ".outcome", $"Unknown outcome '{outcome}': use {string.Join(", ", ScriptOutcomes.All)}.");
        }

        if (expect.Reason is { } reason && !Enum.TryParse<SigningErrorReason>(reason, out _))
        {
            error(at + ".reason", $"Unknown reason '{reason}': use a SigningErrorReason name (CertificateRevoked, UntrustedRoot…).");
        }

        if (expect.Indication is { } indication && indication is not ("TOTAL_PASSED" or "TOTAL_FAILED" or "INDETERMINATE"))
        {
            error(at + ".indication", $"Unknown indication '{indication}': use TOTAL_PASSED, TOTAL_FAILED or INDETERMINATE.");
        }

        if (expect.Level is { } level && level is not ("B-B" or "B-T" or "B-LT" or "B-LTA"))
        {
            error(at + ".level", $"Unknown level '{level}': use B-B, B-T, B-LT or B-LTA.");
        }
    }

    private static void CheckEnum<T>(string? value, string path, Action<string, string> error)
        where T : struct, Enum
    {
        if (value is not null && !Enum.TryParse<T>(value, ignoreCase: true, out _))
        {
            error(path, $"Unknown value '{value}': use {string.Join(", ", Enum.GetNames<T>())}.");
        }
    }

    /// <summary>Every string value of <paramref name="element"/>, with its JSON path.</summary>
    internal static IEnumerable<(string Path, string Value)> Strings(JsonElement? element, string path)
    {
        if (element is not { } e)
        {
            yield break;
        }

        switch (e.ValueKind)
        {
            case JsonValueKind.String:
                yield return (path, e.GetString()!);
                break;
            case JsonValueKind.Object:
                foreach (var property in e.EnumerateObject())
                {
                    foreach (var inner in Strings(property.Value, path + "." + property.Name))
                    {
                        yield return inner;
                    }
                }

                break;
            case JsonValueKind.Array:
                int i = 0;
                foreach (var item in e.EnumerateArray())
                {
                    foreach (var inner in Strings(item, new StringBuilder(path).Append('[').Append(i++).Append(']').ToString()))
                    {
                        yield return inner;
                    }
                }

                break;
        }
    }
}
