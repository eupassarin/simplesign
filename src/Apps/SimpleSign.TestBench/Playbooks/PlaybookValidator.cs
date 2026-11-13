using System.Text.Json;
using System.Text.Json.Nodes;
using SimpleSign.Core.Signing;
using SimpleSign.TestBench.Runs;
using SimpleSign.TestBench.Sandbox;

namespace SimpleSign.TestBench.Playbooks;

/// <summary>A problem of a playbook, at a JSON path; an error stops it, a warning does not.</summary>
public sealed record PlaybookIssue(string Path, string Message, bool IsError = true);

/// <summary>A playbook read from a file, with what is wrong with it.</summary>
public sealed record PlaybookCheck(Playbook? Playbook, IReadOnlyList<PlaybookIssue> Issues)
{
    /// <summary>Whether the playbook can run.</summary>
    public bool CanRun => Playbook is not null && !Issues.Any(i => i.IsError);
}

/// <summary>Reads a playbook and checks everything that can be checked before running it.</summary>
internal static class PlaybookValidator
{
    private static readonly JsonSerializerOptions s_read = new(WorkbenchJson.Options) { ReadCommentHandling = JsonCommentHandling.Skip, AllowTrailingCommas = true };

    /// <summary>Reads <paramref name="json"/> and checks it.</summary>
    /// <param name="json">The playbook file.</param>
    /// <param name="sandbox">The connected Sandbox, to check the signer and certificate ids; null to skip.</param>
    public static PlaybookCheck Check(string json, SandboxConnection? sandbox)
    {
        Playbook? playbook;
        try
        {
            playbook = JsonSerializer.Deserialize<Playbook>(json, s_read);
        }
        catch (JsonException ex)
        {
            return new(null, [new(ex.Path ?? "$", $"Not a playbook: {ex.Message}")]);
        }

        return playbook is null ? new(null, [new("$", "The file is empty.")]) : new(playbook, Validate(playbook, sandbox));
    }

    /// <summary>The problems of a playbook.</summary>
    public static IReadOnlyList<PlaybookIssue> Validate(Playbook playbook, SandboxConnection? sandbox)
    {
        var issues = new List<PlaybookIssue>();
        void Error(string path, string message) => issues.Add(new(path, message));

        if (playbook.Schema != 2)
        {
            Error("$.schema", playbook.Schema == 1
                ? "This is a schema 1 certification script: playbooks are schema 2 (no requirements, no manual steps; steps have tags)."
                : $"Unknown schema {playbook.Schema}: this TestBench reads schema 2.");
        }

        if (string.IsNullOrWhiteSpace(playbook.Id))
        {
            Error("$.id", "The playbook needs an id.");
        }

        if (string.IsNullOrWhiteSpace(playbook.Title))
        {
            Error("$.title", "The playbook needs a title.");
        }

        if (!PlaybookEngines.All.Contains(playbook.Defaults.Engine))
        {
            Error("$.defaults.engine", $"Unknown engine '{playbook.Defaults.Engine}': use library, cli or both.");
        }

        if (!RunFormats.All.Contains(playbook.Defaults.Format))
        {
            Error("$.defaults.format", $"Unknown format '{playbook.Defaults.Format}': use pades, cades or xades.");
        }

        // The policies it adjusts: each one builds, and every playbook:ID a step names is declared.
        var policyIds = new HashSet<string>(StringComparer.Ordinal);
        for (int p = 0; p < playbook.Policies.Count; p++)
        {
            var policy = playbook.Policies[p];
            if (string.IsNullOrWhiteSpace(policy.Id) || !policyIds.Add(policy.Id))
            {
                Error($"$.policies[{p}].id", $"Policy id '{policy.Id}' is empty or repeated.");
                continue;
            }

            try
            {
                _ = PlaybookPolicies.Build(policy);
            }
            catch (ArgumentException ex)
            {
                Error($"$.policies[{p}]", ex.Message);
            }
        }

        foreach (string reference in PlaybookPolicies.References(playbook.Defaults.Options)
            .Concat(playbook.AllSteps().SelectMany(s => PlaybookPolicies.References(s.Step.Options))).Distinct(StringComparer.Ordinal))
        {
            if (!policyIds.Contains(reference))
            {
                Error("$.policies", $"A step names {PlaybookPolicies.Prefix}{reference}, which the playbook does not declare in policies.");
            }
        }

        // The files the person running it uploads: each declared once, each input:ID a step names declared.
        var inputIds = new HashSet<string>(StringComparer.Ordinal);
        for (int i = 0; i < playbook.Inputs.Count; i++)
        {
            var input = playbook.Inputs[i];
            if (string.IsNullOrWhiteSpace(input.Id) || !inputIds.Add(input.Id))
            {
                Error($"$.inputs[{i}].id", $"Input id '{input.Id}' is empty or repeated.");
            }

            if (string.IsNullOrWhiteSpace(input.Title))
            {
                Error($"$.inputs[{i}].title", "Say what to upload (title).");
            }
        }

        var usedInputs = new HashSet<string>(StringComparer.Ordinal);
        foreach (var (path, value) in Strings(playbook.Defaults.Options, "$.defaults.options")
            .Concat(playbook.Sections.SelectMany((section, s) => section.Steps.SelectMany((step, n) => Strings(step.Options, $"$.sections[{s}].steps[{n}].options")))))
        {
            if (value.StartsWith(PlaybookRunner.InputPrefix, StringComparison.Ordinal))
            {
                string id = value[PlaybookRunner.InputPrefix.Length..];
                usedInputs.Add(id);
                if (!inputIds.Contains(id))
                {
                    Error(path, $"'{value}' names no input: declare it in inputs.");
                }
            }
        }

        foreach (string unused in inputIds.Where(id => !usedInputs.Contains(id)))
        {
            issues.Add(new("$.inputs", $"No step uses the input '{unused}'.", IsError: false));
        }

        var stepIds = new HashSet<string>(StringComparer.Ordinal);
        var sectionIds = new HashSet<string>(StringComparer.Ordinal);
        for (int s = 0; s < playbook.Sections.Count; s++)
        {
            var section = playbook.Sections[s];
            if (string.IsNullOrWhiteSpace(section.Id) || !sectionIds.Add(section.Id))
            {
                Error($"$.sections[{s}].id", $"Section id '{section.Id}' is empty or repeated.");
            }

            for (int n = 0; n < section.Steps.Count; n++)
            {
                var step = section.Steps[n];
                string at = $"$.sections[{s}].steps[{n}]";
                CheckStep(step, at, playbook, stepIds, sandbox, Error);
                if (step.Expect?.DssAgrees is not null)
                {
                    if (!(step.CrossValidate ?? playbook.Defaults.CrossValidate))
                    {
                        issues.Add(new(at + ".expect.dssAgrees", "dssAgrees needs crossValidate: true (on the step or in the defaults).", IsError: false));
                    }
                    else if (step.Expect.Outcome is "refused" or "error")
                    {
                        issues.Add(new(at + ".expect.dssAgrees", $"A run expected to be {step.Expect.Outcome} produces no file, so DSS never sees it: dssAgrees cannot pass.", IsError: false));
                    }
                }
                if (string.IsNullOrWhiteSpace(step.Id) || !stepIds.Add(step.Id))
                {
                    Error(at + ".id", $"Step id '{step.Id}' is empty or repeated.");
                }
            }
        }

        if (stepIds.Count == 0)
        {
            issues.Add(new("$.sections", "The playbook has no step.", IsError: false));
        }

        return issues;
    }

    private static void CheckStep(
        PlaybookStep step, string at, Playbook playbook, HashSet<string> earlierSteps, SandboxConnection? sandbox, Action<string, string> error)
    {
        if (!PlaybookStepKinds.All.Contains(step.Kind))
        {
            error(at + ".kind", $"Unknown kind '{step.Kind}': use sign, validate or augment.");
            return;
        }

        if (string.IsNullOrWhiteSpace(step.Title))
        {
            error(at + ".title", "The step needs a title.");
        }

        if (step.Format is { } format && !RunFormats.All.Contains(format))
        {
            error(at + ".format", $"Unknown format '{format}': use pades, cades or xades.");
        }

        if (step.Engine is { } engine && !PlaybookEngines.All.Contains(engine))
        {
            error(at + ".engine", $"Unknown engine '{engine}': use library, cli or both.");
        }

        if (step.Wait is < 0 or > 300)
        {
            error(at + ".wait", "Wait 0 to 300 seconds.");
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
            CheckEnum<LotlFault>(box.Lotl, at + ".sandbox.lotl", error);
            if (sandbox is not null)
            {
                foreach (string id in box.Revoke.Where(id => sandbox.Certificates.All(c => c.Id != id)))
                {
                    error(at + ".sandbox.revoke", $"The Sandbox has no certificate '{id}'.");
                }
            }
        }

        if (step.Kind is PlaybookStepKinds.Validate or PlaybookStepKinds.Augment
            && (step.Options is not { ValueKind: JsonValueKind.Object } options || !options.TryGetProperty("fileId", out _)))
        {
            error(at + ".options.fileId", $"A{(step.Kind == PlaybookStepKinds.Augment ? "n augmentation" : " validation")} needs options.fileId (step:ID, input:ID or a sample).");
        }

        if (step.Kind == PlaybookStepKinds.Augment && (step.Engine ?? playbook.Defaults.Engine) != PlaybookEngines.Library)
        {
            error(at + ".engine", "An augmentation runs through the library: set engine to library.");
        }

        CheckProfiles(PlaybookRunner.Merge(playbook.Defaults.Options, step.Format ?? playbook.Defaults.Format, step.Options), at + ".options", error);

        foreach (var (path, value) in Strings(step.Options, at + ".options").Concat(Strings(playbook.Defaults.Options, "$.defaults.options")))
        {
            if (value.StartsWith(PlaybookRunner.ShortLivedPrefix, StringComparison.Ordinal)
                && (!int.TryParse(value[PlaybookRunner.ShortLivedPrefix.Length..], System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out int seconds)
                    || seconds is < 1 or > 3600))
            {
                error(path, $"'{value}': give the lifetime in seconds, 1 to 3600.");
            }
            else if (value.StartsWith("sandbox:", StringComparison.Ordinal) && sandbox is not null
                && sandbox.Signers.All(s => s.Id != value["sandbox:".Length..]))
            {
                error(path, $"The Sandbox has no signer '{value["sandbox:".Length..]}'.");
            }
            else if (value.StartsWith("step:", StringComparison.Ordinal) && !earlierSteps.Contains(value["step:".Length..]))
            {
                error(path, $"'{value}' names no earlier step.");
            }
        }
    }

    /// <summary>The profiles of a step: known names, <c>profileSource</c> with iofe only, and no Gov.br signature.</summary>
    private static void CheckProfiles(JsonObject options, string at, Action<string, string> error)
    {
        foreach (string part in new[] { "signingControls", "validation", "settings" })
        {
            if (options[part] is not JsonObject holder)
            {
                continue;
            }

            string? profile = Text(holder["profile"]);
            CheckEnum<TrustFrameworks.TrustProfileChoice>(profile, $"{at}.{part}.profile", error);
            CheckEnum<TrustFrameworks.ProfileListSource>(Text(holder["profileSource"]), $"{at}.{part}.profileSource", error);
            if (holder["trustProfiles"] is JsonArray extras)
            {
                foreach (var extra in extras)
                {
                    CheckEnum<TrustFrameworks.TrustProfileChoice>(Text(extra), $"{at}.{part}.trustProfiles", error);
                }
            }

            if (holder["profileSource"] is not null && !string.Equals(profile, nameof(TrustFrameworks.TrustProfileChoice.Iofe), StringComparison.OrdinalIgnoreCase)
                && !string.Equals(profile, nameof(TrustFrameworks.TrustProfileChoice.Eidas), StringComparison.OrdinalIgnoreCase))
            {
                error($"{at}.{part}.profileSource", "profileSource chooses the list of the Iofe or Eidas profile: set profile to one of them.");
            }

            if (part == "signingControls" && string.Equals(profile, nameof(TrustFrameworks.TrustProfileChoice.GovBr), StringComparison.OrdinalIgnoreCase))
            {
                error($"{at}.{part}.profile", "Gov.br signatures are made on Gov.br's service: its profile validates only.");
            }
        }

        static string? Text(JsonNode? node) => node is JsonValue value && value.TryGetValue(out string? text) ? text : null;
    }

    private static void CheckExpectation(PlaybookExpectation expect, string at, Action<string, string> error)
    {
        if (expect.Outcome is { } outcome && !PlaybookOutcomes.All.Contains(outcome))
        {
            error(at + ".outcome", $"Unknown outcome '{outcome}': use {string.Join(", ", PlaybookOutcomes.All)}.");
        }

        if (expect.Reason is { } reason && !Enum.TryParse<SigningErrorReason>(reason, out _))
        {
            error(at + ".reason", $"Unknown reason '{reason}': use a SigningErrorReason name (CertificateRevoked, UntrustedRoot…).");
        }

        if (expect.Indication is { } indication && indication is not ("TOTAL_PASSED" or "TOTAL_FAILED" or "INDETERMINATE"))
        {
            error(at + ".indication", $"Unknown indication '{indication}': use TOTAL_PASSED, TOTAL_FAILED or INDETERMINATE.");
        }

        if (expect.EtsiReport is { } etsiReport && etsiReport != "valid")
        {
            error(at + ".etsiReport", $"Unknown value '{etsiReport}': use valid.");
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
                    foreach (var inner in Strings(item, $"{path}[{i++}]"))
                    {
                        yield return inner;
                    }
                }

                break;
        }
    }
}
