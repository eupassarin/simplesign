using System.Text.Json;
using Shouldly;
using SimpleSign.TestBench.Playbooks;
using SimpleSign.TestHelpers;

namespace SimpleSign.TestBench.Tests.Playbooks;

[Trait("Category", "Unit")]
public sealed class PlaybookValidatorTests
{
    private const string Valid = """
        {
          "schema": 2, "id": "demo", "title": "Demo", "description": "A demo.",
          "sections": [
            { "id": "s1", "title": "Revocation", "steps": [
              { "id": "good", "title": "Good", "description": "Signs with a good certificate.", "tags": ["R1", "signing"], "options": { "credentialId": "sandbox:rsa-2048" }, "expect": { "outcome": "signed" } },
              { "id": "check", "title": "Validate", "description": "Validates what good signed.", "kind": "validate", "tags": ["R1"], "options": { "fileId": "step:good" }, "expect": { "outcome": "valid" } }
            ] }
          ]
        }
        """;

    [Fact]
    public void Check_ValidPlaybook_HasNoErrors()
    {
        var check = PlaybookValidator.Check(Valid, sandbox: null);

        check.CanRun.ShouldBeTrue(string.Join("; ", check.Issues.Select(i => $"{i.Path}: {i.Message}")));
        check.Playbook!.AllSteps().Count().ShouldBe(2);
        check.Playbook.Step("good")!.Tags.ShouldBe(["R1", "signing"]);
    }

    [Fact]
    public void Check_DeclaredInput_HasNoErrors()
    {
        var check = PlaybookValidator.Check(Valid.Replace("\"sections\":", "\"inputs\": [{ \"id\": \"theirs\", \"title\": \"A signed PDF\", \"accept\": \".pdf\" }], \"sections\":", StringComparison.Ordinal)
            .Replace("\"fileId\": \"step:good\"", "\"fileId\": \"input:theirs\"", StringComparison.Ordinal), sandbox: null);

        check.CanRun.ShouldBeTrue(string.Join("; ", check.Issues.Select(i => $"{i.Path}: {i.Message}")));
        check.Issues.ShouldBeEmpty();
        check.Playbook!.Inputs.Single().Accept.ShouldBe(".pdf");
    }

    [Fact]
    public void Check_UndeclaredInput_IsAnError()
    {
        var check = PlaybookValidator.Check(Valid.Replace("\"fileId\": \"step:good\"", "\"fileId\": \"input:theirs\"", StringComparison.Ordinal), sandbox: null);

        check.CanRun.ShouldBeFalse();
        check.Issues.ShouldContain(i => i.IsError && i.Path == "$.sections[0].steps[1].options.fileId" && i.Message.Contains("input:theirs", StringComparison.Ordinal));
    }

    [Fact]
    public void Check_UnusedOrRepeatedInput_WarnsOrFails()
    {
        var check = PlaybookValidator.Check(Valid.Replace("\"sections\":",
            "\"inputs\": [{ \"id\": \"a\", \"title\": \"A\" }, { \"id\": \"a\", \"title\": \"Again\" }], \"sections\":", StringComparison.Ordinal), sandbox: null);

        check.Issues.ShouldContain(i => i.IsError && i.Path == "$.inputs[1].id");
        check.Issues.ShouldContain(i => !i.IsError && i.Path == "$.inputs" && i.Message.Contains("'a'", StringComparison.Ordinal));
    }

    [Fact]
    public void Check_StepWithoutDescription_WarnsAndCanRun()
    {
        var check = PlaybookValidator.Check(Valid.Replace("\"description\": \"Validates what good signed.\", ", "", StringComparison.Ordinal), sandbox: null);

        check.CanRun.ShouldBeTrue();
        check.Issues.ShouldHaveSingleItem().ShouldSatisfyAllConditions(
            i => i.IsError.ShouldBeFalse(),
            i => i.Path.ShouldBe("$.sections[0].steps[1].description"));
    }

    [Fact]
    public void Check_InputWithoutAccept_Warns()
    {
        var check = PlaybookValidator.Check(Valid.Replace("\"sections\":", "\"inputs\": [{ \"id\": \"theirs\", \"title\": \"A signed PDF\" }], \"sections\":", StringComparison.Ordinal)
            .Replace("\"fileId\": \"step:good\"", "\"fileId\": \"input:theirs\"", StringComparison.Ordinal), sandbox: null);

        check.CanRun.ShouldBeTrue();
        check.Issues.ShouldContain(i => !i.IsError && i.Path == "$.inputs[0].accept");
    }

    [Theory]
    [InlineData("pdf")]
    [InlineData(".p df")]
    [InlineData("application/")]
    public void Check_MalformedAccept_IsAnError(string accept)
    {
        var check = PlaybookValidator.Check(Valid.Replace("\"sections\":", $"\"inputs\": [{{ \"id\": \"theirs\", \"title\": \"A signed PDF\", \"accept\": \".xml, {accept}\" }}], \"sections\":", StringComparison.Ordinal)
            .Replace("\"fileId\": \"step:good\"", "\"fileId\": \"input:theirs\"", StringComparison.Ordinal), sandbox: null);

        check.CanRun.ShouldBeFalse();
        check.Issues.ShouldContain(i => i.IsError && i.Path == "$.inputs[0].accept" && i.Message.Contains(accept, StringComparison.Ordinal));
    }

    [Fact]
    public void Check_DssAgreesWithoutCrossValidate_Warns()
    {
        var check = PlaybookValidator.Check(Valid.Replace("\"expect\": { \"outcome\": \"signed\" }", "\"expect\": { \"outcome\": \"signed\", \"dssAgrees\": true }", StringComparison.Ordinal), sandbox: null);

        check.CanRun.ShouldBeTrue();
        check.Issues.ShouldContain(i => !i.IsError && i.Path.EndsWith(".expect.dssAgrees", StringComparison.Ordinal) && i.Message.Contains("crossValidate", StringComparison.Ordinal));
    }

    [Fact]
    public void Check_DssAgreesOnARefusal_Warns()
    {
        var check = PlaybookValidator.Check(Valid.Replace("\"expect\": { \"outcome\": \"signed\" }",
            "\"crossValidate\": true, \"expect\": { \"outcome\": \"refused\", \"dssAgrees\": true }", StringComparison.Ordinal), sandbox: null);

        check.Issues.ShouldContain(i => !i.IsError && i.Message.Contains("never sees it", StringComparison.Ordinal));
    }

    [Fact]
    public void Check_DssAgreesWithCrossValidate_DoesNotWarn()
    {
        var check = PlaybookValidator.Check(Valid.Replace("\"expect\": { \"outcome\": \"signed\" }",
            "\"crossValidate\": true, \"expect\": { \"outcome\": \"signed\", \"dssAgrees\": true }", StringComparison.Ordinal), sandbox: null);

        check.Issues.ShouldBeEmpty();
    }

    [Fact]
    public void Check_SchemaOne_IsAnErrorThatNamesSchemaTwo()
    {
        var check = PlaybookValidator.Check(Valid.Replace("\"schema\": 2", "\"schema\": 1", StringComparison.Ordinal), sandbox: null);

        check.CanRun.ShouldBeFalse();
        check.Issues.ShouldContain(i => i.Path == "$.schema" && i.Message.Contains("schema 2", StringComparison.Ordinal));
    }

    [Fact]
    public void Check_ManualStep_IsAnError() =>
        PlaybookValidator.Check(Valid.Replace("\"kind\": \"validate\"", "\"kind\": \"manual\"", StringComparison.Ordinal), sandbox: null)
            .Issues.ShouldContain(i => i.IsError && i.Path.EndsWith(".kind", StringComparison.Ordinal));

    private static string WithPolicy(string policy, string signingPolicyId) => Valid
        .Replace("\"schema\": 2,", $"\"schema\": 2, \"policies\": [{policy}],", StringComparison.Ordinal)
        .Replace("\"credentialId\": \"sandbox:rsa-2048\"", $"\"credentialId\": \"sandbox:rsa-2048\", \"signingPolicyId\": \"{signingPolicyId}\"", StringComparison.Ordinal);

    [Fact]
    public void Check_DeclaredPolicy_BuildsAndIsAccepted()
    {
        string json = WithPolicy("""{ "id": "agent", "kind": "signing", "base": "iofe", "set": { "SigningCertificate/KeyUsage": { "Level": "FAIL", "Id": ["nonRepudiation"] } } }""",
            "playbook:agent");

        var check = PlaybookValidator.Check(json, sandbox: null);

        check.CanRun.ShouldBeTrue(string.Join("; ", check.Issues.Select(i => $"{i.Path}: {i.Message}")));
        SimpleSign.Core.Policies.SigningPolicy.FromJson(PlaybookPolicies.Build(check.Playbook!.Policies[0]))
            .Find("SigningCertificate/KeyUsage")!.Ids.ShouldBe(["nonRepudiation"]);
    }

    [Theory]
    [InlineData("""{ "id": "agent", "kind": "signing", "base": "nope" }""", "playbook:agent")]
    [InlineData("""{ "id": "agent", "kind": "signing", "base": "iofe", "set": { "SigningCertificate/NoSuchThing": { "Level": "FAIL" } } }""", "playbook:agent")]
    [InlineData("""{ "id": "agent", "kind": "signing", "base": "iofe" }""", "playbook:other")]
    public void Check_BadPolicyOrUndeclaredReference_IsAnError(string policy, string reference) =>
        PlaybookValidator.Check(WithPolicy(policy, reference), sandbox: null).Issues
            .ShouldContain(i => i.IsError && i.Path.StartsWith("$.policies", StringComparison.Ordinal));

    [Fact]
    public void Check_UnknownReasonAndFault_AreErrors()
    {
        string json = Valid
            .Replace("\"tags\": [\"R1\", \"signing\"],", "\"tags\": [\"R1\"], \"sandbox\": { \"crl\": \"Broken\" },", StringComparison.Ordinal)
            .Replace("\"outcome\": \"signed\"", "\"outcome\": \"refused\", \"reason\": \"NoSuchReason\"", StringComparison.Ordinal);

        var issues = PlaybookValidator.Check(json, sandbox: null).Issues.Where(i => i.IsError).Select(i => i.Path).ToList();

        issues.ShouldContain(p => p.EndsWith(".expect.reason", StringComparison.Ordinal));
        issues.ShouldContain(p => p.EndsWith(".sandbox.crl", StringComparison.Ordinal));
    }

    [Fact]
    public void Check_StepWithoutExpectation_IsAnError() =>
        PlaybookValidator.Check(Valid.Replace(", \"expect\": { \"outcome\": \"valid\" }", "", StringComparison.Ordinal), sandbox: null)
            .Issues.ShouldContain(i => i.IsError && i.Path.EndsWith(".expect", StringComparison.Ordinal));

    [Fact]
    public void Check_ValidationOfALaterStep_IsAnError()
    {
        string json = Valid.Replace("\"fileId\": \"step:good\"", "\"fileId\": \"step:later\"", StringComparison.Ordinal);

        PlaybookValidator.Check(json, sandbox: null).Issues.ShouldContain(i => i.IsError && i.Message.Contains("step:later", StringComparison.Ordinal));
    }

    [Fact]
    public void Check_NoStep_IsAWarning()
    {
        var check = PlaybookValidator.Check("""{ "schema": 2, "id": "empty", "title": "Empty", "sections": [] }""", sandbox: null);

        check.CanRun.ShouldBeTrue();
        check.Issues.ShouldContain(i => !i.IsError);
    }

    [Fact]
    public void Check_NotJson_SaysSo() =>
        PlaybookValidator.Check("{ nope", sandbox: null).CanRun.ShouldBeFalse();

    [Fact]
    public void Merge_StepOptions_WinOverTheDefaults()
    {
        using var defaults = JsonDocument.Parse("""{ "common": { "level": "BB", "signingControls": { "auditLog": true } }, "pades": { "level": "BT" } }""");
        using var step = JsonDocument.Parse("""{ "signingControls": { "trust": ["SandboxRoot"] } }""");

        var merged = PlaybookRunner.Merge(defaults.RootElement, "pades", step.RootElement);

        merged["level"]!.GetValue<string>().ShouldBe("BT");
        merged["signingControls"]!["auditLog"]!.GetValue<bool>().ShouldBeTrue();
        merged["signingControls"]!["trust"]![0]!.GetValue<string>().ShouldBe("SandboxRoot");
    }

    [Theory]
    [InlineData("SigningException (CertificateRevoked)", "CertificateRevoked")]
    [InlineData("SigningException", null)]
    [InlineData(null, null)]
    public void ReasonOf_ErrorType_GivesTheReason(string? errorType, string? reason) =>
        PlaybookExpectations.ReasonOf(errorType).ShouldBe(reason);

    [Theory]
    [InlineData("playbook.schema.json")]
    [InlineData("options.md")]
    public void Generated_MatchesTheFileInDocs(string file)
    {
        string generated = (file.EndsWith(".json", StringComparison.Ordinal) ? PlaybookSchema.Json() : PlaybookSchema.OptionsMarkdown()).ReplaceLineEndings("\n");
        if (!generated.EndsWith('\n'))
        {
            generated += "\n";
        }

        string path = file.EndsWith(".json", StringComparison.Ordinal)
            ? RepositoryPaths.Get("docs", "schemas", file)
            : RepositoryPaths.Get("docs", "playbooks", file);
        if (Environment.GetEnvironmentVariable("SIMPLESIGN_UPDATE_DOCS") == "1")
        {
            File.WriteAllText(path, generated);
        }

        File.Exists(path).ShouldBeTrue("Run the TestBench tests once with SIMPLESIGN_UPDATE_DOCS=1 to write it.");
        File.ReadAllText(path).ReplaceLineEndings("\n").ShouldBe(generated,
            "The playbook schema or options changed: run the TestBench tests with SIMPLESIGN_UPDATE_DOCS=1 and commit docs/.");
    }

    [Fact]
    public void Samples_AreValidPlaybooks()
    {
        PlaybookSamples.All.Select(s => s.Id).ShouldBe(["eidas-baseline", "etsi-baseline", "govbr-pades", "icp-brasil-pades", "indecopi-guia-v4", "sandbox-basics"]);
        foreach (var sample in PlaybookSamples.All)
        {
            var check = PlaybookValidator.Check(PlaybookSamples.Json(sample.Id)!, sandbox: null);
            check.CanRun.ShouldBeTrue($"{sample.Id}: " + string.Join("; ", check.Issues.Where(i => i.IsError).Select(i => $"{i.Path}: {i.Message}")));
            check.Playbook!.AllSteps().ShouldAllBe(s => s.Step.Tags.Count > 0, $"{sample.Id}: every step has tags");
            check.Playbook.AllSteps().Where(s => string.IsNullOrWhiteSpace(s.Step.Description)).Select(s => s.Step.Id)
                .ShouldBeEmpty($"{sample.Id}: every step says what it runs and why (description)");
            check.Playbook.Sections.Where(s => string.IsNullOrWhiteSpace(s.Description)).Select(s => s.Id)
                .ShouldBeEmpty($"{sample.Id}: every section says what it shows (description)");
            check.Playbook.Inputs.Where(i => string.IsNullOrWhiteSpace(i.Accept) || string.IsNullOrWhiteSpace(i.Description)).Select(i => i.Id)
                .ShouldBeEmpty($"{sample.Id}: every input says which files it takes and what the steps do with it");
        }
    }

    [Fact]
    public void EtsiSample_CoversEveryChecklistItemARunCanShow()
    {
        // Rows of docs/playbooks/etsi-checklist.md whose "How" starts with P: each needs a step tagged with its id.
        var items = File.ReadAllLines(RepositoryPaths.Get("docs", "playbooks", "etsi-checklist.md"))
            .Select(l => l.Split('|', StringSplitOptions.TrimEntries))
            .Where(c => c.Length > 3 && System.Text.RegularExpressions.Regex.IsMatch(c[1], "^[A-Z]{2}-[0-9]+$") && c[^2].StartsWith('P'))
            .Select(c => c[1])
            .ToList();
        var tags = PlaybookValidator.Check(PlaybookSamples.Json("etsi-baseline")!, sandbox: null).Playbook!
            .AllSteps().SelectMany(s => s.Step.Tags).ToHashSet(StringComparer.Ordinal);

        items.ShouldNotBeEmpty();
        items.Where(i => !tags.Contains(i)).ShouldBeEmpty("checklist items with P and no step");
    }

    [Fact]
    public void IndecopiSample_CoversEveryChecklistItemARunCanShow()
    {
        // Rows of docs/playbooks/indecopi-checklist.md (items of the Guía v4.0, annex B) whose "How" starts with P: each
        // needs a step of indecopi-guia-v4 tagged with its id, or names a step of the generic playbooks that shows it
        // (sandbox-basics:ID, etsi-baseline:ID: the playbooks complement each other); every step the row names must exist.
        var rows = File.ReadAllLines(RepositoryPaths.Get("docs", "playbooks", "indecopi-checklist.md"))
            .Select(l => l.Split('|', StringSplitOptions.TrimEntries))
            .Where(c => c.Length > 3 && System.Text.RegularExpressions.Regex.IsMatch(c[1], "^[FVS]-[0-9]+$"))
            .ToList();
        var steps = PlaybookValidator.Check(PlaybookSamples.Json("indecopi-guia-v4")!, sandbox: null).Playbook!.AllSteps().ToList();
        var tags = steps.SelectMany(s => s.Step.Tags).ToHashSet(StringComparer.Ordinal);
        var ids = new Dictionary<string, HashSet<string>>(StringComparer.Ordinal)
        {
            [""] = steps.Select(s => s.Step.Id).ToHashSet(StringComparer.Ordinal),
            ["sandbox-basics"] = StepIds("sandbox-basics"),
            ["etsi-baseline"] = StepIds("etsi-baseline"),
        };
        var shown = rows.Where(c => c[^2].StartsWith('P')).ToList();
        var named = shown.ToDictionary(c => c[1], c => System.Text.RegularExpressions.Regex.Matches(c[^2], "`(?:([a-z0-9-]+):)?([a-z0-9-]+)`")
            .Select(m => (Playbook: m.Groups[1].Value, Step: m.Groups[2].Value)).ToList());

        rows.Select(c => c[1]).ShouldContain("F-32");
        rows.Select(c => c[1]).ShouldContain("V-32");
        rows.Select(c => c[1]).ShouldContain("S-4");
        shown.Where(c => !tags.Contains(c[1]) && !named[c[1]].Any(n => n.Playbook.Length > 0)).Select(c => c[1])
            .ShouldBeEmpty("checklist items with P and neither a step tagged with them nor a step of sandbox-basics or etsi-baseline");
        named.Values.SelectMany(n => n).Where(n => !ids.TryGetValue(n.Playbook, out var known) || !known.Contains(n.Step))
            .Select(n => n.Playbook.Length > 0 ? $"{n.Playbook}:{n.Step}" : n.Step)
            .ShouldBeEmpty("steps the checklist names but the playbooks do not have");
        tags.Where(t => System.Text.RegularExpressions.Regex.IsMatch(t, "^[FVS]-[0-9]+$") && !shown.Any(c => c[1] == t))
            .ShouldBeEmpty("playbook tags whose checklist item is not marked P");
    }

    [Fact]
    public void SpecificSamples_DoNotRepeatAGenericStep()
    {
        // The playbooks complement each other: a step of a trust-framework playbook that makes the same run as a step of
        // sandbox-basics or etsi-baseline belongs only to the generic one. The same run: same kind, format and options once
        // the defaults are merged, left out what does not change the case (the policy preset, the anchors, the validation
        // after signing), same Sandbox state and same expected result. A step whose file a later step uses stays.
        var generic = new[] { "sandbox-basics", "etsi-baseline" }
            .SelectMany(id => RunKeys(id).Select(r => (r.Key, Name: $"{id}:{r.Step.Id}")))
            .GroupBy(r => r.Key, StringComparer.Ordinal)
            .ToDictionary(g => g.Key, g => g.First().Name, StringComparer.Ordinal);
        var repeated = new[] { "indecopi-guia-v4", "icp-brasil-pades", "govbr-pades", "eidas-baseline" }
            .SelectMany(id => RunKeys(id).Where(r => !r.FileUsed && generic.ContainsKey(r.Key)).Select(r => $"{id}:{r.Step.Id} = {generic[r.Key]}"))
            .ToList();

        repeated.ShouldBeEmpty();
    }

    [Theory]
    [InlineData("sandbox-basics")]
    [InlineData("etsi-baseline")]
    public void GenericSamples_UseNoFrameworkPresetOrProfile(string id)
    {
        // What a trust framework's preset or profile decides belongs in that framework's playbook; the generic ones declare
        // their own policies (PlaybookPoliciesTests keeps them in step with the presets).
        string json = PlaybookSamples.Json(id)!;
        System.Text.RegularExpressions.Regex.Matches(json, "preset:(signing|validation):(iofe|icp-brasil|govbr|eidas)\\b|\"profile\":\\s*\"(Iofe|IcpBrasil|GovBr|Eidas)\"")
            .Select(m => m.Value).ShouldBeEmpty();
    }

    private static IEnumerable<(string Key, PlaybookStep Step, bool FileUsed)> RunKeys(string id)
    {
        var playbook = PlaybookValidator.Check(PlaybookSamples.Json(id)!, sandbox: null).Playbook!;
        var options = playbook.AllSteps().ToDictionary(s => s.Step.Id,
            s => PlaybookRunner.Merge(playbook.Defaults.Options, s.Step.Format ?? playbook.Defaults.Format, s.Step.Options), StringComparer.Ordinal);
        var used = options.Values.SelectMany(o => PlaybookValidator.Strings(JsonSerializer.SerializeToElement(o), "$"))
            .Where(v => v.Value.StartsWith("step:", StringComparison.Ordinal)).Select(v => v.Value[5..]).ToHashSet(StringComparer.Ordinal);
        foreach (var (_, step) in playbook.AllSteps())
        {
            var run = options[step.Id];
            foreach (string name in new[] { "signingPolicyId", "attemptRefused", "validation" })
            {
                run.Remove(name);
            }

            foreach (string name in new[] { "signingControls", "settings" })
            {
                if (run[name] is System.Text.Json.Nodes.JsonObject controls)
                {
                    controls.Remove("trust");
                    controls.Remove("policyId");
                }
            }

            string key = string.Join("|", step.Kind, step.Kind == PlaybookStepKinds.Validate ? "" : step.Format ?? playbook.Defaults.Format,
                Canonical(run), JsonSerializer.Serialize(step.Sandbox), step.Expect?.Outcome, step.Expect?.Reason, step.Expect?.SubIndication);
            yield return (key, step, used.Contains(step.Id));
        }
    }

    // The JSON with the properties of every object sorted, so the order the defaults and the step gave them does not count.
    private static string Canonical(System.Text.Json.Nodes.JsonNode? node) => node switch
    {
        System.Text.Json.Nodes.JsonObject o => "{" + string.Join(",", o.OrderBy(p => p.Key, StringComparer.Ordinal)
            .Select(p => JsonSerializer.Serialize(p.Key) + ":" + Canonical(p.Value))) + "}",
        System.Text.Json.Nodes.JsonArray a => "[" + string.Join(",", a.Select(Canonical)) + "]",
        null => "null",
        _ => node.ToJsonString(),
    };

    private static HashSet<string> StepIds(string playbook) =>
        PlaybookValidator.Check(PlaybookSamples.Json(playbook)!, sandbox: null).Playbook!.AllSteps().Select(s => s.Step.Id).ToHashSet(StringComparer.Ordinal);

    [Fact]
    public void EidasSample_CoversEveryChecklistItemARunCanShow()
    {
        // Rows of docs/playbooks/eidas-checklist.md whose "How" is P: each needs a step of eidas-baseline tagged with its
        // id, and every step id the row names must exist.
        var rows = File.ReadAllLines(RepositoryPaths.Get("docs", "playbooks", "eidas-checklist.md"))
            .Select(l => l.Split('|', StringSplitOptions.TrimEntries))
            .Where(c => c.Length > 4 && System.Text.RegularExpressions.Regex.IsMatch(c[1], "^[LQT]-[0-9]+$"))
            .ToList();
        var steps = PlaybookValidator.Check(PlaybookSamples.Json("eidas-baseline")!, sandbox: null).Playbook!.AllSteps().ToList();
        var tags = steps.SelectMany(s => s.Step.Tags).ToHashSet(StringComparer.Ordinal);
        var ids = steps.Select(s => s.Step.Id).ToHashSet(StringComparer.Ordinal);
        var shown = rows.Where(c => c[3] == "P").ToList();

        shown.ShouldNotBeEmpty();
        shown.Where(c => !tags.Contains(c[1])).Select(c => c[1]).ShouldBeEmpty("checklist items with P and no step tagged with them");
        shown.SelectMany(c => System.Text.RegularExpressions.Regex.Matches(c[4], "`([a-z0-9-]+)`").Select(m => m.Groups[1].Value))
            .Where(id => !ids.Contains(id)).ShouldBeEmpty("step ids the checklist names but the playbook does not have");
        tags.Where(t => System.Text.RegularExpressions.Regex.IsMatch(t, "^[LQT]-[0-9]+$") && !shown.Any(c => c[1] == t))
            .ShouldBeEmpty("playbook tags whose checklist item is not marked P");
    }
}
