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
              { "id": "good", "title": "Good", "tags": ["R1", "signing"], "options": { "credentialId": "sandbox:rsa-2048" }, "expect": { "outcome": "signed" } },
              { "id": "check", "title": "Validate", "kind": "validate", "tags": ["R1"], "options": { "fileId": "step:good" }, "expect": { "outcome": "valid" } }
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
        PlaybookSamples.All.Select(s => s.Id).ShouldBe(["etsi-baseline", "govbr-pades", "icp-brasil-pades", "indecopi-guia-v4", "sandbox-basics"]);
        foreach (var sample in PlaybookSamples.All)
        {
            var check = PlaybookValidator.Check(PlaybookSamples.Json(sample.Id)!, sandbox: null);
            check.CanRun.ShouldBeTrue($"{sample.Id}: " + string.Join("; ", check.Issues.Where(i => i.IsError).Select(i => $"{i.Path}: {i.Message}")));
            check.Playbook!.AllSteps().ShouldAllBe(s => s.Step.Tags.Count > 0, $"{sample.Id}: every step has tags");
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
        // needs a step of indecopi-guia-v4 tagged with its id, and every step id the row names must exist.
        var rows = File.ReadAllLines(RepositoryPaths.Get("docs", "playbooks", "indecopi-checklist.md"))
            .Select(l => l.Split('|', StringSplitOptions.TrimEntries))
            .Where(c => c.Length > 3 && System.Text.RegularExpressions.Regex.IsMatch(c[1], "^[FVS]-[0-9]+$"))
            .ToList();
        var steps = PlaybookValidator.Check(PlaybookSamples.Json("indecopi-guia-v4")!, sandbox: null).Playbook!.AllSteps().ToList();
        var tags = steps.SelectMany(s => s.Step.Tags).ToHashSet(StringComparer.Ordinal);
        var ids = steps.Select(s => s.Step.Id).ToHashSet(StringComparer.Ordinal);
        var shown = rows.Where(c => c[^2].StartsWith('P')).ToList();

        rows.Select(c => c[1]).ShouldContain("F-32");
        rows.Select(c => c[1]).ShouldContain("V-32");
        rows.Select(c => c[1]).ShouldContain("S-4");
        shown.Where(c => !tags.Contains(c[1])).Select(c => c[1]).ShouldBeEmpty("checklist items with P and no step tagged with them");
        shown.SelectMany(c => System.Text.RegularExpressions.Regex.Matches(c[^2], "`([a-z0-9-]+)`").Select(m => m.Groups[1].Value))
            .Where(id => !ids.Contains(id)).ShouldBeEmpty("step ids the checklist names but the playbook does not have");
        tags.Where(t => System.Text.RegularExpressions.Regex.IsMatch(t, "^[FVS]-[0-9]+$") && !shown.Any(c => c[1] == t))
            .ShouldBeEmpty("playbook tags whose checklist item is not marked P");
    }
}
