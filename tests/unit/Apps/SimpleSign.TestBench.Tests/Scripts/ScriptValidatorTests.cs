using System.Text.Json;
using Shouldly;
using SimpleSign.TestBench.Scripts;
using SimpleSign.TestHelpers;

namespace SimpleSign.TestBench.Tests.Scripts;

[Trait("Category", "Unit")]
public sealed class ScriptValidatorTests
{
    private const string Valid = """
        {
          "schema": 1, "id": "demo", "title": "Demo", "language": "es",
          "requirements": [
            { "id": "R1", "text": "Refuse a revoked certificate." },
            { "id": "R2", "text": "Keys in a module.", "applies": false, "justification": "The library holds no key." }
          ],
          "sections": [
            { "id": "s1", "title": "Revocation", "steps": [
              { "id": "good", "title": "Good", "requirements": ["R1"], "options": { "credentialId": "sandbox:rsa-2048" }, "expect": { "outcome": "signed" } },
              { "id": "check", "title": "Validate", "kind": "validate", "requirements": ["R1"], "options": { "fileId": "step:good" }, "expect": { "outcome": "valid" } },
              { "id": "hand", "title": "By hand", "kind": "manual", "requirements": ["R1"], "manual": { "instructions": "Show it." } }
            ] }
          ]
        }
        """;

    [Fact]
    public void Check_ValidScript_HasNoErrors()
    {
        var check = ScriptValidator.Check(Valid, sandbox: null);

        check.CanRun.ShouldBeTrue(string.Join("; ", check.Issues.Select(i => $"{i.Path}: {i.Message}")));
        check.Script!.AllSteps().Count().ShouldBe(3);
    }

    [Fact]
    public void Check_UnknownRequirementReasonAndFault_AreErrors()
    {
        string json = Valid
            .Replace("\"requirements\": [\"R1\"], \"options\": { \"credentialId\"", "\"requirements\": [\"R9\"], \"sandbox\": { \"crl\": \"Broken\" }, \"options\": { \"credentialId\"", StringComparison.Ordinal)
            .Replace("\"outcome\": \"signed\"", "\"outcome\": \"refused\", \"reason\": \"NoSuchReason\"", StringComparison.Ordinal);

        var issues = ScriptValidator.Check(json, sandbox: null).Issues.Where(i => i.IsError).Select(i => i.Path).ToList();

        issues.ShouldContain(p => p.EndsWith(".requirements", StringComparison.Ordinal));
        issues.ShouldContain(p => p.EndsWith(".expect.reason", StringComparison.Ordinal));
        issues.ShouldContain(p => p.EndsWith(".sandbox.crl", StringComparison.Ordinal));
    }

    [Fact]
    public void Check_NotApplicableWithoutJustification_IsAnError()
    {
        string json = Valid.Replace(", \"justification\": \"The library holds no key.\"", "", StringComparison.Ordinal);

        ScriptValidator.Check(json, sandbox: null).Issues.ShouldContain(i => i.IsError && i.Path.EndsWith(".justification", StringComparison.Ordinal));
    }

    [Fact]
    public void Check_RequirementWithoutStep_IsAWarning()
    {
        string json = Valid.Replace("{ \"id\": \"R1\", \"text\": \"Refuse a revoked certificate.\" },",
            "{ \"id\": \"R1\", \"text\": \"Refuse a revoked certificate.\" }, { \"id\": \"R3\", \"text\": \"Uncovered.\" },", StringComparison.Ordinal);

        var check = ScriptValidator.Check(json, sandbox: null);

        check.CanRun.ShouldBeTrue();
        check.Issues.ShouldContain(i => !i.IsError && i.Message.Contains("R3", StringComparison.Ordinal));
    }

    [Fact]
    public void Check_ValidationOfALaterStep_IsAnError()
    {
        string json = Valid.Replace("\"fileId\": \"step:good\"", "\"fileId\": \"step:hand-later\"", StringComparison.Ordinal);

        ScriptValidator.Check(json, sandbox: null).Issues.ShouldContain(i => i.IsError && i.Message.Contains("step:hand-later", StringComparison.Ordinal));
    }

    [Fact]
    public void Check_NotJson_SaysSo() =>
        ScriptValidator.Check("{ nope", sandbox: null).CanRun.ShouldBeFalse();

    [Fact]
    public void Merge_StepOptions_WinOverTheDefaults()
    {
        using var defaults = JsonDocument.Parse("""{ "common": { "level": "BB", "signingControls": { "auditLog": true } }, "pades": { "level": "BT" } }""");
        using var step = JsonDocument.Parse("""{ "signingControls": { "trust": ["SandboxRoot"] } }""");

        var merged = ScriptRunner.Merge(defaults.RootElement, "pades", step.RootElement);

        merged["level"]!.GetValue<string>().ShouldBe("BT");
        merged["signingControls"]!["auditLog"]!.GetValue<bool>().ShouldBeTrue();
        merged["signingControls"]!["trust"]![0]!.GetValue<string>().ShouldBe("SandboxRoot");
    }

    [Theory]
    [InlineData("SigningException (CertificateRevoked)", "CertificateRevoked")]
    [InlineData("SigningException", null)]
    [InlineData(null, null)]
    public void ReasonOf_ErrorType_GivesTheReason(string? errorType, string? reason) =>
        ScriptExpectations.ReasonOf(errorType).ShouldBe(reason);

    [Theory]
    [InlineData("certification-script.schema.json")]
    [InlineData("options.md")]
    public void Generated_MatchesTheFileInDocs(string file)
    {
        string generated = (file.EndsWith(".json", StringComparison.Ordinal) ? ScriptSchema.Json() : ScriptSchema.OptionsMarkdown()).ReplaceLineEndings("\n");
        if (!generated.EndsWith('\n'))
        {
            generated += "\n";
        }

        string path = file.EndsWith(".json", StringComparison.Ordinal)
            ? RepositoryPaths.Get("docs", "schemas", file)
            : RepositoryPaths.Get("docs", "certification-scripts", file);
        if (Environment.GetEnvironmentVariable("SIMPLESIGN_UPDATE_DOCS") == "1")
        {
            File.WriteAllText(path, generated);
        }

        File.Exists(path).ShouldBeTrue("Run the TestBench tests once with SIMPLESIGN_UPDATE_DOCS=1 to write it.");
        File.ReadAllText(path).ReplaceLineEndings("\n").ShouldBe(generated,
            "The script schema or options changed: run the TestBench tests with SIMPLESIGN_UPDATE_DOCS=1 and commit docs/.");
    }

    [Fact]
    public void Samples_AreValidScripts()
    {
        foreach (var sample in ScriptSamples.All)
        {
            var check = ScriptValidator.Check(ScriptSamples.Json(sample.Id)!, sandbox: null);
            check.CanRun.ShouldBeTrue($"{sample.Id}: " + string.Join("; ", check.Issues.Where(i => i.IsError).Select(i => $"{i.Path}: {i.Message}")));
        }
    }
}
