using Shouldly;
using SimpleSign.Playbook.Model;

namespace SimpleSign.Playbook.Tests;

[Trait("Category", "Unit")]
public sealed class PlaybookValidatorTests
{
    private static string SamplePath => Path.Combine(AppContext.BaseDirectory, "Samples", "sandbox-basics", "playbook.json");

    private static IReadOnlyList<PlaybookIssue> Errors(string json) => [.. PlaybookValidator.Parse(json).Issues.Where(i => i.IsError)];

    [Fact]
    public void Parse_Sample_HasNoErrors()
    {
        var (playbook, issues) = PlaybookValidator.Parse(File.ReadAllText(SamplePath));

        playbook.ShouldNotBeNull();
        issues.Where(i => i.IsError).ShouldBeEmpty(string.Join("; ", issues.Select(i => $"{i.Path}: {i.Message}")));
        playbook.Sections.SelectMany(s => s.Steps).Count().ShouldBeGreaterThan(5);
    }

    [Fact]
    public void Parse_NotJson_GivesTheLine()
    {
        var (playbook, issues) = PlaybookValidator.Parse("{\n  \"name\": ,\n}");

        playbook.ShouldBeNull();
        issues.ShouldHaveSingleItem().Message.ShouldContain("line 2");
    }

    [Fact]
    public void Validate_MissingNameAndCommand_AreErrors()
    {
        var errors = Errors("""{ "schema": 1, "sections": [ { "id": "a", "steps": [ { "id": "s", "title": "t" } ] } ] }""");

        errors.ShouldContain(e => e.Path == "name");
        errors.ShouldContain(e => e.Path == "sections[0].steps[0].run.args");
    }

    [Fact]
    public void Validate_DuplicateStepIds_IsAnError()
    {
        var errors = Errors("""
            { "name": "p", "sections": [
              { "id": "a", "steps": [ { "id": "s", "title": "1", "run": { "args": ["version"] } } ] },
              { "id": "b", "steps": [ { "id": "s", "title": "2", "run": { "args": ["version"] } } ] } ] }
            """);

        errors.ShouldContain(e => e.Path == "sections[1].steps[0].id" && e.Message.Contains("twice", StringComparison.Ordinal));
    }

    [Fact]
    public void Validate_SandboxActionWithoutSandbox_IsAnError()
    {
        var errors = Errors("""
            { "name": "p", "sections": [ { "id": "a", "steps": [
              { "id": "s", "title": "t", "setup": [ { "sandbox": "reset" } ], "run": { "args": ["version"] } } ] } ] }
            """);

        errors.ShouldContain(e => e.Path == "sections[0].steps[0].setup[0]");
    }

    [Theory]
    [InlineData("""{ "sandbox": "explode" }""", "sandbox")]
    [InlineData("""{ "sandbox": "faults", "crl": "Broken" }""", "crl")]
    [InlineData("""{ "sandbox": "revoke" }""", "certificate")]
    [InlineData("""{ "sandbox": "revoke", "certificate": "x", "publication": "Somewhere" }""", "publication")]
    [InlineData("""{ "sandbox": "certificate" }""", "id")]
    [InlineData("""{ "sandbox": "shortLived", "seconds": 0 }""", "seconds")]
    public void Validate_BadSandboxAction_PointsAtTheField(string action, string field)
    {
        var errors = Errors($$"""
            { "name": "p", "sandbox": { "url": "http://localhost:5300/" }, "sections": [ { "id": "a", "steps": [
              { "id": "s", "title": "t", "setup": [ {{action}} ], "run": { "args": ["version"] } } ] } ] }
            """);

        errors.ShouldContain(e => e.Path == $"sections[0].steps[0].setup[0].{field}");
    }

    [Theory]
    [InlineData("../outside.pdf")]
    [InlineData("/etc/passwd")]
    public void Validate_AssetOutsideTheWorkspace_IsAnError(string file)
    {
        var errors = Errors($$"""{ "name": "p", "assets": [ { "id": "a", "file": "{{file}}" } ], "sections": [] }""");

        errors.ShouldContain(e => e.Path == "assets[0].file");
    }

    [Fact]
    public void Validate_BadRegex_IsAnError()
    {
        var errors = Errors("""
            { "name": "p", "sections": [ { "id": "a", "steps": [
              { "id": "s", "title": "t", "run": { "args": ["version"] }, "expect": { "stdoutMatches": ["("] } } ] } ] }
            """);

        errors.ShouldContain(e => e.Path == "sections[0].steps[0].expect.stdoutMatches[0]");
    }

    [Fact]
    public void Validate_ManualStep_NeedsNoCommand()
    {
        var errors = Errors("""{ "name": "p", "sections": [ { "id": "a", "steps": [ { "id": "s", "title": "t", "manual": true } ] } ] }""");

        errors.ShouldBeEmpty();
    }
}
