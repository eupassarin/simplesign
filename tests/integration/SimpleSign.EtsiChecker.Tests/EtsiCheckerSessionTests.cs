using System.Text.Json.Nodes;
using Shouldly;
using SimpleSign.TestHelpers;
using Xunit;

namespace SimpleSign.EtsiChecker.Tests;

/// <summary>The table <see cref="EtsiCheckerSession"/> writes, and the committed one kept in step with its results.</summary>
[Trait("Category", "Unit")]
public sealed class EtsiCheckerSessionTests
{
    [Fact]
    public void Summary_ExpectedAndUnexpectedFailures_AreCountedApart()
    {
        var results = new JsonObject
        {
            ["pades-b-t-adbe"] = Result("known-issues", Finding(known: true)),
            ["pades-b-t"] = Result("fail", Finding(known: true), Finding(known: false), Finding(known: false)),
            ["cades-b-b"] = Result("pass"),
        };

        string summary = EtsiCheckerSession.Summary(results);

        summary.ShouldContain("| Checks passed | Failures | Expected | Warnings | Result |");
        summary.ShouldContain("| 10 | 0 | 1 | 0 | ✅ expected |");
        summary.ShouldContain("| 10 | 2 | 1 | 0 | ❌ |");
        summary.ShouldContain("| 10 | 0 | 0 | 0 | ✅ |");
        summary.ShouldContain("`CheckIfValueIsOneOfDefined` (expected) at `SubFilter`");
    }

    /// <summary>
    /// <c>summary.md</c> is made from <c>results.json</c>; a change to how it is written must reach the committed one.
    /// With <c>SIMPLESIGN_ETSI_WRITE_SUMMARY=true</c> this writes it instead of failing.
    /// </summary>
    [Fact]
    public void Summary_CommittedResults_MatchCommittedSummary()
    {
        string directory = RepositoryPaths.Get("docs", "conformance", "etsi-checker");
        var results = JsonNode.Parse(File.ReadAllText(Path.Combine(directory, "results.json")))!.AsObject();
        string path = Path.Combine(directory, "summary.md");

        string expected = EtsiCheckerSession.Summary(results);
        if (string.Equals(Environment.GetEnvironmentVariable("SIMPLESIGN_ETSI_WRITE_SUMMARY"), "true", StringComparison.OrdinalIgnoreCase))
        {
            File.WriteAllText(path, expected);
        }

        File.ReadAllText(path).ReplaceLineEndings("\n").ShouldBe(expected,
            "summary.md is out of step with results.json: run this test with SIMPLESIGN_ETSI_WRITE_SUMMARY=true");
    }

    private static JsonObject Result(string verdict, params JsonObject[] failures) => new()
    {
        ["format"] = "PADES",
        ["level"] = "Timestamped",
        ["description"] = "test",
        ["checkedAt"] = "2026-11-18",
        ["commit"] = "abc1234",
        ["signatures"] = 1,
        ["passed"] = 10,
        ["verdict"] = verdict,
        ["failures"] = new JsonArray([.. failures]),
        ["warnings"] = new JsonArray(),
    };

    private static JsonObject Finding(bool known) => new()
    {
        ["signature"] = "PAdES-signature-1",
        ["element"] = "CheckFailure",
        ["check"] = "CheckIfValueIsOneOfDefined",
        ["path"] = "SubFilter",
        ["message"] = "Found value: 'adbe.pkcs7.detached'",
        ["known"] = known,
    };
}
