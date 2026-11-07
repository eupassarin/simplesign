using System.Text.Json;
using Shouldly;
using SimpleSign.Playbook.Model;
using SimpleSign.Playbook.Runs;

namespace SimpleSign.Playbook.Tests;

[Trait("Category", "Unit")]
public sealed class ExpectationsTests
{
    private static readonly SandboxRequestRecord[] s_requests =
    [
        new(1, DateTimeOffset.UtcNow, "POST", "/ocsp/intermediate", 200, "OCSP", null, 1),
        new(2, DateTimeOffset.UtcNow, "GET", "/crl/root.crl", 200, "CRL", null, 1),
    ];

    private static IReadOnlyList<CheckResult> Check(Expectation expect, string stdout = "", int? exit = 0, bool timedOut = false) =>
        Expectations.Evaluate(expect, new CommandOutcome(exit, stdout, "", timedOut), s_requests, s => s);

    private static JsonElement J(string json) => JsonDocument.Parse(json).RootElement.Clone();

    [Fact]
    public void Evaluate_JsonPaths_CompareByValue()
    {
        const string stdout = """{ "success": false, "error": { "reason": "CertificateRevoked" }, "signatures": [ { "indication": "Valid", "count": 2 } ] }""";

        var checks = Check(new Expectation { Json = new() { ["success"] = J("false"), ["error.reason"] = J("\"CertificateRevoked\""), ["signatures.0.count"] = J("2.0") } }, stdout);

        checks.ShouldAllBe(c => c.Passed);
    }

    [Fact]
    public void Evaluate_JsonPathMissingOrNotJson_Fails()
    {
        Check(new Expectation { Json = new() { ["error.reason"] = J("\"X\"") } }, """{ "success": true }""").Single().Actual.ShouldBe("missing");
        Check(new Expectation { Json = new() { ["a"] = J("1") } }, "not json").Single().Passed.ShouldBeFalse();
    }

    [Fact]
    public void Evaluate_ExitCodeAndText_AreChecked()
    {
        var checks = Check(new Expectation { ExitCode = 0, StdoutContains = ["Signed"], StdoutMatches = ["B-L?T"] }, "Signed at B-LT", exit: 1);

        checks.Single(c => c.Name == "exitCode").Passed.ShouldBeFalse();
        checks.Where(c => c.Name != "exitCode").ShouldAllBe(c => c.Passed);
    }

    [Fact]
    public void Evaluate_SandboxRequests_CountsByServiceAndPath()
    {
        var checks = Check(new Expectation
        {
            SandboxRequests =
            [
                new SandboxRequestExpectation { Service = "ocsp" },
                new SandboxRequestExpectation { PathContains = "/crl/" },
                new SandboxRequestExpectation { Service = "TSA", Min = 0, Max = 0 },
                new SandboxRequestExpectation { Service = "TSA" },
            ],
        });

        checks.Select(c => c.Passed).ShouldBe([true, true, true, false]);
    }

    [Fact]
    public void Evaluate_Files_UseTheResolver()
    {
        string file = Path.GetTempFileName();
        var checks = Expectations.Evaluate(new Expectation { Files = ["${out}/x"] }, new CommandOutcome(0, "", "", false), [], _ => file);

        checks.Single().Passed.ShouldBeTrue();
        File.Delete(file);
    }

    [Fact]
    public void Evaluate_TimedOut_FailsWhateverWasExpected() =>
        Check(new Expectation { ExitCode = 0 }, timedOut: true, exit: null).ShouldHaveSingleItem().Name.ShouldBe("finished");
}
