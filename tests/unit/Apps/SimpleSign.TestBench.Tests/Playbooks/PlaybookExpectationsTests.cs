using System.Text.Json;
using Shouldly;
using SimpleSign.TestBench.CrossValidation;
using SimpleSign.TestBench.Playbooks;
using SimpleSign.TestBench.Runs;

namespace SimpleSign.TestBench.Tests.Playbooks;

[Trait("Category", "Unit")]
public sealed class PlaybookExpectationsTests
{
    private static RunView Signed(object? crossValidation) => new(
        "r1", "pades", "done", DateTimeOffset.UnixEpoch, 10, default(JsonElement), true, null, null, "out", "signed.pdf", 100, "BB", "BB",
        [], 1, 1, null, [], "TOTAL_PASSED", [], null, crossValidation, []);

    private static DssComparison Comparison(bool available, bool agree, string? error = null) =>
        new(available, error, "http://localhost:8080", 5, agree, [], [], [], null);

    [Fact]
    public void Evaluate_DssUnavailable_SaysSoAndKeepsTheStepPassing()
    {
        var run = PlaybookExpectations.Evaluate("library", Signed(Comparison(available: false, agree: false, error: "Connection refused")), new PlaybookExpectation { Outcome = "signed" });

        run.CrossValidated.ShouldBeTrue();
        run.DssAgrees.ShouldBeNull();
        run.DssError.ShouldBe("Connection refused");
        run.Passed.ShouldBeTrue();
    }

    [Fact]
    public void Evaluate_DssUnavailableAndDssAgreesExpected_FailsSayingDssIsUnavailable()
    {
        var run = PlaybookExpectations.Evaluate("library", Signed(Comparison(available: false, agree: false, error: "Connection refused")),
            new PlaybookExpectation { Outcome = "signed", DssAgrees = true });

        run.Passed.ShouldBeFalse();
        run.Checks.Single(c => c.What == "dssAgrees").Found.ShouldBe("DSS unavailable: Connection refused");
    }

    [Fact]
    public void Evaluate_DssAgrees_HasNoError()
    {
        var run = PlaybookExpectations.Evaluate("library", Signed(Comparison(available: true, agree: true)), new PlaybookExpectation { DssAgrees = true });

        run.CrossValidated.ShouldBeTrue();
        run.DssAgrees.ShouldBe(true);
        run.DssError.ShouldBeNull();
        run.Passed.ShouldBeTrue();
    }

    [Fact]
    public void Evaluate_NotCrossValidated_IsNotAsked()
    {
        var run = PlaybookExpectations.Evaluate("library", Signed(null), new PlaybookExpectation { Outcome = "signed" });

        run.CrossValidated.ShouldBeFalse();
        run.DssError.ShouldBeNull();
    }
}
