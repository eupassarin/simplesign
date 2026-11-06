using Shouldly;
using SimpleSign.TestBench.Matrix;
using Xunit.Abstractions;

namespace SimpleSign.TestBench.Tests;

[Collection(TestBenchCollection.Name)]
public sealed class MatrixRunnerTests(TestBenchFixture fixture, ITestOutputHelper output)
{
    [Fact]
    public void Cases_GeneratedFromCompatibility_CoverEverySingleValueAndPairs()
    {
        using var matrix = new MatrixRunner(fixture.Sandbox, fixture.Documents, fixture.Credentials, fixture.Factory);

        var cases = matrix.Cases();

        cases.Count(c => c.Group == "single").ShouldBeGreaterThan(30);
        cases.Count(c => c.Group == "pairwise").ShouldBeGreaterThan(20);
        foreach (var dimension in MatrixRunner.Dimensions())
        {
            foreach (var value in dimension)
            {
                cases.ShouldContain(c => c.Values[value.Dimension] == value.Value, $"{value.Dimension}={value.Value} is never generated");
            }
        }
    }

    [Fact]
    public async Task RunAsync_AllCases_EveryCasePasses()
    {
        using var matrix = new MatrixRunner(fixture.Sandbox, fixture.Documents, fixture.Credentials, fixture.Factory);

        var result = await matrix.RunAsync(new MatrixRunRequest(), default);

        foreach (var failed in result.Cases.Where(c => c.Status != "pass"))
        {
            output.WriteLine($"{failed.Id} {string.Join(" ", failed.Values.Select(v => $"{v.Key}={v.Value}"))}\n    → {failed.Detail}");
        }

        output.WriteLine($"{result.Passed}/{result.Total} passed in {result.Ms} ms; {result.UncoverablePairs} pairs can never be combined.");
        result.Failed.ShouldBe(0);
    }
}
