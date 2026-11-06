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

[Collection(TestBenchCollection.Name)]
public sealed class CadesMatrixTests(TestBenchFixture fixture, ITestOutputHelper output)
{
    private CadesMatrix Matrix() => new(fixture.Cades, new SimpleSign.TestBench.Cades.CadesSampleStore { Samples = fixture.CadesSamples }, fixture.Credentials, fixture.Factory);

    [Fact]
    public void Cases_CoverEveryOperationTypeAndExtendedForm()
    {
        using var matrix = Matrix();

        var cases = matrix.Cases();

        foreach (string value in new[] { "sign", "cosign-detached", "cosign-enveloped", "countersign-detached", "countersign-enveloped" })
        {
            cases.ShouldContain(c => c.Values["operation"] == value, $"operation={value} is never generated");
        }

        foreach (string value in new[] { "B-LTA", "ICP AdRv", "ICP AdRa", "custom-policy" })
        {
            cases.ShouldContain(c => c.Values["type"] == value, $"type={value} is never generated");
        }

        foreach (string value in new[] { "CompleteReferences", "ExtendedLong", "Archive" })
        {
            cases.ShouldContain(c => c.Values["extended"] == value, $"extended={value} is never generated");
        }
    }

    [Fact]
    public async Task RunAsync_AllCases_EveryCasePasses()
    {
        using var matrix = Matrix();

        var result = await matrix.RunAsync(new MatrixRunRequest(Format: "cades"), default);

        foreach (var failed in result.Cases.Where(c => c.Status != "pass"))
        {
            output.WriteLine($"{failed.Id} {string.Join(" ", failed.Values.Select(v => $"{v.Key}={v.Value}"))}\n    → {failed.Detail}");
        }

        output.WriteLine($"{result.Passed}/{result.Total} passed in {result.Ms} ms; {result.UncoverablePairs} pairs can never be combined.");
        result.Failed.ShouldBe(0);
    }
}
