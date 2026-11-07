using Shouldly;
using SimpleSign.TestBench.Signing;

namespace SimpleSign.TestBench.Tests;

[Collection(TestBenchCollection.Name)]
[Trait("Category", "Unit")]
public sealed class SigningRunnerTests(TestBenchFixture fixture)
{
    [Theory]
    [InlineData(BaselineLevel.BB, "B-B")]
    [InlineData(BaselineLevel.BT, "B-T")]
    [InlineData(BaselineLevel.BLT, "B-LT")]
    [InlineData(BaselineLevel.BLTA, "B-LTA")]
    public async Task RunAsync_BaselineLevel_SignsAndValidates(BaselineLevel level, string expected)
    {
        var result = await fixture.Runner.RunAsync(fixture.Options() with { Level = level }, default);

        result.Error.ShouldBeNull();
        result.Success.ShouldBeTrue();
        result.AchievedLevel.ShouldBe(expected);
        result.Validation.ShouldNotBeEmpty();
        result.Validation.Where(v => !v.IsDocumentTimestamp).ShouldAllBe(v => v.Indication == "Valid", string.Join("; ", result.Validation.SelectMany(v => v.Errors)));
    }

    [Fact]
    public async Task RunAsync_CrlFirstAtLongTerm_SignsValidatesAndShowsTheOption()
    {
        var options = fixture.Options() with { Level = BaselineLevel.BLT, RevocationPreference = SimpleSign.Core.Signing.RevocationPreference.CrlFirst };

        var result = await fixture.Runner.RunAsync(options, default);

        result.Error.ShouldBeNull();
        result.AchievedLevel.ShouldBe("B-LT");
        result.Validation.Where(v => !v.IsDocumentTimestamp).ShouldAllBe(v => v.Indication == "Valid", string.Join("; ", result.Validation.SelectMany(v => v.Errors)));
        result.Code.CSharp.ShouldContain("{ RevocationPreference = RevocationPreference.CrlFirst }");
        result.Code.Cli.ShouldContain("--revocation-preference crl");
    }
}
