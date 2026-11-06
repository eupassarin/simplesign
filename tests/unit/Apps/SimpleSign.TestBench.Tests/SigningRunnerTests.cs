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

    [Theory]
    [InlineData(IcpPolicyKind.AdRb)]
    [InlineData(IcpPolicyKind.AdRt)]
    [InlineData(IcpPolicyKind.AdRc)]
    [InlineData(IcpPolicyKind.AdRa)]
    public async Task RunAsync_IcpPolicy_Signs(IcpPolicyKind policy)
    {
        var result = await fixture.Runner.RunAsync(fixture.Options() with { Kind = SignatureKind.IcpBrasil, IcpPolicy = policy }, default);

        result.Error.ShouldBeNull();
        result.Success.ShouldBeTrue();
        result.Code.CSharp.ShouldContain("WithIcpBrasilPolicy");
    }
}
