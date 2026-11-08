using Shouldly;
using SimpleSign.Core.Policies;
using Xunit;

namespace SimpleSign.Core.Tests.Policies;

[Trait("Category", "Unit")]
public sealed class StaticPolicyProviderTests
{
    private static readonly ValidationPolicy Brazil = ValidationPolicy.Default.WithName("ICP-Brasil");
    private static readonly ValidationPolicy Exact = ValidationPolicy.Default.WithName("exact");

    [Fact]
    public void ValidationFor_OidUnderAPrefix_ReturnsItsPolicy() =>
        new StaticPolicyProvider().Add(Brazil, "2.16.76.1.7.1.*").ValidationFor("2.16.76.1.7.1.11.1.1").Name.ShouldBe("ICP-Brasil");

    [Fact]
    public void ValidationFor_ExactOidWithUrnPrefix_ReturnsItsPolicy() =>
        new StaticPolicyProvider().Add(Exact, "1.2.3.4").ValidationFor("urn:oid:1.2.3.4").Name.ShouldBe("exact");

    [Fact]
    public void ValidationFor_OtherOidOrNone_ReturnsTheDefault()
    {
        var provider = new StaticPolicyProvider().Add(Exact, "1.2.3.4");

        provider.ValidationFor("1.2.3.45").ShouldBeSameAs(ValidationPolicy.Default);
        provider.ValidationFor(null).ShouldBeSameAs(ValidationPolicy.Default);
    }

    [Fact]
    public void AppliedPolicy_HasTheNameAndDigest()
    {
        var applied = AppliedPolicy.Of(Brazil);

        applied.Name.ShouldBe("ICP-Brasil");
        applied.Digest.ShouldBe(Brazil.Digest);
        applied.Digest.Length.ShouldBe(64);
    }
}
