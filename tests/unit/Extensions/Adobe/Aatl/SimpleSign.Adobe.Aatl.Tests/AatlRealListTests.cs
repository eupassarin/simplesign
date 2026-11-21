using Shouldly;

namespace SimpleSign.Adobe.Aatl.Tests;

/// <summary>Adobe's list as published, checked against the root bundled with the package. Needs the network.</summary>
[Trait("Category", "Integration")]
public sealed class AatlRealListTests
{
    [Fact]
    public async Task LoadAsync_AdobesList_VerifiesAgainstTheBundledRootAndHasAnchors()
    {
        await using var source = await AatlSource.LoadAsync();

        var list = source.Current;
        list.Signer.Subject.ShouldContain("Adobe");
        list.SignedAt.ShouldNotBeNull();
        list.Identities.Count.ShouldBeGreaterThan(100);
        list.GetTrustAnchors().Count.ShouldBeGreaterThan(50);
        list.Identities.ShouldContain(i => i.IsAnchor && i.HasPolicyRestrictions);
        list.Identities.ShouldAllBe(i => i.Source == "AATL");
    }
}
