using Shouldly;

namespace SimpleSign.Brasil.Tests;

[Trait("Category", "Contract")]
public sealed class BrasilExtensionContractTests
{
    [Fact(DisplayName = "BrasilExtension implements ICountryExtension with non-empty TrustAnchorProviders")]
    public void TrustAnchorProviders_ReturnsNonEmptyList()
    {
        var extension = new BrasilExtension();

        extension.RegionCode.ShouldBe("BR");
        extension.DisplayName.ShouldNotBeNullOrEmpty();
        extension.TrustAnchorProviders.ShouldNotBeEmpty();
        extension.TrustAnchorProviders[0].GetTrustAnchors().ShouldNotBeEmpty();
    }

    [Fact(DisplayName = "BrasilExtension.ManifestProvider is not null")]
    public void ManifestProvider_IsNotNull()
    {
        var extension = new BrasilExtension();

        extension.ManifestProvider.ShouldNotBeNull();
        extension.ManifestProvider!.ManifestOid.ShouldNotBeNullOrEmpty();
    }

    [Fact(DisplayName = "BrasilExtension.ChainValidationProviders returns non-empty list")]
    public void ChainValidationProviders_ReturnsNonEmptyList()
    {
        var extension = new BrasilExtension();

        extension.ChainValidationProviders.ShouldNotBeEmpty();
        foreach (var p in extension.ChainValidationProviders)
            p.RegionCode.ShouldBe("BR");
    }
}
