using Shouldly;

namespace SimpleSign.Brazil.IcpBrasil.Tests;

[Trait("Category", "Contract")]
public sealed class IcpBrasilExtensionContractTests
{
    [Fact(DisplayName = "IcpBrasilExtension implements ICountryExtension with non-empty TrustAnchorProviders")]
    public void TrustAnchorProviders_ReturnsNonEmptyList()
    {
        var extension = new IcpBrasilExtension();

        extension.RegionCode.ShouldBe("BR");
        extension.DisplayName.ShouldNotBeNullOrEmpty();
        extension.TrustAnchorProviders.ShouldNotBeEmpty();
        extension.TrustAnchorProviders[0].GetTrustAnchors().ShouldNotBeEmpty();
    }

    [Fact(DisplayName = "IcpBrasilExtension.ChainValidationProviders returns non-empty list")]
    public void ChainValidationProviders_ReturnsNonEmptyList()
    {
        var extension = new IcpBrasilExtension();

        extension.ChainValidationProviders.ShouldNotBeEmpty();
        foreach (var p in extension.ChainValidationProviders)
            p.RegionCode.ShouldBe("BR");
    }
}
