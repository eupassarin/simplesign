using Shouldly;
using SimpleSign.Core.Extensions;

namespace SimpleSign.Brasil.Tests;

/// <summary>Only the Gov.br AC Raiz is a trust anchor; the intermediate and final ACs only help build chains.</summary>
[Trait("Category", "Unit")]
public sealed class GovBrTrustAnchorProviderTests
{
    [Fact]
    public void GetTrustAnchors_ReturnsOnlyTheRoot()
    {
        ITrustAnchorProvider provider = new GovBrTrustAnchorProvider();

        provider.GetTrustAnchors().ShouldHaveSingleItem().IsSelfSigned().ShouldBeTrue();
        provider.GetIntermediateCertificates().Count.ShouldBe(2);
        provider.GetIntermediateCertificates().ShouldAllBe(c => !c.IsSelfSigned());
    }
}
