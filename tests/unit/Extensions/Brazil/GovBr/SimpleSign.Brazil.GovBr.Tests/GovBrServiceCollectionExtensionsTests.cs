using Microsoft.Extensions.DependencyInjection;
using Shouldly;
using SimpleSign.Core.Extensions;
using SimpleSign.PAdES.DependencyInjection;

namespace SimpleSign.Brazil.GovBr.Tests;

[Trait("Category", "Unit")]
public sealed class GovBrServiceCollectionExtensionsTests
{
    [Fact]
    public void AddSimpleSignGovBr_RegistersExtensionTrustAnchorsAndValidator()
    {
        var services = new ServiceCollection();
        services.AddSimpleSign();
        services.AddSimpleSignGovBr();
        using var provider = services.BuildServiceProvider();

        provider.GetServices<ICountryExtension>().ShouldHaveSingleItem().ShouldBeOfType<GovBrExtension>();
        provider.GetServices<ITrustAnchorProvider>().ShouldContain(p => p.DisplayName == "Gov.br");
        provider.GetService<GovBrChainValidator>().ShouldNotBeNull();
    }

    [Fact]
    public void AddSimpleSignGovBr_TrustAnchorProvider_SplitsRootsFromIntermediates()
    {
        var services = new ServiceCollection();
        services.AddSimpleSignGovBr();
        using var provider = services.BuildServiceProvider();

        var anchors = provider.GetServices<ITrustAnchorProvider>().Single(p => p.DisplayName == "Gov.br");

        anchors.GetTrustAnchors().ShouldNotBeEmpty();
        anchors.GetTrustAnchors().ShouldAllBe(c => c.SubjectName.Name == c.IssuerName.Name);
        anchors.GetIntermediateCertificates().ShouldNotBeEmpty();
        (anchors.GetTrustAnchors().Count + anchors.GetIntermediateCertificates().Count)
            .ShouldBe(GovBrChainValidator.LoadBundledGovBrCerts().Count);
    }
}
