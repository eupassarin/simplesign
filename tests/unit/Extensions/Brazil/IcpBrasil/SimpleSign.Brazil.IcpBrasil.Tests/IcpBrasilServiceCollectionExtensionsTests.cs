using Microsoft.Extensions.DependencyInjection;
using Shouldly;
using SimpleSign.Core.Extensions;
using SimpleSign.PAdES.DependencyInjection;

namespace SimpleSign.Brazil.IcpBrasil.Tests;

[Trait("Category", "Unit")]
public sealed class IcpBrasilServiceCollectionExtensionsTests
{
    [Fact]
    public void AddSimpleSignIcpBrasil_RegistersExtensionTrustAnchorsAndValidator()
    {
        var services = new ServiceCollection();
        services.AddSimpleSign();
        services.AddSimpleSignIcpBrasil();
        using var provider = services.BuildServiceProvider();

        provider.GetServices<ICountryExtension>().ShouldHaveSingleItem().ShouldBeOfType<IcpBrasilExtension>();
        provider.GetServices<ITrustAnchorProvider>().ShouldContain(p => p.DisplayName == "ICP-Brasil");
        provider.GetService<IcpBrasilChainValidator>().ShouldNotBeNull();
    }

    [Fact]
    public void AddSimpleSignIcpBrasil_TrustAnchorProvider_LoadsBundledRoots()
    {
        var services = new ServiceCollection();
        services.AddSimpleSignIcpBrasil();
        using var provider = services.BuildServiceProvider();

        var anchors = provider.GetServices<ITrustAnchorProvider>().Single(p => p.DisplayName == "ICP-Brasil");

        anchors.GetTrustAnchors().Count.ShouldBe(IcpBrasilChainValidator.LoadBundledAcRaizCerts().Count);
        anchors.GetIntermediateCertificates().ShouldNotBeEmpty();
    }
}
