using SimpleSign.Core.Extensions;

namespace SimpleSign.Brasil.Tests;

public class BrasilExtensionTests
{
    [Fact]
    public void RegionCode_IsBR()
    {
        var ext = new BrasilExtension();
        Assert.Equal("BR", ext.RegionCode);
    }

    [Fact]
    public void DisplayName_IsNotEmpty()
    {
        var ext = new BrasilExtension();
        Assert.False(string.IsNullOrWhiteSpace(ext.DisplayName));
    }

    [Fact]
    public void TrustAnchorProviders_ContainsIcpBrasilAndGovBr()
    {
        var ext = new BrasilExtension();
        var providers = ext.TrustAnchorProviders;

        Assert.Equal(2, providers.Count);
        Assert.Contains(providers, p => p.DisplayName == "ICP-Brasil");
        Assert.Contains(providers, p => p.DisplayName == "Gov.br");
    }

    [Fact]
    public void TrustAnchorProviders_LoadCertificates()
    {
        var ext = new BrasilExtension();
        foreach (var provider in ext.TrustAnchorProviders)
        {
            var certs = provider.GetTrustAnchors();
            Assert.NotEmpty(certs);
        }
    }

    [Fact]
    public void ManifestProvider_IsNotNull()
    {
        var ext = new BrasilExtension();
        Assert.NotNull(ext.ManifestProvider);
        Assert.Equal("2.16.76.1.12.1.1", ext.ManifestProvider!.ManifestOid);
    }

    [Fact]
    public void ChainValidationProviders_ContainsTwoProviders()
    {
        var ext = new BrasilExtension();
        Assert.Equal(2, ext.ChainValidationProviders.Count);
    }

    [Fact]
    public void ManifestProvider_BuildManifest_ReturnsValidJson()
    {
        var ext = new BrasilExtension();
        var context = new SignerContext
        {
            SignerName = "Test User",
            SignerId = "12345678901",
            SignerIdType = "CPF",
            Email = "test@example.com",
            IpAddress = "10.0.0.1",
            AuthenticationMethod = "InstitutionalLogin",
            InstitutionName = "Test Org",
        };

        var bytes = ext.ManifestProvider!.BuildManifest(context);
        Assert.NotEmpty(bytes);

        // Should be valid JSON
        var manifest = ext.ManifestProvider.ParseManifest(bytes);
        Assert.NotNull(manifest);
    }
}
