using SimpleSign.Core.Validation;
using SimpleSign.PAdES;
using SimpleSign.TestHelpers;

namespace SimpleSign.Brasil.Tests;

[Trait("Category", "Unit")]
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
    public void ChainValidationProviders_ContainsTwoProviders()
    {
        var ext = new BrasilExtension();
        Assert.Equal(2, ext.ChainValidationProviders.Count);
    }

    [Fact]
    public async Task CreateValidator_SelfSignedSignature_IsNotValid()
    {
        using var cert = TestCertificateFactory.CreateSelfSignedCert("CN=Not ICP-Brasil, C=BR");
        var signed = await PadesSigner.Document(TestPdfFactory.CreateMinimalPdf()).WithCertificate(cert).SignAsync();

        var validator = BrasilExtension.CreateValidator(new ValidationOptions { CheckRevocation = false });
        var results = await validator.ValidateAsync(new MemoryStream(signed));

        Assert.Single(results);
        Assert.True(results[0].IsIntegrityValid);
        Assert.NotEqual(SignatureIndication.Valid, results[0].Indication);
    }

    [Fact]
    public async Task CreateValidator_TrustedRootOption_IsKeptAlongsideBrasilAnchors()
    {
        using var cert = TestCertificateFactory.CreateSelfSignedCert("CN=Own Root Signer, C=BR");
        var signed = await PadesSigner.Document(TestPdfFactory.CreateMinimalPdf()).WithCertificate(cert).SignAsync();

        var validator = BrasilExtension.CreateValidator(new ValidationOptions
        {
            CheckRevocation = false,
            TrustedRoots = [cert],
        });
        var results = await validator.ValidateAsync(new MemoryStream(signed));

        Assert.True(results[0].IsCertificateChainValid);
    }
}
