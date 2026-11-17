using SimpleSign.Core.Validation;
using SimpleSign.PAdES;
using SimpleSign.TestHelpers;

namespace SimpleSign.Brazil.IcpBrasil.Tests;

[Trait("Category", "Unit")]
public class IcpBrasilExtensionTests
{
    [Fact]
    public void RegionCode_IsBR()
    {
        var ext = new IcpBrasilExtension();
        Assert.Equal("BR", ext.RegionCode);
    }

    [Fact]
    public void DisplayName_IsNotEmpty()
    {
        var ext = new IcpBrasilExtension();
        Assert.False(string.IsNullOrWhiteSpace(ext.DisplayName));
    }

    [Fact]
    public void TrustAnchorProviders_ContainsIcpBrasilOnly()
    {
        var ext = new IcpBrasilExtension();
        var provider = Assert.Single(ext.TrustAnchorProviders);

        Assert.Equal("ICP-Brasil", provider.DisplayName);
    }

    [Fact]
    public void TrustAnchorProviders_LoadCertificates()
    {
        var ext = new IcpBrasilExtension();
        foreach (var provider in ext.TrustAnchorProviders)
        {
            var certs = provider.GetTrustAnchors();
            Assert.NotEmpty(certs);
        }
    }

    [Fact]
    public void ChainValidationProviders_ContainsOneProvider()
    {
        var ext = new IcpBrasilExtension();
        Assert.Single(ext.ChainValidationProviders);
    }

    [Fact]
    public async Task CreateValidator_SelfSignedSignature_IsNotValid()
    {
        using var cert = TestCertificateFactory.CreateSelfSignedCert("CN=Not ICP-Brasil, C=BR");
        var signed = await PadesSigner.Document(TestPdfFactory.CreateMinimalPdf()).WithCertificate(cert).SignAsync();

        var validator = IcpBrasilExtension.CreateValidator(new ValidationOptions { CheckRevocation = false });
        var results = await validator.ValidateAsync(new MemoryStream(signed));

        Assert.Single(results);
        Assert.True(results[0].IsIntegrityValid);
        Assert.NotEqual(SignatureIndication.Valid, results[0].Indication);
    }

    [Fact]
    public async Task CreateValidator_TrustedRootOption_IsKeptAlongsideIcpBrasilAnchors()
    {
        using var cert = TestCertificateFactory.CreateSelfSignedCert("CN=Own Root Signer, C=BR");
        var signed = await PadesSigner.Document(TestPdfFactory.CreateMinimalPdf()).WithCertificate(cert).SignAsync();

        var validator = IcpBrasilExtension.CreateValidator(new ValidationOptions
        {
            CheckRevocation = false,
            TrustedRoots = [cert],
        });
        var results = await validator.ValidateAsync(new MemoryStream(signed));

        Assert.True(results[0].IsCertificateChainValid);
    }
}
