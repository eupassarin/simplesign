using SimpleSign.Core.Validation;
using SimpleSign.PAdES;
using SimpleSign.TestHelpers;

namespace SimpleSign.Brazil.GovBr.Tests;

[Trait("Category", "Unit")]
public class GovBrExtensionTests
{
    [Fact]
    public void RegionCode_IsBR()
    {
        var ext = new GovBrExtension();
        Assert.Equal("BR", ext.RegionCode);
    }

    [Fact]
    public void DisplayName_IsNotEmpty()
    {
        var ext = new GovBrExtension();
        Assert.False(string.IsNullOrWhiteSpace(ext.DisplayName));
    }

    [Fact]
    public void TrustAnchorProviders_ContainsGovBrOnly()
    {
        var ext = new GovBrExtension();
        var provider = Assert.Single(ext.TrustAnchorProviders);

        Assert.Equal("Gov.br", provider.DisplayName);
    }

    [Fact]
    public void TrustAnchorProviders_LoadCertificates()
    {
        var ext = new GovBrExtension();
        foreach (var provider in ext.TrustAnchorProviders)
        {
            var certs = provider.GetTrustAnchors();
            Assert.NotEmpty(certs);
        }
    }

    [Fact]
    public void ChainValidationProviders_ContainsOneProvider()
    {
        var ext = new GovBrExtension();
        Assert.Single(ext.ChainValidationProviders);
    }

    [Fact]
    public async Task CreateValidator_SelfSignedSignature_IsNotValid()
    {
        using var cert = TestCertificateFactory.CreateSelfSignedCert("CN=Not Gov.br, C=BR");
        var signed = await PadesSigner.Document(TestPdfFactory.CreateMinimalPdf()).WithCertificate(cert).SignAsync();

        var validator = GovBrExtension.CreateValidator(new ValidationOptions { CheckRevocation = false });
        var results = await validator.ValidateAsync(new MemoryStream(signed));

        Assert.Single(results);
        Assert.True(results[0].IsIntegrityValid);
        Assert.NotEqual(SignatureIndication.Valid, results[0].Indication);
    }

    [Fact]
    public async Task CreateValidator_TrustedRootOption_IsKeptAlongsideGovBrAnchors()
    {
        using var cert = TestCertificateFactory.CreateSelfSignedCert("CN=Own Root Signer, C=BR");
        var signed = await PadesSigner.Document(TestPdfFactory.CreateMinimalPdf()).WithCertificate(cert).SignAsync();

        var validator = GovBrExtension.CreateValidator(new ValidationOptions
        {
            CheckRevocation = false,
            TrustedRoots = [cert],
        });
        var results = await validator.ValidateAsync(new MemoryStream(signed));

        Assert.True(results[0].IsCertificateChainValid);
    }
}
