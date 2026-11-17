using Microsoft.Extensions.DependencyInjection;
using Shouldly;
using SimpleSign.Brazil.GovBr;
using SimpleSign.Core.Extensions;
using SimpleSign.Core.Validation;
using SimpleSign.PAdES;
using SimpleSign.PAdES.DependencyInjection;
using SimpleSign.PAdES.Validation;
using SimpleSign.TestHelpers;

namespace SimpleSign.Brazil.IcpBrasil.Tests;

/// <summary>
/// The two Brazilian extensions used together, as an application that accepts both hierarchies
/// does: their providers add up, and each certificate is claimed only by its own hierarchy.
/// </summary>
[Trait("Category", "Unit")]
public sealed class IcpBrasilAndGovBrExtensionsTests
{
    private static readonly ICountryExtension[] Both = [new IcpBrasilExtension(), new GovBrExtension()];

    [Fact]
    public void Both_ProvidersAddUp_OnePerHierarchy()
    {
        var anchors = Both.SelectMany(e => e.TrustAnchorProviders).ToList();
        var validators = Both.SelectMany(e => e.ChainValidationProviders).ToList();

        anchors.Select(p => p.DisplayName).ShouldBe(["ICP-Brasil", "Gov.br"], ignoreOrder: true);
        validators.Count.ShouldBe(2);
        Both.ShouldAllBe(e => e.RegionCode == "BR");
    }

    [Theory]
    [InlineData("CN=Titular, O=ICP-Brasil, C=BR", true, false)]
    [InlineData("CN=Cidadao, O=Gov-Br, C=BR", false, true)]
    [InlineData("CN=Outro, O=Example, C=US", false, false)]
    public void Both_EachCertificateIsClaimedOnlyByItsHierarchy(string subject, bool icp, bool govBr)
    {
        using var certificate = TestCertificateFactory.CreateSelfSignedCert(subject);
        var icpProvider = new IcpBrasilExtension().ChainValidationProviders.ShouldHaveSingleItem();
        var govBrProvider = new GovBrExtension().ChainValidationProviders.ShouldHaveSingleItem();

        icpProvider.CanValidate(certificate).ShouldBe(icp);
        govBrProvider.CanValidate(certificate).ShouldBe(govBr);
    }

    [Fact]
    public async Task Both_InOneValidator_SelfSignedSignatureIsNotValid()
    {
        using var cert = TestCertificateFactory.CreateSelfSignedCert("CN=Not Brazilian, C=US");
        var signed = await PadesSigner.Document(TestPdfFactory.CreateMinimalPdf()).WithCertificate(cert).SignAsync();

        var validator = new PdfSignatureValidator(new ValidationOptions { CheckRevocation = false }, httpClient: null,
            logger: null, countryExtensions: Both);
        var results = await validator.ValidateAsync(new MemoryStream(signed));

        results.ShouldHaveSingleItem().IsIntegrityValid.ShouldBeTrue();
        results[0].Indication.ShouldNotBe(SignatureIndication.Valid);
    }

    [Fact]
    public void AddBoth_ResolvesBothExtensions()
    {
        var services = new ServiceCollection();
        services.AddSimpleSign();
        services.AddSimpleSignIcpBrasil();
        services.AddSimpleSignGovBr();
        using var provider = services.BuildServiceProvider();

        provider.GetServices<ICountryExtension>().Select(e => e.GetType())
            .ShouldBe([typeof(IcpBrasilExtension), typeof(GovBrExtension)], ignoreOrder: true);
    }
}
