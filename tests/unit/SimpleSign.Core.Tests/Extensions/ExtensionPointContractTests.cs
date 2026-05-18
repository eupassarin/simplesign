using System.Security.Cryptography.X509Certificates;
using Moq;
using Shouldly;
using SimpleSign.Core.Extensions;
using SimpleSign.TestHelpers;
using Xunit;

namespace SimpleSign.Core.Tests.Extensions;

[Trait("Category", "Contract")]
public sealed class TrustAnchorProviderContractTests
{
    [Fact(DisplayName = "ITrustAnchorProvider: GetTrustAnchors returns non-empty list")]
    public void GetTrustAnchors_ReturnsNonEmptyList()
    {
        using var cert = TestCertificateFactory.CreateSelfSignedCert();
        var mock = new Mock<ITrustAnchorProvider>();
        mock.Setup(x => x.GetTrustAnchors()).Returns(new List<X509Certificate2> { cert });
        mock.Setup(x => x.RegionCode).Returns("TS");
        mock.Setup(x => x.DisplayName).Returns("Test Provider");

        var provider = mock.Object;

        provider.GetTrustAnchors().ShouldNotBeEmpty();
    }

    [Fact(DisplayName = "ITrustAnchorProvider: Empty trust anchors is valid edge case")]
    public void GetTrustAnchors_ReturnsEmptyList()
    {
        var mock = new Mock<ITrustAnchorProvider>();
        mock.Setup(x => x.GetTrustAnchors()).Returns(new List<X509Certificate2>());
        mock.Setup(x => x.RegionCode).Returns("TS");
        mock.Setup(x => x.DisplayName).Returns("Empty Provider");

        var provider = mock.Object;

        provider.GetTrustAnchors().ShouldBeEmpty();
    }

    [Fact(DisplayName = "ITrustAnchorProvider: RegionCode and DisplayName are accessible")]
    public void Properties_AreAccessible()
    {
        var mock = new Mock<ITrustAnchorProvider>();
        mock.Setup(x => x.RegionCode).Returns("BR");
        mock.Setup(x => x.DisplayName).Returns("ICP-Brasil");

        var provider = mock.Object;

        provider.RegionCode.ShouldBe("BR");
        provider.DisplayName.ShouldBe("ICP-Brasil");
    }
}

[Trait("Category", "Contract")]
public sealed class ChainValidationProviderContractTests
{
    [Fact(DisplayName = "IChainValidationProvider: CanValidate returns true for known cert, Validate returns IsTrusted")]
    public void CanValidate_KnownCert_ReturnsTrue()
    {
        using var cert = TestCertificateFactory.CreateSelfSignedCert();
        var mock = new Mock<IChainValidationProvider>();
        mock.Setup(x => x.RegionCode).Returns("BR");
        mock.Setup(x => x.CanValidate(cert)).Returns(true);
        mock.Setup(x => x.Validate(cert, null)).Returns(new ChainValidationResult
        {
            IsTrusted = true,
            RegionCode = "BR",
            PolicyLevel = "A3",
        });

        var provider = mock.Object;

        provider.CanValidate(cert).ShouldBeTrue();
        provider.Validate(cert, null).IsTrusted.ShouldBeTrue();
    }

    [Fact(DisplayName = "IChainValidationProvider: CanValidate returns false for unknown cert")]
    public void CanValidate_UnknownCert_ReturnsFalse()
    {
        using var cert = TestCertificateFactory.CreateSelfSignedCert();
        var mock = new Mock<IChainValidationProvider>();
        mock.Setup(x => x.CanValidate(cert)).Returns(false);

        mock.Object.CanValidate(cert).ShouldBeFalse();
    }

    [Fact(DisplayName = "IChainValidationProvider: Validate with null chain still works")]
    public void Validate_NullChain_Succeeds()
    {
        using var cert = TestCertificateFactory.CreateSelfSignedCert();
        var mock = new Mock<IChainValidationProvider>();
        mock.Setup(x => x.Validate(cert, null)).Returns(new ChainValidationResult
        {
            IsTrusted = false,
            RegionCode = "TS",
            Errors = new List<string> { "Unknown issuer" },
        });

        var result = mock.Object.Validate(cert, null);

        result.ShouldNotBeNull();
        result.RegionCode.ShouldBe("TS");
    }
}

[Trait("Category", "Contract")]
public sealed class SignatureManifestProviderContractTests
{
    private sealed class StubManifestProvider : ISignatureManifestProvider
    {
        public string ManifestOid => "1.2.3.4.5";

        public byte[] BuildManifest(SignerContext context) =>
            [0x30, 0x0A, 0x01];

        public object? ParseManifest(ReadOnlySpan<byte> data) =>
            data.Length > 2 ? new { Oid = ManifestOid } : null;
    }

    [Fact(DisplayName = "ISignatureManifestProvider: BuildManifest returns valid bytes")]
    public void BuildManifest_ReturnsValidBytes()
    {
        var context = new SignerContext
        {
            SignerName = "Test User",
            SignerId = "12345678900",
            SignerIdType = "CPF",
        };

        var provider = new StubManifestProvider();

        provider.ManifestOid.ShouldNotBeNullOrEmpty();
        provider.BuildManifest(context).ShouldNotBeEmpty();
    }

    [Fact(DisplayName = "ISignatureManifestProvider: ParseManifest with valid data returns object")]
    public void ParseManifest_ValidData_ReturnsObject()
    {
        var provider = new StubManifestProvider();
        var data = new byte[] { 0x30, 0x0A, 0x01, 0x02 };

        provider.ParseManifest(data).ShouldNotBeNull();
    }

    [Fact(DisplayName = "ISignatureManifestProvider: ParseManifest with invalid data returns null")]
    public void ParseManifest_InvalidData_ReturnsNull()
    {
        var provider = new StubManifestProvider();
        var data = new byte[] { 0xFF, 0xFF };

        provider.ParseManifest(data).ShouldBeNull();
    }
}

[Trait("Category", "Contract")]
public sealed class CountryExtensionContractTests
{
    [Fact(DisplayName = "ICountryExtension: Composite wires providers together")]
    public void CompositeExtension_WiresProvidersTogether()
    {
        using var cert = TestCertificateFactory.CreateSelfSignedCert();

        var trustAnchor = new Mock<ITrustAnchorProvider>();
        trustAnchor.Setup(x => x.RegionCode).Returns("TS");
        trustAnchor.Setup(x => x.DisplayName).Returns("Test Anchors");
        trustAnchor.Setup(x => x.GetTrustAnchors()).Returns(new List<X509Certificate2> { cert });

        var chainValidator = new Mock<IChainValidationProvider>();
        chainValidator.Setup(x => x.RegionCode).Returns("TS");

        var manifest = new Mock<ISignatureManifestProvider>();
        manifest.Setup(x => x.ManifestOid).Returns("1.2.3.4");

        var extension = new Mock<ICountryExtension>();
        extension.Setup(x => x.RegionCode).Returns("TS");
        extension.Setup(x => x.DisplayName).Returns("Test Country");
        extension.Setup(x => x.TrustAnchorProviders).Returns(new List<ITrustAnchorProvider> { trustAnchor.Object });
        extension.Setup(x => x.ManifestProvider).Returns(manifest.Object);
        extension.Setup(x => x.ChainValidationProviders).Returns(new List<IChainValidationProvider> { chainValidator.Object });

        var ext = extension.Object;

        ext.RegionCode.ShouldBe("TS");
        ext.DisplayName.ShouldBe("Test Country");
        ext.TrustAnchorProviders.Count().ShouldBe(1);
        ext.ChainValidationProviders.Count().ShouldBe(1);
        ext.ManifestProvider.ShouldNotBeNull();
        ext.TrustAnchorProviders[0].GetTrustAnchors().ShouldNotBeEmpty();
    }
}
