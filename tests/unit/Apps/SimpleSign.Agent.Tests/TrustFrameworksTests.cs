using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Shouldly;
using SimpleSign.Agent.Services;
using SimpleSign.Core.Extensions;
using SimpleSign.TestHelpers;

namespace SimpleSign.Agent.Tests;

/// <summary>Two synthetic PKIs, made once for the class (their keys take seconds to generate).</summary>
public sealed class TwoPkis : IDisposable
{
    public SyntheticPki First { get; } = new();

    public SyntheticPki Second { get; } = new();

    public void Dispose()
    {
        First.Dispose();
        Second.Dispose();
    }
}

[Trait("Category", "Unit")]
public sealed class TrustFrameworksTests(TwoPkis pkis) : IClassFixture<TwoPkis>
{
    private readonly SyntheticPki _pki = pkis.First;
    private readonly SyntheticPki _other = pkis.Second;

    [Fact]
    public void Select_TrustId_ReturnsThatFramework() =>
        Frameworks().Select(null, "LAB").ShouldHaveSingleItem().Id.ShouldBe("lab");

    [Fact]
    public void Select_Country_ReturnsEveryFrameworkOfIt() =>
        Frameworks().Select("xx", null)!.Select(f => f.Id).ShouldBe(["lab", "other"]);

    [Theory]
    [InlineData("ZZ", null)]
    [InlineData(null, "nope")]
    public void Select_Unknown_ThrowsArgumentException(string? country, string? trust) =>
        Should.Throw<ArgumentException>(() => Frameworks().Select(country, trust));

    [Fact]
    public void Select_Neither_ReturnsNull() =>
        Frameworks().Select("", null).ShouldBeNull();

    [Fact]
    public async Task AnyTrustsAsync_LeafUnderTheFrameworksRoot_ReturnsTrue()
    {
        var frameworks = Frameworks();

        (await frameworks.AnyTrustsAsync(frameworks.Select(null, "lab")!, _pki.Leaf, CancellationToken.None)).ShouldBeTrue();
    }

    [Fact]
    public async Task AnyTrustsAsync_LeafOfAnotherPki_ReturnsFalse()
    {
        var frameworks = Frameworks();

        (await frameworks.AnyTrustsAsync(frameworks.Select(null, "lab")!, _other.Leaf, CancellationToken.None)).ShouldBeFalse();
    }

    [Fact]
    public async Task AnyTrustsAsync_CountryWithSeveralFrameworks_TrustsWhatAnyOfThemTrusts()
    {
        var frameworks = Frameworks();

        (await frameworks.AnyTrustsAsync(frameworks.Select("XX", null)!, _other.Leaf, CancellationToken.None)).ShouldBeTrue();
    }

    [Fact]
    public async Task AnyTrustsAsync_IcpBrasilOfTheAgent_DoesNotTrustATestCertificate()
    {
        var frameworks = TrustFrameworks.Default;

        (await frameworks.AnyTrustsAsync(frameworks.Select("BR", null)!, _pki.Leaf, CancellationToken.None)).ShouldBeFalse();
    }

    [Fact]
    public void CanSignNow_ValidWithSigningKeyUsage_ReturnsTrue() =>
        TrustFrameworks.CanSignNow(_pki.Leaf).ShouldBeTrue();

    [Fact]
    public void CanSignNow_Expired_ReturnsFalse()
    {
        using var expired = Certificate(X509KeyUsageFlags.DigitalSignature, DateTimeOffset.UtcNow.AddDays(-1));

        TrustFrameworks.CanSignNow(expired).ShouldBeFalse();
    }

    [Fact]
    public void CanSignNow_KeyEnciphermentOnly_ReturnsFalse()
    {
        using var encryption = Certificate(X509KeyUsageFlags.KeyEncipherment, DateTimeOffset.UtcNow.AddDays(10));

        TrustFrameworks.CanSignNow(encryption).ShouldBeFalse();
    }

    private TrustFrameworks Frameworks() => new(
    [
        new TrustFramework("lab", new Lazy<ICountryExtension>(() => new TestExtension("XX", _pki))),
        new TrustFramework("other", new Lazy<ICountryExtension>(() => new TestExtension("XX", _other))),
    ]);

    private static X509Certificate2 Certificate(X509KeyUsageFlags usage, DateTimeOffset notAfter)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest("CN=Test", key, HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(new X509KeyUsageExtension(usage, true));
        return request.CreateSelfSigned(notAfter.AddYears(-1), notAfter);
    }

    /// <summary>A country extension whose anchor is a synthetic PKI's root and whose intermediate is its CA.</summary>
    internal sealed class TestExtension(string region, SyntheticPki pki) : ICountryExtension, ITrustAnchorProvider
    {
        public string RegionCode => region;

        public string DisplayName => "Test framework";

        public IReadOnlyList<ITrustAnchorProvider> TrustAnchorProviders => [this];

        public IReadOnlyList<IChainValidationProvider> ChainValidationProviders => [];

        public IReadOnlyList<X509Certificate2> GetTrustAnchors() => [pki.RootCa];

        public IReadOnlyList<X509Certificate2> GetIntermediateCertificates() => [pki.IntermediateCa];
    }
}
