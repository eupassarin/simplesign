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
    private static readonly IReadOnlyList<TrustFramework> s_catalog =
    [
        new("lab", "XX", "Lab", NeedsTrustedList: false) { Aliases = ["laboratory"] },
        new("other", "XX", "Other", NeedsTrustedList: true),
    ];

    private readonly SyntheticPki _pki = pkis.First;
    private readonly SyntheticPki _other = pkis.Second;

    [Fact]
    public void Select_TrustId_ReturnsThatFramework() =>
        Frameworks().Select(null, "LAB").ShouldHaveSingleItem().Id.ShouldBe("lab");

    [Fact]
    public void Select_Alias_ReturnsThatFramework() =>
        Frameworks().Select(null, "laboratory").ShouldHaveSingleItem().Id.ShouldBe("lab");

    [Fact]
    public void Select_Country_ReturnsEveryEnabledFrameworkOfIt() =>
        Frameworks().Select("xx", null)!.Select(f => f.Id).ShouldBe(["lab", "other"]);

    [Theory]
    [InlineData("ZZ", null)]
    [InlineData(null, "nope")]
    public void Select_Unknown_ThrowsArgumentException(string? country, string? trust) =>
        Should.Throw<ArgumentException>(() => Frameworks().Select(country, trust));

    [Fact]
    public void Select_KnownButNotEnabled_ThrowsTrustFrameworkDisabled() =>
        Should.Throw<TrustFrameworkDisabledException>(() => Frameworks("lab").Select(null, "other"));

    [Fact]
    public void Select_CountryWhoseFrameworksAreAllDisabled_ThrowsTrustFrameworkDisabled() =>
        Should.Throw<TrustFrameworkDisabledException>(() => None().Select("XX", null));

    [Fact]
    public void Select_CountryWithOneFrameworkEnabled_ReturnsOnlyThatOne() =>
        Frameworks("other").Select("XX", null).ShouldHaveSingleItem().Id.ShouldBe("other");

    [Fact]
    public void Select_Neither_ReturnsNull() =>
        Frameworks().Select("", null).ShouldBeNull();

    [Fact]
    public void Enabled_NoneEnabled_IsEmptyAndSummarySaysSo()
    {
        var frameworks = None();

        frameworks.Enabled.ShouldBeEmpty();
        frameworks.EnabledSummary.ShouldNotBeEmpty();
    }

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
    public async Task AvailableAsync_FrameworkThatLoads_ReturnsItAndReportsReady()
    {
        var frameworks = Frameworks();
        var selected = frameworks.Select(null, "lab")!;

        (await frameworks.AvailableAsync(selected, CancellationToken.None)).ShouldHaveSingleItem().Id.ShouldBe("lab");
        frameworks.StateOf(selected[0]).Status.ShouldBe(TrustFrameworkStatus.Ready);
    }

    [Fact]
    public async Task AvailableAsync_TrustedListCannotBeRead_IsEmptyAndReportsUnavailable()
    {
        var frameworks = Offline();
        var selected = frameworks.Select(null, "other")!;

        (await frameworks.AvailableAsync(selected, CancellationToken.None)).ShouldBeEmpty();
        var state = frameworks.StateOf(selected[0]);
        state.Status.ShouldBe(TrustFrameworkStatus.Unavailable);
        state.Error.ShouldNotBeNull();
    }

    [Fact]
    public async Task AvailableAsync_AfterAFailure_DoesNotTryAgainBeforeTheRetryDelay()
    {
        int attempts = 0;
        var time = new FakeTimeProvider();
        var frameworks = new TrustFrameworks(Store("other"), s_catalog, (_, _) =>
        {
            attempts++;
            throw new HttpRequestException("INDECOPI is unreachable.");
        }, time: time);
        var selected = frameworks.Select(null, "other")!;

        await frameworks.AvailableAsync(selected, CancellationToken.None);
        await frameworks.AvailableAsync(selected, CancellationToken.None);
        attempts.ShouldBe(1);

        time.Advance(TimeSpan.FromMinutes(2));
        await frameworks.AvailableAsync(selected, CancellationToken.None);
        attempts.ShouldBe(2);
    }

    [Fact]
    public async Task AvailableAsync_OneOfTwoUnavailable_KeepsTheOtherOne()
    {
        var frameworks = new TrustFrameworks(Store("lab", "other"), s_catalog, (framework, _) => framework.Id == "lab"
            ? Task.FromResult<ICountryExtension>(new TestExtension("XX", _pki))
            : throw new HttpRequestException("offline"));

        (await frameworks.AvailableAsync(frameworks.Select("XX", null)!, CancellationToken.None))
            .ShouldHaveSingleItem().Id.ShouldBe("lab");
    }

    [Fact]
    public async Task RecognizedByAsync_FrameworkThatTrustsIt_ReturnsItsTitle()
    {
        var frameworks = Frameworks("lab");
        await frameworks.AvailableAsync(frameworks.Select(null, "lab")!, CancellationToken.None);

        (await frameworks.RecognizedByAsync(_pki.Leaf, CancellationToken.None)).ShouldBe(["Lab"]);
    }

    [Fact]
    public async Task RecognizedByAsync_CertificateOfAnotherPki_ReturnsNothing()
    {
        var frameworks = Frameworks("lab");
        await frameworks.AvailableAsync(frameworks.Select(null, "lab")!, CancellationToken.None);

        (await frameworks.RecognizedByAsync(_other.Leaf, CancellationToken.None)).ShouldBeEmpty();
    }

    [Fact]
    public async Task RecognizedByAsync_FrameworkNotLoadedYet_ReturnsNothing() =>
        (await Frameworks("lab").RecognizedByAsync(_pki.Leaf, CancellationToken.None)).ShouldBeEmpty();

    [Fact]
    public void Catalog_HasTheFourFrameworksWithTheirRegionsAndAliases()
    {
        TrustFrameworkCatalog.All.Select(f => f.Id).ShouldBe(["icp-brasil", "govbr", "iofe", "eidas"]);
        TrustFrameworkCatalog.All.Select(f => f.RegionCode).ShouldBe(["BR", "BR", "PE", "EU"]);
        TrustFrameworkCatalog.Find("gov-br")!.Id.ShouldBe("govbr");
        TrustFrameworkCatalog.All.Where(f => f.NeedsTrustedList).Select(f => f.Id).ShouldBe(["iofe", "eidas"]);
    }

    [Fact]
    public async Task AnyTrustsAsync_IcpBrasilOfTheAgent_DoesNotTrustATestCertificate()
    {
        var frameworks = new TrustFrameworks(Store(TrustFrameworkCatalog.IcpBrasil));
        var selected = frameworks.Select("BR", null)!;

        (await frameworks.AvailableAsync(selected, CancellationToken.None)).ShouldNotBeEmpty();
        (await frameworks.AnyTrustsAsync(selected, _pki.Leaf, CancellationToken.None)).ShouldBeFalse();
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

    private static SettingsStore Store(params string[] enabled)
    {
        var store = new SettingsStore(Directory.CreateTempSubdirectory("simplesign-agent-").FullName, ManagedPolicy.None);
        store.Current.EnabledTrustFrameworks = [.. enabled];
        return store;
    }

    /// <summary>The same catalog with nothing enabled.</summary>
    private TrustFrameworks None() =>
        new(Store(), s_catalog, (framework, _) =>
            Task.FromResult<ICountryExtension>(new TestExtension(framework.RegionCode, _pki)));

    private TrustFrameworks Frameworks(params string[] enabled) =>
        new(Store(enabled.Length > 0 ? enabled : ["lab", "other"]), s_catalog, (framework, _) =>
            Task.FromResult<ICountryExtension>(new TestExtension(framework.RegionCode, framework.Id == "lab" ? _pki : _other)));

    private static TrustFrameworks Offline() =>
        new(Store("lab", "other"), s_catalog, (_, _) => throw new HttpRequestException("The trusted list could not be downloaded."));

    private static X509Certificate2 Certificate(X509KeyUsageFlags usage, DateTimeOffset notAfter)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest("CN=Test", key, HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(new X509KeyUsageExtension(usage, true));
        return request.CreateSelfSigned(notAfter.AddYears(-1), notAfter);
    }

    /// <summary>A clock the test moves forward, for the retry delay after a trusted list fails.</summary>
    private sealed class FakeTimeProvider : TimeProvider
    {
        private DateTimeOffset _now = DateTimeOffset.UnixEpoch.AddYears(56);

        public override DateTimeOffset GetUtcNow() => _now;

        public void Advance(TimeSpan by) => _now += by;
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
