using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Shouldly;
using SimpleSign.Core.Extensions;
using SimpleSign.Core.Http;
using SimpleSign.Core.Policies;
using SimpleSign.TestHelpers;
using SimpleSign.XAdES.TrustedLists;
using Xunit;

namespace SimpleSign.XAdES.Tests.TrustedLists;

/// <summary>The PKIs and the list operator, made once for the class: generating their RSA keys is most of the time.</summary>
public sealed class TrustedListSourceFixture : IDisposable
{
    internal TrustedListBuilder Lists { get; } = new();

    public SyntheticPki CaA { get; } = new();

    public SyntheticPki CaB { get; } = new();

    public void Dispose()
    {
        Lists.Dispose();
        CaA.Dispose();
        CaB.Dispose();
    }
}

[Trait("Category", "Unit")]
public sealed class TrustedListSourceTests(TrustedListSourceFixture fixture) : IClassFixture<TrustedListSourceFixture>, IDisposable
{
    private const string Url = "https://198.51.100.7/tsl/tsl-zz.xml";
    private readonly string _cache = Path.Combine(Directory.CreateTempSubdirectory("simplesign-tsl-").FullName, "tsl-zz.xml");

    // What the fake server answers: a list, or null for a 404.
    private byte[]? _served;
    private int _downloads;

    public void Dispose() => Directory.Delete(Path.GetDirectoryName(_cache)!, recursive: true);

    [Fact]
    public async Task LoadAsync_Downloads_ServesTheListAndKeepsItInTheCache()
    {
        _served = List(25, A);

        await using var source = await LoadAsync();

        source.Current.SequenceNumber.ShouldBe("25");
        source.Current.FromCache.ShouldBeFalse();
        source.Current.Sha256.ShouldBe(Convert.ToHexString(SHA256.HashData(_served)).ToLowerInvariant());
        source.Current.List.Location.ShouldBe(new Uri(Url));
        source.RegionCode.ShouldBe("ZZ");
        source.GetTrustAnchors().ShouldHaveSingleItem().Thumbprint.ShouldBe(fixture.CaA.RootCa.Thumbprint);
        source.TrustedLists.ShouldHaveSingleItem().Territory.ShouldBe("ZZ");
        source.IsExpired.ShouldBeFalse();
        (await File.ReadAllBytesAsync(_cache)).ShouldBe(_served);
    }

    [Fact]
    public async Task RefreshAsync_NewSequence_SwapsAndReportsTheServicesAddedAndRemoved()
    {
        _served = List(25, A);
        await using var source = await LoadAsync();
        TrustedListChangedEventArgs? changed = null;
        source.Changed += (_, e) => changed = e;
        _served = List(26, B);

        (await source.RefreshAsync()).ShouldBeTrue();

        source.Current.SequenceNumber.ShouldBe("26");
        source.GetTrustAnchors().ShouldHaveSingleItem().Thumbprint.ShouldBe(fixture.CaB.RootCa.Thumbprint);
        changed.ShouldNotBeNull();
        changed.Previous.SequenceNumber.ShouldBe("25");
        changed.Current.SequenceNumber.ShouldBe("26");
        changed.AddedServices.ShouldHaveSingleItem().ServiceName.ShouldBe("CA B");
        changed.RemovedServices.ShouldHaveSingleItem().ServiceName.ShouldBe("CA A");
        (await File.ReadAllBytesAsync(_cache)).ShouldBe(_served);
    }

    [Fact]
    public async Task RefreshAsync_SameList_ChangesNothing()
    {
        _served = List(25, A);
        await using var source = await LoadAsync();
        var before = source.Current;
        bool raised = false;
        source.Changed += (_, _) => raised = true;

        (await source.RefreshAsync()).ShouldBeFalse();

        raised.ShouldBeFalse();
        source.Current.ShouldBeSameAs(before);
        source.LastError.ShouldBeNull();
        _downloads.ShouldBe(2);
    }

    [Fact]
    public async Task RefreshAsync_DownloadFails_KeepsTheListAndReportsIt()
    {
        _served = List(25, A);
        await using var source = await LoadAsync();
        TrustedListRefreshFailedEventArgs? failed = null;
        source.RefreshFailed += (_, e) => failed = e;
        _served = null;

        (await source.RefreshAsync()).ShouldBeFalse();

        failed.ShouldNotBeNull().Reason.ShouldContain("could not be downloaded");
        failed.Current.SequenceNumber.ShouldBe("25");
        source.LastError.ShouldNotBeNull();
        source.GetTrustAnchors().ShouldHaveSingleItem().Thumbprint.ShouldBe(fixture.CaA.RootCa.Thumbprint);
    }

    [Fact]
    public async Task RefreshAsync_SignedByAnotherKey_IsRefused()
    {
        _served = List(25, A);
        await using var source = await LoadAsync();
        TrustedListRefreshFailedEventArgs? failed = null;
        source.RefreshFailed += (_, e) => failed = e;
        using var forger = new TrustedListBuilder();
        _served = forger.List(26, [B]);

        (await source.RefreshAsync()).ShouldBeFalse();

        failed.ShouldNotBeNull().Exception.ShouldBeOfType<CryptographicException>();
        source.Current.SequenceNumber.ShouldBe("25");
        source.GetTrustAnchors().ShouldNotContain(c => c.Thumbprint == fixture.CaB.RootCa.Thumbprint);
    }

    [Fact]
    public async Task RefreshAsync_LowerSequence_IsRefusedAsARollback()
    {
        _served = List(25, A);
        await using var source = await LoadAsync();
        TrustedListRefreshFailedEventArgs? failed = null;
        source.RefreshFailed += (_, e) => failed = e;
        _served = List(24, B);

        (await source.RefreshAsync()).ShouldBeFalse();

        failed.ShouldNotBeNull().Reason.ShouldContain("lower");
        source.Current.SequenceNumber.ShouldBe("25");
    }

    [Fact]
    public async Task LoadAsync_DownloadFails_ServesTheCacheUntilTheNetworkComesBack()
    {
        _served = List(25, A);
        await (await LoadAsync()).DisposeAsync();
        _served = null;

        await using var source = await LoadAsync();

        source.Current.FromCache.ShouldBeTrue();
        source.LastError.ShouldNotBeNull();
        source.GetTrustAnchors().ShouldHaveSingleItem().Thumbprint.ShouldBe(fixture.CaA.RootCa.Thumbprint);
        _served = await File.ReadAllBytesAsync(_cache);
        // The network serves the same list again: nothing changes, but it is no longer only the cache's word.
        (await source.RefreshAsync()).ShouldBeFalse();
        source.Current.FromCache.ShouldBeFalse();
        source.LastError.ShouldBeNull();
    }

    [Fact]
    public async Task LoadAsync_DownloadFailsNoCache_Throws()
    {
        _served = null;

        await Should.ThrowAsync<HttpRequestException>(LoadAsync);
    }

    [Fact]
    public async Task LoadAsync_SignedByAnotherKeyNoCache_ThrowsWhyTheListWasRefused()
    {
        using var forger = new TrustedListBuilder();
        _served = forger.List(25, [A]);

        await Should.ThrowAsync<CryptographicException>(LoadAsync);
    }

    [Theory]
    [InlineData("https://198.51.100.7/tsl/tsl-zz.xml", null)]
    [InlineData("http://localhost:5300/tl/tl.xml", "http://localhost:5300")]
    [InlineData("http://127.0.0.1:5300/tl/tl.xml", "http://127.0.0.1:5300")]
    public void RefusedLoopback_UrlAllowedOrNotOnThisMachine_IsNull(string url, string? allowed)
    {
        var policy = allowed is null ? OutboundHttpPolicy.Default : new OutboundHttpPolicy { LoopbackOrigins = [new Uri(allowed)] };

        TrustedListSource.RefusedLoopback(new Uri(url), policy).ShouldBeNull();
    }

    [Theory]
    [InlineData("http://localhost:5300/tl/tl.xml")]
    [InlineData("http://127.0.0.1:5300/tl/tl.xml")]
    [InlineData("http://[::1]:5300/tl/tl.xml")]
    public void RefusedLoopback_UrlOnThisMachineNotAllowed_SaysWhy(string url) =>
        TrustedListSource.RefusedLoopback(new Uri(url), OutboundHttpPolicy.Default).ShouldNotBeNull().ShouldContain("LoopbackOrigins");

    [Fact]
    public async Task Anchors_AfterNextUpdate_AreNoneUntilAGoodCopyIsRead()
    {
        var clock = new ManualClock(DateTimeOffset.UtcNow);
        _served = fixture.Lists.List(25, [A], DateTimeOffset.UtcNow.AddDays(10));
        await using var source = await TrustedListSource.LoadAsync(Options(), clock, default);
        _served = null;

        clock.Now = clock.Now.AddDays(11);
        await source.RefreshAsync();

        source.IsExpired.ShouldBeTrue();
        source.GetTrustAnchors().ShouldBeEmpty();
        source.GetTrustAnchors(clock.Now.AddDays(-20)).ShouldBeEmpty();
        source.GetIntermediateCertificates().ShouldBeEmpty();
    }

    [Fact]
    public async Task Anchors_ExpiredListKeptForValidation_StayForThePolicyToJudge()
    {
        var clock = new ManualClock(DateTimeOffset.UtcNow);
        _served = fixture.Lists.List(25, [A], DateTimeOffset.UtcNow.AddDays(-1));
        var options = Options();

        await using var source = await TrustedListSource.LoadAsync(options with { List = options.List with { RejectExpired = false } }, clock, default);

        source.IsExpired.ShouldBeFalse();
        source.GetTrustAnchors().ShouldHaveSingleItem();
    }

    [Fact]
    public async Task Anchors_AtATime_ComeFromTheServicesHistory()
    {
        _served = List(25, A, ("CA B", TrustedListBuilder.Withdrawn, fixture.CaB.RootCa));
        await using var source = await LoadAsync();

        ITimedTrustAnchorProvider timed = source;
        timed.GetTrustAnchors(DateTimeOffset.UtcNow).ShouldHaveSingleItem().Thumbprint.ShouldBe(fixture.CaA.RootCa.Thumbprint);
    }

    [Fact]
    public async Task StartAutoRefresh_TooShortOrTwice_IsRefused()
    {
        _served = List(25, A);
        await using var source = await LoadAsync();

        Should.Throw<ArgumentOutOfRangeException>(() => source.StartAutoRefresh(TimeSpan.FromSeconds(5)));
        source.StartAutoRefresh(TimeSpan.FromHours(1));
        Should.Throw<InvalidOperationException>(() => source.StartAutoRefresh(TimeSpan.FromHours(1)));
        await source.StopAutoRefreshAsync();
    }

    [Fact]
    public async Task Profile_OverTheSource_TrustsTheListAndNothingElse()
    {
        _served = List(25, A);
        await using var source = await LoadAsync();

        var profile = TrustedListProfile.Create(source);

        profile.Name.ShouldBe("tsl");
        profile.Title.ShouldBe(source.DisplayName);
        profile.TrustSystemRoots.ShouldBeFalse();
        profile.CanSign.ShouldBeTrue();
        profile.SigningPolicy.ShouldBeSameAs(SigningPolicy.Default);
        profile.ValidationPolicy.ShouldBeSameAs(ValidationPolicy.Default);
        profile.SignatureQualifiers.ShouldBeEmpty();
        profile.TrustAnchorProviders.ShouldHaveSingleItem().ShouldBeSameAs(source);
        _served = List(26, B);
        await source.RefreshAsync();
        // The profile serves the copy read last.
        profile.TrustAnchorProviders[0].GetTrustAnchors().ShouldHaveSingleItem().Thumbprint.ShouldBe(fixture.CaB.RootCa.Thumbprint);
    }

    [Fact]
    public async Task Profile_LoadAsync_ReadsTheListUnderTheNameGiven()
    {
        _served = List(25, A);

        var profile = await TrustedListProfile.LoadAsync(Options(), "tsl:zz", "Zedland");

        profile.Name.ShouldBe("tsl:zz");
        profile.Title.ShouldBe("Zedland");
        var source = profile.TrustAnchorProviders.ShouldHaveSingleItem().ShouldBeOfType<TrustedListSource>();
        source.GetTrustAnchors().ShouldHaveSingleItem().Thumbprint.ShouldBe(fixture.CaA.RootCa.Thumbprint);
        await source.DisposeAsync();
    }

    private (string, string, X509Certificate2) A => ("CA A", TrustedListBuilder.Granted, fixture.CaA.RootCa);

    private (string, string, X509Certificate2) B => ("CA B", TrustedListBuilder.Granted, fixture.CaB.RootCa);

    private byte[] List(int sequence, params (string, string, X509Certificate2)[] services) => fixture.Lists.List(sequence, services);

    private TrustedListSourceOptions Options() => new()
    {
        Location = new Uri(Url),
        List = new TrustedListOptions { SignerCertificates = [fixture.Lists.Operator] },
        CacheFile = _cache,
        HttpClientProvider = new SingleClientProvider(new HttpClient(new MockHttpHandler(_ =>
        {
            Interlocked.Increment(ref _downloads);
            return Task.FromResult(_served is { } body
                ? new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(body) }
                : new HttpResponseMessage(HttpStatusCode.NotFound));
        }))),
    };

    private Task<TrustedListSource> LoadAsync() => TrustedListSource.LoadAsync(Options());
}
