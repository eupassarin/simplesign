using System.Net;
using System.Security.Cryptography;
using Shouldly;
using SimpleSign.Core.Http;
using SimpleSign.TestHelpers;

namespace SimpleSign.Adobe.Aatl.Tests;

[Trait("Category", "Unit")]
public sealed class AatlSourceTests(AatlFixture fixture) : IClassFixture<AatlFixture>, IDisposable
{
    private const string Url = "https://198.51.100.9/tl12.acrobatsecuritysettings";
    private static readonly DateTimeOffset s_first = new(2026, 10, 1, 9, 0, 0, TimeSpan.Zero);
    private readonly string _cache = Path.Combine(Directory.CreateTempSubdirectory("simplesign-aatl-").FullName, "aatl.pdf");

    // What the fake server answers: a list, or null for a 404.
    private byte[]? _served;
    private int _downloads;

    public void Dispose() => Directory.Delete(Path.GetDirectoryName(_cache)!, recursive: true);

    [Fact]
    public async Task LoadAsync_Downloads_ServesTheListAndKeepsItInTheCache()
    {
        _served = await ListAsync(s_first, fixture.Open);

        await using var source = await AatlSource.LoadAsync(Options());

        source.Current.SignedAt.ShouldBe(s_first);
        source.Current.Location.ShouldBe(new Uri(Url));
        source.FromCache.ShouldBeFalse();
        source.LastError.ShouldBeNull();
        source.RegionCode.ShouldBe("AATL");
        source.GetTrustAnchors().ShouldHaveSingleItem().Thumbprint.ShouldBe(fixture.Open.Root.Thumbprint);
        (await File.ReadAllBytesAsync(_cache)).ShouldBe(_served);
    }

    [Fact]
    public async Task RefreshAsync_NewerList_SwapsAndSaysSo()
    {
        _served = await ListAsync(s_first, fixture.Open);
        await using var source = await AatlSource.LoadAsync(Options());
        AatlChangedEventArgs? changed = null;
        source.Changed += (_, e) => changed = e;
        _served = await ListAsync(s_first.AddDays(30), fixture.Restricted);

        (await source.RefreshAsync()).ShouldBeTrue();

        source.GetTrustAnchors().ShouldHaveSingleItem().Thumbprint.ShouldBe(fixture.Restricted.Root.Thumbprint);
        changed.ShouldNotBeNull().Previous.SignedAt.ShouldBe(s_first);
        changed.Current.SignedAt.ShouldBe(s_first.AddDays(30));
        (await File.ReadAllBytesAsync(_cache)).ShouldBe(_served);
    }

    [Fact]
    public async Task RefreshAsync_SameList_ChangesNothing()
    {
        _served = await ListAsync(s_first, fixture.Open);
        await using var source = await AatlSource.LoadAsync(Options());
        var before = source.Current;

        (await source.RefreshAsync()).ShouldBeFalse();

        source.Current.ShouldBeSameAs(before);
        _downloads.ShouldBe(2);
    }

    [Fact]
    public async Task RefreshAsync_ListSignedBeforeTheOneServed_IsRefusedAsARollback()
    {
        _served = await ListAsync(s_first, fixture.Open);
        await using var source = await AatlSource.LoadAsync(Options());
        AatlRefreshFailedEventArgs? failed = null;
        source.RefreshFailed += (_, e) => failed = e;
        _served = await ListAsync(s_first.AddDays(-30), fixture.Restricted);

        (await source.RefreshAsync()).ShouldBeFalse();

        failed.ShouldNotBeNull().Reason.ShouldContain("before the one served");
        source.GetTrustAnchors().ShouldHaveSingleItem().Thumbprint.ShouldBe(fixture.Open.Root.Thumbprint);
    }

    [Fact]
    public async Task RefreshAsync_SignedUnderAnotherRoot_IsRefused()
    {
        _served = await ListAsync(s_first, fixture.Open);
        await using var source = await AatlSource.LoadAsync(Options());
        AatlRefreshFailedEventArgs? failed = null;
        source.RefreshFailed += (_, e) => failed = e;
        using var forger = new AatlListBuilder();
        _served = await forger.ListAsync([new TestIdentity(fixture.Unknown.Root)], s_first.AddDays(30));

        (await source.RefreshAsync()).ShouldBeFalse();

        failed.ShouldNotBeNull().Exception.ShouldBeOfType<CryptographicException>();
        source.LastError.ShouldNotBeNull();
        source.GetTrustAnchors().ShouldHaveSingleItem().Thumbprint.ShouldBe(fixture.Open.Root.Thumbprint);
    }

    [Fact]
    public async Task RefreshAsync_DownloadFails_KeepsTheList()
    {
        _served = await ListAsync(s_first, fixture.Open);
        await using var source = await AatlSource.LoadAsync(Options());
        _served = null;

        (await source.RefreshAsync()).ShouldBeFalse();

        source.LastError.ShouldNotBeNull().ShouldContain("could not be downloaded");
        source.GetTrustAnchors().ShouldHaveSingleItem();
    }

    [Fact]
    public async Task LoadAsync_DownloadFails_ServesTheCacheUntilTheNetworkComesBack()
    {
        _served = await ListAsync(s_first, fixture.Open);
        await (await AatlSource.LoadAsync(Options())).DisposeAsync();
        _served = null;

        await using var source = await AatlSource.LoadAsync(Options());

        source.FromCache.ShouldBeTrue();
        source.LastError.ShouldNotBeNull();
        source.GetTrustAnchors().ShouldHaveSingleItem().Thumbprint.ShouldBe(fixture.Open.Root.Thumbprint);
        _served = await File.ReadAllBytesAsync(_cache);
        (await source.RefreshAsync()).ShouldBeFalse();
        source.FromCache.ShouldBeFalse();
        source.LastError.ShouldBeNull();
    }

    [Fact]
    public async Task LoadAsync_CacheTamperedWith_IsRefused()
    {
        byte[] list = await ListAsync(s_first, fixture.Open);
        int target = System.Text.Encoding.Latin1.GetString(list).IndexOf("/Type /Catalog", StringComparison.Ordinal);
        list[target + 1] = (byte)'X';
        await File.WriteAllBytesAsync(_cache, list);
        _served = null;

        await Should.ThrowAsync<CryptographicException>(() => AatlSource.LoadAsync(Options()));
    }

    [Fact]
    public async Task LoadAsync_DownloadFailsNoCache_Throws()
    {
        _served = null;

        await Should.ThrowAsync<HttpRequestException>(() => AatlSource.LoadAsync(Options()));
    }

    [Fact]
    public async Task LoadAsync_ListRefusedNoCache_ThrowsWhy()
    {
        using var forger = new AatlListBuilder();
        _served = await forger.ListAsync([new TestIdentity(fixture.Open.Root)]);

        await Should.ThrowAsync<CryptographicException>(() => AatlSource.LoadAsync(Options()));
    }

    [Fact]
    public async Task Extension_OverTheSource_ServesTheCopyReadLast()
    {
        _served = await ListAsync(s_first, fixture.Open);
        await using var source = await AatlSource.LoadAsync(Options());
        var extension = new AatlExtension(source);
        _served = await ListAsync(s_first.AddDays(1), fixture.Restricted);

        await source.RefreshAsync();

        extension.Source.ShouldBeSameAs(source);
        extension.List.GetTrustAnchors().ShouldHaveSingleItem().Thumbprint.ShouldBe(fixture.Restricted.Root.Thumbprint);
        AatlProfile.Create(extension).TrustAnchorProviders.ShouldHaveSingleItem().GetTrustAnchors().ShouldHaveSingleItem()
            .Thumbprint.ShouldBe(fixture.Restricted.Root.Thumbprint);
    }

    [Fact]
    public async Task StartAutoRefresh_TooShortOrTwice_IsRefused()
    {
        _served = await ListAsync(s_first, fixture.Open);
        await using var source = await AatlSource.LoadAsync(Options());

        Should.Throw<ArgumentOutOfRangeException>(() => source.StartAutoRefresh(TimeSpan.FromSeconds(5)));
        source.StartAutoRefresh(TimeSpan.FromHours(1));
        Should.Throw<InvalidOperationException>(() => source.StartAutoRefresh(TimeSpan.FromHours(1)));
        await source.StopAutoRefreshAsync();
    }

    private Task<byte[]> ListAsync(DateTimeOffset signedAt, PolicyCa authority) =>
        fixture.Lists.ListAsync([new TestIdentity(authority.Root)], signedAt);

    private AatlOptions Options() => fixture.Lists.Options with
    {
        ListUrl = new Uri(Url),
        CacheFile = _cache,
        HttpClientProvider = new SingleClientProvider(new HttpClient(new MockHttpHandler(_ =>
        {
            Interlocked.Increment(ref _downloads);
            return Task.FromResult(_served is { } body
                ? new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(body) }
                : new HttpResponseMessage(HttpStatusCode.NotFound));
        }))),
    };
}
