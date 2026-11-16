using Shouldly;
using SimpleSign.Core.Revocation;
using SimpleSign.TestHelpers;
using Xunit;

namespace SimpleSign.Core.Tests.Revocation;

/// <summary>When a CRL collected for B-LT comes from the shared cache and when it is downloaded again.</summary>
[Trait("Category", "Unit")]
public sealed class CachedCrlTests : IDisposable
{
    private const string Url = "http://198.51.100.9/leaf.crl";
    private readonly SyntheticPki _pki = new();
    private readonly InMemoryRevocationCache _cache = new(TimeSpan.FromHours(1));
    private int _downloads;

    public void Dispose() => _pki.Dispose();

    private Func<Task<byte[]?>> Download(byte[] crl) => () =>
    {
        _downloads++;
        return Task.FromResult<byte[]?>(crl);
    };

    private byte[] Crl(DateTimeOffset thisUpdate) => _pki.BuildLeafCrl(thisUpdate, thisUpdate.AddDays(7));

    [Fact]
    public async Task GetAsync_CachedCrlIssuedAfterTheTime_IsReusedWithoutDownloading()
    {
        var now = DateTimeOffset.UtcNow;
        byte[] cached = Crl(now.AddMinutes(-5));
        _cache.Set(Url, cached, now.AddDays(7));

        byte[]? crl = await CachedCrl.GetAsync(_cache, Url, now.AddHours(-1), Download(Crl(now)));

        crl.ShouldBe(cached);
        _downloads.ShouldBe(0);
    }

    [Fact]
    public async Task GetAsync_CachedCrlIssuedBeforeTheTime_IsDownloadedAgainAndReplaced()
    {
        var now = DateTimeOffset.UtcNow;
        _cache.Set(Url, Crl(now.AddHours(-2)), now.AddDays(7));
        byte[] fresh = Crl(now.AddMinutes(-1));

        byte[]? crl = await CachedCrl.GetAsync(_cache, Url, now.AddHours(-1), Download(fresh));

        crl.ShouldBe(fresh);
        _downloads.ShouldBe(1);
        _cache.TryGet(Url, out byte[] kept).ShouldBeTrue();
        kept.ShouldBe(fresh);
    }

    [Fact]
    public async Task GetAsync_NoTimeToProve_DownloadsAndRemembers()
    {
        var now = DateTimeOffset.UtcNow;
        _cache.Set(Url, Crl(now.AddMinutes(-5)), now.AddDays(7));
        byte[] fresh = Crl(now);

        byte[]? crl = await CachedCrl.GetAsync(_cache, Url, issuedAfter: null, Download(fresh));

        crl.ShouldBe(fresh);
        _downloads.ShouldBe(1);
    }

    [Fact]
    public async Task GetAsync_CachedCrlPastItsNextUpdate_IsDownloadedAgain()
    {
        var now = DateTimeOffset.UtcNow;
        byte[] expired = _pki.BuildLeafCrl(now.AddDays(-2), now.AddDays(-1));
        _cache.Set(Url, expired, now.AddDays(7));

        await CachedCrl.GetAsync(_cache, Url, now.AddDays(-3), Download(Crl(now)));

        _downloads.ShouldBe(1);
    }

    [Fact]
    public async Task GetAsync_NoCache_AlwaysDownloads()
    {
        await CachedCrl.GetAsync(null, Url, DateTimeOffset.UtcNow.AddYears(-1), Download(Crl(DateTimeOffset.UtcNow)));
        await CachedCrl.GetAsync(null, Url, DateTimeOffset.UtcNow.AddYears(-1), Download(Crl(DateTimeOffset.UtcNow)));

        _downloads.ShouldBe(2);
    }

    [Fact]
    public void GenTime_TokenAndNoToken()
    {
        var genTime = new DateTimeOffset(2025, 3, 4, 5, 6, 7, TimeSpan.Zero);
        byte[] token = TimestampTestResponseBuilder.CreateTokenForData("x"u8, new TimestampTokenOptions { GenTime = genTime });

        CachedCrl.GenTime(token).ShouldBe(genTime);
        CachedCrl.GenTime(null).ShouldBeNull();
    }
}
