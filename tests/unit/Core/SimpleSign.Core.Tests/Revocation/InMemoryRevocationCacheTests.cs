using Shouldly;
using SimpleSign.Core.Revocation;
using Xunit;

namespace SimpleSign.Core.Tests.Revocation;

[Trait("Category", "Unit")]
public sealed class InMemoryRevocationCacheTests
{
    [Fact]
    public void TryGet_BeforeExpiry_ReturnsData()
    {
        var clock = new ManualClock();
        var cache = new InMemoryRevocationCache(TimeSpan.FromHours(1), clock);
        cache.Set("http://ca/crl", [1, 2], clock.GetUtcNow().AddMinutes(10));

        cache.TryGet("http://ca/crl", out var data).ShouldBeTrue();
        data.ShouldBe([1, 2]);
    }

    [Fact]
    public void TryGet_AfterOwnExpiry_ReturnsFalse()
    {
        var clock = new ManualClock();
        var cache = new InMemoryRevocationCache(TimeSpan.FromHours(1), clock);
        cache.Set("k", [1], clock.GetUtcNow().AddMinutes(10));

        clock.Advance(TimeSpan.FromMinutes(11));

        cache.TryGet("k", out _).ShouldBeFalse();
        cache.Count.ShouldBe(0);
    }

    [Fact]
    public void TryGet_AfterMaxLifetime_ReturnsFalse()
    {
        var clock = new ManualClock();
        var cache = new InMemoryRevocationCache(TimeSpan.FromMinutes(5), clock);
        cache.Set("k", [1], DateTimeOffset.MaxValue);

        clock.Advance(TimeSpan.FromMinutes(6));

        cache.TryGet("k", out _).ShouldBeFalse();
    }

    [Fact]
    public void Constructor_NonPositiveLifetime_Throws() =>
        Should.Throw<ArgumentOutOfRangeException>(() => new InMemoryRevocationCache(TimeSpan.Zero));

    private sealed class ManualClock : TimeProvider
    {
        private DateTimeOffset _now = new(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);

        public override DateTimeOffset GetUtcNow() => _now;

        public void Advance(TimeSpan by) => _now += by;
    }
}
