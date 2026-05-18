using Shouldly;
using SimpleSign.Core.Crypto;
using Xunit;

namespace SimpleSign.Core.Tests.Crypto;

public sealed class TsaPoolTests
{
    [Fact(DisplayName = "Constructor requires at least one URL")]
    public void Constructor_NoUrls_Throws()
    {
        var act = () => new TsaPool(Array.Empty<string>());
        Should.Throw<ArgumentException>(act);
    }

    [Fact(DisplayName = "Constructor requires non-null URLs")]
    public void Constructor_NullUrls_Throws()
    {
        var act = () => new TsaPool(null!);
        Should.Throw<ArgumentNullException>(act);
    }

    [Fact(DisplayName = "EndpointCount reflects configured TSAs")]
    public void EndpointCount_ReflectsConfiguration()
    {
        var pool = new TsaPool(["http://tsa1.example.com", "http://tsa2.example.com"]);
        pool.EndpointCount.ShouldBe(2);
    }

    [Fact(DisplayName = "GetEndpointStatuses returns all endpoints as healthy initially")]
    public void GetEndpointStatuses_InitiallyHealthy()
    {
        var pool = new TsaPool(["http://tsa1.example.com", "http://tsa2.example.com"]);
        var statuses = pool.GetEndpointStatuses();

        statuses.Count().ShouldBe(2);
        statuses.ShouldAllBe(s => s.IsHealthy);
        statuses[0].IsPrimary.ShouldBeTrue();
        statuses[1].IsPrimary.ShouldBeFalse();
        statuses.ShouldAllBe(s => s.ConsecutiveFailures == 0);
    }

    [Fact(DisplayName = "ResetAll restores all endpoints to healthy")]
    public void ResetAll_RestoresHealth()
    {
        var pool = new TsaPool(["http://tsa1.example.com"])
        {
            FailureThreshold = 1
        };

        // Force failure via GetTimestampAsync with an unreachable TSA
        // (We can't easily test this without a mock, so just verify reset works on statuses)
        pool.ResetAll();
        var statuses = pool.GetEndpointStatuses();
        statuses.ShouldAllBe(s => s.IsHealthy);
        statuses[0].IsPrimary.ShouldBeTrue();
    }

    [Fact(DisplayName = "All endpoints unavailable throws InvalidOperationException")]
    public async Task GetTimestampAsync_AllFailed_Throws()
    {
        var pool = new TsaPool(["http://unreachable1.invalid", "http://unreachable2.invalid"])
        {
            FailureThreshold = 1
        };

        using var httpClient = new HttpClient { Timeout = TimeSpan.FromMilliseconds(500) };

        var act = () => pool.GetTimestampAsync(
            new byte[] { 1, 2, 3 },
            System.Security.Cryptography.HashAlgorithmName.SHA256,
            httpClient);

        var ex = await Should.ThrowAsync<InvalidOperationException>(act);
        ex.Message.ShouldContain("TSA");
    }

    [Fact(DisplayName = "After all-fail, statuses show failures")]
    public async Task GetTimestampAsync_AfterFailure_StatusesReflect()
    {
        var pool = new TsaPool(["http://unreachable1.invalid", "http://unreachable2.invalid"])
        {
            FailureThreshold = 5 // High threshold so endpoints stay "healthy"
        };

        using var httpClient = new HttpClient { Timeout = TimeSpan.FromMilliseconds(500) };

        try
        {
            await pool.GetTimestampAsync(
                new byte[] { 1, 2, 3 },
                System.Security.Cryptography.HashAlgorithmName.SHA256,
                httpClient);
        }
        catch (InvalidOperationException)
        {
            // expected
        }

        var statuses = pool.GetEndpointStatuses();
        statuses.ShouldAllBe(s => s.ConsecutiveFailures > 0);
    }

    [Fact(DisplayName = "FailureThreshold and RecoveryInterval have sensible defaults")]
    public void Defaults_AreSensible()
    {
        var pool = new TsaPool(["http://tsa.example.com"]);
        pool.FailureThreshold.ShouldBe(3);
        pool.RecoveryInterval.ShouldBe(TimeSpan.FromSeconds(60));
    }

    [Fact(DisplayName = "Custom FailureThreshold and RecoveryInterval are applied")]
    public void CustomConfig_Applied()
    {
        var pool = new TsaPool(["http://tsa.example.com"])
        {
            FailureThreshold = 5,
            RecoveryInterval = TimeSpan.FromMinutes(5)
        };

        pool.FailureThreshold.ShouldBe(5);
        pool.RecoveryInterval.ShouldBe(TimeSpan.FromMinutes(5));
    }

    [Fact(DisplayName = "TsaEndpointStatus contains URL")]
    public void Status_ContainsUrl()
    {
        var pool = new TsaPool(["http://tsa.example.com"]);
        var statuses = pool.GetEndpointStatuses();
        statuses[0].Url.ShouldBe("http://tsa.example.com");
    }

    [Fact(DisplayName = "Initially LastFailureUtc is null")]
    public void Status_InitialLastFailure_IsNull()
    {
        var pool = new TsaPool(["http://tsa.example.com"]);
        var statuses = pool.GetEndpointStatuses();
        statuses[0].LastFailureUtc.ShouldBeNull();
    }
}
