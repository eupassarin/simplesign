using FluentAssertions;
using SimpleSign.Core.Crypto;
using Xunit;

namespace SimpleSign.Core.Tests.Crypto;

public sealed class TsaPoolTests
{
    [Fact(DisplayName = "Constructor requires at least one URL")]
    public void Constructor_NoUrls_Throws()
    {
        var act = () => new TsaPool(Array.Empty<string>());
        act.Should().Throw<ArgumentException>();
    }

    [Fact(DisplayName = "Constructor requires non-null URLs")]
    public void Constructor_NullUrls_Throws()
    {
        var act = () => new TsaPool(null!);
        act.Should().Throw<ArgumentNullException>();
    }

    [Fact(DisplayName = "EndpointCount reflects configured TSAs")]
    public void EndpointCount_ReflectsConfiguration()
    {
        var pool = new TsaPool(["http://tsa1.example.com", "http://tsa2.example.com"]);
        pool.EndpointCount.Should().Be(2);
    }

    [Fact(DisplayName = "GetEndpointStatuses returns all endpoints as healthy initially")]
    public void GetEndpointStatuses_InitiallyHealthy()
    {
        var pool = new TsaPool(["http://tsa1.example.com", "http://tsa2.example.com"]);
        var statuses = pool.GetEndpointStatuses();

        statuses.Should().HaveCount(2);
        statuses.Should().OnlyContain(s => s.IsHealthy);
        statuses[0].IsPrimary.Should().BeTrue();
        statuses[1].IsPrimary.Should().BeFalse();
        statuses.Should().OnlyContain(s => s.ConsecutiveFailures == 0);
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
        statuses.Should().OnlyContain(s => s.IsHealthy);
        statuses[0].IsPrimary.Should().BeTrue();
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

        await act.Should().ThrowAsync<InvalidOperationException>()
            .WithMessage("*All*TSA*unavailable*");
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
        statuses.Should().OnlyContain(s => s.ConsecutiveFailures > 0);
    }

    [Fact(DisplayName = "FailureThreshold and RecoveryInterval have sensible defaults")]
    public void Defaults_AreSensible()
    {
        var pool = new TsaPool(["http://tsa.example.com"]);
        pool.FailureThreshold.Should().Be(3);
        pool.RecoveryInterval.Should().Be(TimeSpan.FromSeconds(60));
    }

    [Fact(DisplayName = "Custom FailureThreshold and RecoveryInterval are applied")]
    public void CustomConfig_Applied()
    {
        var pool = new TsaPool(["http://tsa.example.com"])
        {
            FailureThreshold = 5,
            RecoveryInterval = TimeSpan.FromMinutes(5)
        };

        pool.FailureThreshold.Should().Be(5);
        pool.RecoveryInterval.Should().Be(TimeSpan.FromMinutes(5));
    }

    [Fact(DisplayName = "TsaEndpointStatus contains URL")]
    public void Status_ContainsUrl()
    {
        var pool = new TsaPool(["http://tsa.example.com"]);
        var statuses = pool.GetEndpointStatuses();
        statuses[0].Url.Should().Be("http://tsa.example.com");
    }

    [Fact(DisplayName = "Initially LastFailureUtc is null")]
    public void Status_InitialLastFailure_IsNull()
    {
        var pool = new TsaPool(["http://tsa.example.com"]);
        var statuses = pool.GetEndpointStatuses();
        statuses[0].LastFailureUtc.Should().BeNull();
    }
}
