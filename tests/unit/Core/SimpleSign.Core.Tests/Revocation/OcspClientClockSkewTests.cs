using System.Net;
using Shouldly;
using SimpleSign.Core.Revocation;
using SimpleSign.Core.Tests.TestHelpers;
using SimpleSign.TestHelpers;
using Xunit;

namespace SimpleSign.Core.Tests.Revocation;

/// <summary>
/// Issue #215: responders stamp <c>thisUpdate</c> with their own clock, so a fetched response may be
/// slightly "in the future" for this machine. Online fetches tolerate a configurable clock skew.
/// </summary>
[Trait("Category", "Unit")]
public sealed class OcspClientClockSkewTests
{
    // Public IP literal, so the SSRF guard needs no DNS lookup.
    private const string ResponderUrl = "http://8.8.8.8/ocsp";

    [Fact]
    public async Task FetchOcspResponseAsync_ThisUpdateSecondsAhead_AcceptedWithDefaultTolerance()
    {
        using var pki = new SyntheticPki();
        DateTimeOffset now = DateTimeOffset.UtcNow;
        using var client = Responding(pki, now.AddSeconds(2), now.AddHours(1));

        var result = await new OcspClient(client)
            .FetchOcspResponseAsync(pki.Leaf, pki.IntermediateCa, ResponderUrl, CancellationToken.None);

        result.IsValid.ShouldBeTrue();
    }

    [Fact]
    public async Task FetchOcspResponseAsync_ThisUpdateBeyondTolerance_Throws()
    {
        using var pki = new SyntheticPki();
        DateTimeOffset now = DateTimeOffset.UtcNow;
        using var client = Responding(pki, now.AddMinutes(10), now.AddHours(1));

        var ex = await Should.ThrowAsync<InvalidDataException>(() => new OcspClient(client)
            .FetchOcspResponseAsync(pki.Leaf, pki.IntermediateCa, ResponderUrl, CancellationToken.None));

        ex.Message.ShouldContain("issued after the validation time");
    }

    [Fact]
    public async Task FetchOcspResponseAsync_ZeroTolerance_RejectsResponseSecondsAhead()
    {
        using var pki = new SyntheticPki();
        DateTimeOffset now = DateTimeOffset.UtcNow;
        using var client = Responding(pki, now.AddSeconds(30), now.AddHours(1));

        await Should.ThrowAsync<InvalidDataException>(() => new OcspClient(client) { ClockSkewTolerance = TimeSpan.Zero }
            .FetchOcspResponseAsync(pki.Leaf, pki.IntermediateCa, ResponderUrl, CancellationToken.None));
    }

    [Fact]
    public async Task FetchOcspResponseAsync_NextUpdateWithinTolerance_Accepted()
    {
        using var pki = new SyntheticPki();
        DateTimeOffset now = DateTimeOffset.UtcNow;
        using var client = Responding(pki, now.AddHours(-1), now.AddMinutes(-2));

        var result = await new OcspClient(client)
            .FetchOcspResponseAsync(pki.Leaf, pki.IntermediateCa, ResponderUrl, CancellationToken.None);

        result.IsValid.ShouldBeTrue();
    }

    [Fact]
    public async Task FetchOcspResponseAsync_NextUpdateBeyondTolerance_Throws()
    {
        using var pki = new SyntheticPki();
        DateTimeOffset now = DateTimeOffset.UtcNow;
        using var client = Responding(pki, now.AddHours(-1), now.AddMinutes(-10));

        var ex = await Should.ThrowAsync<InvalidDataException>(() => new OcspClient(client)
            .FetchOcspResponseAsync(pki.Leaf, pki.IntermediateCa, ResponderUrl, CancellationToken.None));

        ex.Message.ShouldContain("expired before the validation time");
    }

    [Fact]
    public void CheckEmbeddedOcspResponse_ThisUpdateSecondsAfterSigningTime_StillUnknown()
    {
        using var pki = new SyntheticPki();
        using var httpClient = new HttpClient();
        DateTimeOffset signingTime = DateTimeOffset.UtcNow;
        byte[] response = OcspResponseFactory.Build(
            pki.Leaf, pki.IntermediateCa, pki.IntermediateCa, signingTime.AddSeconds(2), signingTime.AddHours(1));

        new OcspClient(httpClient).CheckEmbeddedOcspResponse(pki.Leaf, pki.IntermediateCa, response, signingTime)
            .ShouldBeNull();
    }

    [Fact]
    public void ClockSkewTolerance_Negative_Throws()
    {
        using var httpClient = new HttpClient();

        Should.Throw<ArgumentOutOfRangeException>(() => new OcspClient(httpClient) { ClockSkewTolerance = TimeSpan.FromSeconds(-1) });
    }

    private static HttpClient Responding(SyntheticPki pki, DateTimeOffset thisUpdate, DateTimeOffset nextUpdate)
    {
        byte[] body = OcspResponseFactory.Build(pki.Leaf, pki.IntermediateCa, pki.IntermediateCa, thisUpdate, nextUpdate);
        return new HttpClient(new MockHttpHandler(_ =>
            Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(body) })));
    }
}
