using System.Net;
using Shouldly;
using SimpleSign.Core.Http;
using SimpleSign.TestHelpers;
using Xunit;

namespace SimpleSign.Core.Tests.Http;

/// <summary>
/// <see cref="OutboundHttpPolicy.LoopbackOrigins"/>: a local test service (the SimpleSign Sandbox)
/// listed by scheme, host and port passes the SSRF guard; everything else on this machine stays blocked.
/// </summary>
[Trait("Category", "Unit")]
public sealed class OutboundHttpPolicyLoopbackTests
{
    private static readonly OutboundHttpPolicy s_policy = new()
    {
        LoopbackOrigins = [new Uri("http://localhost:5300"), new Uri("ldap://127.0.0.1:3890/")],
    };

    [Fact]
    public void Default_HasNoLoopbackOrigins() => OutboundHttpPolicy.Default.LoopbackOrigins.ShouldBeEmpty();

    [Fact]
    public void LoopbackOrigins_Entries_AreNormalizedToOrigins() =>
        new OutboundHttpPolicy { LoopbackOrigins = [new Uri("HTTP://LOCALHOST:5300"), new Uri("https://[::1]:8443/"), new Uri("tcp://127.0.0.1:318")] }
            .LoopbackOrigins.Select(o => o.AbsoluteUri).ShouldBe(["http://localhost:5300/", "https://[::1]:8443/", "tcp://127.0.0.1:318/"]);

    [Theory]
    [InlineData("http://sandbox.lab:5300")]
    [InlineData("http://10.0.0.1:5300")]
    [InlineData("ftp://localhost:21")]
    [InlineData("http://localhost:5300/crl/")]
    [InlineData("http://user@localhost:5300")]
    [InlineData("http://localhost:5300/?x=1")]
    public void LoopbackOrigins_InvalidEntry_Throws(string entry) =>
        Should.Throw<ArgumentException>(() => new OutboundHttpPolicy { LoopbackOrigins = [new Uri(entry)] });

    [Theory]
    [InlineData("http://localhost:5300/crl/intermediate.crl", true)]
    [InlineData("http://LOCALHOST:5300/tsa/tsr", true)]
    [InlineData("http://localhost:5301/crl/intermediate.crl", false)]
    [InlineData("https://localhost:5300/crl/intermediate.crl", false)]
    [InlineData("http://127.0.0.1:5300/crl/intermediate.crl", false)]
    [InlineData("http://localhost/crl.crl", false)]
    [InlineData("http://10.1.2.3:5300/crl.crl", false)]
    [InlineData("http://169.254.169.254/latest/meta-data", false)]
    public async Task IsSafeUrlAsync_LoopbackOrigins_AllowOnlyTheListedOrigins(string url, bool expected) =>
        (await UrlValidator.IsSafeUrlAsync(url, s_policy)).ShouldBe(expected);

    [Theory]
    [InlineData("http://localhost:5300/crl/intermediate.crl")]
    [InlineData("http://127.0.0.1:5300/crl/intermediate.crl")]
    public async Task IsSafeUrlAsync_DefaultPolicy_BlocksLoopback(string url) =>
        (await UrlValidator.IsSafeUrlAsync(url, OutboundHttpPolicy.Default)).ShouldBeFalse();

    [Fact]
    public async Task GetBytesAsync_ListedOrigin_SendsTheRequest()
    {
        int calls = 0;
        using var client = new HttpClient(new MockHttpHandler(_ =>
        {
            Interlocked.Increment(ref calls);
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent([1, 2, 3]) });
        }));

        byte[]? listed = await ResilientHttp.GetBytesAsync(client, new Uri("http://localhost:5300/crl/root.crl"), s_policy);
        byte[]? other = await ResilientHttp.GetBytesAsync(client, new Uri("http://localhost:6000/crl/root.crl"), s_policy);

        listed.ShouldBe([1, 2, 3]);
        other.ShouldBeNull();
        calls.ShouldBe(1);
    }

    [Theory]
    [InlineData("127.0.0.1", "ldap://127.0.0.1:3890/", false)]
    [InlineData("127.0.0.1", "ldap://127.0.0.1:389/", true)]
    [InlineData("127.0.0.1", "ldaps://127.0.0.1:3890/", true)]
    public void IsBlockedAddress_LoopbackOrigin_MatchesSchemeAndPort(string host, string origin, bool blocked) =>
        UrlValidator.IsBlockedAddress(host, IPAddress.Loopback, s_policy, new Uri(origin)).ShouldBe(blocked);
}
