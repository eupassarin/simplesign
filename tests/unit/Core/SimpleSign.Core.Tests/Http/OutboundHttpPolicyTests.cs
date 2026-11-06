using System.Net;
using Shouldly;
using SimpleSign.Core.Http;
using SimpleSign.Core.Signing;
using SimpleSign.TestHelpers;
using Xunit;

namespace SimpleSign.Core.Tests.Http;

/// <summary>
/// Issue #215: on split-DNS networks a public CA host may resolve to a private address while the
/// request goes through a proxy. <see cref="OutboundHttpPolicy.PrivateNetworkHosts"/> lets listed
/// hosts through the SSRF guard; loopback, link-local and literal addresses stay blocked.
/// </summary>
[Trait("Category", "Unit")]
public sealed class OutboundHttpPolicyTests
{
    private static readonly OutboundHttpPolicy s_policy = new()
    {
        PrivateNetworkHosts = ["crl.ca.example", "*.ocsp.example"],
    };

    [Theory]
    [InlineData("crl.ca.example", true)]
    [InlineData("CRL.CA.EXAMPLE", true)]
    [InlineData("crl.ca.example.", true)]
    [InlineData("a.ocsp.example", true)]
    [InlineData("a.b.ocsp.example", true)]
    [InlineData("ocsp.example", false)]
    [InlineData("evilocsp.example", false)]
    [InlineData("other.ca.example", false)]
    public void AllowsPrivateAddressesFor_ListedHosts_Matches(string host, bool expected) =>
        s_policy.AllowsPrivateAddressesFor(host).ShouldBe(expected);

    [Theory]
    [InlineData("")]
    [InlineData("10.0.0.1")]
    [InlineData("localhost")]
    [InlineData("*")]
    [InlineData("crl.*.example")]
    [InlineData("http://crl.ca.example")]
    public void PrivateNetworkHosts_InvalidEntry_Throws(string entry) =>
        Should.Throw<ArgumentException>(() => new OutboundHttpPolicy { PrivateNetworkHosts = [entry] });

    [Fact]
    public void Default_HasNoHosts() => OutboundHttpPolicy.Default.PrivateNetworkHosts.ShouldBeEmpty();

    [Theory]
    [InlineData("http://crl.ca.example/ca.crl", "10.20.30.40", true)]
    [InlineData("http://x.ocsp.example/", "192.168.1.5", true)]
    [InlineData("http://other.example/ca.crl", "10.20.30.40", false)]
    [InlineData("http://crl.ca.example/ca.crl", "127.0.0.1", false)]
    [InlineData("http://crl.ca.example/ca.crl", "169.254.169.254", false)]
    [InlineData("http://crl.ca.example/ca.crl", "::1", false)]
    [InlineData("http://crl.ca.example/ca.crl", "::ffff:169.254.169.254", false)]
    [InlineData("http://crl.ca.example/ca.crl", "0.0.0.0", false)]
    public async Task IsSafeUrlAsync_WithPolicy_AllowsOnlyListedHostsOnPrivateAddresses(string url, string resolved, bool expected)
    {
        bool safe = await UrlValidator.IsSafeUrlAsync(url, s_policy, Resolve(resolved));

        safe.ShouldBe(expected);
    }

    [Fact]
    public async Task IsSafeUrlAsync_DefaultPolicy_BlocksHostResolvingToPrivateAddress()
    {
        bool safe = await UrlValidator.IsSafeUrlAsync("http://crl.ca.example/ca.crl", OutboundHttpPolicy.Default, Resolve("10.20.30.40"));

        safe.ShouldBeFalse();
    }

    [Theory]
    [InlineData("http://10.0.0.1/ca.crl")]
    [InlineData("http://localhost/ca.crl")]
    public async Task IsSafeUrlAsync_LiteralPrivateOrLocalhost_BlockedEvenWithPolicy(string url)
    {
        var everything = new OutboundHttpPolicy { PrivateNetworkHosts = ["*.example"] };

        (await UrlValidator.IsSafeUrlAsync(url, everything, Resolve("10.0.0.1"))).ShouldBeFalse();
    }

    [Fact]
    public async Task GetBytesAsync_PrivateLiteralWithPolicy_StillBlockedWithoutRequest()
    {
        int calls = 0;
        using var client = new HttpClient(new MockHttpHandler(_ =>
        {
            Interlocked.Increment(ref calls);
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK));
        }));

        byte[]? bytes = await ResilientHttp.GetBytesAsync(client, new Uri("http://10.1.2.3/ca.crl"), s_policy);

        bytes.ShouldBeNull();
        calls.ShouldBe(0);
    }

    [Fact]
    public void SingleClientProvider_OutboundPolicy_DefaultsAndInit()
    {
        using var client = new HttpClient();
        IHttpClientProvider plain = new SingleClientProvider(client);
        IHttpClientProvider configured = new SingleClientProvider(client) { OutboundPolicy = s_policy };

        plain.OutboundPolicy.ShouldBeSameAs(OutboundHttpPolicy.Default);
        configured.OutboundPolicy.ShouldBeSameAs(s_policy);
        ((IHttpClientProvider)DefaultHttpClientProvider.Instance).OutboundPolicy.ShouldBeSameAs(OutboundHttpPolicy.Default);
    }

    [Fact]
    public void LongTermValidationOptions_ClockSkewTolerance_DefaultsToFiveMinutesAndRejectsNegative()
    {
        new LongTermValidationOptions().ClockSkewTolerance.ShouldBe(TimeSpan.FromMinutes(5));
        Should.Throw<ArgumentOutOfRangeException>(() => new LongTermValidationOptions { ClockSkewTolerance = TimeSpan.FromSeconds(-1) });
    }

    private static Func<string, CancellationToken, Task<IPAddress[]>> Resolve(string address) =>
        (_, _) => Task.FromResult(new[] { IPAddress.Parse(address) });
}
