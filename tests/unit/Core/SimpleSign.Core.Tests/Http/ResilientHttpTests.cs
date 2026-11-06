using System.Net;
using System.Net.Http.Headers;
using Shouldly;
using SimpleSign.Core.Http;
using SimpleSign.TestHelpers;
using Xunit;

namespace SimpleSign.Core.Tests.Http;

/// <summary>
/// The outbound HTTP rules of ADR 0020: URLs that point to local or private addresses are refused
/// before any request is sent, transient failures (5xx, network errors) are retried, and client
/// errors are not.
/// </summary>
[Trait("Category", "Unit")]
public sealed class ResilientHttpTests
{
    // Public IP literals, so the SSRF check needs no DNS lookup.
    private const string PublicUrl = "http://8.8.8.8/ca.crl";

    private static readonly byte[] Body = [0x30, 0x03, 0x02, 0x01, 0x01];

    [Fact]
    public async Task GetBytesAsync_PublicUrl_ReturnsBody()
    {
        var (client, calls) = Client(_ => Ok());

        byte[]? bytes = await ResilientHttp.GetBytesAsync(client, new Uri(PublicUrl));

        bytes.ShouldBe(Body);
        calls().ShouldBe(1);
    }

    [Theory]
    [InlineData("http://127.0.0.1/crl")]
    [InlineData("http://10.1.2.3/crl")]
    [InlineData("http://192.168.0.10/crl")]
    [InlineData("http://169.254.169.254/latest/meta-data/")]
    [InlineData("http://[::1]/crl")]
    public async Task GetBytesAsync_LocalOrPrivateAddress_ReturnsNullWithoutSendingRequest(string url)
    {
        var (client, calls) = Client(_ => Ok());

        byte[]? bytes = await ResilientHttp.GetBytesAsync(client, new Uri(url));

        bytes.ShouldBeNull();
        calls().ShouldBe(0);
    }

    [Fact]
    public async Task GetBytesAsync_ServerErrorThenSuccess_RetriesAndReturnsBody()
    {
        var (client, calls) = Client(attempt => attempt < 3 ? Status(HttpStatusCode.ServiceUnavailable) : Ok());

        byte[]? bytes = await ResilientHttp.GetBytesAsync(client, new Uri(PublicUrl));

        bytes.ShouldBe(Body);
        calls().ShouldBe(3);
    }

    [Fact]
    public async Task GetBytesAsync_NetworkErrorThenSuccess_Retries()
    {
        var (client, calls) = Client(attempt => attempt == 1 ? throw new HttpRequestException("connection reset") : Ok());

        byte[]? bytes = await ResilientHttp.GetBytesAsync(client, new Uri(PublicUrl));

        bytes.ShouldBe(Body);
        calls().ShouldBe(2);
    }

    [Fact]
    public async Task GetBytesAsync_AlwaysServerError_ReturnsNullAfterThreeRetries()
    {
        var (client, calls) = Client(_ => Status(HttpStatusCode.InternalServerError));

        byte[]? bytes = await ResilientHttp.GetBytesAsync(client, new Uri(PublicUrl));

        bytes.ShouldBeNull();
        calls().ShouldBe(4);
    }

    [Theory]
    [InlineData(HttpStatusCode.NotFound)]
    [InlineData(HttpStatusCode.Forbidden)]
    public async Task GetBytesAsync_ClientError_ReturnsNullWithoutRetry(HttpStatusCode status)
    {
        var (client, calls) = Client(_ => Status(status));

        byte[]? bytes = await ResilientHttp.GetBytesAsync(client, new Uri(PublicUrl));

        bytes.ShouldBeNull();
        calls().ShouldBe(1);
    }

    [Fact]
    public async Task GetBytesAsync_CancelledToken_Throws()
    {
        var (client, _) = Client(_ => Ok());
        using var cts = new CancellationTokenSource();
        await cts.CancelAsync();

        await Should.ThrowAsync<OperationCanceledException>(
            () => ResilientHttp.GetBytesAsync(client, new Uri(PublicUrl), cancellationToken: cts.Token));
    }

    [Fact]
    public async Task PostAsync_PrivateAddress_ThrowsWithoutSendingRequest()
    {
        var (client, calls) = Client(_ => Ok());
        using var content = new ByteArrayContent(Body);

        var ex = await Should.ThrowAsync<InvalidOperationException>(
            () => ResilientHttp.PostAsync(client, "http://10.0.0.5/tsa", content));

        ex.Message.ShouldContain("SSRF blocked");
        calls().ShouldBe(0);
    }

    [Fact]
    public async Task PostAsync_WithAuthorization_SendsHeaderOnEveryAttemptButNotOnClient()
    {
        var seen = new List<string?>();
        var (client, calls) = Client(
            attempt => attempt == 1 ? Status(HttpStatusCode.BadGateway) : Ok(),
            request => seen.Add(request.Headers.Authorization?.ToString()));

        using var response = await ResilientHttp.PostAsync(client, PublicUrl, Body,
            new MediaTypeHeaderValue("application/timestamp-query"), new AuthenticationHeaderValue("Bearer", "token"));

        response.StatusCode.ShouldBe(HttpStatusCode.OK);
        calls().ShouldBe(2);
        seen.ShouldAllBe(h => h == "Bearer token");
        client.DefaultRequestHeaders.Authorization.ShouldBeNull();
    }

    private static (HttpClient Client, Func<int> Calls) Client(
        Func<int, HttpResponseMessage> respond, Action<HttpRequestMessage>? inspect = null)
    {
        int count = 0;
        var client = new HttpClient(new MockHttpHandler(request =>
        {
            int attempt = Interlocked.Increment(ref count);
            inspect?.Invoke(request);
            return Task.FromResult(respond(attempt));
        }));
        return (client, () => Volatile.Read(ref count));
    }

    private static HttpResponseMessage Ok() => new(HttpStatusCode.OK) { Content = new ByteArrayContent(Body) };

    private static HttpResponseMessage Status(HttpStatusCode status) => new(status);
}
