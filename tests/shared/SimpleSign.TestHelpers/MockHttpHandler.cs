using System.Net;

namespace SimpleSign.TestHelpers;

/// <summary>
/// Test double for HttpMessageHandler — routes requests to a user-provided delegate.
/// Usage: new HttpClient(new MockHttpHandler(async req => new HttpResponseMessage { ... }))
/// </summary>
public sealed class MockHttpHandler(Func<HttpRequestMessage, Task<HttpResponseMessage>> handler) : HttpMessageHandler
{
    protected override Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request, CancellationToken cancellationToken) =>
        handler(request);

    /// <summary>Creates an HttpClient that returns the given bytes for any GET request.</summary>
    public static HttpClient ForGetBytes(byte[] responseBytes, HttpStatusCode status = HttpStatusCode.OK) =>
        new(new MockHttpHandler(_ => Task.FromResult(new HttpResponseMessage(status)
        {
            Content = new ByteArrayContent(responseBytes)
        })));

    /// <summary>Creates an HttpClient that returns the given bytes for any POST request.</summary>
    public static HttpClient ForPostBytes(byte[] responseBytes, HttpStatusCode status = HttpStatusCode.OK) =>
        new(new MockHttpHandler(_ => Task.FromResult(new HttpResponseMessage(status)
        {
            Content = new ByteArrayContent(responseBytes)
        })));

    /// <summary>Creates an HttpClient that always fails.</summary>
    public static HttpClient Failing() =>
        new(new MockHttpHandler(_ => throw new HttpRequestException("Simulated network failure")));
}
