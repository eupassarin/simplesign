using SimpleSign.Core.Http;

namespace SimpleSign.TestHelpers;

/// <summary>An <see cref="IHttpClientProvider"/> with a given client and outbound policy (a loopback origin allowed, say).</summary>
/// <param name="client">The client every request goes through (a <see cref="MockHttpHandler"/>'s, typically).</param>
/// <param name="policy">The outbound policy of the provider.</param>
public sealed class PolicyHttpClientProvider(HttpClient client, OutboundHttpPolicy policy) : IHttpClientProvider
{
    /// <inheritdoc />
    public HttpClient GetClient() => client;

    /// <inheritdoc />
    public OutboundHttpPolicy OutboundPolicy => policy;
}
