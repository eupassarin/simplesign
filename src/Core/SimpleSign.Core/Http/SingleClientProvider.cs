namespace SimpleSign.Core.Http;

/// <summary>
/// An <see cref="IHttpClientProvider"/> that always returns one caller-owned
/// <see cref="HttpClient"/>. The signer never disposes the wrapped client.
/// </summary>
/// <remarks>
/// Use this adapter to keep using a single pre-configured <see cref="HttpClient"/>
/// (proxies, testing, mTLS) with the provider-based signing APIs.
/// </remarks>
public sealed class SingleClientProvider : IHttpClientProvider
{
    private readonly HttpClient _client;

    /// <summary>Creates a provider around a single non-owned <see cref="HttpClient"/>.</summary>
    /// <param name="client">The client to return from <see cref="GetClient"/>. Must not be null.</param>
    /// <exception cref="ArgumentNullException"><paramref name="client"/> is null.</exception>
    public SingleClientProvider(HttpClient client)
    {
        ArgumentNullException.ThrowIfNull(client);
        _client = client;
    }

    /// <inheritdoc/>
    public HttpClient GetClient() => _client;

    /// <inheritdoc/>
    /// <remarks>
    /// Set it to let hosts that a corporate DNS resolves to private addresses through, for example
    /// <c>new OutboundHttpPolicy { PrivateNetworkHosts = ["crl.ca.example"] }</c>.
    /// </remarks>
    public OutboundHttpPolicy OutboundPolicy { get; init; } = OutboundHttpPolicy.Default;
}
