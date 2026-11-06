namespace SimpleSign.Core.Http;

/// <summary>
/// <see cref="IHttpClientProvider"/> backed by <see cref="IHttpClientFactory"/>.
/// Each call to <see cref="GetClient"/> calls <c>IHttpClientFactory.CreateClient(name)</c>,
/// which respects the named-client configuration and lifetime managed by the factory.
/// </summary>
/// <remarks>
/// Register in ASP.NET Core:
/// <code>
/// services.AddHttpClient("SimpleSign", client =>
/// {
///     client.Timeout = TimeSpan.FromSeconds(10);
/// });
/// services.AddSimpleSign();   // auto-wired when IHttpClientFactory is in the container
/// </code>
/// </remarks>
public sealed class HttpClientFactoryProvider : IHttpClientProvider
{
    private readonly IHttpClientFactory _factory;
    private readonly string _clientName;

    /// <summary>
    /// Creates a provider that resolves named clients from <paramref name="factory"/>.
    /// </summary>
    /// <param name="factory">The factory to delegate to.</param>
    /// <param name="clientName">
    /// The named-client key passed to <see cref="IHttpClientFactory.CreateClient(string)"/>.
    /// Defaults to <c>"SimpleSign"</c>.
    /// </param>
    public HttpClientFactoryProvider(IHttpClientFactory factory, string clientName = "SimpleSign")
    {
        ArgumentNullException.ThrowIfNull(factory);
        ArgumentException.ThrowIfNullOrWhiteSpace(clientName);
        _factory = factory;
        _clientName = clientName;
    }

    /// <inheritdoc/>
    public HttpClient GetClient() => _factory.CreateClient(_clientName);
}
