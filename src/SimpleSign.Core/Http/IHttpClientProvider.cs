namespace SimpleSign.Core.Http;

/// <summary>
/// Provides <see cref="HttpClient"/> instances for SimpleSign network operations.
/// <para>
/// In ASP.NET Core, implement this interface using <c>IHttpClientFactory</c> to avoid socket exhaustion.
/// The default implementation (<see cref="DefaultHttpClientProvider"/>) uses a shared static instance.
/// </para>
/// </summary>
public interface IHttpClientProvider
{
    /// <summary>Returns an <see cref="HttpClient"/> suitable for OCSP, CRL, TSA, and AIA requests.</summary>
    HttpClient GetClient();
}

/// <summary>
/// Default provider that uses a shared static <see cref="HttpClient"/> with a 30-second timeout.
/// Safe for console apps and background services. For ASP.NET Core, prefer <c>IHttpClientFactory</c>.
/// </summary>
public sealed class DefaultHttpClientProvider : IHttpClientProvider
{
    /// <summary>Singleton instance for convenience.</summary>
    public static readonly DefaultHttpClientProvider Instance = new();

    private static readonly Lazy<HttpClient> SharedClient = new(() => new HttpClient
    {
        Timeout = ResilientHttp.DefaultHttpTimeout
    });

    /// <inheritdoc/>
    public HttpClient GetClient() => SharedClient.Value;
}
