using SimpleSign.Core.Http;

namespace SimpleSign.Core.Signing;

/// <summary>
/// Configuration for the signature timestamp (TSA) required by B-T and higher.
/// </summary>
public sealed record TimestampOptions
{
    /// <summary>The absolute TSA endpoint URI.</summary>
    public Uri Endpoint { get; }

    /// <summary>
    /// Optional TSA-specific <see cref="IHttpClientProvider"/>. When <see langword="null"/>,
    /// the builder-wide provider is used as fallback.
    /// </summary>
    public IHttpClientProvider? HttpClientProvider { get; }

    /// <summary>Creates a new instance with the specified TSA endpoint.</summary>
    /// <param name="endpoint">The absolute TSA endpoint URI. Must not be null.</param>
    /// <param name="httpClientProvider">Optional TSA-specific HTTP client provider.</param>
    /// <exception cref="ArgumentNullException"><paramref name="endpoint"/> is null.</exception>
    /// <exception cref="ArgumentException"><paramref name="endpoint"/> is not absolute.</exception>
    public TimestampOptions(
        Uri endpoint,
        IHttpClientProvider? httpClientProvider = null)
    {
        ArgumentNullException.ThrowIfNull(endpoint);
        if (!endpoint.IsAbsoluteUri)
        {
            throw new ArgumentException("TSA endpoint must be absolute.", nameof(endpoint));
        }

        Endpoint = endpoint;
        HttpClientProvider = httpClientProvider;
    }
}
