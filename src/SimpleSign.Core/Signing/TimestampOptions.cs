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
        if (!endpoint.IsAbsoluteUri || (endpoint.Scheme != Uri.UriSchemeHttp && endpoint.Scheme != Uri.UriSchemeHttps))
        {
            throw new ArgumentException("TSA endpoint must be an absolute HTTP(S) URI.", nameof(endpoint));
        }

        Endpoint = endpoint;
        HttpClientProvider = httpClientProvider;
    }

    /// <summary>
    /// DigiCert's free public RFC 3161 timestamp service (<c>http://timestamp.digicert.com</c>).
    /// Its responses are trusted by Adobe Acrobat and most validators.
    /// </summary>
    /// <remarks>
    /// Public TSAs are shared, rate-limited services without an SLA. For production volume,
    /// use a TSA you have a contract with (for ICP-Brasil, an ACT accredited by ITI).
    /// </remarks>
    public static TimestampOptions DigiCert { get; } = new(new Uri("http://timestamp.digicert.com"));

    /// <summary>
    /// Sectigo's free public RFC 3161 timestamp service (<c>http://timestamp.sectigo.com</c>).
    /// </summary>
    /// <remarks>
    /// Public TSAs are shared, rate-limited services without an SLA. Sectigo asks clients
    /// to wait at least 15 seconds between requests.
    /// </remarks>
    public static TimestampOptions Sectigo { get; } = new(new Uri("http://timestamp.sectigo.com"));

    /// <summary>
    /// The FreeTSA.org community timestamp service (<c>https://freetsa.org/tsr</c>).
    /// </summary>
    /// <remarks>
    /// FreeTSA's root is not in the Adobe or system trust stores, so timestamps from it are
    /// usually reported as untrusted. Use it for development and testing.
    /// </remarks>
    public static TimestampOptions FreeTsa { get; } = new(new Uri("https://freetsa.org/tsr"));
}
