using SimpleSign.Core.Http;

namespace SimpleSign.Core.Signing;

/// <summary>
/// Configuration for the archive timestamp (B-LTA). When <see cref="Endpoint"/>
/// is <see langword="null"/>, the signature timestamp endpoint and provider from
/// <see cref="TimestampOptions"/> are reused.
/// </summary>
public sealed record ArchiveTimestampOptions
{
    /// <summary>
    /// Optional archival TSA endpoint. When <see langword="null"/>, the signature
    /// timestamp endpoint is reused.
    /// </summary>
    public Uri? Endpoint { get; }

    /// <summary>
    /// Optional archive-TSA-specific <see cref="IHttpClientProvider"/>. When
    /// <see langword="null"/>, resolution falls back to the signature timestamp
    /// provider and then to the builder-wide provider.
    /// </summary>
    public IHttpClientProvider? HttpClientProvider { get; }

    /// <summary>Creates a new instance.</summary>
    /// <param name="endpoint">Optional archival TSA endpoint (null reuses the signature TSA endpoint).</param>
    /// <param name="httpClientProvider">Optional archive-TSA-specific HTTP client provider.</param>
    /// <exception cref="ArgumentException"><paramref name="endpoint"/> is supplied but not absolute.</exception>
    public ArchiveTimestampOptions(
        Uri? endpoint = null,
        IHttpClientProvider? httpClientProvider = null)
    {
        if (endpoint is not null && !endpoint.IsAbsoluteUri)
        {
            throw new ArgumentException(
                "Archive TSA endpoint must be absolute.",
                nameof(endpoint));
        }

        Endpoint = endpoint;
        HttpClientProvider = httpClientProvider;
    }
}
