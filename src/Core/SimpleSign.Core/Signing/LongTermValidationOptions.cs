using SimpleSign.Core.Http;

namespace SimpleSign.Core.Signing;

/// <summary>
/// Configuration for collecting and embedding long-term validation material
/// (certificate and revocation values) required by B-LT and higher.
/// </summary>
public sealed record LongTermValidationOptions
{
    /// <summary>
    /// Optional certificate/revocation-specific <see cref="IHttpClientProvider"/>.
    /// When <see langword="null"/>, the builder-wide provider is used as fallback.
    /// </summary>
    public IHttpClientProvider? HttpClientProvider { get; }

    /// <summary>Creates a new instance.</summary>
    /// <param name="httpClientProvider">Optional certificate/revocation HTTP client provider.</param>
    public LongTermValidationOptions(IHttpClientProvider? httpClientProvider = null)
    {
        HttpClientProvider = httpClientProvider;
    }
}
