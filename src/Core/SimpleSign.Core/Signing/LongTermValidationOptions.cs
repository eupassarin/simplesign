using SimpleSign.Core.Http;
using SimpleSign.Core.Revocation;

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

    /// <summary>
    /// How far an OCSP response fetched during collection may disagree with this machine's clock:
    /// its <c>thisUpdate</c> may be up to this much in the future and its <c>nextUpdate</c> up to this
    /// much in the past. Responders stamp <c>thisUpdate</c> with their own clock, so without a
    /// tolerance a responder a fraction of a second ahead rejects its own fresh response.
    /// Default: <see cref="OcspClient.DefaultClockSkewTolerance"/> (5 minutes).
    /// </summary>
    /// <exception cref="ArgumentOutOfRangeException">The value is negative.</exception>
    public TimeSpan ClockSkewTolerance
    {
        get => _clockSkewTolerance;
        init
        {
            ArgumentOutOfRangeException.ThrowIfLessThan(value, TimeSpan.Zero);
            _clockSkewTolerance = value;
        }
    }

    private readonly TimeSpan _clockSkewTolerance = OcspClient.DefaultClockSkewTolerance;

    /// <summary>Creates a new instance.</summary>
    /// <param name="httpClientProvider">Optional certificate/revocation HTTP client provider.</param>
    public LongTermValidationOptions(IHttpClientProvider? httpClientProvider = null)
    {
        HttpClientProvider = httpClientProvider;
    }
}
