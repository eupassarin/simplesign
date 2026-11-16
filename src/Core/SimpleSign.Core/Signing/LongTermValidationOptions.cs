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
    /// The revocation source tried first for each certificate; the other one is the fallback.
    /// Default: <see cref="RevocationPreference.OcspFirst"/>.
    /// </summary>
    public RevocationPreference RevocationPreference { get; init; }

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

    /// <summary>
    /// A CRL cache shared with other operations (the one a <see cref="ChainRevocationChecker"/> or the validators use):
    /// CRLs downloaded while collecting are remembered, and a cached CRL is embedded instead of downloading again when
    /// it was issued after the signature time-stamp's genTime and is still current — so extending a batch of older
    /// signatures downloads each CRL once. A CRL issued before that time is downloaded again, since revocation data
    /// must postdate the time it proves. Default: <see langword="null"/>, every CRL is downloaded.
    /// </summary>
    public IRevocationCache? RevocationCache { get; init; }

    /// <summary>Creates a new instance.</summary>
    /// <param name="httpClientProvider">Optional certificate/revocation HTTP client provider.</param>
    public LongTermValidationOptions(IHttpClientProvider? httpClientProvider = null)
    {
        HttpClientProvider = httpClientProvider;
    }
}
