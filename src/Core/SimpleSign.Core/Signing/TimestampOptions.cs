using System.Net.Http.Headers;
using System.Security.Cryptography.X509Certificates;
using SimpleSign.Core.Http;

namespace SimpleSign.Core.Signing;

/// <summary>
/// Configuration for the signature timestamp (TSA) required by B-T and higher.
/// </summary>
public sealed record TimestampOptions
{
    /// <summary>
    /// The absolute TSA endpoint URI: <c>http(s)://</c>, or <c>tcp://host:port</c> for the
    /// socket transport of RFC 3161 §3.3 (port 318 by default), used by some ICP-Brasil ACTs.
    /// </summary>
    public Uri Endpoint { get; }

    /// <summary>
    /// Credentials sent with each HTTP request, for ACTs that require them
    /// (e.g. <c>new AuthenticationHeaderValue("Basic", base64)</c> or a bearer token).
    /// </summary>
    public AuthenticationHeaderValue? Authorization { get; init; }

    /// <summary>
    /// Client certificate (with private key) for ACTs that authenticate with mutual TLS.
    /// Ignored when <see cref="HttpClientProvider"/> is set: configure the certificate on that client instead.
    /// </summary>
    public X509Certificate2? ClientCertificate { get; init; }

    /// <summary>
    /// The certificate the TSA is expected to sign with. When set, a timestamp signed by any other certificate is
    /// refused (<see cref="SigningErrorReason.TimestampUntrusted"/>). Null (default) accepts any certificate that
    /// passes the other checks.
    /// </summary>
    public X509Certificate2? ExpectedTsaCertificate { get; init; }

    /// <summary>Whether the endpoint uses the RFC 3161 TCP transport.</summary>
    public bool IsTcp => Endpoint.Scheme == "tcp";

    /// <summary>Whether this TSA needs more than a URL (credentials, client certificate or TCP).</summary>
    internal bool NeedsDedicatedClient => Authorization is not null || ClientCertificate is not null || IsTcp;

    /// <summary>
    /// Optional TSA-specific <see cref="IHttpClientProvider"/>. When <see langword="null"/>,
    /// the builder-wide provider is used as fallback.
    /// </summary>
    public IHttpClientProvider? HttpClientProvider { get; }

    /// <summary>Creates a new instance with the specified TSA endpoint.</summary>
    /// <param name="endpoint">The absolute TSA endpoint URI. Must not be null.</param>
    /// <param name="httpClientProvider">Optional TSA-specific HTTP client provider.</param>
    /// <exception cref="ArgumentNullException"><paramref name="endpoint"/> is null.</exception>
    /// <exception cref="ArgumentException"><paramref name="endpoint"/> is not an absolute http(s) or tcp URI.</exception>
    public TimestampOptions(
        Uri endpoint,
        IHttpClientProvider? httpClientProvider = null)
    {
        ArgumentNullException.ThrowIfNull(endpoint);
        if (!endpoint.IsAbsoluteUri || endpoint.Scheme is not ("http" or "https" or "tcp"))
        {
            throw new ArgumentException("TSA endpoint must be an absolute http(s):// or tcp:// URI.", nameof(endpoint));
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
