using System.Security.Cryptography.X509Certificates;

namespace SimpleSign.Core.DependencyInjection;

/// <summary>
/// Configuration options for SimpleSign services when registered via dependency injection.
/// </summary>
public sealed class SimpleSignOptions
{
    /// <summary>TSA (Time Stamp Authority) URL for timestamp requests. Null disables timestamping.</summary>
    public string? TsaUrl { get; set; }

    /// <summary>Timeout for network operations (CRL, OCSP, TSA, AIA). Default: 30 seconds.</summary>
    public TimeSpan NetworkTimeout { get; set; } = TimeSpan.FromSeconds(30);

    /// <summary>Whether to check certificate revocation during validation. Default: true.</summary>
    public bool CheckRevocation { get; set; } = true;

    /// <summary>Whether to trust system-installed root certificates. Default: true.</summary>
    public bool TrustSystemRoots { get; set; } = true;

    /// <summary>Additional trusted root certificates (e.g., ICP-Brasil roots).</summary>
    public List<X509Certificate2> TrustedRoots { get; set; } = [];

    /// <summary>Named HttpClient name used by IHttpClientFactory. Default: "SimpleSign".</summary>
    public string HttpClientName { get; set; } = "SimpleSign";
}
