using Microsoft.Extensions.Logging;
using System.Security.Cryptography.X509Certificates;

namespace SimpleSign.Core.Validation;

/// <summary>Service for certificate chain operations: AIA chasing, certificate loading.</summary>
public interface ICertificateChainService
{
    /// <summary>
    /// Downloads intermediate certificates via AIA (Authority Information Access)
    /// using iterative BFS so that each downloaded intermediate's own AIA is also chased.
    /// </summary>
    Task<List<X509Certificate2>> DownloadAiaCertsAsync(
        HttpClient httpClient,
        X509Certificate2 cert,
        IReadOnlyList<X509Certificate2>? extraCerts,
        List<string> warnings,
        CancellationToken ct);

    /// <summary>Loads one or more X509 certificates from raw bytes (DER, PEM, PKCS#7, PKCS#12).</summary>
    IEnumerable<X509Certificate2> LoadCertsFromBytes(byte[] bytes, ILogger? logger = null);

    /// <summary>Loads an X509 certificate from a PKCS#12 file.</summary>
    X509Certificate2 LoadPkcs12FromFile(string path, string? password);

    /// <summary>Loads all certificates from a PKCS#12 collection file.</summary>
    X509Certificate2Collection LoadPkcs12CollectionFromFile(string path, string? password);

    /// <summary>Extracts the CN from a certificate subject string.</summary>
    string ShortName(string subject);
}
