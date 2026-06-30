using Microsoft.Extensions.Logging;
using SimpleSign.Core.Crypto;
using System.Security.Cryptography.X509Certificates;

namespace SimpleSign.Core.Validation;

/// <summary>Default implementation of <see cref="ICertificateChainService"/>.</summary>
public sealed class CertificateChainService : ICertificateChainService
{
    /// <inheritdoc />
    public Task<List<X509Certificate2>> DownloadAiaCertsAsync(
        HttpClient httpClient,
        X509Certificate2 cert,
        IReadOnlyList<X509Certificate2>? extraCerts,
        List<string> warnings,
        CancellationToken ct)
        => CertificateChainUtility.DownloadAiaCertsAsync(httpClient, cert, extraCerts, warnings, ct);

    /// <inheritdoc />
    public IEnumerable<X509Certificate2> LoadCertsFromBytes(byte[] bytes, ILogger? logger = null)
        => CertificateChainUtility.LoadCertsFromBytes(bytes, logger);

    /// <inheritdoc />
    public X509Certificate2 LoadPkcs12FromFile(string path, string? password)
        => CertificateLoader.LoadPkcs12FromFile(path, password);

    /// <inheritdoc />
    public X509Certificate2Collection LoadPkcs12CollectionFromFile(string path, string? password)
        => CertificateLoader.LoadPkcs12CollectionFromFile(path, password);

    /// <inheritdoc />
    public string ShortName(string subject)
        => CertificateChainUtility.ShortName(subject);
}
