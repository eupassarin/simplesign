using System.Security.Cryptography.X509Certificates;

namespace SimpleSign.Core.Crypto;

/// <summary>
/// Interface for caching intermediate certificates to avoid repeated AIA downloads.
/// </summary>
public interface ICertificateCache
{
    /// <summary>Attempts to retrieve a certificate by its SHA-256 thumbprint.</summary>
    /// <param name="thumbprint">SHA-256 thumbprint (hex, uppercase).</param>
    /// <param name="certificate">The cached certificate, or null.</param>
    /// <returns>True if found in cache.</returns>
    bool TryGet(string thumbprint, out X509Certificate2? certificate);

    /// <summary>Adds or updates a certificate in the cache.</summary>
    /// <param name="certificate">The certificate to cache.</param>
    void Set(X509Certificate2 certificate);

    /// <summary>Removes all entries from the cache.</summary>
    void Clear();

    /// <summary>Number of certificates currently cached.</summary>
    int Count { get; }
}
