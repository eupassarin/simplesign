using System.Security.Cryptography.X509Certificates;

namespace SimpleSign.Core.Crypto;

/// <summary>
/// Abstraction for loading certificates from various stores (file system, OS store, HSM).
/// </summary>
public interface ICertificateStore
{
    /// <summary>Finds a certificate by SHA-1 thumbprint (hex string).</summary>
    /// <param name="thumbprint">SHA-1 thumbprint, case-insensitive.</param>
    /// <returns>The certificate, or null if not found.</returns>
    X509Certificate2? FindByThumbprint(string thumbprint);

    /// <summary>Finds all certificates matching a subject name (partial match).</summary>
    /// <param name="subjectName">Subject CN or partial match.</param>
    /// <returns>Matching certificates.</returns>
    IReadOnlyList<X509Certificate2> FindBySubject(string subjectName);

    /// <summary>Lists all certificates in the store.</summary>
    IReadOnlyList<X509Certificate2> ListAll();
}
