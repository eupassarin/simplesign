using System.Security.Cryptography.X509Certificates;

namespace SimpleSign.Core.Revocation;

/// <summary>CRL (Certificate Revocation List) client for certificate revocation checking.</summary>
public interface ICrlClient
{
    /// <summary>Downloads and checks a CRL for the given certificate.</summary>
    /// <returns><see langword="true"/> when the certificate is not revoked; <see langword="false"/> when it is.</returns>
    Task<bool> CheckCrlAsync(X509Certificate2 cert, string crlUrl, CancellationToken ct);

    /// <summary>
    /// Downloads and checks a CRL for the given certificate, after checking the CRL against
    /// <paramref name="issuer"/>: its signature, its issuer name and that it is current.
    /// </summary>
    /// <returns><see langword="true"/> when the certificate is not revoked; <see langword="false"/> when it is.</returns>
    Task<bool> CheckCrlAsync(X509Certificate2 cert, X509Certificate2 issuer, string crlUrl, CancellationToken ct) =>
        CheckCrlAsync(cert, crlUrl, ct);
}
