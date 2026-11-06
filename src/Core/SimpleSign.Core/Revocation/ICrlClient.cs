using System.Security.Cryptography.X509Certificates;

namespace SimpleSign.Core.Revocation;

/// <summary>CRL (Certificate Revocation List) client for certificate revocation checking.</summary>
public interface ICrlClient
{
    /// <summary>Downloads and checks a CRL for the given certificate.</summary>
    Task<bool> CheckCrlAsync(X509Certificate2 cert, string crlUrl, CancellationToken ct);
}
