using System.Security.Cryptography.X509Certificates;

namespace SimpleSign.Core.Revocation;

/// <summary>OCSP (Online Certificate Status Protocol) client for certificate revocation checking.</summary>
public interface IOcspClient
{
    /// <summary>Checks revocation status via OCSP for a certificate with the given responder URL.</summary>
    Task<bool> CheckOcspAsync(X509Certificate2 cert, string ocspUrl, CancellationToken ct);

    /// <summary>Checks revocation status via OCSP with the full certificate chain.</summary>
    Task<bool> CheckOcspWithChainAsync(X509Certificate2 cert, IReadOnlyList<X509Certificate2> chain, string ocspUrl, CancellationToken ct);

    /// <summary>Fetches and validates a raw OCSP response for the given certificate.</summary>
    Task<OcspFetchResult> FetchOcspResponseAsync(X509Certificate2 cert, X509Certificate2? issuerCert, string ocspUrl, CancellationToken ct);

    /// <summary>Validates an embedded OCSP response against the certificate and issuer.</summary>
    bool? CheckEmbeddedOcspResponse(X509Certificate2 cert, X509Certificate2? issuerCert, byte[] ocspResponseBytes, DateTimeOffset? signingTime);
}
