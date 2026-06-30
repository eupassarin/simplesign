using System.Security.Cryptography.X509Certificates;

namespace SimpleSign.Core.Validation;

/// <summary>Checks certificate revocation status via embedded CRLs, OCSP, and online CRL.</summary>
public interface IRevocationChecker
{
    /// <summary>Checks revocation status using available revocation mechanisms.</summary>
    Task<(bool IsNotRevoked, RevocationSource Source)> CheckRevocationAsync(
        X509Certificate2 cert,
        IReadOnlyList<X509Certificate2> chain,
        IReadOnlyList<byte[]> embeddedCrls,
        CancellationToken ct,
        DateTimeOffset? signingTime = null);

    /// <summary>Checks revocation status using available revocation mechanisms including embedded OCSPs.</summary>
    Task<(bool IsNotRevoked, RevocationSource Source)> CheckRevocationAsync(
        X509Certificate2 cert,
        IReadOnlyList<X509Certificate2> chain,
        IReadOnlyList<byte[]> embeddedCrls,
        IReadOnlyList<byte[]> embeddedOcsps,
        CancellationToken ct,
        DateTimeOffset? signingTime = null);
}
