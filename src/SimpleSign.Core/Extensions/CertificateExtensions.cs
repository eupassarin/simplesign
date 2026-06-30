using System.Security.Cryptography.X509Certificates;

namespace SimpleSign.Core.Extensions;

/// <summary>Extension methods for <see cref="X509Certificate2"/> chain operations.</summary>
public static class CertificateExtensions
{
    /// <summary>Returns true when the certificate is self-signed (Subject == Issuer).</summary>
    public static bool IsSelfSigned(this X509Certificate2 cert) =>
        cert.Subject == cert.Issuer;

    /// <summary>Finds the issuer of <paramref name="cert"/> in the given chain. First tries binary SubjectName/IusserName match, then falls back to string comparison.</summary>
    public static X509Certificate2? FindIssuerOf(
        this IEnumerable<X509Certificate2> chain,
        X509Certificate2 cert) =>
        chain.FirstOrDefault(c => c.SubjectName.RawData.AsSpan().SequenceEqual(cert.IssuerName.RawData))
            ?? chain.FirstOrDefault(c => string.Equals(c.Subject, cert.Issuer, StringComparison.OrdinalIgnoreCase));
}
