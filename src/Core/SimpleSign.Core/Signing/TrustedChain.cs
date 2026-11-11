using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SimpleSign.Core.Crypto;
using SimpleSign.Core.Extensions;

namespace SimpleSign.Core.Signing;

/// <summary>
/// Builds the chain of a certificate up to one of the trust anchors given to a signer, without the system store,
/// without downloads and without revocation. Validity periods are left to the policy's own time constraints.
/// </summary>
internal static class TrustedChain
{
    /// <summary>
    /// The chain of <paramref name="certificate"/>, leaf first and ending at a trust anchor, or null when it does not
    /// reach one; <paramref name="error"/> then says why.
    /// </summary>
    /// <param name="certificate">The certificate whose chain is built.</param>
    /// <param name="extraCertificates">Certificates that may complete the chain (never trusted by themselves).</param>
    /// <param name="trustAnchors">Where the trust anchors come from.</param>
    /// <param name="time">The time the chain is built for.</param>
    /// <param name="error">Why the chain does not reach an anchor, or null.</param>
    /// <returns>The chain, or null.</returns>
    internal static IReadOnlyList<X509Certificate2>? Build(
        X509Certificate2 certificate,
        IEnumerable<X509Certificate2> extraCertificates,
        IReadOnlyList<ITrustAnchorProvider> trustAnchors,
        DateTimeOffset time,
        out string? error)
    {
        var anchors = trustAnchors.SelectMany(p => p.GetTrustAnchors()).ToArray();
        if (anchors.Length == 0)
        {
            error = $"No trust anchor was given to check that '{certificate.Subject}' chains to a trusted root. " +
                "Pass them with WithTrustAnchors or with a country extension.";
            return null;
        }

        var extra = extraCertificates.Concat(trustAnchors.SelectMany(p => p.GetIntermediateCertificates())).ToArray();
        using var x509 = new X509Chain();
        x509.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        x509.ChainPolicy.CustomTrustStore.AddRange(anchors);
        x509.ChainPolicy.ExtraStore.AddRange(extra);
        x509.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        x509.ChainPolicy.DisableCertificateDownloads = true;
        x509.ChainPolicy.VerificationTime = time.UtcDateTime;
        x509.ChainPolicy.VerificationFlags = X509VerificationFlags.IgnoreNotTimeValid | X509VerificationFlags.IgnoreNotTimeNested;
        try
        {
            if (!x509.Build(certificate))
            {
                error = $"'{certificate.Subject}' does not chain to a trusted root: " +
                    string.Join(", ", x509.ChainStatus.Select(s => s.StatusInformation.Trim()).Where(s => s.Length > 0).Distinct());
                return null;
            }
        }
        catch (CryptographicException ex)
        {
            error = $"The chain of '{certificate.Subject}' could not be built: {ex.Message}";
            return null;
        }

        var known = extra.Concat(anchors).Append(certificate).ToArray();
        var ordered = new List<X509Certificate2>(x509.ChainElements.Count);
        foreach (var element in x509.ChainElements)
        {
            byte[] raw = element.Certificate.RawData;
            ordered.Add(known.FirstOrDefault(c => raw.AsSpan().SequenceEqual(c.RawData)) ?? CertificateLoader.LoadCertificate(raw));
        }

        error = null;
        return ordered;
    }
}
