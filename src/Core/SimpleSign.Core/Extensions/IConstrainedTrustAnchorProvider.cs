using System.Security.Cryptography.X509Certificates;

namespace SimpleSign.Core.Extensions;

/// <summary>
/// A source of trust anchors that can refuse a chain that reaches one of them: an anchor trusted only for signer
/// certificates of certain certificate policies, say (the policy restrictions of Adobe's AATL). Once the chain of a
/// signer's certificate is built to an anchor of this provider, the validators (PAdES, CAdES, XAdES) and the checks made
/// before signing ask <see cref="WhyRefused"/>; a chain it refuses is not trusted.
/// <para>
/// The anchor asked about is the one nearest to the signer's certificate. A chain is not refused when another provider
/// of the same <see cref="TrustProfile"/> gives the same anchor without conditions: trust added with
/// <see cref="TrustProfile.WithTrustFrom"/> is a union. The chain of a time-stamp's TSA is not asked about.
/// </para>
/// </summary>
public interface IConstrainedTrustAnchorProvider : ITrustAnchorProvider
{
    /// <summary>Says why a chain that reached <paramref name="anchor"/> is refused.</summary>
    /// <param name="anchor">The anchor of this provider that the chain reached.</param>
    /// <param name="chain">The chain: the signer's certificate first, <paramref name="anchor"/> last.</param>
    /// <returns>Why the chain is refused, in a sentence; null when it is accepted.</returns>
    string? WhyRefused(X509Certificate2 anchor, IReadOnlyList<X509Certificate2> chain);
}
