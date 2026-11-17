using System.Security.Cryptography.X509Certificates;
using SimpleSign.Core.Extensions;

namespace SimpleSign.Core.Validation;

/// <summary>
/// The conditions trust anchors put on the chains that reach them (<see cref="IConstrainedTrustAnchorProvider"/>),
/// applied after a chain is built.
/// </summary>
internal static class ConstrainedTrust
{
    /// <summary>
    /// The constrained providers among <paramref name="providers"/>, each made to accept a chain whose anchor another
    /// provider of the set gives without conditions: the trust of several providers is a union.
    /// </summary>
    public static IReadOnlyList<IConstrainedTrustAnchorProvider> From(IEnumerable<ITrustAnchorProvider> providers)
    {
        var all = providers.ToList();
        var constrained = all.OfType<IConstrainedTrustAnchorProvider>().ToList();
        if (constrained.Count == 0)
        {
            return [];
        }

        var plain = all.Where(p => p is not IConstrainedTrustAnchorProvider).ToList();
        return plain.Count == 0 ? constrained : [.. constrained.Select(c => new UnlessGivenWithoutConditions(c, plain))];
    }

    /// <summary>Why the chain is refused by the anchor it reached; null when no provider refuses it.</summary>
    /// <param name="chain">The chain as built: the signer's certificate first.</param>
    /// <param name="providers">The constrained providers; null or empty for none.</param>
    public static string? Refusal(X509Chain chain, IEnumerable<IConstrainedTrustAnchorProvider>? providers) =>
        providers is null ? null : Refusal([.. chain.ChainElements.Select(e => e.Certificate)], providers);

    /// <summary>Why the chain is refused by the anchor it reached; null when no provider refuses it.</summary>
    /// <param name="chain">The chain: the signer's certificate first.</param>
    /// <param name="providers">The constrained providers.</param>
    public static string? Refusal(IReadOnlyList<X509Certificate2> chain, IEnumerable<IConstrainedTrustAnchorProvider> providers)
    {
        var constrained = providers.ToList();
        if (constrained.Count == 0)
        {
            return null;
        }

        // The anchor that decides is the one nearest to the signer's certificate, as a chain builder stops at it.
        for (int i = 0; i < chain.Count; i++)
        {
            var owners = constrained.Where(p => Gives(p, chain[i])).ToList();
            if (owners.Count == 0)
            {
                continue;
            }

            IReadOnlyList<X509Certificate2> path = [.. chain.Take(i + 1)];
            string? refusal = null;
            foreach (var owner in owners)
            {
                refusal = owner.WhyRefused(chain[i], path);
                if (refusal is null)
                {
                    // One provider that gives the anchor accepts the chain: that is enough.
                    return null;
                }
            }

            return refusal;
        }

        return null;
    }

    private static bool Gives(ITrustAnchorProvider provider, X509Certificate2 certificate) =>
        provider.GetTrustAnchors().Any(a => a.RawDataMemory.Span.SequenceEqual(certificate.RawDataMemory.Span));

    /// <summary>A constrained provider that accepts a chain whose anchor a provider without conditions also gives.</summary>
    private sealed class UnlessGivenWithoutConditions(IConstrainedTrustAnchorProvider inner, IReadOnlyList<ITrustAnchorProvider> plain)
        : IConstrainedTrustAnchorProvider
    {
        public string RegionCode => inner.RegionCode;

        public string DisplayName => inner.DisplayName;

        public IReadOnlyList<X509Certificate2> GetTrustAnchors() => inner.GetTrustAnchors();

        public IReadOnlyList<X509Certificate2> GetIntermediateCertificates() => inner.GetIntermediateCertificates();

        public string? WhyRefused(X509Certificate2 anchor, IReadOnlyList<X509Certificate2> chain) =>
            plain.Any(p => Gives(p, anchor)) ? null : inner.WhyRefused(anchor, chain);
    }
}
