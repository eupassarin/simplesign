using System.Security.Cryptography.X509Certificates;
using SimpleSign.Core.Extensions;

namespace SimpleSign.TestHelpers;

/// <summary>Trust anchors held in memory that refuse a chain with a reason, or accept it with null.</summary>
/// <param name="whyRefused">The anchor reached and the chain (signer first); the reason, or null to accept.</param>
/// <param name="anchors">The trust anchors.</param>
public sealed class ConstrainedTrustAnchors(Func<X509Certificate2, IReadOnlyList<X509Certificate2>, string?> whyRefused, params X509Certificate2[] anchors)
    : IConstrainedTrustAnchorProvider
{
    /// <summary>Anchors that refuse every chain with <paramref name="reason"/>.</summary>
    public static ConstrainedTrustAnchors Refusing(string reason, params X509Certificate2[] anchors) => new((_, _) => reason, anchors);

    /// <summary>Anchors that accept every chain.</summary>
    public static ConstrainedTrustAnchors Accepting(params X509Certificate2[] anchors) => new((_, _) => null, anchors);

    /// <inheritdoc />
    public string RegionCode => "TEST";

    /// <inheritdoc />
    public string DisplayName => "Test anchors with conditions";

    /// <inheritdoc />
    public IReadOnlyList<X509Certificate2> GetTrustAnchors() => anchors;

    /// <inheritdoc />
    public string? WhyRefused(X509Certificate2 anchor, IReadOnlyList<X509Certificate2> chain) => whyRefused(anchor, chain);
}
