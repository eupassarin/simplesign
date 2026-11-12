using System.Security.Cryptography.X509Certificates;

namespace SimpleSign.Core.Extensions;

/// <summary>
/// A source of trust anchors that knows when each anchor was trusted (a trusted list with its service history,
/// ETSI TS 119 612 §5.6, TS 119 615): a signature proven to exist at some time is checked against the anchors trusted
/// then, so a service withdrawn later does not undo it.
/// </summary>
public interface ITimedTrustAnchorProvider : ITrustAnchorProvider
{
    /// <summary>The anchors trusted at <paramref name="at"/>: root CAs, as <see cref="ITrustAnchorProvider.GetTrustAnchors()"/> returns them now.</summary>
    /// <param name="at">The time.</param>
    /// <returns>The anchors.</returns>
    IReadOnlyList<X509Certificate2> GetTrustAnchors(DateTimeOffset at);
}
