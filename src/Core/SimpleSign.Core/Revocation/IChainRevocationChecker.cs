using System.Security.Cryptography.X509Certificates;
using SimpleSign.Core.Extensions;

namespace SimpleSign.Core.Revocation;

/// <summary>
/// Checks the revocation status of every certificate of a chain, except the trust anchor, at a given time.
/// </summary>
public interface IChainRevocationChecker
{
    /// <summary>Checks <paramref name="chain"/> (leaf first, root last) at <paramref name="time"/>.</summary>
    /// <param name="chain">The ordered chain: the leaf first, each issuer after its subject, the root last.</param>
    /// <param name="time">The time the status must hold at.</param>
    /// <param name="embeddedCrls">CRLs already at hand (embedded in the signature, for instance).</param>
    /// <param name="embeddedOcsps">OCSP responses already at hand.</param>
    /// <param name="allowOnline">Whether the CRL distribution points and OCSP responders may be queried.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The status of the chain and one message per certificate that is revoked or whose status is unknown.</returns>
    Task<ChainRevocationResult> CheckAsync(
        IReadOnlyList<X509Certificate2> chain,
        DateTimeOffset time,
        IReadOnlyList<byte[]> embeddedCrls,
        IReadOnlyList<byte[]> embeddedOcsps,
        bool allowOnline,
        CancellationToken cancellationToken);
}

/// <summary>The outcome of a chain revocation check.</summary>
/// <param name="Status">Good when no certificate is revoked and every status is known; Revoked when any is revoked; Unknown otherwise.</param>
/// <param name="Messages">One message per certificate that is revoked or whose status is unknown.</param>
public sealed record ChainRevocationResult(ChainRevocationStatus Status, IReadOnlyList<string> Messages);
