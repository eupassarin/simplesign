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

    /// <summary>
    /// Checks <paramref name="chain"/> (leaf first, root last) as it stands now, online, before a
    /// signature is made. Unlike <see cref="CheckAsync"/>, a cached CRL must not decide: the
    /// certificate may have been revoked since it was cached.
    /// </summary>
    /// <param name="chain">The ordered chain: the leaf first, each issuer after its subject, the root last.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The status of the chain and one message per certificate that is revoked or whose status is unknown.</returns>
    /// <remarks>
    /// The default implementation calls <see cref="CheckAsync"/> online at the current time;
    /// <see cref="ChainRevocationChecker"/> asks the OCSP responders first and downloads the CRLs again.
    /// </remarks>
    Task<ChainRevocationResult> CheckCurrentAsync(IReadOnlyList<X509Certificate2> chain, CancellationToken cancellationToken) =>
        CheckAsync(chain, DateTimeOffset.UtcNow, [], [], allowOnline: true, cancellationToken);
}

/// <summary>The outcome of a chain revocation check.</summary>
/// <param name="Status">Good when no certificate is revoked and every status is known; Revoked when any is revoked; Unknown otherwise.</param>
/// <param name="Messages">One message per certificate that is revoked or whose status is unknown.</param>
public sealed record ChainRevocationResult(ChainRevocationStatus Status, IReadOnlyList<string> Messages)
{
    /// <summary>
    /// When the revocation data used for the first certificate of the chain (the signer) was issued: the CRL's
    /// thisUpdate or the OCSP response's producedAt; null when not known. Validation policies check its freshness
    /// (<c>RevocationFreshness</c>).
    /// </summary>
    public DateTimeOffset? IssuedAt { get; init; }
}
