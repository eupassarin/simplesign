using SimpleSign.Core.Validation;

namespace SimpleSign.Core.Revocation;

/// <summary>
/// The CRLs collected for B-LT/B-LTA through a shared <see cref="IRevocationCache"/>: a cached CRL is reused only when
/// it was issued after the time it has to prove (the signature time-stamp's genTime) and is still current — what a
/// policy's freshness rule (revocation data issued after the best-signature-time) asks for. Otherwise the CRL is
/// downloaded again, and the new one is remembered.
/// </summary>
internal static class CachedCrl
{
    /// <summary>A CRL for <paramref name="url"/>: a fresh enough cached copy, or <paramref name="download"/>'s, remembered.</summary>
    /// <param name="cache">The shared cache; null to always download.</param>
    /// <param name="url">The CRL's URL (the cache key).</param>
    /// <param name="issuedAfter">The time a reused CRL must have been issued after; null to never reuse (only remember).</param>
    /// <param name="download">Downloads the CRL (DER), or returns null.</param>
    internal static async Task<byte[]?> GetAsync(IRevocationCache? cache, string url, DateTimeOffset? issuedAfter, Func<Task<byte[]?>> download)
    {
        if (cache is not null && issuedAfter is { } after && cache.TryGet(url, out byte[] cached)
            && CrlEvaluator.ReadThisUpdate(cached) is { } thisUpdate && thisUpdate > after
            && (CrlEvaluator.ReadNextUpdate(cached) is not { } nextUpdate || nextUpdate > DateTimeOffset.UtcNow))
        {
            return cached;
        }

        byte[]? crl = await download().ConfigureAwait(false);
        if (crl is not null)
        {
            cache?.Set(url, crl, CrlEvaluator.ReadNextUpdate(crl) ?? DateTimeOffset.MaxValue);
        }

        return crl;
    }

    /// <summary>The genTime of a time-stamp token, or null (no token, or one that cannot be read).</summary>
    internal static DateTimeOffset? GenTime(byte[]? timestampToken) =>
        timestampToken is null ? null : TimestampValidator.ReadGenTime(timestampToken);
}
