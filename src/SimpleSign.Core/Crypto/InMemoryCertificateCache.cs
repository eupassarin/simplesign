using System.Collections.Concurrent;
using System.Security.Cryptography.X509Certificates;

namespace SimpleSign.Core.Crypto;

/// <summary>
/// In-memory certificate cache with configurable TTL (time-to-live).
/// Thread-safe for concurrent reads and writes.
/// </summary>
public sealed class InMemoryCertificateCache : ICertificateCache
{
    private readonly ConcurrentDictionary<string, CacheEntry> _cache = new(StringComparer.OrdinalIgnoreCase);
    private readonly TimeSpan _ttl;

    /// <summary>
    /// Creates a new in-memory certificate cache.
    /// </summary>
    /// <param name="ttl">Time-to-live for cached entries. Default: 1 hour.</param>
    public InMemoryCertificateCache(TimeSpan? ttl = null)
    {
        _ttl = ttl ?? TimeSpan.FromHours(1);
        if (_ttl <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(ttl), "TTL must be positive.");
        }
    }

    /// <inheritdoc/>
    public bool TryGet(string thumbprint, out X509Certificate2? certificate)
    {
        if (_cache.TryGetValue(thumbprint, out var entry) && !entry.IsExpired(_ttl))
        {
            certificate = entry.Certificate;
            return true;
        }

        certificate = null;
        return false;
    }

    /// <inheritdoc/>
    public void Set(X509Certificate2 certificate)
    {
        var thumbprint = certificate.GetCertHashString(System.Security.Cryptography.HashAlgorithmName.SHA256);
        _cache[thumbprint] = new CacheEntry(certificate, DateTime.UtcNow);
    }

    /// <inheritdoc/>
    public void Clear()
    {
        _cache.Clear();
    }

    /// <inheritdoc/>
    public int Count => _cache.Count;

    /// <summary>
    /// Removes expired entries from the cache.
    /// Call periodically in long-running applications to free memory.
    /// </summary>
    /// <returns>Number of entries removed.</returns>
    public int Evict()
    {
        var removed = 0;
        foreach (var key in _cache.Keys)
        {
            if (_cache.TryGetValue(key, out var entry) && entry.IsExpired(_ttl))
            {
                if (_cache.TryRemove(key, out _))
                {
                    removed++;
                }
            }
        }

        return removed;
    }

    private sealed record CacheEntry(X509Certificate2 Certificate, DateTime CreatedUtc)
    {
        public bool IsExpired(TimeSpan ttl) => DateTime.UtcNow - CreatedUtc >= ttl;
    }
}
