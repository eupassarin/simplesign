using System.Collections.Concurrent;

namespace SimpleSign.Core.Revocation;

/// <summary>
/// A thread-safe in-memory <see cref="IRevocationCache"/>. An entry lives until its own expiry or
/// <see cref="MaxLifetime"/> after it was stored, whichever comes first.
/// </summary>
public sealed class InMemoryRevocationCache : IRevocationCache
{
    private readonly ConcurrentDictionary<string, (byte[] Data, DateTimeOffset Expires)> _entries = new(StringComparer.Ordinal);
    private readonly TimeProvider _timeProvider;

    /// <summary>Creates a cache whose entries live at most <paramref name="maxLifetime"/> (default 1 hour).</summary>
    /// <param name="maxLifetime">The longest time an entry is served; must be positive.</param>
    /// <param name="timeProvider">The clock; the system clock when null.</param>
    public InMemoryRevocationCache(TimeSpan? maxLifetime = null, TimeProvider? timeProvider = null)
    {
        MaxLifetime = maxLifetime ?? TimeSpan.FromHours(1);
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(MaxLifetime, TimeSpan.Zero, nameof(maxLifetime));
        _timeProvider = timeProvider ?? TimeProvider.System;
    }

    /// <summary>The longest time an entry is served after it was stored.</summary>
    public TimeSpan MaxLifetime { get; }

    /// <summary>The number of entries, expired ones included until they are next read.</summary>
    public int Count => _entries.Count;

    /// <inheritdoc />
    public bool TryGet(string key, out byte[] data)
    {
        ArgumentNullException.ThrowIfNull(key);
        if (_entries.TryGetValue(key, out var entry))
        {
            if (entry.Expires > _timeProvider.GetUtcNow())
            {
                data = entry.Data;
                return true;
            }

            _entries.TryRemove(key, out _);
        }

        data = [];
        return false;
    }

    /// <inheritdoc />
    public void Set(string key, byte[] data, DateTimeOffset expires)
    {
        ArgumentNullException.ThrowIfNull(key);
        ArgumentNullException.ThrowIfNull(data);
        var cap = _timeProvider.GetUtcNow() + MaxLifetime;
        _entries[key] = (data, expires < cap ? expires : cap);
    }

    /// <summary>Removes every entry.</summary>
    public void Clear() => _entries.Clear();
}
