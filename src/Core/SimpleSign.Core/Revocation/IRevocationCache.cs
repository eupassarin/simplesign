namespace SimpleSign.Core.Revocation;

/// <summary>
/// Keeps downloaded revocation data (CRLs) between checks, so a chain checked many times does not
/// download the same CRL each time. Entries carry their own expiry, at the latest the CRL's nextUpdate.
/// </summary>
public interface IRevocationCache
{
    /// <summary>Gets the data stored under <paramref name="key"/> if it has not expired.</summary>
    /// <param name="key">The cache key (the CRL URL).</param>
    /// <param name="data">The cached data when found.</param>
    /// <returns><see langword="true"/> when current data was found.</returns>
    bool TryGet(string key, out byte[] data);

    /// <summary>Stores <paramref name="data"/> under <paramref name="key"/> until <paramref name="expires"/>.</summary>
    /// <param name="key">The cache key (the CRL URL).</param>
    /// <param name="data">The data to keep.</param>
    /// <param name="expires">When the entry stops being served.</param>
    void Set(string key, byte[] data, DateTimeOffset expires);
}
