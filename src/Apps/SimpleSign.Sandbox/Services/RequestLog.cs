namespace SimpleSign.Sandbox.Services;

/// <summary>One request a Sandbox service answered: AIA, CRL, TSA or CSC, and the failure applied to it, if any.</summary>
public sealed record SandboxRequest(long Id, DateTimeOffset Time, string Method, string Path, int Status, string Service, string? Fault, long Ms, string? Client);

/// <summary>The last requests the services answered (the UI's live log), at most <see cref="Capacity"/>: the oldest go first.</summary>
internal sealed class RequestLog
{
    /// <summary>How many requests the log keeps.</summary>
    public const int Capacity = 500;

    private readonly Lock _gate = new();
    private readonly LinkedList<SandboxRequest> _entries = [];
    private long _next;

    public void Add(string method, string path, int status, string service, string? fault, long ms, string? client)
    {
        lock (_gate)
        {
            _entries.AddLast(new SandboxRequest(++_next, DateTimeOffset.UtcNow, method, path, status, service, fault, ms, client));
            if (_entries.Count > Capacity)
            {
                _entries.RemoveFirst();
            }
        }
    }

    /// <summary>The entries after <paramref name="after"/>, newest last.</summary>
    public IReadOnlyList<SandboxRequest> Since(long after) => Since(after, null, null);

    /// <summary>
    /// The entries after <paramref name="after"/> of <paramref name="service"/> (all when null), newest last;
    /// with <paramref name="limit"/>, only the newest that many.
    /// </summary>
    public IReadOnlyList<SandboxRequest> Since(long after, int? limit, string? service)
    {
        lock (_gate)
        {
            var entries = _entries.Where(e => e.Id > after && (service is null || string.Equals(e.Service, service, StringComparison.OrdinalIgnoreCase))).ToList();
            return limit is { } n && entries.Count > n ? entries[^n..] : entries;
        }
    }

    public void Clear()
    {
        lock (_gate)
        {
            _entries.Clear();
        }
    }
}
