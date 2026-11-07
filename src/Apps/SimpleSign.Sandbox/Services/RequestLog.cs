namespace SimpleSign.Sandbox.Services;

/// <summary>One request a Sandbox service answered: AIA, CRL, TSA or CSC, and the failure applied to it, if any.</summary>
public sealed record SandboxRequest(long Id, DateTimeOffset Time, string Method, string Path, int Status, string Service, string? Fault, long Ms, string? Client);

/// <summary>The last requests the services answered (the UI's live log).</summary>
internal sealed class RequestLog
{
    private const int Capacity = 500;
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
    public IReadOnlyList<SandboxRequest> Since(long after)
    {
        lock (_gate)
        {
            return [.. _entries.Where(e => e.Id > after)];
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
