using SimpleSign.Agent.Services;

namespace SimpleSign.Agent.Server;

internal enum OriginState
{
    Unknown,
    Allowed,
    Blocked,
}

/// <summary>
/// Which web origins may use the agent. Exact scheme://host[:port] matches only; the user allows
/// an origin once (this session) or always (saved in the settings), or blocks it.
/// </summary>
internal sealed class OriginPolicy(SettingsStore settings)
{
    /// <summary>Key used for requests without an Origin header (local programs, curl).</summary>
    public const string LocalApplication = "local-application";

    private readonly HashSet<string> _session = new(StringComparer.Ordinal);
    private readonly Lock _gate = new();

    /// <summary>
    /// Normalizes an Origin header to scheme://host[:port] (lower case, default ports dropped);
    /// null for "null", file:// and anything that is not an http(s) origin.
    /// </summary>
    public static string? Normalize(string? origin)
    {
        if (string.IsNullOrWhiteSpace(origin) || origin.Trim() == "null"
            || !Uri.TryCreate(origin.Trim(), UriKind.Absolute, out var uri)
            || uri.Scheme is not ("http" or "https") || uri.AbsolutePath != "/" || uri.Query.Length > 0 || !string.IsNullOrEmpty(uri.UserInfo))
        {
            return null;
        }

        return uri.IsDefaultPort ? $"{uri.Scheme}://{uri.Host}" : $"{uri.Scheme}://{uri.Host}:{uri.Port}";
    }

    public OriginState Check(string origin)
    {
        lock (_gate)
        {
            var s = settings.Current;
            return s.BlockedOrigins.Contains(origin) ? OriginState.Blocked
                : s.AllowedOrigins.Contains(origin) || _session.Contains(origin) ? OriginState.Allowed
                : OriginState.Unknown;
        }
    }

    public void Allow(string origin, bool permanently)
    {
        lock (_gate)
        {
            _session.Add(origin);
            if (permanently && !settings.Current.AllowedOrigins.Contains(origin))
            {
                settings.Current.AllowedOrigins.Add(origin);
                settings.Current.BlockedOrigins.Remove(origin);
            }
        }

        if (permanently)
        {
            settings.Save();
        }
    }

    /// <summary>Origins allowed for this session only (not saved).</summary>
    public IReadOnlyList<string> SessionOnly
    {
        get
        {
            lock (_gate)
            {
                return [.. _session.Where(o => o != LocalApplication && !settings.Current.AllowedOrigins.Contains(o)).Order(StringComparer.Ordinal)];
            }
        }
    }

    /// <summary>Blocks an origin permanently: its requests are refused without asking.</summary>
    public void Block(string origin)
    {
        lock (_gate)
        {
            _session.Remove(origin);
            settings.Current.AllowedOrigins.Remove(origin);
            if (!settings.Current.BlockedOrigins.Contains(origin))
            {
                settings.Current.BlockedOrigins.Add(origin);
            }
        }

        settings.Save();
    }

    public void Forget(string origin)
    {
        lock (_gate)
        {
            _session.Remove(origin);
            settings.Current.AllowedOrigins.Remove(origin);
            settings.Current.BlockedOrigins.Remove(origin);
        }

        settings.Save();
    }
}

/// <summary>A fixed-window rate limit per origin.</summary>
internal sealed class RateLimiter(int limit, TimeSpan window, TimeProvider? time = null)
{
    private readonly Dictionary<string, (DateTimeOffset Start, int Count)> _windows = new(StringComparer.Ordinal);
    private readonly Lock _gate = new();
    private readonly TimeProvider _time = time ?? TimeProvider.System;

    public bool TryAcquire(string key)
    {
        var now = _time.GetUtcNow();
        lock (_gate)
        {
            if (!_windows.TryGetValue(key, out var w) || now - w.Start >= window)
            {
                _windows[key] = (now, 1);
                return true;
            }

            if (w.Count >= limit)
            {
                return false;
            }

            _windows[key] = (w.Start, w.Count + 1);
            return true;
        }
    }
}
