namespace SimpleSign.Agent.Services;

/// <summary>What the agent asks the user for: secrets and consent.</summary>
internal interface IDialogService
{
    /// <summary>Asks for a secret (token PIN); null when cancelled.</summary>
    Task<string?> AskSecretAsync(string title, string message, string confirmText);

    /// <summary>Asks the user to approve an agent request.</summary>
    Task<ConsentDecision> AskConsentAsync(ConsentRequest request);
}

/// <summary>What a web page asks the agent to do.</summary>
internal sealed record ConsentRequest(string Origin, string Title, string Message, string? CertificateHolder, bool OfferRemember);

internal enum ConsentDecision
{
    Deny,
    AllowOnce,
    AllowAlways,
}

/// <summary>The agent-wide services (a tiny composition root).</summary>
internal sealed class AgentServices(SettingsStore settings, IDialogService dialogs)
{
    public SettingsStore Settings { get; } = settings;

    public IDialogService Dialogs { get; } = dialogs;

    public ActivityLog Log { get; } = new();
}

/// <summary>An in-memory log of what the agent did (also written to the debug trace).</summary>
internal sealed class ActivityLog
{
    private readonly Lock _gate = new();
    private readonly List<LogEntry> _entries = [];

    public event EventHandler<LogEntry>? Added;

    public IReadOnlyList<LogEntry> Entries
    {
        get
        {
            lock (_gate)
            {
                return [.. _entries];
            }
        }
    }

    public void Add(string source, string message, bool isError = false)
    {
        var entry = new LogEntry(DateTimeOffset.Now, source, message, isError);
        lock (_gate)
        {
            _entries.Add(entry);
            if (_entries.Count > 500)
            {
                _entries.RemoveAt(0);
            }
        }

        System.Diagnostics.Trace.WriteLine($"{entry.TimeText} [{source}] {message}");
        Added?.Invoke(this, entry);
    }
}

internal sealed record LogEntry(DateTimeOffset Time, string Source, string Message, bool IsError)
{
    public string TimeText => Time.ToString("HH:mm:ss", System.Globalization.CultureInfo.InvariantCulture);
}
