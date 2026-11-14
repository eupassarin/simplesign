namespace SimpleSign.Agent.Services;

/// <summary>What the agent asks the user for: secrets and consent.</summary>
internal interface IDialogService
{
    /// <summary>Asks for a secret (token PIN); null when cancelled.</summary>
    /// <param name="title">The dialog's title.</param>
    /// <param name="message">What is being asked and why.</param>
    /// <param name="confirmText">The confirm button's text.</param>
    /// <param name="warning">A warning shown above the box (the token is on its last try…); null for none.</param>
    /// <param name="severe">Whether the warning is shown as an error rather than a caution.</param>
    Task<string?> AskSecretAsync(string title, string message, string confirmText, string? warning = null, bool severe = false);

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
internal sealed class AgentServices
{
    /// <summary>Creates the agent's services.</summary>
    /// <param name="settings">The settings store.</param>
    /// <param name="dialogs">What asks the user.</param>
    /// <param name="trustFrameworks">The trust frameworks; null builds the ones this agent ships with.</param>
    public AgentServices(SettingsStore settings, IDialogService dialogs, TrustFrameworks? trustFrameworks = null)
    {
        Settings = settings;
        Dialogs = dialogs;
        TrustFrameworks = trustFrameworks ?? new TrustFrameworks(settings, log: Log);
    }

    public SettingsStore Settings { get; }

    public IDialogService Dialogs { get; }

    /// <summary>The trust frameworks of <c>?country=</c> and <c>?trust=</c>, those the user enabled.</summary>
    public TrustFrameworks TrustFrameworks { get; }

    public ActivityLog Log { get; } = new();

    /// <summary>Signatures made since the agent started.</summary>
    public int Signatures => Volatile.Read(ref _signatures);

    private int _signatures;

    public void CountSignatures(int count) => Interlocked.Add(ref _signatures, count);
}

/// <summary>An in-memory log of what the agent did (also written to the debug trace).</summary>
internal sealed class ActivityLog
{
    private readonly Lock _gate = new();
    private readonly List<LogEntry> _entries = [];

    public event EventHandler<LogEntry>? Added;

    public event EventHandler? Cleared;

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

    public void Clear()
    {
        lock (_gate)
        {
            _entries.Clear();
        }

        Cleared?.Invoke(this, EventArgs.Empty);
    }
}

internal sealed record LogEntry(DateTimeOffset Time, string Source, string Message, bool IsError)
{
    public string TimeText => Time.ToString("HH:mm:ss", System.Globalization.CultureInfo.InvariantCulture);
}
