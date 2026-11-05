namespace SimpleSign.Desktop.Services;

/// <summary>Things the view models ask the UI for: files, secrets and consent.</summary>
internal interface IDialogService
{
    Task<string?> OpenFileAsync(string title, params string[] patterns);

    Task<string?> SaveFileAsync(string title, string suggestedName);

    Task<string?> PickFolderAsync(string title);

    /// <summary>Asks for a secret (PFX password, token PIN); null when cancelled.</summary>
    Task<string?> AskSecretAsync(string title, string message, string confirmText);

    /// <summary>Asks the user to approve an agent request.</summary>
    Task<ConsentDecision> AskConsentAsync(ConsentRequest request);

    Task ShowMessageAsync(string title, string message);
}

/// <summary>What a web page asks the agent to do.</summary>
internal sealed record ConsentRequest(string Origin, string Title, string Message, string? CertificateHolder, bool OfferRemember);

internal enum ConsentDecision
{
    Deny,
    AllowOnce,
    AllowAlways,
}

/// <summary>The app-wide services (a tiny composition root).</summary>
internal sealed class AppServices
{
    public AppServices(SettingsStore settings, IDialogService dialogs)
    {
        Settings = settings;
        Dialogs = dialogs;
        Documents = new DocumentService(settings);
        Log = new ActivityLog();
    }

    public SettingsStore Settings { get; }

    public IDialogService Dialogs { get; }

    public DocumentService Documents { get; }

    public ActivityLog Log { get; }
}

/// <summary>An in-memory log of what the app and the agent did.</summary>
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

        Added?.Invoke(this, entry);
    }
}

internal sealed record LogEntry(DateTimeOffset Time, string Source, string Message, bool IsError)
{
    public string TimeText => Time.ToString("HH:mm:ss", System.Globalization.CultureInfo.InvariantCulture);
}
