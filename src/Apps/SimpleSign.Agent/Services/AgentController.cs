using System.Net.Sockets;
using SimpleSign.Agent.Localization;
using SimpleSign.Agent.Server;

namespace SimpleSign.Agent.Services;

/// <summary>What the window lists: the signing certificates and the installed token drivers.</summary>
internal sealed record CertificateInventory(IReadOnlyList<CertificateEntry> Certificates, IReadOnlyList<string> Drivers);

internal enum AgentState
{
    Running,
    Paused,
    Error,
}

/// <summary>Runs the agent for the tray and the window: start, pause, port, start at login.</summary>
internal sealed class AgentController : IAsyncDisposable
{
    private readonly TokenSessionCache _sessions = new();
    private readonly Func<CancellationToken, Task<IReadOnlyList<CertificateEntry>>>? _certificates;

    public AgentController(AgentServices services, Func<CancellationToken, Task<IReadOnlyList<CertificateEntry>>>? certificates = null)
    {
        Services = services;
        _certificates = certificates;
        Server = new AgentServer(services, _sessions, certificates);
        Server.StateChanged += (_, _) => Changed?.Invoke(this, EventArgs.Empty);
        services.Settings.Changed += (_, _) => Changed?.Invoke(this, EventArgs.Empty);
    }

    public AgentServices Services { get; }

    public AgentServer Server { get; }

    public AppSettings Settings => Services.Settings.Current;

    /// <summary>The agent started, stopped or a setting changed. Raised on any thread.</summary>
    public event EventHandler? Changed;

    public AgentState State =>
        Server.IsRunning ? AgentState.Running
        : Settings.AgentEnabled && Server.LastError is not null ? AgentState.Error
        : AgentState.Paused;

    /// <summary>Where the agent listens (or would listen).</summary>
    public string Address => $"127.0.0.1:{(Server.IsRunning ? Server.Port : Settings.AgentPort)}";

    public string StatusText => State switch
    {
        AgentState.Running => L.T("status.listening", Address),
        AgentState.Error => Server.LastError ?? L.T("status.error"),
        _ => L.T("status.paused"),
    };

    /// <summary>Whether this platform and process can be registered to start at login.</summary>
    public static bool CanStartAtLogin => LoginItem.IsSupported && Environment.ProcessPath is not null;

    public static bool StartsAtLogin => LoginItem.IsSupported && LoginItem.IsEnabled;

    /// <summary>Starts listening when the agent is enabled. A failure is kept in <see cref="AgentServer.LastError"/>.</summary>
    public async Task StartAsync()
    {
        if (!Settings.AgentEnabled)
        {
            return;
        }

        try
        {
            await Server.StartAsync(Settings.AgentPort);
        }
        catch (Exception ex) when (ex is IOException or SocketException)
        {
            Services.Log.Add("Agent", Server.LastError ?? ex.Message, isError: true);
        }
    }

    public async Task SetEnabledAsync(bool enabled)
    {
        Settings.AgentEnabled = enabled;
        Services.Settings.Save();
        if (enabled)
        {
            await StartAsync();
        }
        else
        {
            await Server.StopAsync();
        }
    }

    /// <summary>Saves the port and, when the agent is enabled, listens on it.</summary>
    public async Task SetPortAsync(int port)
    {
        Settings.AgentPort = port;
        Services.Settings.Save();
        await StartAsync();
    }

    public void SetStartAtLogin(bool enabled)
    {
        try
        {
            LoginItem.Set(enabled, Environment.ProcessPath!);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Security.SecurityException)
        {
            Services.Log.Add("Agent", L.T("log.loginItemFailed", ex.Message), isError: true);
        }

        Changed?.Invoke(this, EventArgs.Empty);
    }

    /// <summary>Changes and saves the settings.</summary>
    public void Update(Action<AppSettings> change)
    {
        change(Settings);
        Services.Settings.Save();
    }

    /// <summary>The certificates the agent can sign with and the PKCS#11 drivers it found (off the UI thread).</summary>
    public Task<CertificateInventory> InventoryAsync(CancellationToken cancellationToken) => Task.Run(async () =>
    {
        if (_certificates is not null)
        {
            return new CertificateInventory(await _certificates(cancellationToken), []);
        }

        var store = CertificateService.ListStore();
        var (tokens, drivers) = await CertificateService.ListTokensAsync(cancellationToken);
        return new CertificateInventory(
            [.. store, .. tokens],
            [.. drivers.Select(d => $"{d.Driver.Driver.Product} ({d.Tokens.Count})")]);
    }, cancellationToken);

    public async ValueTask DisposeAsync()
    {
        await Server.DisposeAsync();
        _sessions.Dispose();
    }
}
