using System.Runtime.InteropServices;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Markup.Xaml;
using Avalonia.Platform;
using Avalonia.Threading;
using SimpleSign.Agent.Server;
using SimpleSign.Agent.Services;
using SimpleSign.Agent.Views;

namespace SimpleSign.Agent;

/// <summary>
/// The tray / menu-bar app: no main window. The menu shows the agent's state and lets the user
/// pause it, review authorized sites, start it at login and quit.
/// </summary>
#pragma warning disable CA1001 // The agent and token sessions are disposed in Quit, when the app exits.
internal sealed partial class App : Application
{
    private AgentServices? _services;
    private AgentServer? _agent;
    private TokenSessionCache? _sessions;
    private IDisposable? _sigterm;
    private OriginsWindow? _originsWindow;
    private TrayIcon? _tray;
    private bool _quitting;

    private readonly NativeMenuItem _status = new() { IsEnabled = false };
    private readonly NativeMenuItem _enabled = new("Agente ativo") { ToggleType = NativeMenuItemToggleType.CheckBox };
    private readonly NativeMenuItem _origins = new("Sites autorizados…");
    private readonly NativeMenuItem _login = new("Iniciar com o sistema") { ToggleType = NativeMenuItemToggleType.CheckBox };
    private readonly NativeMenuItem _quit = new("Sair");

    public override void Initialize() => AvaloniaXamlLoader.Load(this);

    public override void OnFrameworkInitializationCompleted()
    {
        if (ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop)
        {
            var settings = new SettingsStore();
            _services = new AgentServices(settings, new DialogService());
            _sessions = new TokenSessionCache();
            _agent = new AgentServer(_services, _sessions);
            _agent.StateChanged += (_, _) => Dispatcher.UIThread.Post(RefreshMenu);

            _enabled.Click += (_, _) => _ = SetEnabledAsync(!settings.Current.AgentEnabled);
            _origins.Click += (_, _) => ShowOrigins();
            _login.IsVisible = LoginItem.IsSupported && Environment.ProcessPath is not null;
            _login.Click += (_, _) => ToggleLoginItem();
            _quit.Click += (_, _) => Quit();
            _tray = new TrayIcon
            {
                Icon = new WindowIcon(AssetLoader.Open(new Uri("avares://SimpleSign.Agent/Assets/icon.png"))),
                ToolTipText = "SimpleSign Agent",
                Menu = [_status, new NativeMenuItemSeparator(), _enabled, _origins, _login, new NativeMenuItemSeparator(), _quit],
                IsVisible = true,
            };
            TrayIcon.SetIcons(this, [_tray]);

            desktop.ShutdownRequested += (_, _) => _quitting = true;
            // SIGTERM (e.g. logout, kill) quits cleanly: the agent stops and token sessions close.
            _sigterm = PosixSignalRegistration.Create(PosixSignal.SIGTERM, e =>
            {
                e.Cancel = true;
                Dispatcher.UIThread.Post(Quit);
            });

            RefreshMenu();
            if (settings.Current.AgentEnabled)
            {
                _ = StartAgentAsync(settings.Current.AgentPort);
            }
        }

        base.OnFrameworkInitializationCompleted();
    }

    private async Task StartAgentAsync(int port)
    {
        try
        {
            await _agent!.StartAsync(port);
        }
        catch (IOException)
        {
            // Shown in the menu (LastError).
        }
    }

    private async Task SetEnabledAsync(bool enabled)
    {
        var settings = _services!.Settings;
        settings.Current.AgentEnabled = enabled;
        settings.Save();
        if (enabled)
        {
            await StartAgentAsync(settings.Current.AgentPort);
        }
        else
        {
            await _agent!.StopAsync();
        }

        RefreshMenu();
    }

    private void ToggleLoginItem()
    {
        try
        {
            LoginItem.Set(!LoginItem.IsEnabled, Environment.ProcessPath!);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Security.SecurityException)
        {
            _services!.Log.Add("Agente", $"Não foi possível alterar o início automático: {ex.Message}", isError: true);
        }

        RefreshMenu();
    }

    private void ShowOrigins()
    {
        if (_originsWindow is { } open)
        {
            open.Activate();
            return;
        }

        _originsWindow = new OriginsWindow(_services!.Settings, _agent!.Origins, StatusText());
        _originsWindow.Closed += (_, _) => _originsWindow = null;
        _originsWindow.Show();
        _originsWindow.Activate();
    }

    private string StatusText() => _agent switch
    {
        { IsRunning: true } agent => $"Ouvindo em 127.0.0.1:{agent.Port}",
        { LastError: { } error } => error,
        _ => "Agente pausado",
    };

    private void RefreshMenu()
    {
        _status.Header = StatusText();
        _enabled.IsChecked = _services?.Settings.Current.AgentEnabled ?? false;
        _login.IsChecked = LoginItem.IsSupported && LoginItem.IsEnabled;
    }

    private async void Quit()
    {
        if (_quitting && _agent is null)
        {
            return;
        }

        _quitting = true;
        var agent = _agent;
        _agent = null;
        if (agent is not null)
        {
            // Awaited, not blocked on: the agent's shutdown continues on this (UI) thread.
            await agent.DisposeAsync();
        }

        _sessions?.Dispose();
        _sigterm?.Dispose();
        _tray?.Dispose();
        if (ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop)
        {
            desktop.Shutdown();
        }
    }
}
#pragma warning restore CA1001
