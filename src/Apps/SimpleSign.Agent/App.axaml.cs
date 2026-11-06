using System.Runtime.InteropServices;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Markup.Xaml;
using Avalonia.Threading;
using SimpleSign.Agent.Localization;
using SimpleSign.Agent.Services;
using SimpleSign.Agent.Views;

namespace SimpleSign.Agent;

/// <summary>
/// The tray / menu-bar app. The tray menu shows the agent's state and opens the window, which has
/// everything else (certificates, sites, activity, test, documentation, settings, about).
/// </summary>
#pragma warning disable CA1001 // The controller is disposed in Quit, when the app exits.
internal sealed partial class App : Application
{
    private AgentController? _controller;
    private IDisposable? _sigterm;
    private MainWindow? _window;
    private TrayIcon? _tray;
    private AgentState? _trayState;
    private bool _quitting;

    private readonly NativeMenuItem _status = new() { IsEnabled = false };
    private readonly NativeMenuItem _open = new();
    private readonly NativeMenuItem _toggle = new();
    private readonly NativeMenuItem _quit = new();

    public override void Initialize() => AvaloniaXamlLoader.Load(this);

    public override void OnFrameworkInitializationCompleted()
    {
        if (ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop)
        {
            var settings = new SettingsStore();
            Appearance.Apply(settings.Current);
            _controller = new AgentController(new AgentServices(settings, new DialogService()));
            _controller.Changed += (_, _) => Dispatcher.UIThread.Post(RefreshTray);
            L.Changed += (_, _) => Dispatcher.UIThread.Post(RefreshTray);

            _open.Click += (_, _) => ShowWindow();
            _toggle.Click += (_, _) => _ = _controller.SetEnabledAsync(!_controller.Settings.AgentEnabled);
            _quit.Click += (_, _) => Quit();
            _tray = new TrayIcon
            {
                ToolTipText = "SimpleSign Agent",
                Menu = [_status, new NativeMenuItemSeparator(), _open, _toggle, new NativeMenuItemSeparator(), _quit],
                IsVisible = true,
            };
            MacOSProperties.SetIsTemplateIcon(_tray, AgentIcons.IsTemplate);
            // Windows and Linux: a click opens the window (on macOS a click opens the menu).
            _tray.Clicked += (_, _) => ShowWindow();
            TrayIcon.SetIcons(this, [_tray]);

            if (Program.Instance is { } instance)
            {
                instance.ShowRequested += (_, _) => Dispatcher.UIThread.Post(ShowWindow);
            }

            desktop.ShutdownRequested += (_, _) => _quitting = true;
            // SIGTERM (e.g. logout, kill) quits cleanly: the agent stops and token sessions close.
            _sigterm = PosixSignalRegistration.Create(PosixSignal.SIGTERM, e =>
            {
                e.Cancel = true;
                Dispatcher.UIThread.Post(Quit);
            });

            RefreshTray();
            _ = _controller.StartAsync();
            if (!settings.Current.FirstRunDone)
            {
                // The first run opens the window, so the user sees what was installed.
                _controller.Update(s => s.FirstRunDone = true);
                ShowWindow();
            }
        }

        base.OnFrameworkInitializationCompleted();
    }

    private void ShowWindow()
    {
        if (_controller is null || _quitting)
        {
            return;
        }

        if (_window is null)
        {
            _window = new MainWindow(_controller);
            _window.Closed += (_, _) => _window = null;
        }

        _window.Show();
        if (_window.WindowState == WindowState.Minimized)
        {
            _window.WindowState = WindowState.Normal;
        }

        _window.Activate();
    }

    private void RefreshTray()
    {
        if (_controller is null || _tray is null)
        {
            return;
        }

        var state = _controller.State;
        if (_trayState != state)
        {
            _trayState = state;
            _tray.Icon = AgentIcons.Tray(state);
        }

        _tray.ToolTipText = $"SimpleSign Agent · {_controller.StatusText}";
        _status.Header = _controller.StatusText;
        _open.Header = L.T("tray.open");
        _toggle.Header = L.T(_controller.Settings.AgentEnabled ? "tray.pause" : "tray.resume");
        _quit.Header = L.T("tray.quit");
    }

    private async void Quit()
    {
        if (_quitting && _controller is null)
        {
            return;
        }

        _quitting = true;
        _window?.Close();
        var controller = _controller;
        _controller = null;
        if (controller is not null)
        {
            // Awaited, not blocked on: the agent's shutdown continues on this (UI) thread.
            await controller.DisposeAsync();
        }

        _sigterm?.Dispose();
        _tray?.Dispose();
        if (ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop)
        {
            desktop.Shutdown();
        }
    }
}
#pragma warning restore CA1001
