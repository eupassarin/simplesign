using Avalonia;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Markup.Xaml;
using Avalonia.Styling;
using SimpleSign.Desktop.Agent;
using SimpleSign.Desktop.Services;
using SimpleSign.Desktop.ViewModels;
using SimpleSign.Desktop.Views;

namespace SimpleSign.Desktop;

#pragma warning disable CA1001 // The agent and token sessions are disposed in Quit, when the app exits.
internal sealed partial class App : Application
{
    private MainWindow? _window;
    private AgentServer? _agent;
    private TokenSessionCache? _sessions;
    private bool _quitting;
    private IDisposable? _sigterm;

    public override void Initialize() => AvaloniaXamlLoader.Load(this);

    public override void OnFrameworkInitializationCompleted()
    {
        if (ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop)
        {
            var settings = new SettingsStore();
            ApplyTheme(settings.Current.Theme);
            var dialogs = new DialogService(() => _window);
            var services = new AppServices(settings, dialogs);
            _sessions = new TokenSessionCache();
            _agent = new AgentServer(services, _sessions);
            var viewModel = new MainWindowViewModel(services, _agent);
            viewModel.Page<SettingsViewModel>().ThemeChanged += (_, theme) => ApplyTheme(theme);
            _window = new MainWindow { DataContext = viewModel };
            _window.Closing += (_, e) =>
            {
                // Closing the window keeps the agent running in the menu bar / tray.
                if (!_quitting && _agent.IsRunning)
                {
                    e.Cancel = true;
                    _window.Hide();
                }
            };
            _window.Closed += (_, _) => Quit();
            desktop.MainWindow = _window;
            desktop.ShutdownRequested += (_, _) => _quitting = true;
            // SIGTERM (e.g. logout, kill) quits cleanly: the agent stops and token sessions close.
            _sigterm = System.Runtime.InteropServices.PosixSignalRegistration.Create(System.Runtime.InteropServices.PosixSignal.SIGTERM, e =>
            {
                e.Cancel = true;
                Avalonia.Threading.Dispatcher.UIThread.Post(Quit);
            });
            _window.Show();
            if (settings.Current.AgentEnabled)
            {
                _ = StartAgentAsync(settings.Current.AgentPort);
            }

            _ = viewModel.SelectedPage.OnShownAsync();
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
            // Reported in the sidebar and on the Agent page.
        }
    }

    private void ApplyTheme(string theme) => RequestedThemeVariant = theme switch
    {
        "Light" => ThemeVariant.Light,
        "Dark" => ThemeVariant.Dark,
        _ => ThemeVariant.Default,
    };

    private void OnTrayOpen(object? sender, EventArgs e)
    {
        _window?.Show();
        _window?.Activate();
    }

    private void OnTrayQuit(object? sender, EventArgs e) => Quit();

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
        if (ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop)
        {
            desktop.Shutdown();
        }
    }
}
#pragma warning restore CA1001
