using Avalonia;
using SimpleSign.Agent.Services;
using SimpleSign.Agent.Views;

namespace SimpleSign.Agent;

internal static class Program
{
    /// <summary>This process's hold on "one agent per user"; null in design tools and tests.</summary>
    public static SingleInstance? Instance { get; private set; }

    [STAThread]
    public static int Main(string[] args)
    {
        // Developer command: writes the application icons drawn by AgentIcons (see Assets/).
        if (args is ["--export-icons", var directory])
        {
            BuildAvaloniaApp().SetupWithoutStarting();
            AgentIcons.Export(directory);
            return 0;
        }

        // Checks a published binary without opening a window (used by CI after the AOT publish).
        if (args is ["--self-check"])
        {
            return SelfCheck.RunAsync(Console.Out, Console.Error).GetAwaiter().GetResult();
        }

        using var instance = SingleInstance.Acquire();
        if (instance is null)
        {
            // Already running: it was asked to show its window.
            return 0;
        }

        Instance = instance;
        return BuildAvaloniaApp().StartWithClassicDesktopLifetime(args, Avalonia.Controls.ShutdownMode.OnExplicitShutdown);
    }

    public static AppBuilder BuildAvaloniaApp() =>
        AppBuilder.Configure<App>()
            .UsePlatformDetect()
            .WithInterFont()
            // A menu-bar / tray app: no Dock icon; the window opens from the tray.
            .With(new MacOSPlatformOptions { ShowInDock = false })
            .LogToTrace();
}
