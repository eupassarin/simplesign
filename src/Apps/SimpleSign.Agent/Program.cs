using Avalonia;

namespace SimpleSign.Agent;

internal static class Program
{
    [STAThread]
    public static void Main(string[] args) =>
        BuildAvaloniaApp().StartWithClassicDesktopLifetime(args, Avalonia.Controls.ShutdownMode.OnExplicitShutdown);

    public static AppBuilder BuildAvaloniaApp() =>
        AppBuilder.Configure<App>()
            .UsePlatformDetect()
            .WithInterFont()
            // A menu-bar / tray app: no Dock icon, no main window.
            .With(new MacOSPlatformOptions { ShowInDock = false })
            .LogToTrace();
}
