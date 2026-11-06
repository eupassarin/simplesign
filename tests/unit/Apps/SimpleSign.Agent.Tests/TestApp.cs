using Avalonia;
using Avalonia.Headless;

[assembly: AvaloniaTestApplication(typeof(SimpleSign.Agent.Tests.TestApp))]

namespace SimpleSign.Agent.Tests;

/// <summary>The agent's real <see cref="App"/> (styles, theme) on the headless platform, drawn with Skia so frames can be captured.</summary>
public static class TestApp
{
    public static AppBuilder BuildAvaloniaApp() =>
        AppBuilder.Configure<App>()
            .UseSkia()
            .UseHeadless(new AvaloniaHeadlessPlatformOptions { UseHeadlessDrawing = false })
            .WithInterFont();
}
