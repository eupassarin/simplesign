using Avalonia;
using Avalonia.Styling;
using SimpleSign.Agent.Localization;
using SimpleSign.Agent.Services;

namespace SimpleSign.Agent.Views;

/// <summary>The theme (system, light, dark) and the language, applied and saved.</summary>
internal static class Appearance
{
    public static IReadOnlyList<string> Themes { get; } = ["system", "light", "dark"];

    /// <summary>Applies the saved theme and language (at startup).</summary>
    public static void Apply(AppSettings settings)
    {
        L.Use(settings.Language);
        ApplyTheme(settings.Theme);
    }

    public static void SetTheme(AgentController controller, string theme)
    {
        ApplyTheme(theme);
        controller.Update(s => s.Theme = theme);
    }

    public static void SetLanguage(AgentController controller, string language)
    {
        controller.Update(s => s.Language = language);
        L.Use(language);
    }

    /// <summary>The theme after this one: light → dark → system → light (the TestBench's button).</summary>
    public static string NextTheme(string theme) => theme switch
    {
        "light" => "dark",
        "dark" => "system",
        _ => "light",
    };

    public static string ThemeIcon(string theme) => theme switch
    {
        "light" => Icons.Sun,
        "dark" => Icons.Moon,
        _ => Icons.Monitor,
    };

    private static void ApplyTheme(string theme)
    {
        if (Application.Current is { } app)
        {
            app.RequestedThemeVariant = theme switch
            {
                "light" => ThemeVariant.Light,
                "dark" => ThemeVariant.Dark,
                _ => ThemeVariant.Default,
            };
        }
    }
}
