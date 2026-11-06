using System.Globalization;

namespace SimpleSign.Agent.Localization;

/// <summary>A language the agent speaks.</summary>
internal sealed record LanguageOption(string Id, string Label, string Short);

/// <summary>
/// The agent's language: en-US or pt-BR, for the window, the dialogs, the tray menu, the activity
/// log and the API error messages. Same rule as the TestBench: pt* → pt-BR, anything else → en-US.
/// </summary>
internal static class L
{
    public const string English = "en-US";
    public const string Portuguese = "pt-BR";

    private static IReadOnlyDictionary<string, string> s_current = Strings.English;

    public static IReadOnlyList<LanguageOption> Languages { get; } =
    [
        new(English, "English (US)", "EN"),
        new(Portuguese, "Português (Brasil)", "PT"),
    ];

    /// <summary>The language in use.</summary>
    public static string Language { get; private set; } = English;

    /// <summary>The culture that formats dates and numbers.</summary>
    public static CultureInfo Culture { get; private set; } = CultureInfo.GetCultureInfo(English);

    /// <summary>Raised after the language changed.</summary>
    public static event EventHandler? Changed;

    /// <summary>The language for a culture (the OS language when null).</summary>
    public static string Detect(CultureInfo? culture = null) =>
        (culture ?? CultureInfo.CurrentUICulture).Name.StartsWith("pt", StringComparison.OrdinalIgnoreCase) ? Portuguese : English;

    /// <summary>Switches to <paramref name="language"/>; null or unknown follows the OS.</summary>
    public static void Use(string? language)
    {
        string next = language is Portuguese or English ? language : Detect();
        if (next == Language)
        {
            return;
        }

        Language = next;
        Culture = CultureInfo.GetCultureInfo(next);
        s_current = Strings.For(next);
        Changed?.Invoke(null, EventArgs.Empty);
    }

    /// <summary>The text for <paramref name="key"/> (English when missing, the key when unknown).</summary>
    public static string T(string key) =>
        s_current.TryGetValue(key, out string? text) ? text : Strings.English.GetValueOrDefault(key, key);

    /// <summary>The text for <paramref name="key"/> with {0}, {1}… replaced.</summary>
    public static string T(string key, params object?[] args) => string.Format(Culture, T(key), args);
}
