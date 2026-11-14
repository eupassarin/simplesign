using System.Globalization;

namespace SimpleSign.Agent.Localization;

/// <summary>A language the agent speaks.</summary>
internal sealed record LanguageOption(string Id, string Label, string Short);

/// <summary>
/// The agent's language: en-US, pt-BR or es-ES, for the window, the dialogs, the tray menu, the
/// activity log and the API error messages. Same rule as the TestBench, widened: pt* → pt-BR,
/// es* → es-ES, anything else → en-US. There is one neutral Spanish, so es-PE, es-MX and es-ES all
/// get it, and names of standards and regions stay as they are.
/// </summary>
internal static class L
{
    public const string English = "en-US";
    public const string Portuguese = "pt-BR";
    public const string Spanish = "es-ES";

    private static IReadOnlyDictionary<string, string> s_current = Strings.English;

    public static IReadOnlyList<LanguageOption> Languages { get; } =
    [
        new(English, "English (US)", "EN"),
        new(Portuguese, "Português (Brasil)", "PT"),
        new(Spanish, "Español", "ES"),
    ];

    /// <summary>The language in use.</summary>
    public static string Language { get; private set; } = English;

    /// <summary>The culture that formats dates and numbers.</summary>
    public static CultureInfo Culture { get; private set; } = CultureInfo.GetCultureInfo(English);

    /// <summary>Raised after the language changed.</summary>
    public static event EventHandler? Changed;

    /// <summary>The language for a culture (the OS language when null).</summary>
    /// <param name="culture">The culture to map; null uses the operating system's.</param>
    public static string Detect(CultureInfo? culture = null)
    {
        string name = (culture ?? CultureInfo.CurrentUICulture).Name;
        return name.StartsWith("pt", StringComparison.OrdinalIgnoreCase) ? Portuguese
            : name.StartsWith("es", StringComparison.OrdinalIgnoreCase) ? Spanish
            : English;
    }

    /// <summary>Switches to <paramref name="language"/>; null or unknown follows the OS.</summary>
    public static void Use(string? language)
    {
        string next = language is Portuguese or English or Spanish ? language : Detect();
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
