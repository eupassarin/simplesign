using System.Globalization;

namespace SimpleSign.TestBench.Localization;

/// <summary>
/// UI text in en-US and pt-BR. The English text is the key (gettext style), so code stays
/// readable; <see cref="Translations"/> holds the pt-BR version. The language is the
/// request's (<c>Accept-Language</c>, set by the UI's language selector).
/// </summary>
public static class L
{
    public static readonly string[] Cultures = ["en-US", "pt-BR"];

    /// <summary>Translates <paramref name="english"/> to the current UI culture; <c>{0}</c>… are filled with <paramref name="args"/>.</summary>
    public static string T(string english, params object?[] args)
    {
        ArgumentNullException.ThrowIfNull(english);
        string text = Language(CultureInfo.CurrentUICulture) switch
        {
            "pt-BR" when Translations.All.TryGetValue(english, out string? t) => t,
            _ => english,
        };
        return args.Length == 0 ? text : string.Format(CultureInfo.CurrentCulture, text, args);
    }

    /// <summary>The supported language of a culture: pt-* → pt-BR, anything else → en-US.</summary>
    public static string Language(CultureInfo culture)
    {
        ArgumentNullException.ThrowIfNull(culture);
        return culture.TwoLetterISOLanguageName switch
        {
            "pt" => "pt-BR",
            _ => "en-US",
        };
    }
}
