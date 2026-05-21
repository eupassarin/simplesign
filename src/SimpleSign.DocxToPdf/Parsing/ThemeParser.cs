using DocumentFormat.OpenXml.Drawing;
using DocumentFormat.OpenXml.Packaging;
using SimpleSign.DocxToPdf.Model;

namespace SimpleSign.DocxToPdf.Parsing;

/// <summary>Parses theme1.xml for font and color information.</summary>
internal sealed class ThemeParser
{
    /// <summary>Parses the theme part.</summary>
    /// <param name="themePart">The theme part (may be null).</param>
    /// <returns>Populated theme data.</returns>
    public static ThemeData Parse(ThemePart? themePart)
    {
        var theme = new ThemeData();

        if (themePart?.Theme is null)
        {
            return theme;
        }

        Theme themeXml = themePart.Theme;
        ThemeElements? elements = themeXml.ThemeElements;

        if (elements?.FontScheme is not null)
        {
            string? majorFont = elements.FontScheme.MajorFont?.LatinFont?.Typeface?.Value;
            if (majorFont is not null)
            {
                theme.MajorFont = majorFont;
            }

            string? minorFont = elements.FontScheme.MinorFont?.LatinFont?.Typeface?.Value;
            if (minorFont is not null)
            {
                theme.MinorFont = minorFont;
            }
        }

        if (elements?.ColorScheme is not null)
        {
            ColorScheme cs = elements.ColorScheme;
            AddColor(theme, "dk1", cs.Dark1Color);
            AddColor(theme, "lt1", cs.Light1Color);
            AddColor(theme, "dk2", cs.Dark2Color);
            AddColor(theme, "lt2", cs.Light2Color);
            AddColor(theme, "accent1", cs.Accent1Color);
            AddColor(theme, "accent2", cs.Accent2Color);
            AddColor(theme, "accent3", cs.Accent3Color);
            AddColor(theme, "accent4", cs.Accent4Color);
            AddColor(theme, "accent5", cs.Accent5Color);
            AddColor(theme, "accent6", cs.Accent6Color);
            AddColor(theme, "hlink", cs.Hyperlink);
            AddColor(theme, "folHlink", cs.FollowedHyperlinkColor);
        }

        return theme;
    }

    private static void AddColor(ThemeData theme, string name, Color2Type? colorType)
    {
        if (colorType is null)
        {
            return;
        }

        string? hex = colorType.RgbColorModelHex?.Val?.Value
                      ?? colorType.SystemColor?.LastColor?.Value;

        if (hex is not null)
        {
            theme.ColorScheme[name] = hex;
        }
    }
}
