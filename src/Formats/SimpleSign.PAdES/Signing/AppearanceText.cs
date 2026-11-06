using System.Globalization;
using System.Text;

namespace SimpleSign.PAdES.Signing;

/// <summary>
/// Text helpers for the signature stamp: limits text to the characters the stamp font can
/// render (WinAnsi code points 0x20–0x7E and 0xA0–0xFF, the glyphs of the embedded font)
/// and measures text with the font's advance widths.
/// </summary>
internal static class AppearanceText
{
    private const int CourierWidth = 600;
    private const int FallbackWidth = 556;

    /// <summary>
    /// Returns <paramref name="text"/> with every character the stamp font cannot render replaced:
    /// typographic punctuation becomes its ASCII form, accented letters outside Latin-1 lose the
    /// accent, control characters become spaces, and anything else becomes '?'.
    /// </summary>
    internal static string ToEncodable(string text)
    {
        int i = 0;
        while (i < text.Length && IsEncodable(text[i]))
        {
            i++;
        }

        if (i == text.Length)
        {
            return text;
        }

        var sb = new StringBuilder(text.Length);
        sb.Append(text, 0, i);
        for (; i < text.Length; i++)
        {
            char c = text[i];
            if (IsEncodable(c))
            {
                sb.Append(c);
            }
            else if (char.IsHighSurrogate(c))
            {
                if (i + 1 < text.Length && char.IsLowSurrogate(text[i + 1]))
                {
                    i++;
                }

                sb.Append('?');
            }
            else
            {
                sb.Append(Replacement(c));
            }
        }

        return sb.ToString();
    }

    /// <summary>Width in points of already-encodable text rendered with a Base14 font at the given size.</summary>
    internal static float Measure(string text, string baseFontName, float fontSize)
    {
        if (fontSize <= 0f || text.Length == 0)
        {
            return 0f;
        }

        ushort[]? table = WidthTable(baseFontName);
        float units = 0f;
        foreach (char c in text)
        {
            units += table is null ? CourierWidth : WidthOf(table, c);
        }

        return units * fontSize / 1000f;
    }

    /// <summary>Returns the width table for a Base14 font, or null for the monospaced Courier faces.</summary>
    private static ushort[]? WidthTable(string baseFontName)
    {
        if (baseFontName.StartsWith("Courier", StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        bool bold = baseFontName.Contains("Bold", StringComparison.OrdinalIgnoreCase);
        if (baseFontName.StartsWith("Times", StringComparison.OrdinalIgnoreCase))
        {
            return bold ? Base14Widths.TimesBold : Base14Widths.TimesRoman;
        }

        return bold ? Base14Widths.HelveticaBold : FontResources.Widths;
    }

    private static int WidthOf(ushort[] table, char c)
    {
        int index = c - FontResources.FirstChar;
        if (index < 0 || index >= table.Length)
        {
            return FallbackWidth;
        }

        int width = table[index];
        return width == 0 ? FallbackWidth : width;
    }

    private static bool IsEncodable(char c) => c is (>= ' ' and <= '~') or (>= ' ' and <= 'ÿ');

    private static string Replacement(char c)
    {
        switch (c)
        {
            case '‘' or '’' or '‚' or '‛' or '′' or 'ʼ':
                return "'";
            case '“' or '”' or '„' or '‟' or '″':
                return "\"";
            case (>= '‐' and <= '―') or '−':
                return "-";
            case '…':
                return "...";
            case '•' or '∙':
                return "·";
            case '€':
                return "EUR";
            case '™':
                return "TM";
            case '‹':
                return "<";
            case '›':
                return ">";
            case 'Ł':
                return "L";
            case 'ł':
                return "l";
            case 'Đ':
                return "D";
            case 'đ':
                return "d";
            case 'Œ':
                return "OE";
            case 'œ':
                return "oe";
            case 'ı':
                return "i";
            case '​' or '‌' or '‍' or '⁠' or '﻿' or '­':
                return string.Empty;
            default:
                break;
        }

        if (char.IsControl(c) || char.IsWhiteSpace(c))
        {
            return " ";
        }

        // Strip accents that Latin-1 lacks (e.g. ő → o, ș → s).
        string decomposed;
        try
        {
            decomposed = c.ToString().Normalize(NormalizationForm.FormD);
        }
        catch (PlatformNotSupportedException)
        {
            // Invariant globalization mode may lack normalization data.
            return "?";
        }

        var sb = new StringBuilder(decomposed.Length);
        foreach (char d in decomposed)
        {
            if (IsEncodable(d) && CharUnicodeInfo.GetUnicodeCategory(d) != UnicodeCategory.NonSpacingMark)
            {
                sb.Append(d);
            }
        }

        return sb.Length > 0 ? sb.ToString() : "?";
    }
}
