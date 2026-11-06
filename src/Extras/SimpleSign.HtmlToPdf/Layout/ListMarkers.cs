// Licensed to SimpleSign under the MIT License.

using System.Globalization;
using System.Text;
using SimpleSign.HtmlToPdf.Parsing;

namespace SimpleSign.HtmlToPdf.Layout;

/// <summary>Generates list marker text/shapes for CSS <c>list-style-type</c> values.</summary>
internal static class ListMarkers
{
    private static readonly (int Value, string Numeral)[] Roman =
    [
        (1000, "M"), (900, "CM"), (500, "D"), (400, "CD"), (100, "C"), (90, "XC"),
        (50, "L"), (40, "XL"), (10, "X"), (9, "IX"), (5, "V"), (4, "IV"), (1, "I"),
    ];

    /// <summary>Creates the marker for the n-th item. Returns (null, Text) for <c>none</c>.</summary>
    internal static (string? Text, MarkerShape Shape) Create(string listStyleType, int ordinal)
    {
        string type = listStyleType.Trim();
        if (type.Length >= 2 && type[0] is '"' or '\'' && type[^1] == type[0])
        {
            return (type[1..^1], MarkerShape.Text);
        }

        return type.ToLowerInvariant() switch
        {
            "none" => (null, MarkerShape.Text),
            "disc" => (null, MarkerShape.Disc),
            "circle" => (null, MarkerShape.Circle),
            "square" => (null, MarkerShape.Square),
            "decimal" => (ordinal.ToString(CultureInfo.InvariantCulture) + ".", MarkerShape.Text),
            "decimal-leading-zero" => (ordinal.ToString("00", CultureInfo.InvariantCulture) + ".", MarkerShape.Text),
            "lower-alpha" or "lower-latin" => (Alphabetic(ordinal, 'a') + ".", MarkerShape.Text),
            "upper-alpha" or "upper-latin" => (Alphabetic(ordinal, 'A') + ".", MarkerShape.Text),
            "lower-roman" => (ToRoman(ordinal).ToLowerInvariant() + ".", MarkerShape.Text),
            "upper-roman" => (ToRoman(ordinal) + ".", MarkerShape.Text),
            "lower-greek" => (Greek(ordinal) + ".", MarkerShape.Text),
            _ => (null, MarkerShape.Disc),
        };
    }

    /// <summary>Formats a counter value for <c>counter()</c>/<c>counters()</c> (no trailing period).</summary>
    internal static string FormatCounter(int value, string style) => style.Trim().ToLowerInvariant() switch
    {
        "none" => string.Empty,
        "disc" => "•",
        "circle" => "◦",
        "square" => "▪",
        "decimal-leading-zero" => value.ToString("00", CultureInfo.InvariantCulture),
        "lower-alpha" or "lower-latin" => Alphabetic(value, 'a'),
        "upper-alpha" or "upper-latin" => Alphabetic(value, 'A'),
        "lower-roman" when value is > 0 and < 4000 => ToRoman(value).ToLowerInvariant(),
        "upper-roman" when value is > 0 and < 4000 => ToRoman(value),
        "lower-greek" when value > 0 => Greek(value),
        _ => value.ToString(CultureInfo.InvariantCulture),
    };

    private static string Alphabetic(int n, char first)
    {
        if (n <= 0)
        {
            return n.ToString(CultureInfo.InvariantCulture);
        }

        var sb = new StringBuilder();
        while (n > 0)
        {
            n--;
            sb.Insert(0, (char)(first + (n % 26)));
            n /= 26;
        }

        return sb.ToString();
    }

    private static string ToRoman(int n)
    {
        if (n is <= 0 or >= 4000)
        {
            return n.ToString(CultureInfo.InvariantCulture);
        }

        var sb = new StringBuilder();
        foreach (var (value, numeral) in Roman)
        {
            while (n >= value)
            {
                sb.Append(numeral);
                n -= value;
            }
        }

        return sb.ToString();
    }

    private static string Greek(int n) =>
        n is >= 1 and <= 24 ? ((char)(0x03B1 + n - 1 + (n > 17 ? 1 : 0))).ToString() : n.ToString(CultureInfo.InvariantCulture);
}

/// <summary>Tracks list item numbering for one list container (start, reversed, value).</summary>
internal sealed class ListCounter
{
    private readonly int _step;
    private int _next;

    internal ListCounter(HtmlNode list)
    {
        bool reversed = list.GetAttribute("reversed") is not null;
        _step = reversed ? -1 : 1;
        int itemCount = list.Children.Count(c => c.ComputedStyle?.Display == DisplayType.ListItem);
        _next = int.TryParse(list.GetAttribute("start"), NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out int start)
            ? start
            : reversed ? itemCount : 1;
    }

    /// <summary>Returns the ordinal for the item and advances the counter.</summary>
    internal int Next(HtmlNode item)
    {
        if (int.TryParse(item.GetAttribute("value"), NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out int value))
        {
            _next = value;
        }

        int current = _next;
        _next += _step;
        return current;
    }
}
