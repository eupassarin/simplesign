namespace SimpleSign.HtmlToPdf.Parsing;

/// <summary>
/// Encoding of percentage lengths inside plain <see cref="float"/> style values.
/// A percentage <c>p</c> is stored as <c>-(100000 + p)</c>, so ordinary negative
/// lengths (negative margins, offsets and indents) remain representable.
/// </summary>
internal static class CssLength
{
    /// <summary>Offset that moves percentages out of the range of real lengths.</summary>
    public const float PercentBase = 100000f;

    /// <summary>Encodes a percentage.</summary>
    /// <param name="percent">The percentage (50 for 50%).</param>
    /// <returns>The encoded value.</returns>
    public static float Percent(float percent) => -(PercentBase + Math.Clamp(percent, -(PercentBase / 2) + 1, PercentBase / 2));

    /// <summary>Returns true when <paramref name="value"/> encodes a percentage.</summary>
    /// <param name="value">The stored value.</param>
    /// <returns>True for percentages.</returns>
    public static bool IsPercent(float value) => value <= -(PercentBase / 2);

    /// <summary>Returns true when <paramref name="value"/> encodes a percentage.</summary>
    /// <param name="value">The stored value.</param>
    /// <returns>True for percentages.</returns>
    public static bool IsPercent(float? value) => value is float v && IsPercent(v);

    /// <summary>Decodes a percentage.</summary>
    /// <param name="value">The encoded value.</param>
    /// <returns>The percentage (50 for 50%).</returns>
    public static float PercentOf(float value) => -value - PercentBase;

    /// <summary>Resolves a stored length against a reference length.</summary>
    /// <param name="value">The stored value.</param>
    /// <param name="reference">The length 100% corresponds to.</param>
    /// <returns>The length in points.</returns>
    public static float Resolve(float value, float reference) => IsPercent(value) ? reference * PercentOf(value) / 100f : value;
}
