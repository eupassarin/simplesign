namespace SimpleSign.PAdES.Signing;

/// <summary>Visual appearance settings for a visible signature annotation.</summary>
public sealed class SignatureAppearance
{
    private const float FontSize = 7f;
    private const float LabelFontSize = 6f;
    private const float LineHeight = 10f;
    private const float Padding = 4f;
    private const float CharWidth = 3.8f;
    private const int MaxTextLength = 40;
    private const float Margin = 8f;

    /// <summary>Page number (1-based) where the signature annotation is placed.</summary>
    public int Page { get; init; } = 1;

    /// <summary>X coordinate of the annotation rectangle (lower-left corner, in points). Ignored when <see cref="AutoPosition"/> is true.</summary>
    public float X { get; init; } = 20f;

    /// <summary>Y coordinate of the annotation rectangle (lower-left corner, in points). Ignored when <see cref="AutoPosition"/> is true.</summary>
    public float Y { get; init; } = 20f;

    /// <summary>
    /// When true, the library automatically positions the signature at the bottom of the page,
    /// left-to-right, wrapping to a new row above when the current row is full.
    /// </summary>
    public bool AutoPosition { get; init; }

    /// <summary>Whether to display the signing date/time. Default true.</summary>
    public bool ShowDate { get; init; } = true;

    /// <summary>Whether to display the signing reason.</summary>
    public bool ShowReason { get; init; }

    /// <summary>Whether to display the signing location.</summary>
    public bool ShowLocation { get; init; }

    /// <summary>
    /// Background image bytes (JPEG format). Rendered behind the text in the signature stamp.
    /// If both JPEG and PNG are set, PNG takes precedence.
    /// </summary>
    public ReadOnlyMemory<byte>? BackgroundImageJpeg { get; init; }

    /// <summary>
    /// Background image bytes (PNG format, RGB/Gray, 8-bit, non-interlaced).
    /// Rendered behind the text in the signature stamp.
    /// If both JPEG and PNG are set, PNG takes precedence.
    /// </summary>
    public ReadOnlyMemory<byte>? BackgroundImagePng { get; init; }

    /// <summary>Custom font size for the signer name. Default: 7pt.</summary>
    public float? CustomFontSize { get; init; }

    /// <summary>Custom font size for labels ("Signed by", date, reason, location). Default: 6pt.</summary>
    public float? CustomLabelFontSize { get; init; }

    /// <summary>
    /// Base14 font name used by the appearance text (default: Helvetica).
    /// Examples: Helvetica, Times-Roman, Courier, Helvetica-Bold.
    /// </summary>
    public string? BaseFontName { get; init; } = "Helvetica";

    /// <summary>Text color as RGB triplet (0.0–1.0 each). Default: black (0, 0, 0).</summary>
    public (float R, float G, float B)? TextColor { get; init; }

    /// <summary>Border color as RGB triplet (0.0–1.0 each). When null, no border is drawn.</summary>
    public (float R, float G, float B)? BorderColor { get; init; }

    /// <summary>Border width in points. Only used when <see cref="BorderColor"/> is set. Default: 0.5.</summary>
    public float BorderWidth { get; init; } = 0.5f;

    /// <summary>
    /// URL for a verification endpoint. When set, a QR code encoding this URL
    /// is rendered on the left side of the visual signature stamp.
    /// </summary>
    public string? VerificationUrl { get; init; }

    /// <summary>
    /// Extra text lines rendered after the standard fields (date, reason, location).
    /// Useful for AEA manifesto data (CPF, e-mail, IP).
    /// Each entry is rendered as a separate line in the stamp.
    /// </summary>
    public IReadOnlyList<string>? ExtraLines { get; init; }

    /// <summary>
    /// Creates an auto-positioned signature appearance. Signatures are placed left-to-right
    /// at the bottom of the page, wrapping to a new row when the line is full.
    /// </summary>
    public static SignatureAppearance Auto() => new() { AutoPosition = true };

    /// <summary>
    /// Creates an auto-positioned signature appearance with reason and location visible.
    /// </summary>
    public static SignatureAppearance Auto(bool showReason, bool showLocation) => new()
    {
        AutoPosition = true,
        ShowReason = showReason,
        ShowLocation = showLocation,
    };

    /// <summary>Computes X/Y for auto-positioning given page width and existing signature count.</summary>
    internal static (float X, float Y) ComputeAutoPosition(float pageWidth, float pageBottomMargin, int existingSigCount, float stampWidth, float stampHeight)
    {
        float usableWidth = pageWidth - (Margin * 2);
        int perRow = Math.Max(1, (int)(usableWidth / (stampWidth + Margin)));
        int row = existingSigCount / perRow;
        int col = existingSigCount % perRow;
        float x = Margin + (col * (stampWidth + Margin));
        float y = pageBottomMargin + Margin + (row * (stampHeight + Margin));
        return (x, y);
    }

    /// <summary>Computes the number of text lines that will be rendered.</summary>
    internal int LineCount(bool hasReason, bool hasLocation)
    {
        int lines = 2; // "Signed by" + name
        if (ShowDate)
        {
            lines++;
        }

        if (ShowReason && hasReason)
        {
            lines++;
        }

        if (ShowLocation && hasLocation)
        {
            lines++;
        }

        if (ExtraLines is { Count: > 0 })
        {
            lines += ExtraLines.Count;
        }

        return lines;
    }

    /// <summary>Auto-computed height based on visible lines.</summary>
    internal float ComputeHeight(bool hasReason, bool hasLocation)
    {
        float textHeight = (LineCount(hasReason, hasLocation) * LineHeight) + Padding;

        // QR codes need minimum height to be scannable (~2.5pt per module)
        if (!string.IsNullOrEmpty(VerificationUrl))
        {
            return Math.Max(textHeight, 80f);
        }

        return textHeight;
    }

    /// <summary>Auto-computed width based on the longest text line, plus optional QR code space.</summary>
    internal float ComputeWidth(string signerName, string? reason, string? location, DateTime sigTime)
    {
        float maxLen = Math.Max(Truncate(signerName).Length, "Signed by".Length);
        if (ShowDate)
        {
            maxLen = Math.Max(maxLen, sigTime.ToString("dd/MM/yyyy HH:mm").Length + 4);
        }

        if (ShowReason && !string.IsNullOrEmpty(reason))
        {
            maxLen = Math.Max(maxLen, ("Reason: " + Truncate(reason)).Length);
        }

        if (ShowLocation && !string.IsNullOrEmpty(location))
        {
            maxLen = Math.Max(maxLen, ("Location: " + Truncate(location)).Length);
        }

        if (ExtraLines is { Count: > 0 })
        {
            foreach (string line in ExtraLines)
            {
                maxLen = Math.Max(maxLen, Truncate(line).Length);
            }
        }

        float textWidth = (maxLen * CharWidth) + (Padding * 2);

        // Reserve space for QR code on the left side
        if (!string.IsNullOrEmpty(VerificationUrl))
        {
            float stampHeight = ComputeHeight(!string.IsNullOrEmpty(reason), !string.IsNullOrEmpty(location));
            float qrSize = stampHeight - 4; // 2pt margin each side
            textWidth += qrSize + 6; // QR area + gap
        }

        return textWidth;
    }

    /// <summary>Truncates text to the max display length.</summary>
    internal static string Truncate(string text)
    {
        return text.Length <= MaxTextLength ? text : string.Concat(text.AsSpan(0, MaxTextLength - 3), "...");
    }

    /// <summary>Font size used for rendering.</summary>
    internal float GetFontSizeValue() => CustomFontSize ?? FontSize;

    /// <summary>Label font size (smaller).</summary>
    internal float GetLabelFontSizeValue() => CustomLabelFontSize ?? LabelFontSize;

    /// <summary>Font size used for rendering (static, backward compat).</summary>
    internal static float GetFontSize() => FontSize;

    /// <summary>Label font size (smaller, static, backward compat).</summary>
    internal static float GetLabelFontSize() => LabelFontSize;

    /// <summary>Line height for text layout.</summary>
    internal static float GetLineHeight() => LineHeight;

    /// <summary>Returns true when a background image (JPEG or PNG) is configured.</summary>
    internal bool HasBackgroundImage() =>
        (BackgroundImagePng?.Length ?? 0) > 0 || (BackgroundImageJpeg?.Length ?? 0) > 0;

    /// <summary>Normalizes the Base14 font name used in PDF resources.</summary>
    internal string GetBaseFontName()
    {
        if (string.IsNullOrWhiteSpace(BaseFontName))
        {
            return "Helvetica";
        }

        // PDF Name-safe subset for Base14 fonts.
        foreach (char ch in BaseFontName)
        {
            if (!(char.IsLetterOrDigit(ch) || ch is '-' or '_'))
            {
                return "Helvetica";
            }
        }

        return BaseFontName;
    }
}
