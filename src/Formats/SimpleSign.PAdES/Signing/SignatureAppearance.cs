using System.Globalization;

namespace SimpleSign.PAdES.Signing;

/// <summary>Visual appearance settings for a visible signature annotation.</summary>
public sealed class SignatureAppearance
{
    private const float FontSize = 7f;
    private const float LabelFontSize = 6f;
    private const float LineHeight = 10f;
    private const float LineSpacingFactor = 1.25f;
    private const float Padding = 4f;
    private const float TextLeft = 3f;
    private const int DefaultMaxTextLength = 40;
    private const float Margin = 8f;
    private const float MinQrHeight = 80f;
    private const string DefaultDateFormat = "dd/MM/yyyy HH:mm";
    private const float ShrinkTolerance = 0.999f;
    private const float MinShrinkScale = 0.1f;

    /// <summary>Page number (1-based) where the signature annotation is placed.</summary>
    public int Page { get; init; } = 1;

    /// <summary>X coordinate of the annotation rectangle (lower-left corner, in points). Ignored when <see cref="AutoPosition"/> is true.</summary>
    public float X { get; init; } = 20f;

    /// <summary>Y coordinate of the annotation rectangle (lower-left corner, in points). Ignored when <see cref="AutoPosition"/> is true.</summary>
    public float Y { get; init; } = 20f;

    /// <summary>
    /// Fixed stamp width in points. When null (default), the width is computed from the text,
    /// the font sizes and the optional QR code. See <see cref="ShrinkToFit"/> for text that does not fit.
    /// </summary>
    public float? Width { get; init; }

    /// <summary>
    /// Fixed stamp height in points. When null (default), the height is computed from the
    /// number of lines and their font sizes. See <see cref="ShrinkToFit"/> for text that does not fit.
    /// </summary>
    public float? Height { get; init; }

    /// <summary>Horizontal alignment of the text lines inside the stamp. Default: <see cref="SignatureTextAlignment.Left"/>.</summary>
    public SignatureTextAlignment TextAlignment { get; init; } = SignatureTextAlignment.Left;

    /// <summary>
    /// Vertical position of the text block when the stamp is taller than the text (fixed <see cref="Height"/>
    /// or a QR code). Default: <see cref="SignatureVerticalAlignment.Top"/>.
    /// </summary>
    public SignatureVerticalAlignment VerticalAlignment { get; init; } = SignatureVerticalAlignment.Top;

    /// <summary>
    /// When true (default), text that does not fit a fixed <see cref="Width"/> or <see cref="Height"/>
    /// is scaled down so every line fits. When false, the text keeps its size and is clipped.
    /// </summary>
    public bool ShrinkToFit { get; init; } = true;

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
    /// Label rendered on the first line, above the signer name. Default: "Signed by".
    /// Set to an empty string to omit the line (e.g. "Assinado digitalmente por" for Portuguese).
    /// </summary>
    public string SignedByLabel { get; init; } = "Signed by";

    /// <summary>
    /// Name rendered in the stamp. When null (default), the signer name from the signing options
    /// is used. The /Name entry of the signature dictionary is not affected.
    /// </summary>
    public string? SignerDisplayName { get; init; }

    /// <summary>Prefix of the reason line. Default: "Reason: ".</summary>
    public string ReasonLabel { get; init; } = "Reason: ";

    /// <summary>Prefix of the location line. Default: "Location: ".</summary>
    public string LocationLabel { get; init; } = "Location: ";

    /// <summary>Prefix of the date line (e.g. "Date: "). Default: none.</summary>
    public string DateLabel { get; init; } = string.Empty;

    /// <summary>
    /// .NET date/time format string for the signing time, applied after conversion to
    /// <see cref="TimeZone"/> (e.g. "dd/MM/yyyy HH:mm:ss zzz" or "f").
    /// When null (default), the format is "dd/MM/yyyy HH:mm" followed by the UTC offset,
    /// such as "15/06/2025 14:30 UTC" or "15/06/2025 11:30 UTC-03:00".
    /// </summary>
    public string? DateFormat { get; init; }

    /// <summary>Time zone used to display the signing time. Default: UTC.</summary>
    public TimeZoneInfo? TimeZone { get; init; }

    /// <summary>Culture used by <see cref="DateFormat"/> (month and day names). Default: invariant culture.</summary>
    public CultureInfo? DateCulture { get; init; }

    /// <summary>
    /// Maximum number of characters per line; longer text is cut and ends in "...".
    /// Default: 40. Set to 0 to disable truncation.
    /// </summary>
    public int MaxTextLength { get; init; } = DefaultMaxTextLength;

    /// <summary>
    /// Background image bytes (JPEG format, grayscale, RGB or CMYK). Rendered behind the text in the signature stamp.
    /// If both JPEG and PNG are set, PNG takes precedence.
    /// </summary>
    public ReadOnlyMemory<byte>? BackgroundImageJpeg { get; init; }

    /// <summary>
    /// Background image bytes (PNG format, non-interlaced: 8-bit grayscale, RGB, grayscale+alpha or RGBA,
    /// or palette images with 1, 2, 4 or 8 bits). Transparency is kept through a soft mask, so a
    /// handwritten signature scan with a transparent background can be placed over the stamp.
    /// Rendered behind the text in the signature stamp.
    /// If both JPEG and PNG are set, PNG takes precedence.
    /// </summary>
    public ReadOnlyMemory<byte>? BackgroundImagePng { get; init; }

    /// <summary>How the background image is scaled into the stamp. Default: <see cref="SignatureImageFit.Stretch"/>.</summary>
    public SignatureImageFit BackgroundImageFit { get; init; } = SignatureImageFit.Stretch;

    /// <summary>Fill color of the stamp as RGB triplet (0.0–1.0 each). When null (default), the stamp is transparent.</summary>
    public (float R, float G, float B)? BackgroundColor { get; init; }

    /// <summary>Custom font size for the signer name. Default: 7pt.</summary>
    public float? CustomFontSize { get; init; }

    /// <summary>Custom font size for the label, date, reason, location and extra lines. Default: 6pt.</summary>
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

    /// <summary>Initializes a new signature appearance with default values.</summary>
    public SignatureAppearance()
    {
    }

    /// <summary>
    /// Internal copy constructor that copies all property values from source.
    /// </summary>
    private SignatureAppearance(SignatureAppearance source) : this()
    {
        Page = source.Page;
        X = source.X;
        Y = source.Y;
        Width = source.Width;
        Height = source.Height;
        TextAlignment = source.TextAlignment;
        VerticalAlignment = source.VerticalAlignment;
        ShrinkToFit = source.ShrinkToFit;
        AutoPosition = source.AutoPosition;
        ShowDate = source.ShowDate;
        ShowReason = source.ShowReason;
        ShowLocation = source.ShowLocation;
        SignedByLabel = source.SignedByLabel;
        SignerDisplayName = source.SignerDisplayName;
        ReasonLabel = source.ReasonLabel;
        LocationLabel = source.LocationLabel;
        DateLabel = source.DateLabel;
        DateFormat = source.DateFormat;
        TimeZone = source.TimeZone;
        DateCulture = source.DateCulture;
        MaxTextLength = source.MaxTextLength;
        BackgroundImageJpeg = source.BackgroundImageJpeg is { } jpeg ? jpeg.ToArray() : null;
        BackgroundImagePng = source.BackgroundImagePng is { } png ? png.ToArray() : null;
        BackgroundImageFit = source.BackgroundImageFit;
        BackgroundColor = source.BackgroundColor;
        CustomFontSize = source.CustomFontSize;
        CustomLabelFontSize = source.CustomLabelFontSize;
        BaseFontName = source.BaseFontName;
        TextColor = source.TextColor;
        BorderColor = source.BorderColor;
        BorderWidth = source.BorderWidth;
        VerificationUrl = source.VerificationUrl;
        ExtraLines = source.ExtraLines?.ToArray();
    }

    /// <summary>Returns a clone with the PNG background image set.</summary>
    public SignatureAppearance WithBackgroundImagePng(byte[] imageBytes) =>
        new(this) { BackgroundImagePng = imageBytes.ToArray(), BackgroundImageJpeg = null };

    /// <summary>Returns a clone with the JPEG background image set.</summary>
    public SignatureAppearance WithBackgroundImageJpeg(byte[] imageBytes) =>
        new(this) { BackgroundImageJpeg = imageBytes.ToArray(), BackgroundImagePng = null };

    /// <summary>Returns a clone with extra lines.</summary>
    public SignatureAppearance WithExtraLines(IReadOnlyList<string> extraLines) =>
        new(this) { ExtraLines = [.. extraLines] };

    /// <summary>
    /// Returns a clone with the given stamp labels. A null argument keeps the current value;
    /// an empty <paramref name="signedBy"/> removes the first line.
    /// </summary>
    /// <param name="signedBy">Label above the signer name (e.g. "Assinado digitalmente por").</param>
    /// <param name="reason">Prefix of the reason line (e.g. "Motivo: ").</param>
    /// <param name="location">Prefix of the location line (e.g. "Local: ").</param>
    /// <param name="date">Prefix of the date line (e.g. "Data: ").</param>
    public SignatureAppearance WithLabels(string? signedBy = null, string? reason = null, string? location = null, string? date = null) =>
        new(this)
        {
            SignedByLabel = signedBy ?? SignedByLabel,
            ReasonLabel = reason ?? ReasonLabel,
            LocationLabel = location ?? LocationLabel,
            DateLabel = date ?? DateLabel,
        };

    /// <summary>Returns a clone that displays the signing time with the given format, time zone and culture.</summary>
    /// <param name="format">.NET date/time format string; null keeps the default format.</param>
    /// <param name="timeZone">Time zone for display; null means UTC.</param>
    /// <param name="culture">Culture for month and day names; null means invariant.</param>
    public SignatureAppearance WithDateFormat(string? format, TimeZoneInfo? timeZone = null, CultureInfo? culture = null) =>
        new(this) { DateFormat = format, TimeZone = timeZone, DateCulture = culture };

    internal SignatureAppearance Snapshot() => new(this);

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
    internal int LineCount(bool hasReason, bool hasLocation) => LineFontSizes(hasReason, hasLocation).Count;

    /// <summary>
    /// Builds the text lines of the stamp, in order, with the font size of each line.
    /// The text is already truncated and limited to characters the stamp font can render.
    /// </summary>
    internal List<AppearanceLine> BuildLines(string? signerName, string? reason, string? location, DateTime sigTime)
    {
        float fontSize = GetFontSizeValue();
        float labelSize = GetLabelFontSizeValue();
        var lines = new List<AppearanceLine>();

        if (!string.IsNullOrEmpty(SignedByLabel))
        {
            lines.Add(new AppearanceLine(Prepare(SignedByLabel), labelSize));
        }

        lines.Add(new AppearanceLine(Prepare(SignerDisplayName ?? signerName ?? "Signer"), fontSize));

        if (ShowDate)
        {
            lines.Add(new AppearanceLine(Prepare(DateLabel + FormatDate(sigTime)), labelSize));
        }

        if (ShowReason && !string.IsNullOrEmpty(reason))
        {
            lines.Add(new AppearanceLine(Prepare(ReasonLabel + reason), labelSize));
        }

        if (ShowLocation && !string.IsNullOrEmpty(location))
        {
            lines.Add(new AppearanceLine(Prepare(LocationLabel + location), labelSize));
        }

        if (ExtraLines is { Count: > 0 })
        {
            foreach (string line in ExtraLines)
            {
                lines.Add(new AppearanceLine(Prepare(line), labelSize));
            }
        }

        return lines;
    }

    /// <summary>Formats the signing time with <see cref="DateFormat"/>, <see cref="TimeZone"/> and <see cref="DateCulture"/>.</summary>
    internal string FormatDate(DateTime sigTime)
    {
        DateTime utc = sigTime.Kind switch
        {
            DateTimeKind.Local => sigTime.ToUniversalTime(),
            _ => DateTime.SpecifyKind(sigTime, DateTimeKind.Utc),
        };
        TimeZoneInfo zone = TimeZone ?? TimeZoneInfo.Utc;
        TimeSpan offset = zone.GetUtcOffset(utc);
        var local = new DateTimeOffset(DateTime.SpecifyKind(utc + offset, DateTimeKind.Unspecified), offset);

        if (DateFormat is not null)
        {
            return local.ToString(DateFormat, DateCulture ?? CultureInfo.InvariantCulture);
        }

        string text = local.ToString(DefaultDateFormat, CultureInfo.InvariantCulture);
        if (offset == TimeSpan.Zero)
        {
            return text + " UTC";
        }

        char sign = offset < TimeSpan.Zero ? '-' : '+';
        TimeSpan abs = offset.Duration();
        return string.Create(CultureInfo.InvariantCulture, $"{text} UTC{sign}{abs.Hours:00}:{abs.Minutes:00}");
    }

    /// <summary>Line height for a line rendered at the given font size.</summary>
    internal static float LineHeightFor(float fontSize) => Math.Max(LineHeight, fontSize * LineSpacingFactor);

    /// <summary>
    /// Positions the text lines inside a stamp of the given size: applies <see cref="ShrinkToFit"/>,
    /// <see cref="TextAlignment"/> and <see cref="VerticalAlignment"/>, and leaves room for the QR code.
    /// </summary>
    internal List<PositionedLine> Layout(string? signerName, string? reason, string? location, DateTime sigTime, float width, float height)
    {
        var lines = BuildLines(signerName, reason, location, sigTime);
        string font = GetBaseFontName();
        float qrOffset = string.IsNullOrEmpty(VerificationUrl) ? 0f : QrSize(height) + 6;
        float areaLeft = TextLeft + qrOffset;
        float areaRight = width - ((Padding * 2) - TextLeft);
        float areaWidth = Math.Max(0f, areaRight - areaLeft);
        float areaHeight = Math.Max(0f, height - Padding);

        float[] widths = new float[lines.Count];
        float maxWidth = 0f;
        float blockHeight = 0f;
        for (int i = 0; i < lines.Count; i++)
        {
            widths[i] = AppearanceText.Measure(lines[i].Text, font, lines[i].FontSize);
            maxWidth = Math.Max(maxWidth, widths[i]);
            blockHeight += LineHeightFor(lines[i].FontSize);
        }

        float scale = 1f;
        if (ShrinkToFit)
        {
            if (maxWidth > 0f && areaWidth < maxWidth * ShrinkTolerance)
            {
                scale = areaWidth / maxWidth;
            }

            if (blockHeight > 0f && areaHeight < blockHeight * ShrinkTolerance)
            {
                scale = Math.Min(scale, areaHeight / blockHeight);
            }

            scale = Math.Max(scale, MinShrinkScale);
        }

        blockHeight *= scale;
        float top = VerticalAlignment switch
        {
            SignatureVerticalAlignment.Middle => Padding + ((areaHeight + blockHeight) / 2),
            SignatureVerticalAlignment.Bottom => Padding + blockHeight,
            _ => height,
        };
        top = Math.Min(top, height);

        var positioned = new List<PositionedLine>(lines.Count);
        float y = top;
        for (int i = 0; i < lines.Count; i++)
        {
            float size = lines[i].FontSize * scale;
            float lineWidth = widths[i] * scale;
            y -= LineHeightFor(lines[i].FontSize) * scale;
            float x = TextAlignment switch
            {
                SignatureTextAlignment.Center => areaLeft + ((areaWidth - lineWidth) / 2),
                SignatureTextAlignment.Right => areaRight - lineWidth,
                _ => areaLeft,
            };
            positioned.Add(new PositionedLine(lines[i].Text, size, Math.Max(areaLeft, x), y));
        }

        return positioned;
    }

    /// <summary>Auto-computed height based on visible lines.</summary>
    internal float ComputeHeight(bool hasReason, bool hasLocation)
    {
        if (Height is > 0f and var fixedHeight)
        {
            return fixedHeight;
        }

        float textHeight = Padding;
        foreach (float size in LineFontSizes(hasReason, hasLocation))
        {
            textHeight += LineHeightFor(size);
        }

        // QR codes need minimum height to be scannable (~2.5pt per module)
        return !string.IsNullOrEmpty(VerificationUrl) ? Math.Max(textHeight, MinQrHeight) : textHeight;
    }

    /// <summary>Auto-computed width based on the longest text line, plus optional QR code space.</summary>
    internal float ComputeWidth(string signerName, string? reason, string? location, DateTime sigTime)
    {
        if (Width is > 0f and var fixedWidth)
        {
            return fixedWidth;
        }

        string font = GetBaseFontName();
        float maxWidth = 0f;
        foreach (var line in BuildLines(signerName, reason, location, sigTime))
        {
            maxWidth = Math.Max(maxWidth, AppearanceText.Measure(line.Text, font, line.FontSize));
        }

        float textWidth = maxWidth + (Padding * 2);

        // Reserve space for QR code on the left side
        if (!string.IsNullOrEmpty(VerificationUrl))
        {
            float stampHeight = ComputeHeight(!string.IsNullOrEmpty(reason), !string.IsNullOrEmpty(location));
            textWidth += QrSize(stampHeight) + 6; // QR area + gap
        }

        return textWidth;
    }

    /// <summary>Side of the QR code for a stamp of the given height.</summary>
    internal static float QrSize(float stampHeight) => Math.Max(0f, stampHeight - 4); // 2pt margin each side

    /// <summary>Truncates text to the default max display length (40 characters).</summary>
    internal static string Truncate(string text) => Truncate(text, DefaultMaxTextLength);

    private static string Truncate(string text, int maxLength) =>
        maxLength <= 0 || text.Length <= maxLength
            ? text
            : maxLength <= 3 ? text[..maxLength] : string.Concat(text.AsSpan(0, maxLength - 3), "...");

    private string Prepare(string text) => Truncate(AppearanceText.ToEncodable(text), MaxTextLength);

    private List<float> LineFontSizes(bool hasReason, bool hasLocation)
    {
        float labelSize = GetLabelFontSizeValue();
        var sizes = new List<float>();
        if (!string.IsNullOrEmpty(SignedByLabel))
        {
            sizes.Add(labelSize);
        }

        sizes.Add(GetFontSizeValue());
        if (ShowDate)
        {
            sizes.Add(labelSize);
        }

        if (ShowReason && hasReason)
        {
            sizes.Add(labelSize);
        }

        if (ShowLocation && hasLocation)
        {
            sizes.Add(labelSize);
        }

        if (ExtraLines is { Count: > 0 })
        {
            sizes.AddRange(Enumerable.Repeat(labelSize, ExtraLines.Count));
        }

        return sizes;
    }

    /// <summary>Font size used for rendering.</summary>
    internal float GetFontSizeValue() => CustomFontSize ?? FontSize;

    /// <summary>Label font size (smaller).</summary>
    internal float GetLabelFontSizeValue() => CustomLabelFontSize ?? LabelFontSize;

    /// <summary>Font size used for rendering (static, backward compat).</summary>
    internal static float GetFontSize() => FontSize;

    /// <summary>Label font size (smaller, static, backward compat).</summary>
    internal static float GetLabelFontSize() => LabelFontSize;

    /// <summary>Minimum line height for text layout.</summary>
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

/// <summary>How a background image is scaled into the signature stamp.</summary>
public enum SignatureImageFit
{
    /// <summary>Scale the image to fill the stamp, ignoring its aspect ratio (default).</summary>
    Stretch,

    /// <summary>Scale the image to fit inside the stamp, keeping its aspect ratio; the image is centered.</summary>
    Contain,

    /// <summary>Scale the image to cover the whole stamp, keeping its aspect ratio; the overflow is clipped.</summary>
    Cover,
}

/// <summary>Horizontal alignment of the text in a signature stamp.</summary>
public enum SignatureTextAlignment
{
    /// <summary>Lines start at the left edge of the text area (default).</summary>
    Left,

    /// <summary>Lines are centered in the text area.</summary>
    Center,

    /// <summary>Lines end at the right edge of the text area.</summary>
    Right,
}

/// <summary>Vertical position of the text block in a signature stamp.</summary>
public enum SignatureVerticalAlignment
{
    /// <summary>The text block starts at the top of the stamp (default).</summary>
    Top,

    /// <summary>The text block is centered vertically.</summary>
    Middle,

    /// <summary>The text block ends at the bottom padding of the stamp.</summary>
    Bottom,
}

/// <summary>A text line placed in the stamp.</summary>
/// <param name="Text">Text to draw.</param>
/// <param name="FontSize">Font size in points, after any shrink-to-fit scaling.</param>
/// <param name="X">Left edge of the line in stamp coordinates.</param>
/// <param name="Y">Baseline of the line in stamp coordinates.</param>
internal readonly record struct PositionedLine(string Text, float FontSize, float X, float Y);

/// <summary>One text line of the signature stamp.</summary>
/// <param name="Text">Text, truncated and restricted to characters the stamp font can render.</param>
/// <param name="FontSize">Font size in points.</param>
internal readonly record struct AppearanceLine(string Text, float FontSize);
