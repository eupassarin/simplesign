using SimpleSign.PAdES.Signing;

namespace SimpleSign.Cli.Rendering;

internal static class AppearanceBuilder
{
    internal static SignatureAppearance Build(
        bool visible, string? backgroundImage, string? qrUrl,
        int? page, float? x, float? y,
        bool hasReason, bool hasLocation,
        float? fontSize = null, float? labelFontSize = null,
        string? textColor = null, string? font = null,
        string? borderColor = null, float? borderWidth = null,
        bool noDate = false,
        AppearanceTextOptions? text = null,
        string? backgroundColor = null,
        string? imageFit = null,
        AppearanceLayoutOptions? layout = null,
        AppearanceExtraOptions? extra = null,
        string? imagePosition = null,
        AnchorOptions? anchor = null)
    {
        if (!visible)
        {
            return null!;
        }

        bool hasCoords = page.HasValue || x.HasValue || y.HasValue;

        var appearance = new SignatureAppearance
        {
            AutoPosition = !hasCoords,
            Page = page ?? 1,
            X = x ?? 20f,
            Y = y ?? 20f,
            ShowReason = hasReason && extra?.HideReason != true,
            ShowLocation = hasLocation && extra?.HideLocation != true,
            ShowDate = !noDate,
            VerificationUrl = qrUrl,
            CustomFontSize = fontSize,
            CustomLabelFontSize = labelFontSize,
            BaseFontName = font,
            TextColor = ParseColor(textColor),
            BorderColor = ParseColor(borderColor),
            BorderWidth = borderWidth ?? 0.5f,
            BackgroundColor = ParseColor(backgroundColor),
            BackgroundImageFit = ParseImageFit(imageFit) ?? SignatureImageFit.Stretch,
            BackgroundImagePosition = ParseImagePosition(imagePosition) ?? SignatureImagePosition.Behind,
            Anchor = anchor is null ? null : new SignatureAnchor(anchor.Text)
            {
                OffsetX = ParseOffset(anchor.Offset)?.X ?? 0f,
                OffsetY = ParseOffset(anchor.Offset)?.Y ?? 0f,
                Occurrence = anchor.Occurrence ?? -1,
                IgnoreCase = anchor.IgnoreCase,
            },
            Width = layout?.Width,
            Height = layout?.Height,
            TextAlignment = ParseTextAlignment(layout?.TextAlign) ?? SignatureTextAlignment.Left,
            VerticalAlignment = ParseVerticalAlignment(extra?.VerticalAlign) ?? SignatureVerticalAlignment.Top,
            ShrinkToFit = extra?.NoShrinkToFit != true,
            SignerDisplayName = extra?.SignerDisplayName,
            MaxTextLength = extra?.MaxTextLength ?? new SignatureAppearance().MaxTextLength,
        };

        if (extra?.ExtraLines is { Count: > 0 } lines)
        {
            appearance = appearance.WithExtraLines(lines);
        }

        if (text is not null)
        {
            appearance = appearance
                .WithLabels(text.SignedBy, text.Reason, text.Location, text.Date)
                .WithDateFormat(text.DateFormat, text.TimeZone is null ? null : ParseTimeZone(text.TimeZone),
                    extra?.DateCulture is null ? null : System.Globalization.CultureInfo.GetCultureInfo(extra.DateCulture));
        }

        if (backgroundImage is not null)
        {
            // PNG or JPEG by its signature, whatever the extension says.
            var imageBytes = File.ReadAllBytes(backgroundImage);
            bool isPng = imageBytes is [0x89, (byte)'P', (byte)'N', (byte)'G', ..];
            appearance = isPng ? appearance.WithBackgroundImagePng(imageBytes) : appearance.WithBackgroundImageJpeg(imageBytes);
        }

        return appearance;
    }

    /// <summary>Parses a time zone ID (IANA or Windows) or a fixed UTC offset such as "-03:00".</summary>
    internal static TimeZoneInfo? ParseTimeZone(string value)
    {
        string trimmed = value.Trim();
        if (trimmed.Equals("UTC", StringComparison.OrdinalIgnoreCase) || trimmed.Equals("Z", StringComparison.OrdinalIgnoreCase))
        {
            return TimeZoneInfo.Utc;
        }

        if (trimmed.Length > 1 && trimmed[0] is '+' or '-'
            && TimeSpan.TryParseExact(trimmed[1..], ["hh\\:mm", "hhmm", "hh"], System.Globalization.CultureInfo.InvariantCulture, out var offset)
            && offset <= TimeSpan.FromHours(14))
        {
            if (trimmed[0] == '-')
            {
                offset = offset.Negate();
            }

            string id = "UTC" + trimmed;
            return TimeZoneInfo.CreateCustomTimeZone(id, offset, id, id);
        }

        try
        {
            return TimeZoneInfo.FindSystemTimeZoneById(trimmed);
        }
        catch (TimeZoneNotFoundException)
        {
            return null;
        }
        catch (InvalidTimeZoneException)
        {
            return null;
        }
    }

    /// <summary>Parses an image fit mode name (stretch, contain, cover).</summary>
    internal static SignatureImageFit? ParseImageFit(string? value) =>
        value?.Trim().ToLowerInvariant() switch
        {
            "stretch" => SignatureImageFit.Stretch,
            "contain" => SignatureImageFit.Contain,
            "cover" => SignatureImageFit.Cover,
            _ => null,
        };

    /// <summary>Parses an anchor offset "X,Y" in points (e.g. "0,30" or "-10.5,-20"); null when it is not one.</summary>
    internal static (float X, float Y)? ParseOffset(string? value)
    {
        string[] parts = (value ?? "").Split(',', StringSplitOptions.TrimEntries);
        return parts.Length == 2
            && float.TryParse(parts[0], System.Globalization.NumberStyles.Float, System.Globalization.CultureInfo.InvariantCulture, out float x)
            && float.TryParse(parts[1], System.Globalization.NumberStyles.Float, System.Globalization.CultureInfo.InvariantCulture, out float y)
            && float.IsFinite(x) && float.IsFinite(y)
            ? (x, y)
            : null;
    }

    /// <summary>Parses where the image goes (behind, left, right, top, bottom).</summary>
    internal static SignatureImagePosition? ParseImagePosition(string? value) =>
        value?.Trim().ToLowerInvariant() switch
        {
            "behind" => SignatureImagePosition.Behind,
            "left" => SignatureImagePosition.Left,
            "right" => SignatureImagePosition.Right,
            "top" => SignatureImagePosition.Top,
            "bottom" => SignatureImagePosition.Bottom,
            _ => null,
        };

    /// <summary>Parses a text alignment name (left, center, right).</summary>
    internal static SignatureVerticalAlignment? ParseVerticalAlignment(string? value) =>
        value?.Trim().ToLowerInvariant() switch
        {
            "top" => SignatureVerticalAlignment.Top,
            "middle" => SignatureVerticalAlignment.Middle,
            "bottom" => SignatureVerticalAlignment.Bottom,
            _ => null,
        };

    /// <summary>Whether <paramref name="name"/> is a culture .NET knows (pt-BR, en-US…).</summary>
    internal static bool IsValidCulture(string name)
    {
        try
        {
            _ = System.Globalization.CultureInfo.GetCultureInfo(name, predefinedOnly: true);
            return true;
        }
        catch (System.Globalization.CultureNotFoundException)
        {
            return false;
        }
    }

    internal static SignatureTextAlignment? ParseTextAlignment(string? value) =>
        value?.Trim().ToLowerInvariant() switch
        {
            "left" => SignatureTextAlignment.Left,
            "center" => SignatureTextAlignment.Center,
            "right" => SignatureTextAlignment.Right,
            _ => null,
        };

    /// <summary>Returns true when the format string can format a date.</summary>
    internal static bool IsValidDateFormat(string format)
    {
        try
        {
            _ = DateTimeOffset.UnixEpoch.ToString(format, System.Globalization.CultureInfo.InvariantCulture);
            return format.Length > 0;
        }
        catch (FormatException)
        {
            return false;
        }
    }

    internal static (float R, float G, float B)? ParseColor(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        var parts = value.Split(',', StringSplitOptions.TrimEntries);
        if (parts.Length != 3)
        {
            return null;
        }

        if (float.TryParse(parts[0], System.Globalization.NumberStyles.Float, System.Globalization.CultureInfo.InvariantCulture, out var r)
            && float.TryParse(parts[1], System.Globalization.NumberStyles.Float, System.Globalization.CultureInfo.InvariantCulture, out var g)
            && float.TryParse(parts[2], System.Globalization.NumberStyles.Float, System.Globalization.CultureInfo.InvariantCulture, out var b))
        {
            return (Math.Clamp(r, 0f, 1f), Math.Clamp(g, 0f, 1f), Math.Clamp(b, 0f, 1f));
        }

        return null;
    }
}

/// <summary>Text options for the visible signature stamp.</summary>
/// <param name="SignedBy">Label above the signer name.</param>
/// <param name="Reason">Prefix of the reason line.</param>
/// <param name="Location">Prefix of the location line.</param>
/// <param name="Date">Prefix of the date line.</param>
/// <param name="DateFormat">.NET date format string.</param>
/// <param name="TimeZone">Time zone ID or UTC offset.</param>
internal sealed record AppearanceTextOptions(
    string? SignedBy, string? Reason, string? Location, string? Date, string? DateFormat, string? TimeZone);

/// <summary>Size and alignment options for the visible signature stamp.</summary>
/// <param name="Width">Fixed stamp width in points.</param>
/// <param name="Height">Fixed stamp height in points.</param>
/// <param name="TextAlign">Text alignment name.</param>
internal sealed record AppearanceLayoutOptions(float? Width, float? Height, string? TextAlign);

/// <summary>A stamp anchored to a text of the document.</summary>
/// <param name="Text">The text to find.</param>
/// <param name="Offset">"X,Y" in points from the start of the text (right and up are positive); null is 0,0.</param>
/// <param name="Occurrence">Which match: 1 the first, -1 (null) the last.</param>
/// <param name="IgnoreCase">Whether case does not matter.</param>
internal sealed record AnchorOptions(string Text, string? Offset, int? Occurrence, bool IgnoreCase);

/// <summary>More stamp options: vertical alignment, fitting, the name and extra lines, the date culture, what to hide.</summary>
/// <param name="VerticalAlign">Vertical alignment name (top, middle, bottom).</param>
/// <param name="NoShrinkToFit">Clip the text instead of shrinking it to the rectangle.</param>
/// <param name="MaxTextLength">Longer values are cut.</param>
/// <param name="DateCulture">Culture of the date text (pt-BR…).</param>
/// <param name="SignerDisplayName">Name on the stamp instead of the certificate's.</param>
/// <param name="ExtraLines">More lines of text.</param>
/// <param name="HideReason">Keep the reason off the stamp (it stays in the signature).</param>
/// <param name="HideLocation">Keep the location off the stamp (it stays in the signature).</param>
internal sealed record AppearanceExtraOptions(
    string? VerticalAlign, bool NoShrinkToFit, int? MaxTextLength, string? DateCulture, string? SignerDisplayName,
    IReadOnlyList<string>? ExtraLines, bool HideReason, bool HideLocation);
