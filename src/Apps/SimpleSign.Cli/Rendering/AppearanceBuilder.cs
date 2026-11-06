using SimpleSign.Brazil.Signing;
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
        AppearanceLayoutOptions? layout = null)
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
            ShowReason = hasReason,
            ShowLocation = hasLocation,
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
            Width = layout?.Width,
            Height = layout?.Height,
            TextAlignment = ParseTextAlignment(layout?.TextAlign) ?? SignatureTextAlignment.Left,
        };

        if (text is not null)
        {
            appearance = appearance
                .WithLabels(text.SignedBy, text.Reason, text.Location, text.Date)
                .WithDateFormat(text.DateFormat, text.TimeZone is null ? null : ParseTimeZone(text.TimeZone));
        }

        if (backgroundImage is not null)
        {
            var imageBytes = File.ReadAllBytes(backgroundImage);
            var ext = Path.GetExtension(backgroundImage).ToLowerInvariant();
            appearance = ext switch
            {
                ".png" => appearance.WithBackgroundImagePng(imageBytes),
                _ => appearance.WithBackgroundImageJpeg(imageBytes),
            };
        }

        return appearance;
    }

    internal static SignatureAppearance AddAeaExtraLines(SignatureAppearance appearance, string signerName, string cpf)
    {
        var masked = AdvancedSignatureInfo.MaskCpf(cpf);
        return appearance.WithExtraLines([signerName, $"CPF: {masked}"]);
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

    /// <summary>Parses a text alignment name (left, center, right).</summary>
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
