using System.Globalization;
using System.Text.Json;
using SimpleSign.PAdES.Signing;

namespace SimpleSign.HostSigner.Services;

/// <summary>
/// Visible stamp settings sent in the optional <c>stamp</c> object of <c>POST /api/sign-file</c>.
/// Every field is optional; missing fields keep the library defaults.
/// </summary>
internal sealed record StampOptions
{
    /// <summary>1-based page number.</summary>
    public int? Page { get; init; }

    /// <summary>Lower-left X in points; when X and Y are both missing the stamp is auto-positioned.</summary>
    public float? X { get; init; }

    /// <summary>Lower-left Y in points.</summary>
    public float? Y { get; init; }

    /// <summary>Fixed stamp width in points.</summary>
    public float? Width { get; init; }

    /// <summary>Fixed stamp height in points.</summary>
    public float? Height { get; init; }

    /// <summary>Label above the signer name ("" hides the line).</summary>
    public string? SignedByLabel { get; init; }

    /// <summary>Prefix of the reason line.</summary>
    public string? ReasonLabel { get; init; }

    /// <summary>Prefix of the location line.</summary>
    public string? LocationLabel { get; init; }

    /// <summary>Prefix of the date line.</summary>
    public string? DateLabel { get; init; }

    /// <summary>.NET date format string.</summary>
    public string? DateFormat { get; init; }

    /// <summary>Time zone for the date; already validated.</summary>
    public TimeZoneInfo? TimeZone { get; init; }

    /// <summary>Whether to show the signing date.</summary>
    public bool ShowDate { get; init; } = true;

    /// <summary>Horizontal text alignment.</summary>
    public SignatureTextAlignment TextAlignment { get; init; } = SignatureTextAlignment.Left;

    /// <summary>Reads the <c>stamp</c> object of a request body; returns null when it is absent.</summary>
    /// <exception cref="FormatException">A field has an invalid value.</exception>
    public static StampOptions? FromJson(JsonElement root)
    {
        if (root.ValueKind != JsonValueKind.Object
            || !root.TryGetProperty("stamp", out var stamp)
            || stamp.ValueKind == JsonValueKind.Null)
        {
            return null;
        }

        if (stamp.ValueKind != JsonValueKind.Object)
        {
            throw new FormatException("stamp must be an object.");
        }

        string? timeZone = Text(stamp, "timeZone");
        string? dateFormat = Text(stamp, "dateFormat");
        if (dateFormat is not null)
        {
            try
            {
                _ = DateTimeOffset.UnixEpoch.ToString(dateFormat, CultureInfo.InvariantCulture);
            }
            catch (FormatException)
            {
                throw new FormatException("stamp.dateFormat is not a valid date format.");
            }
        }

        int? page = Number(stamp, "page") is { } p ? (int)p : null;
        if (page is < 1)
        {
            throw new FormatException("stamp.page must be 1 or greater.");
        }

        return new StampOptions
        {
            Page = page,
            X = Number(stamp, "x"),
            Y = Number(stamp, "y"),
            Width = Positive(stamp, "width"),
            Height = Positive(stamp, "height"),
            SignedByLabel = Text(stamp, "signedByLabel"),
            ReasonLabel = Text(stamp, "reasonLabel"),
            LocationLabel = Text(stamp, "locationLabel"),
            DateLabel = Text(stamp, "dateLabel"),
            DateFormat = string.IsNullOrEmpty(dateFormat) ? null : dateFormat,
            TimeZone = string.IsNullOrWhiteSpace(timeZone)
                ? null
                : ParseTimeZone(timeZone) ?? throw new FormatException("stamp.timeZone must be a time zone ID (e.g. America/Sao_Paulo) or an offset (e.g. -03:00)."),
            ShowDate = !stamp.TryGetProperty("showDate", out var sd) || sd.ValueKind != JsonValueKind.False,
            TextAlignment = Text(stamp, "textAlign")?.ToLowerInvariant() switch
            {
                null or "" or "left" => SignatureTextAlignment.Left,
                "center" => SignatureTextAlignment.Center,
                "right" => SignatureTextAlignment.Right,
                _ => throw new FormatException("stamp.textAlign must be left, center or right."),
            },
        };
    }

    /// <summary>Builds the library appearance; reason and location lines are shown when they were given.</summary>
    public SignatureAppearance ToAppearance(bool hasReason, bool hasLocation)
    {
        bool hasPosition = X.HasValue || Y.HasValue;
        var appearance = new SignatureAppearance
        {
            Page = Page ?? 1,
            AutoPosition = !hasPosition,
            X = X ?? 20f,
            Y = Y ?? 20f,
            Width = Width,
            Height = Height,
            ShowDate = ShowDate,
            ShowReason = hasReason,
            ShowLocation = hasLocation,
            TextAlignment = TextAlignment,
            DateFormat = DateFormat,
            TimeZone = TimeZone,
        };

        return appearance.WithLabels(SignedByLabel, ReasonLabel, LocationLabel, DateLabel);
    }

    /// <summary>Parses an IANA/Windows time zone ID, "UTC", or a fixed offset such as "-03:00".</summary>
    internal static TimeZoneInfo? ParseTimeZone(string value)
    {
        string trimmed = value.Trim();
        if (trimmed.Equals("UTC", StringComparison.OrdinalIgnoreCase) || trimmed.Equals("Z", StringComparison.OrdinalIgnoreCase))
        {
            return TimeZoneInfo.Utc;
        }

        if (trimmed.Length > 1 && trimmed[0] is '+' or '-')
        {
            if (!TimeSpan.TryParseExact(trimmed[1..], ["hh\\:mm", "hhmm", "hh"], CultureInfo.InvariantCulture, out var offset)
                || offset > TimeSpan.FromHours(14))
            {
                return null;
            }

            offset = trimmed[0] == '-' ? offset.Negate() : offset;
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

    private static string? Text(JsonElement obj, string name) =>
        obj.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;

    private static float? Number(JsonElement obj, string name)
    {
        if (!obj.TryGetProperty(name, out var v) || v.ValueKind == JsonValueKind.Null)
        {
            return null;
        }

        return v.ValueKind == JsonValueKind.Number && v.TryGetSingle(out float f) && float.IsFinite(f)
            ? f
            : throw new FormatException($"stamp.{name} must be a number.");
    }

    private static float? Positive(JsonElement obj, string name)
    {
        float? value = Number(obj, name);
        return value is <= 0 ? throw new FormatException($"stamp.{name} must be greater than 0.") : value;
    }
}
