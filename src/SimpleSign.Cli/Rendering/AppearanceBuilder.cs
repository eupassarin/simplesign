using SimpleSign.Brasil.Signing;
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
        bool noDate = false)
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
        };

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
