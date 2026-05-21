using System.Globalization;
using DocumentFormat.OpenXml.Packaging;
using DocumentFormat.OpenXml.Wordprocessing;
using SimpleSign.DocxToPdf.Model;
using ParagraphAlignment = SimpleSign.DocxToPdf.Model.ParagraphAlignment;

namespace SimpleSign.DocxToPdf.Parsing;

/// <summary>Parses styles.xml into a <see cref="StyleMap"/>.</summary>
internal sealed class StylesParser
{
    /// <summary>Parses the style definitions part.</summary>
    /// <param name="stylesPart">The styles part (may be null).</param>
    /// <returns>A populated style map.</returns>
    public static StyleMap Parse(StyleDefinitionsPart? stylesPart)
    {
        var map = new StyleMap();

        if (stylesPart?.Styles is null)
        {
            return map;
        }

        Styles styles = stylesPart.Styles;

        // Parse default properties
        DocDefaults? defaults = styles.DocDefaults;
        if (defaults?.RunPropertiesDefault?.RunPropertiesBaseStyle is not null)
        {
            RunPropertiesBaseStyle rPrDefault = defaults.RunPropertiesDefault.RunPropertiesBaseStyle;
            if (rPrDefault.RunFonts?.Ascii?.Value is not null)
            {
                map.DefaultFontName = rPrDefault.RunFonts.Ascii.Value;
            }

            if (rPrDefault.FontSize?.Val?.Value is not null &&
                int.TryParse(rPrDefault.FontSize.Val.Value, CultureInfo.InvariantCulture, out int sz))
            {
                map.DefaultFontSizeHalfPoints = sz;
            }
        }

        // Parse named styles
        foreach (Style style in styles.Elements<Style>())
        {
            if (style.StyleId?.Value is null)
            {
                continue;
            }

            string styleId = style.StyleId.Value;
            string styleName = style.StyleName?.Val?.Value ?? styleId;

            if (style.Type?.Value == StyleValues.Paragraph)
            {
                ParseParagraphStyle(map, style, styleId, styleName);
            }
            else if (style.Type?.Value == StyleValues.Character)
            {
                ParseCharacterStyle(map, style, styleId, styleName);
            }
        }

        return map;
    }

    private static void ParseParagraphStyle(StyleMap map, Style style, string styleId, string styleName)
    {
        var pStyle = new DocParagraphStyle
        {
            Id = styleId,
            Name = styleName,
            BasedOn = style.BasedOn?.Val?.Value
        };

        if (style.StyleParagraphProperties?.Justification?.Val?.Value is not null)
        {
            pStyle.Alignment = MapJustification(style.StyleParagraphProperties.Justification.Val.Value);
        }

        StyleRunProperties? rPr = style.StyleRunProperties;
        if (rPr is not null)
        {
            pStyle.FontName = rPr.RunFonts?.Ascii?.Value;
            if (rPr.FontSize?.Val?.Value is not null &&
                int.TryParse(rPr.FontSize.Val.Value, CultureInfo.InvariantCulture, out int size))
            {
                pStyle.SizeHalfPoints = size;
            }

            pStyle.Bold = rPr.Bold is not null ? rPr.Bold.Val?.Value != false : null;
            pStyle.Italic = rPr.Italic is not null ? rPr.Italic.Val?.Value != false : null;
        }

        map.ParagraphStyles[styleId] = pStyle;
    }

    private static void ParseCharacterStyle(StyleMap map, Style style, string styleId, string styleName)
    {
        var cStyle = new DocCharacterStyle
        {
            Id = styleId,
            Name = styleName,
            BasedOn = style.BasedOn?.Val?.Value
        };

        StyleRunProperties? rPr = style.StyleRunProperties;
        if (rPr is not null)
        {
            cStyle.FontName = rPr.RunFonts?.Ascii?.Value;
            if (rPr.FontSize?.Val?.Value is not null &&
                int.TryParse(rPr.FontSize.Val.Value, CultureInfo.InvariantCulture, out int size))
            {
                cStyle.SizeHalfPoints = size;
            }

            cStyle.Bold = rPr.Bold is not null ? rPr.Bold.Val?.Value != false : null;
            cStyle.Italic = rPr.Italic is not null ? rPr.Italic.Val?.Value != false : null;
            cStyle.Color = rPr.Color?.Val?.Value;
        }

        map.CharacterStyles[styleId] = cStyle;
    }

    private static ParagraphAlignment MapJustification(JustificationValues val)
    {
        if (val == JustificationValues.Center)
        {
            return ParagraphAlignment.Center;
        }

        if (val == JustificationValues.Right)
        {
            return ParagraphAlignment.Right;
        }

        if (val == JustificationValues.Both)
        {
            return ParagraphAlignment.Justify;
        }

        return ParagraphAlignment.Left;
    }
}
