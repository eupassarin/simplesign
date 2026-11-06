using System.Globalization;
using System.Text;
using System.Xml;
using SimpleSign.HtmlToPdf.Parsing;

namespace SimpleSign.HtmlToPdf.Rendering.Svg;

/// <summary>Loads SVG files into the DOM model used for inline SVG, and measures SVG roots.</summary>
internal static class SvgDocument
{
    private const int MaxElements = 200_000;
    private const int MaxDepth = 128;

    /// <summary>Returns true when the reference or bytes look like an SVG document.</summary>
    public static bool LooksLikeSvg(string? reference, byte[]? bytes)
    {
        if (reference is not null && (reference.StartsWith("data:image/svg", StringComparison.OrdinalIgnoreCase)
            || reference.Split('?', '#')[0].EndsWith(".svg", StringComparison.OrdinalIgnoreCase)))
        {
            return true;
        }

        if (bytes is null || bytes.Length < 4)
        {
            return false;
        }

        string head = Encoding.UTF8.GetString(bytes, 0, Math.Min(bytes.Length, 1024)).TrimStart('﻿', ' ', '\t', '\r', '\n');
        return head.StartsWith("<svg", StringComparison.OrdinalIgnoreCase)
            || ((head.StartsWith("<?xml", StringComparison.Ordinal) || head.StartsWith("<!", StringComparison.Ordinal))
                && head.Contains("<svg", StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>Loads and styles an SVG referenced by an image source; null when it is not SVG or is malformed.</summary>
    public static HtmlNode? Load(string? reference, ResourceLoader loader)
    {
        if (string.IsNullOrWhiteSpace(reference))
        {
            return null;
        }

        byte[]? bytes = loader.Load(reference);
        return bytes is null || !LooksLikeSvg(reference, bytes) ? null : Parse(bytes);
    }

    /// <summary>Parses SVG markup. Element and attribute names are lower-cased like the HTML parser does.</summary>
    public static HtmlNode? Parse(byte[] bytes)
    {
        var settings = new XmlReaderSettings
        {
            DtdProcessing = DtdProcessing.Ignore,
            XmlResolver = null,
            IgnoreComments = true,
            IgnoreProcessingInstructions = true,
            MaxCharactersInDocument = 64L * 1024 * 1024,
        };

        try
        {
            using var stream = new MemoryStream(bytes);
            using var reader = XmlReader.Create(stream, settings);
            HtmlNode? root = null;
            HtmlNode? current = null;
            int count = 0;
            int depth = 0;
            int skipped = 0;
            while (reader.Read())
            {
                switch (reader.NodeType)
                {
                    case XmlNodeType.Element:
                        if (++count > MaxElements)
                        {
                            return root;
                        }

                        // Content nested deeper than any real drawing is dropped (keeps later recursion bounded).
                        if (skipped > 0 || depth >= MaxDepth)
                        {
                            if (!reader.IsEmptyElement)
                            {
                                skipped++;
                            }

                            break;
                        }

                        var element = HtmlNode.CreateElement(reader.LocalName);
                        if (reader.HasAttributes)
                        {
                            while (reader.MoveToNextAttribute())
                            {
                                if (reader.Prefix == "xmlns" || reader.LocalName == "xmlns")
                                {
                                    continue;
                                }

                                element.Attributes[reader.LocalName.ToLowerInvariant()] = reader.Value;
                            }

                            reader.MoveToElement();
                        }

                        if (current is null)
                        {
                            root = element;
                        }
                        else
                        {
                            current.AppendChild(element);
                        }

                        if (!reader.IsEmptyElement)
                        {
                            current = element;
                            depth++;
                        }

                        break;

                    case XmlNodeType.EndElement:
                        if (skipped > 0)
                        {
                            skipped--;
                            break;
                        }

                        current = current?.Parent;
                        depth--;
                        break;

                    case XmlNodeType.Text or XmlNodeType.CDATA or XmlNodeType.SignificantWhitespace or XmlNodeType.Whitespace:
                        if (skipped == 0)
                        {
                            current?.AppendChild(HtmlNode.CreateText(reader.Value));
                        }

                        break;
                }
            }

            if (root is null || root.Tag != "svg")
            {
                return null;
            }

            // Apply the document's own <style> sheets (and style attributes).
            var css = new StringBuilder();
            foreach (HtmlNode style in root.Descendants("style"))
            {
                css.Append(string.Concat(style.Children.Select(c => c.Text))).Append('\n');
            }

            StyleResolver.Resolve(root, css.Length > 0 ? CssParser.ParseStylesheet(css.ToString()) : []);
            return root;
        }
        catch (XmlException)
        {
            return null;
        }
    }

    /// <summary>Gets the intrinsic size of an SVG root in CSS pixels.</summary>
    public static (float Width, float Height) IntrinsicSize(HtmlNode svg)
    {
        float[]? viewBox = ParseViewBox(svg.GetAttribute("viewbox"));
        float? w = ParseAbsolute(svg.GetAttribute("width"));
        float? h = ParseAbsolute(svg.GetAttribute("height"));
        float? ratio = viewBox is { } vb && vb[3] > 0 ? vb[2] / vb[3] : null;
        if (w is float fw && h is float fh)
        {
            return (fw, fh);
        }

        if (w is float onlyW)
        {
            return (onlyW, ratio is float r1 ? onlyW / r1 : 150);
        }

        if (h is float onlyH)
        {
            return (ratio is float r2 ? onlyH * r2 : 300, onlyH);
        }

        return viewBox is { } box && box[2] > 0 && box[3] > 0 ? (box[2], box[3]) : (300, 150);
    }

    /// <summary>Parses a viewBox attribute into [x, y, width, height].</summary>
    public static float[]? ParseViewBox(string? value)
    {
        if (value is null)
        {
            return null;
        }

        float[] numbers = SvgPathParser.ParseNumbers(value);
        return numbers.Length == 4 && numbers[2] > 0 && numbers[3] > 0 ? numbers : null;
    }

    /// <summary>Parses an absolute SVG length in px (percentages and unknown units yield null).</summary>
    public static float? ParseAbsolute(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        string v = value.Trim().ToLowerInvariant();
        if (v.EndsWith('%') || v == "auto")
        {
            return null;
        }

        (string Unit, float Factor)[] units = [("px", 1f), ("pt", 4f / 3f), ("pc", 16f), ("mm", 96f / 25.4f), ("cm", 96f / 2.54f), ("in", 96f), ("em", 16f), ("ex", 8f)];
        foreach (var (unit, factor) in units)
        {
            if (v.EndsWith(unit, StringComparison.Ordinal))
            {
                return float.TryParse(v[..^unit.Length], NumberStyles.Float, CultureInfo.InvariantCulture, out float n) && n > 0 ? n * factor : null;
            }
        }

        return float.TryParse(v, NumberStyles.Float, CultureInfo.InvariantCulture, out float plain) && plain > 0 ? plain : null;
    }
}
