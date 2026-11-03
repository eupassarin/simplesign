// Licensed to SimpleSign under the MIT License.

using System.Globalization;
using SimpleSign.HtmlToPdf.Fonts;
using SimpleSign.HtmlToPdf.Layout;
using SimpleSign.HtmlToPdf.Parsing;
using SimpleSign.HtmlToPdf.Rendering;

namespace SimpleSign.HtmlToPdf;

/// <summary>Immutable conversion settings captured by <see cref="HtmlToPdfBuilder"/>.</summary>
internal sealed record ConversionOptions
{
    public required string Html { get; init; }

    public PageSize? PageSize { get; init; }

    public PageOrientation? Orientation { get; init; }

    public Thickness? Margins { get; init; }

    public string? Stylesheet { get; init; }

    public string? Title { get; init; }

    public string? Author { get; init; }

    public string? HeaderTemplate { get; init; }

    public string? FooterTemplate { get; init; }

    public string? Language { get; init; }

    public IReadOnlyList<FontRegistration> Fonts { get; init; } = [];

    public string? BaseDirectory { get; init; }

    public Func<string, byte[]?>? ResourceLoader { get; init; }

    public bool PdfA { get; init; }
}

/// <summary>Runs parse → style → layout → render for one conversion.</summary>
internal static class ConversionPipeline
{
    internal static byte[] Run(ConversionOptions options)
    {
        // 1. Parse HTML → DOM (with an implied <body>, like browsers)
        HtmlNode dom = HtmlTokenizer.Parse(options.Html);
        EnsureBody(dom);
        if (options.Language is { Length: > 0 } documentLanguage && FindLanguage(dom) is null
            && (Walk(dom).FirstOrDefault(n => n.Tag == "html") ?? Walk(dom).FirstOrDefault(n => n.Tag == "body")) is { } languageRoot)
        {
            // The builder language also drives hyphenation, like a lang attribute on the root.
            languageRoot.Attributes["lang"] = documentLanguage;
        }

        var loader = new ResourceLoader(options.BaseDirectory, options.ResourceLoader);

        // 2. Collect CSS: document <style>/<link> in order, then the builder stylesheet.
        List<CssRule> rules = CollectDocumentStyles(dom, loader);
        if (options.Stylesheet is not null)
        {
            rules.AddRange(CssParser.ParseStylesheet(options.Stylesheet));
        }

        for (int i = 0; i < rules.Count; i++)
        {
            rules[i].Order = i;
        }

        StyleResolver.Resolve(dom, rules);

        // 3. Fonts: builder registrations, then @font-face rules (builder wins on conflicts).
        List<FontRegistration> registrations = [.. LoadFontFaces(rules, loader)];
        foreach (FontRegistration registration in options.Fonts)
        {
            registrations.RemoveAll(r => string.Equals(r.Family, registration.Family, StringComparison.OrdinalIgnoreCase) && r.Variant == registration.Variant);
            registrations.Add(registration);
        }

        var fonts = new FontCollection(registrations) { EmbeddedOnly = options.PdfA };
        if (options.PdfA && fonts.IsEmpty)
        {
            throw new InvalidOperationException(
                "PDF/A requires every font to be embedded. Register at least one font with WithFont/WithFontFile or @font-face.");
        }

        // 4. Layout → pages
        PageSettings pageSettings = BuildPageSettings(options, rules);
        var engine = new LayoutEngine(pageSettings, fonts, loader);
        LayoutResult layout = engine.Layout(dom);

        string? title = options.Title ?? FindTitle(dom);
        string? language = options.Language ?? FindLanguage(dom);
        var result = new LayoutResult
        {
            Settings = layout.Settings,
            Metadata = new PdfMetadata(title, options.Author, options.HeaderTemplate, options.FooterTemplate),
            Fonts = fonts,
            Resources = loader,
            Language = language,
            PdfA = options.PdfA,
            CanvasNode = layout.CanvasNode,
            CanvasStyle = layout.CanvasStyle,
            MarginBoxes = CollectMarginBoxes(rules, dom),
        };
        result.Pages.AddRange(layout.Pages);
        result.Bookmarks.AddRange(layout.Bookmarks);

        // 5. Render → PDF bytes
        return PdfDocumentRenderer.Render(result, fonts);
    }

    /// <summary>Wraps loose content in a &lt;body&gt; element when the document has none, so body rules apply.</summary>
    internal static void EnsureBody(HtmlNode dom)
    {
        if (Walk(dom).Any(n => n.Tag == "body"))
        {
            return;
        }

        HtmlNode container = dom.Children.FirstOrDefault(c => c.Tag == "html") ?? dom;
        HtmlNode body = HtmlNode.CreateElement("body");
        var moved = container.Children.Where(c => c.Tag != "head").ToList();
        foreach (HtmlNode child in moved)
        {
            container.Children.Remove(child);
            body.AppendChild(child);
        }

        container.AppendChild(body);
    }

    internal static List<CssRule> CollectDocumentStyles(HtmlNode dom, ResourceLoader loader)
    {
        var rules = new List<CssRule>();
        foreach (HtmlNode node in Walk(dom))
        {
            if (node.Tag == "style")
            {
                string? media = node.GetAttribute("media");
                if (media is not null && !CssParser.MediaQueryAppliesToPrint(media))
                {
                    continue;
                }

                string css = string.Concat(node.Children.Where(c => c.NodeType == HtmlNodeType.Text).Select(c => c.Text));
                rules.AddRange(CssParser.ParseStylesheet(css));
            }
            else if (node.Tag == "link"
                && node.GetAttribute("rel")?.Split(' ', StringSplitOptions.RemoveEmptyEntries).Contains("stylesheet", StringComparer.OrdinalIgnoreCase) == true)
            {
                string? media = node.GetAttribute("media");
                if (media is not null && !CssParser.MediaQueryAppliesToPrint(media))
                {
                    continue;
                }

                if (loader.LoadText(node.GetAttribute("href")) is { } css)
                {
                    rules.AddRange(CssParser.ParseStylesheet(css));
                }
            }
        }

        return rules;
    }

    private static IEnumerable<HtmlNode> Walk(HtmlNode node)
    {
        var stack = new Stack<HtmlNode>();
        stack.Push(node);
        while (stack.Count > 0)
        {
            HtmlNode current = stack.Pop();
            yield return current;
            for (int i = current.Children.Count - 1; i >= 0; i--)
            {
                if (current.Children[i].NodeType == HtmlNodeType.Element)
                {
                    stack.Push(current.Children[i]);
                }
            }
        }
    }

    private static string? FindTitle(HtmlNode dom)
    {
        // An SVG <title> is an element tooltip, not the document title.
        HtmlNode? title = Walk(dom).FirstOrDefault(n => n.Tag == "title" && !HasSvgAncestor(n));
        string? text = title is null ? null : string.Concat(title.Children.Select(c => c.Text)).Trim();
        return string.IsNullOrWhiteSpace(text) ? null : string.Join(' ', text.Split([' ', '\t', '\r', '\n'], StringSplitOptions.RemoveEmptyEntries));
    }

    private static bool HasSvgAncestor(HtmlNode node)
    {
        for (HtmlNode? p = node.Parent; p is not null; p = p.Parent)
        {
            if (p.Tag == "svg")
            {
                return true;
            }
        }

        return false;
    }

    private static string? FindLanguage(HtmlNode dom) =>
        Walk(dom).FirstOrDefault(n => n.Tag is "html" or "body" && n.GetAttribute("lang") is not null)?.GetAttribute("lang");

    private static IEnumerable<FontRegistration> LoadFontFaces(List<CssRule> rules, ResourceLoader loader)
    {
        foreach (CssRule rule in rules.Where(r => r.Selector == CssParser.FontFaceRuleSelector))
        {
            if (!rule.Properties.TryGetValue("font-family", out string? family) || !rule.Properties.TryGetValue("src", out string? src))
            {
                continue;
            }

            family = family.Trim().Trim('\'', '"');
            bool bold = rule.Properties.TryGetValue("font-weight", out string? weight)
                && (weight.Trim().Equals("bold", StringComparison.OrdinalIgnoreCase)
                    || (int.TryParse(weight.Trim().Split(' ')[0], NumberStyles.Integer, CultureInfo.InvariantCulture, out int w) && w >= 600));
            bool italic = rule.Properties.TryGetValue("font-style", out string? style)
                && style.Trim().ToLowerInvariant() is "italic" or "oblique";
            FontVariant variant = (bold, italic) switch
            {
                (true, true) => FontVariant.BoldItalic,
                (true, false) => FontVariant.Bold,
                (false, true) => FontVariant.Italic,
                _ => FontVariant.Regular,
            };

            foreach (string source in CssParser.SplitTopLevel(src, ','))
            {
                string? url = ExtractUrl(source);
                if (url is null || loader.Load(url) is not { } data)
                {
                    continue;
                }

                FontRegistration? registration = null;
                try
                {
                    _ = new EmbeddedFont(family, data, variant);
                    registration = new FontRegistration(family, variant, data);
                }
                catch (ArgumentException)
                {
                    // Unsupported format (WOFF, TTC, ...): try the next source.
                }

                if (registration is not null)
                {
                    yield return registration;
                    break;
                }
            }
        }
    }

    internal static string? ExtractUrl(string value)
    {
        string v = value.Trim();
        int start = v.IndexOf("url(", StringComparison.OrdinalIgnoreCase);
        if (start < 0)
        {
            return null;
        }

        int end = v.IndexOf(')', start + 4);
        if (end < 0)
        {
            end = v.Length;
        }

        return v[(start + 4)..end].Trim().Trim('\'', '"');
    }

    /// <summary>Collects <c>@page</c> margin boxes; their text style inherits from the root element.</summary>
    internal static List<PageMarginBox> CollectMarginBoxes(List<CssRule> rules, HtmlNode dom)
    {
        var boxes = new List<PageMarginBox>();
        ComputedStyle? rootStyle = (dom.Tag == "html" ? dom : dom.Descendants("html").FirstOrDefault())?.ComputedStyle
            ?? dom.Descendants("body").FirstOrDefault()?.ComputedStyle;
        string prefix = CssParser.PageRuleSelector;
        foreach (CssRule rule in rules)
        {
            if (!rule.Selector.StartsWith(prefix, StringComparison.Ordinal))
            {
                continue;
            }

            int at = rule.Selector.LastIndexOf(" @", StringComparison.Ordinal);
            if (at < 0)
            {
                continue;
            }

            string position = rule.Selector[(at + 2)..];
            if (!PageMarginBox.Positions.Contains(position, StringComparer.Ordinal) || !rule.Properties.TryGetValue("content", out string? content))
            {
                continue;
            }

            string pageSelector = rule.Selector[prefix.Length..at].Trim().ToLowerInvariant();
            ComputedStyle style = StyleResolver.ResolveDetached(rule.Properties.Where(p => p.Key != "content"), rootStyle);
            boxes.Add(new PageMarginBox(position, pageSelector, content, style, rule.Order));
        }

        return boxes;
    }

    private static PageSettings BuildPageSettings(ConversionOptions options, List<CssRule> rules)
    {
        CssRule? pageRule = null;
        foreach (CssRule rule in rules.Where(r => r.Selector == CssParser.PageRuleSelector))
        {
            pageRule ??= new CssRule { Selector = CssParser.PageRuleSelector, Properties = new(StringComparer.Ordinal) };
            foreach (var (name, value) in rule.Properties)
            {
                pageRule.Properties[name] = value;
            }
        }

        float width = 595.28f;
        float height = 841.89f;
        bool sizeFromCss = false;
        if (pageRule is not null && pageRule.Properties.TryGetValue("size", out string? size) && ParsePageSize(size) is { } cssSize)
        {
            (width, height) = cssSize;
            sizeFromCss = true;
        }

        if (options.PageSize is not null || !sizeFromCss)
        {
            PaperSize paper = (options.PageSize ?? PageSize.A4) switch
            {
                PageSize.Letter => PaperSize.Letter,
                PageSize.Legal => PaperSize.Legal,
                PageSize.A3 => PaperSize.A3,
                _ => PaperSize.A4,
            };
            PageSettings basePaper = PageSettings.FromPaperSize(paper);
            (width, height) = (basePaper.PageWidth, basePaper.PageHeight);
        }

        if (options.Orientation is { } orientation)
        {
            bool landscape = orientation == PageOrientation.Landscape;
            if (landscape != (width > height))
            {
                (width, height) = (height, width);
            }
        }

        Thickness margins = new(72, 72, 72, 72);
        if (pageRule is not null)
        {
            float Margin(string side, float fallback) =>
                pageRule.Properties.TryGetValue($"margin-{side}", out string? v) && ResolvePageLength(v, side is "top" or "bottom" ? height : width) is { } m
                    ? m
                    : fallback;

            margins = new Thickness(Margin("top", 72), Margin("right", 72), Margin("bottom", 72), Margin("left", 72));
        }

        if (options.Margins is { } explicitMargins)
        {
            margins = explicitMargins;
        }

        return new PageSettings { PageWidth = width, PageHeight = height, Margins = margins };
    }

    private static float? ResolvePageLength(string value, float reference)
    {
        float? length = CssParser.ParseLength(value);
        if (length is null)
        {
            return null;
        }

        return length < 0 ? reference * -length.Value / 100f : length;
    }

    /// <summary>Parses a CSS <c>@page size</c> value into points (width, height).</summary>
    internal static (float Width, float Height)? ParsePageSize(string value)
    {
        List<string> tokens = [.. CssParser.SplitValueTokens(value.Trim().ToLowerInvariant())];
        if (tokens.Count == 0 || tokens[0] is "auto")
        {
            return null;
        }

        bool landscape = tokens.Remove("landscape");
        bool portrait = tokens.Remove("portrait");
        (float W, float H)? size = null;

        if (tokens.Count >= 1 && NamedPageSize(tokens[0]) is { } named)
        {
            size = named;
        }
        else if (tokens.Count >= 1 && CssParser.ParseLength(tokens[0]) is { } first && first > 0)
        {
            float second = tokens.Count >= 2 && CssParser.ParseLength(tokens[1]) is { } s && s > 0 ? s : first;
            size = (first, second);
        }
        else if (landscape || portrait)
        {
            size = (595.28f, 841.89f);
        }

        if (size is not { } result)
        {
            return null;
        }

        if ((landscape && result.W < result.H) || (portrait && result.W > result.H))
        {
            result = (result.H, result.W);
        }

        return result;
    }

    private static (float W, float H)? NamedPageSize(string name) => name switch
    {
        "a3" => (841.89f, 1190.55f),
        "a4" => (595.28f, 841.89f),
        "a5" => (419.53f, 595.28f),
        "a6" => (297.64f, 419.53f),
        "b4" => (708.66f, 1000.63f),
        "b5" => (498.9f, 708.66f),
        "letter" => (612f, 792f),
        "legal" => (612f, 1008f),
        "ledger" => (1224f, 792f),
        "tabloid" => (792f, 1224f),
        _ => null,
    };
}
