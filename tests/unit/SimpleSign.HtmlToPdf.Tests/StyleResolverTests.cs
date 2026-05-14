using FluentAssertions;
using SimpleSign.HtmlToPdf.Parsing;
using Xunit;

namespace SimpleSign.HtmlToPdf.Tests;

public class StyleResolverTests
{
    // ── Default styles ──────────────────────────────────────────────────

    [Fact(DisplayName = "Resolve applies default styles to h1")]
    public void Resolve_H1_AppliesDefaultBoldAndSize()
    {
        var root = HtmlTokenizer.Parse("<h1>Title</h1>");
        StyleResolver.Resolve(root, []);

        var h1 = FindFirstByTag(root, "h1");
        h1.Should().NotBeNull();
        h1!.ComputedStyle.Should().NotBeNull();
        h1.ComputedStyle!.IsBold.Should().BeTrue();
        h1.ComputedStyle.FontSize.Should().BeGreaterThan(12f);
    }

    [Fact(DisplayName = "Resolve applies default styles to p")]
    public void Resolve_P_AppliesDefaultBlockDisplay()
    {
        var root = HtmlTokenizer.Parse("<p>Text</p>");
        StyleResolver.Resolve(root, []);

        var p = FindFirstByTag(root, "p");
        p.Should().NotBeNull();
        p!.ComputedStyle.Should().NotBeNull();
        p.ComputedStyle!.Display.Should().Be(DisplayType.Block);
    }

    [Fact(DisplayName = "Resolve applies bold to strong/b")]
    public void Resolve_StrongAndB_AppliesBold()
    {
        var root = HtmlTokenizer.Parse("<p><strong>Bold</strong></p>");
        StyleResolver.Resolve(root, []);

        var strong = FindFirstByTag(root, "strong");
        strong.Should().NotBeNull();
        strong!.ComputedStyle!.IsBold.Should().BeTrue();
    }

    [Fact(DisplayName = "Resolve applies italic to em/i")]
    public void Resolve_EmAndI_AppliesItalic()
    {
        var root = HtmlTokenizer.Parse("<p><em>Italic</em></p>");
        StyleResolver.Resolve(root, []);

        var em = FindFirstByTag(root, "em");
        em.Should().NotBeNull();
        em!.ComputedStyle!.IsItalic.Should().BeTrue();
    }

    // ── CSS rule application ────────────────────────────────────────────

    [Fact(DisplayName = "Resolve applies stylesheet rules")]
    public void Resolve_WithStylesheet_AppliesRules()
    {
        var root = HtmlTokenizer.Parse("<p>Text</p>");
        var rules = CssParser.ParseStylesheet("p { color: red; font-size: 18pt; }");
        StyleResolver.Resolve(root, rules);

        var p = FindFirstByTag(root, "p");
        p.Should().NotBeNull();
        p!.ComputedStyle!.FontSize.Should().Be(18f);
    }

    [Fact(DisplayName = "Resolve applies class selector")]
    public void Resolve_ClassSelector_AppliesStyles()
    {
        var root = HtmlTokenizer.Parse("<p class=\"big\">Text</p>");
        var rules = CssParser.ParseStylesheet(".big { font-size: 24pt; }");
        StyleResolver.Resolve(root, rules);

        var p = FindFirstByTag(root, "p");
        p.Should().NotBeNull();
        p!.ComputedStyle!.FontSize.Should().Be(24f);
    }

    [Fact(DisplayName = "Resolve applies id selector")]
    public void Resolve_IdSelector_AppliesStyles()
    {
        var root = HtmlTokenizer.Parse("<div id=\"main\">X</div>");
        var rules = CssParser.ParseStylesheet("#main { font-size: 20pt; }");
        StyleResolver.Resolve(root, rules);

        var div = FindFirstByTag(root, "div");
        div.Should().NotBeNull();
        div!.ComputedStyle!.FontSize.Should().Be(20f);
    }

    // ── Inline styles ───────────────────────────────────────────────────

    [Fact(DisplayName = "Resolve applies inline styles")]
    public void Resolve_InlineStyle_AppliesStyles()
    {
        var root = HtmlTokenizer.Parse("<p style=\"font-size: 20pt\">Text</p>");
        StyleResolver.Resolve(root, []);

        var p = FindFirstByTag(root, "p");
        p.Should().NotBeNull();
        p!.ComputedStyle!.FontSize.Should().Be(20f);
    }

    [Fact(DisplayName = "Inline styles override stylesheet")]
    public void Resolve_InlineOverridesStylesheet()
    {
        var root = HtmlTokenizer.Parse("<p style=\"font-size: 30pt\">Text</p>");
        var rules = CssParser.ParseStylesheet("p { font-size: 14pt; }");
        StyleResolver.Resolve(root, rules);

        var p = FindFirstByTag(root, "p");
        p!.ComputedStyle!.FontSize.Should().Be(30f);
    }

    // ── Inheritance ─────────────────────────────────────────────────────

    [Fact(DisplayName = "Font properties inherit from parent")]
    public void Resolve_FontInheritance_ChildInheritsFromParent()
    {
        var root = HtmlTokenizer.Parse("<div><span>Text</span></div>");
        var rules = CssParser.ParseStylesheet("div { font-size: 20pt; }");
        StyleResolver.Resolve(root, rules);

        var span = FindFirstByTag(root, "span");
        span.Should().NotBeNull();
        span!.ComputedStyle!.FontSize.Should().Be(20f);
    }

    // ── Table display ───────────────────────────────────────────────────

    [Fact(DisplayName = "Resolve sets table display types")]
    public void Resolve_Table_SetsDisplayTypes()
    {
        var root = HtmlTokenizer.Parse("<table><tr><td>Cell</td></tr></table>");
        StyleResolver.Resolve(root, []);

        // Table uses Block display (handled specially by LayoutEngine via tag check)
        var table = FindFirstByTag(root, "table");
        table!.ComputedStyle!.Display.Should().Be(DisplayType.Block);

        var tr = FindFirstByTag(root, "tr");
        tr!.ComputedStyle!.Display.Should().Be(DisplayType.TableRow);

        var td = FindFirstByTag(root, "td");
        td!.ComputedStyle!.Display.Should().Be(DisplayType.TableCell);
    }

    [Fact(DisplayName = "Resolve sets list-item display for li")]
    public void Resolve_Li_SetsListItemDisplay()
    {
        var root = HtmlTokenizer.Parse("<ul><li>Item</li></ul>");
        StyleResolver.Resolve(root, []);

        var li = FindFirstByTag(root, "li");
        li!.ComputedStyle!.Display.Should().Be(DisplayType.ListItem);
    }

    // ── Heading size hierarchy ──────────────────────────────────────────

    [Fact(DisplayName = "Headings h1 > h2 > h3 in font size")]
    public void Resolve_Headings_SizeHierarchy()
    {
        var root = HtmlTokenizer.Parse("<h1>H1</h1><h2>H2</h2><h3>H3</h3>");
        StyleResolver.Resolve(root, []);

        var h1 = FindFirstByTag(root, "h1")!.ComputedStyle!.FontSize;
        var h2 = FindFirstByTag(root, "h2")!.ComputedStyle!.FontSize;
        var h3 = FindFirstByTag(root, "h3")!.ComputedStyle!.FontSize;

        h1.Should().BeGreaterThan(h2);
        h2.Should().BeGreaterThan(h3);
    }

    // ── Helpers ──────────────────────────────────────────────────────────

    private static HtmlNode? FindFirstByTag(HtmlNode root, string tag)
    {
        if (root.Tag == tag)
        {
            return root;
        }

        foreach (var child in root.Children)
        {
            var found = FindFirstByTag(child, tag);
            if (found is not null)
            {
                return found;
            }
        }

        return null;
    }
}
