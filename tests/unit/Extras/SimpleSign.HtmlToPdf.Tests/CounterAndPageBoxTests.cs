// Licensed to SimpleSign under the MIT License.

using Shouldly;
using SimpleSign.HtmlToPdf.Layout;
using SimpleSign.HtmlToPdf.Parsing;
using Xunit;
using static SimpleSign.HtmlToPdf.Tests.TestSupport;

namespace SimpleSign.HtmlToPdf.Tests;

[Trait("Category", "Unit")]
public sealed class CounterAndPageBoxTests
{
    private static List<string> PseudoTexts(HtmlNode root) =>
        [.. Descendants(root).Where(n => n.IsPseudo).Select(n => string.Concat(n.Children.Select(c => c.Text)))];

    private static IEnumerable<HtmlNode> Descendants(HtmlNode node)
    {
        foreach (HtmlNode child in node.Children)
        {
            yield return child;
            foreach (HtmlNode d in Descendants(child))
            {
                yield return d;
            }
        }
    }

    // ── Counters ─────────────────────────────────────────────────────────

    [Fact]
    public void Counter_IncrementOnElement_NumbersHeadings()
    {
        HtmlNode root = Resolve("<h2>A</h2><h2>B</h2><h2>C</h2>",
            "body { counter-reset: sec; } h2 { counter-increment: sec; } h2::before { content: counter(sec) '. '; }");

        PseudoTexts(root).ShouldBe(["1. ", "2. ", "3. "]);
    }

    [Fact]
    public void Counter_IncrementOnPseudo_AppliesBeforeContent()
    {
        HtmlNode root = Resolve("<p>a</p><p>b</p>", "p::before { counter-increment: n; content: '#' counter(n); }");

        PseudoTexts(root).ShouldBe(["#1", "#2"]);
    }

    [Fact]
    public void Counter_NestedSections_Counters()
    {
        const string css = """
            ol { counter-reset: item; list-style: none; }
            li { counter-increment: item; }
            li::before { content: counters(item, ".") " "; }
            """;
        HtmlNode root = Resolve("<ol><li>a<ol><li>a1</li><li>a2</li></ol></li><li>b</li></ol>", css);

        PseudoTexts(root).ShouldBe(["1 ", "1.1 ", "1.2 ", "2 "]);
    }

    [Fact]
    public void Counter_HeadingHierarchy_ResetsSubCounter()
    {
        const string css = """
            body { counter-reset: h2; }
            h2 { counter-increment: h2; counter-reset: h3; }
            h3 { counter-increment: h3; }
            h3::before { content: counter(h2) "." counter(h3) " "; }
            """;
        HtmlNode root = Resolve("<h2>A</h2><h3>x</h3><h3>y</h3><h2>B</h2><h3>z</h3>", css);

        PseudoTexts(root).ShouldBe(["1.1 ", "1.2 ", "2.1 "]);
    }

    [Theory]
    [InlineData("upper-roman", "IV")]
    [InlineData("lower-alpha", "d")]
    [InlineData("decimal-leading-zero", "04")]
    [InlineData("lower-greek", "δ")]
    public void Counter_Styles(string style, string expected)
    {
        HtmlNode root = Resolve("<p>x</p>", $"p {{ counter-reset: n 3; counter-increment: n; }} p::before {{ content: counter(n, {style}); }}");

        PseudoTexts(root).ShouldBe([expected]);
    }

    [Fact]
    public void Counter_ResetValueAndIncrementStep()
    {
        HtmlNode root = Resolve("<div><p>a</p><p>b</p></div>", "div { counter-reset: n 10; } p { counter-increment: n -2; } p::after { content: counter(n); }");

        PseudoTexts(root).ShouldBe(["8", "6"]);
    }

    [Fact]
    public void Counter_Set_OverridesValue()
    {
        HtmlNode root = Resolve("<p>a</p><p class='j'>b</p><p>c</p>", "p { counter-increment: n; } .j { counter-set: n 10; } p::after { content: counter(n); }");

        PseudoTexts(root).ShouldBe(["1", "11", "12"]);
    }

    [Fact]
    public void Counter_DisplayNone_DoesNotCount()
    {
        HtmlNode root = Resolve("<p>a</p><p style='display:none'>b</p><p>c</p>", "p { counter-increment: n; } p::after { content: counter(n); }");

        PseudoTexts(root).ShouldBe(["1", "2"]);
    }

    [Fact]
    public void Counter_ScopeEndsWithParent()
    {
        HtmlNode root = Resolve("<div><p>a</p></div><span>after</span>",
            "p { counter-reset: inner 5; } span::after { content: counter(inner); }");

        PseudoTexts(root).ShouldBe(["0"]);
    }

    [Fact]
    public void Counter_AfterSeesDescendantIncrements()
    {
        HtmlNode root = Resolve("<div><p>a</p><p>b</p></div>", "div { counter-reset: n; } p { counter-increment: n; } div::after { content: 'total ' counter(n); }");

        PseudoTexts(root).ShouldBe(["total 2"]);
    }

    [Fact]
    public void Counter_ImplicitListItem()
    {
        HtmlNode root = Resolve("<ol start='5'><li>a</li><li>b</li></ol>", "li::before { content: counter(list-item) ') '; }");

        PseudoTexts(root).ShouldBe(["5) ", "6) "]);
    }

    [Fact]
    public void Counter_RendersInPdf()
    {
        byte[] pdf = HtmlToPdfConverter.Html("<h2>Intro</h2><h2>Body</h2>")
            .WithStylesheet("h2 { counter-increment: c; } h2::before { content: 'Chapter ' counter(c, upper-roman) ': '; }")
            .Convert();

        string text = Decompressed(pdf);
        text.ShouldContain("(Chapter I:)");
        text.ShouldContain("(Chapter II:)");
    }

    [Fact]
    public void Counter_EmptyArguments_AreIgnored()
    {
        HtmlNode root = Resolve("<p>x</p>", "p::before { content: 'a' counter() counters() 'b'; }");

        PseudoTexts(root).ShouldBe(["ab"]);
    }

    [Theory]
    [InlineData("none", 0)]
    [InlineData("a", 1)]
    [InlineData("a 2 b", 2)]
    [InlineData("a -3", 1)]
    public void ParsePairs_Counts(string value, int expected) =>
        CssCounters.ParsePairs(value, 1).Count.ShouldBe(expected);

    // ── Page margin boxes ────────────────────────────────────────────────

    [Fact]
    public void Parser_PageMarginBoxes_BecomeRules()
    {
        List<CssRule> rules = CssParser.ParseStylesheet("@page { margin: 2cm; @bottom-center { content: counter(page); font-size: 8pt; } } @page :first { @top-right { content: 'first'; } }");

        rules.Select(r => r.Selector).ShouldBe(["@page", "@page @bottom-center", "@page :first", "@page :first @top-right"]);
        rules[1].Properties["font-size"].ShouldBe("8pt");
        rules[0].Properties.ShouldContainKey("margin-top");
    }

    [Fact]
    public void MarginBox_EvaluatesPageCounters()
    {
        var box = new PageMarginBox("bottom-center", string.Empty, "'Page ' counter(page) ' of ' counter(pages, upper-roman)", new ComputedStyle(), 0);

        box.Evaluate(3, 4).ShouldBe("Page 3 of IV");
    }

    [Fact]
    public void MarginBox_FirstPageOverridesDefault()
    {
        var boxes = new List<PageMarginBox>
        {
            new("top-center", ":first", "none", new ComputedStyle(), 2),
            new("top-center", string.Empty, "'Header'", new ComputedStyle(), 1),
        };

        PageMarginBox.ForPage(boxes, 1).Single().Evaluate(1, 2).ShouldBeNull();
        PageMarginBox.ForPage(boxes, 2).Single().Evaluate(2, 2).ShouldBe("Header");
    }

    [Theory]
    [InlineData(":left", 2, true)]
    [InlineData(":left", 3, false)]
    [InlineData(":right", 3, true)]
    [InlineData(":blank", 1, false)]
    public void MarginBox_PageSelectors(string selector, int page, bool matches) =>
        new PageMarginBox("top-left", selector, "'x'", new ComputedStyle(), 0).Matches(page).ShouldBe(matches);

    [Fact]
    public void Render_MarginBoxes_DrawOnEveryPage()
    {
        string body = string.Concat(Enumerable.Repeat("<p style='page-break-after:always'>x</p>", 2)) + "<p>end</p>";
        byte[] pdf = HtmlToPdfConverter.Html(body)
            .WithStylesheet("@page { @bottom-right { content: 'Página ' counter(page) ' de ' counter(pages); color: #555; } @top-left { content: 'Relatório'; } }")
            .Convert();

        string text = Decompressed(pdf);
        text.ShouldContain("gina 1 de 3)");
        text.ShouldContain("gina 3 de 3)");
        text.Split("rio) Tj").Length.ShouldBe(4);
    }

    [Fact]
    public void BreakAfterLastElement_DoesNotAddBlankPage() =>
        LayoutHtml("<p style='page-break-after:always'>a</p><p style='page-break-after:always'>b</p>").Pages.Count.ShouldBe(2);

    [Fact]
    public void Render_MarginBox_UsesStyleAndAlignment()
    {
        LayoutResult result = LayoutHtml("<p>x</p>");
        result.ShouldNotBeNull();

        byte[] pdf = HtmlToPdfConverter.Html("<p>x</p>")
            .WithStylesheet("@page { @bottom-center { content: 'centered'; font-size: 20pt; font-weight: bold; } }")
            .Convert();

        Decompressed(pdf).ShouldContain("/Helvetica-Bold");
        Decompressed(pdf).ShouldContain("20.00 Tf");
    }
}
