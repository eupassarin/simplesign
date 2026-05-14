using FluentAssertions;
using SimpleSign.HtmlToPdf.Parsing;
using Xunit;

namespace SimpleSign.HtmlToPdf.Tests;

public class HtmlTokenizerTests
{
    // ── Basic parsing ───────────────────────────────────────────────────

    [Fact(DisplayName = "Parse empty string returns root node")]
    public void Parse_EmptyString_ReturnsRootNode()
    {
        var root = HtmlTokenizer.Parse("");

        root.Should().NotBeNull();
        root.Tag.Should().Be("html");
    }

    [Fact(DisplayName = "Parse single element")]
    public void Parse_SingleElement_ReturnsCorrectStructure()
    {
        var root = HtmlTokenizer.Parse("<p>Hello</p>");

        var body = root.Children.FirstOrDefault(c => c.Tag == "body")
            ?? root.Children.FirstOrDefault(c => c.Tag == "p")
            ?? root;
        var p = body.Tag == "p" ? body : body.Children.FirstOrDefault(c => c.Tag == "p");
        p.Should().NotBeNull();
        p!.Tag.Should().Be("p");
        p.Children.Should().ContainSingle();
        p.Children[0].NodeType.Should().Be(HtmlNodeType.Text);
        p.Children[0].Text.Should().Contain("Hello");
    }

    [Fact(DisplayName = "Parse nested elements")]
    public void Parse_NestedElements_ReturnsNestedStructure()
    {
        var root = HtmlTokenizer.Parse("<div><p>Text</p></div>");
        var div = FindFirstByTag(root, "div");

        div.Should().NotBeNull();
        var p = div!.Children.FirstOrDefault(c => c.Tag == "p");
        p.Should().NotBeNull();
        p!.Children.Should().ContainSingle();
    }

    [Fact(DisplayName = "Parse attributes")]
    public void Parse_Attributes_ExtractsCorrectly()
    {
        var root = HtmlTokenizer.Parse("<div id=\"main\" class=\"container\">X</div>");
        var div = FindFirstByTag(root, "div");

        div.Should().NotBeNull();
        div!.Attributes["id"].Should().Be("main");
        div.Attributes["class"].Should().Be("container");
    }

    // ── Self-closing and void elements ──────────────────────────────────

    [Fact(DisplayName = "Parse void elements (br, hr, img)")]
    public void Parse_VoidElements_DoNotRequireClosingTag()
    {
        var root = HtmlTokenizer.Parse("<p>Line1<br>Line2</p>");
        var p = FindFirstByTag(root, "p");

        p.Should().NotBeNull();
        var br = p!.Children.FirstOrDefault(c => c.Tag == "br");
        br.Should().NotBeNull();
    }

    [Fact(DisplayName = "Parse hr element")]
    public void Parse_HrElement_IsRecognized()
    {
        var root = HtmlTokenizer.Parse("<div><hr></div>");
        var hr = FindFirstByTag(root, "hr");

        hr.Should().NotBeNull();
        hr!.IsVoid.Should().BeTrue();
    }

    // ── Entity decoding ─────────────────────────────────────────────────

    [Fact(DisplayName = "Parse HTML entities")]
    public void Parse_HtmlEntities_DecodesCorrectly()
    {
        var root = HtmlTokenizer.Parse("<p>A &amp; B &lt; C &gt; D &quot;E&quot;</p>");
        var p = FindFirstByTag(root, "p");

        p.Should().NotBeNull();
        var text = p!.Children.First(c => c.NodeType == HtmlNodeType.Text).Text;
        text.Should().Contain("A & B");
        text.Should().Contain("< C");
        text.Should().Contain("> D");
    }

    // ── Auto-closing ────────────────────────────────────────────────────

    [Fact(DisplayName = "Parse auto-closes <p> when new block starts")]
    public void Parse_AutoCloseP_WhenNewBlockStarts()
    {
        var root = HtmlTokenizer.Parse("<p>First<p>Second");
        var paragraphs = FindAllByTag(root, "p");

        paragraphs.Should().HaveCountGreaterThanOrEqualTo(2);
    }

    // ── Complex documents ───────────────────────────────────────────────

    [Fact(DisplayName = "Parse full HTML document with head and body")]
    public void Parse_FullDocument_ExtractsBodyContent()
    {
        var root = HtmlTokenizer.Parse(
            "<html><head><title>Test</title></head><body><h1>Title</h1></body></html>");

        var h1 = FindFirstByTag(root, "h1");
        h1.Should().NotBeNull();
    }

    [Fact(DisplayName = "Parse table structure")]
    public void Parse_Table_PreservesStructure()
    {
        var root = HtmlTokenizer.Parse(
            "<table><tr><td>A</td><td>B</td></tr><tr><td>C</td><td>D</td></tr></table>");

        var table = FindFirstByTag(root, "table");
        table.Should().NotBeNull();
        var rows = FindAllByTag(table!, "tr");
        rows.Should().HaveCount(2);
        var cells = FindAllByTag(table!, "td");
        cells.Should().HaveCount(4);
    }

    [Fact(DisplayName = "Parse unordered list")]
    public void Parse_UnorderedList_PreservesItems()
    {
        var root = HtmlTokenizer.Parse("<ul><li>A</li><li>B</li><li>C</li></ul>");

        var items = FindAllByTag(root, "li");
        items.Should().HaveCount(3);
    }

    [Fact(DisplayName = "Parse ordered list")]
    public void Parse_OrderedList_PreservesItems()
    {
        var root = HtmlTokenizer.Parse("<ol><li>First</li><li>Second</li></ol>");

        var items = FindAllByTag(root, "li");
        items.Should().HaveCount(2);
    }

    // ── Style element ───────────────────────────────────────────────────

    [Fact(DisplayName = "Parse style element preserves CSS content")]
    public void Parse_StyleElement_PreservesCssContent()
    {
        var root = HtmlTokenizer.Parse(
            "<html><head><style>body { color: red; }</style></head><body>X</body></html>");

        var style = FindFirstByTag(root, "style");
        style.Should().NotBeNull();
        var text = style!.Children.FirstOrDefault(c => c.NodeType == HtmlNodeType.Text);
        text.Should().NotBeNull();
        text!.Text.Should().Contain("color: red");
    }

    // ── Inline formatting ───────────────────────────────────────────────

    [Fact(DisplayName = "Parse strong/em/b/i inline elements")]
    public void Parse_InlineFormatting_RecognizesElements()
    {
        var root = HtmlTokenizer.Parse("<p><strong>Bold</strong> and <em>italic</em></p>");

        var strong = FindFirstByTag(root, "strong");
        strong.Should().NotBeNull();
        var em = FindFirstByTag(root, "em");
        em.Should().NotBeNull();
    }

    [Fact(DisplayName = "Parse headings h1-h6")]
    public void Parse_Headings_AllLevels()
    {
        var root = HtmlTokenizer.Parse(
            "<h1>H1</h1><h2>H2</h2><h3>H3</h3><h4>H4</h4><h5>H5</h5><h6>H6</h6>");

        for (int i = 1; i <= 6; i++)
        {
            FindFirstByTag(root, $"h{i}").Should().NotBeNull($"h{i} should be parsed");
        }
    }

    // ── Node properties ─────────────────────────────────────────────────

    [Fact(DisplayName = "HtmlNode.IsBlock identifies block elements")]
    public void HtmlNode_IsBlock_IdentifiesBlockElements()
    {
        var div = HtmlNode.CreateElement("div");
        var p = HtmlNode.CreateElement("p");
        var span = HtmlNode.CreateElement("span");

        div.IsBlock.Should().BeTrue();
        p.IsBlock.Should().BeTrue();
        span.IsBlock.Should().BeFalse();
    }

    [Fact(DisplayName = "HtmlNode.IsVoid identifies void elements")]
    public void HtmlNode_IsVoid_IdentifiesVoidElements()
    {
        var br = HtmlNode.CreateElement("br");
        var hr = HtmlNode.CreateElement("hr");
        var p = HtmlNode.CreateElement("p");

        br.IsVoid.Should().BeTrue();
        hr.IsVoid.Should().BeTrue();
        p.IsVoid.Should().BeFalse();
    }

    [Fact(DisplayName = "HtmlNode.IsTableElement identifies table elements")]
    public void HtmlNode_IsTableElement_IdentifiesTableElements()
    {
        var table = HtmlNode.CreateElement("table");
        var tr = HtmlNode.CreateElement("tr");
        var td = HtmlNode.CreateElement("td");
        var div = HtmlNode.CreateElement("div");

        table.IsTableElement.Should().BeTrue();
        tr.IsTableElement.Should().BeTrue();
        td.IsTableElement.Should().BeTrue();
        div.IsTableElement.Should().BeFalse();
    }

    [Fact(DisplayName = "HtmlNode factory methods set parent correctly")]
    public void HtmlNode_FactoryMethods_SetParentCorrectly()
    {
        var parent = HtmlNode.CreateElement("div");
        var child = HtmlNode.CreateElement("p", parent);

        child.Parent.Should().Be(parent);
        // CreateElement with parent sets Parent but doesn't auto-append;
        // use AppendChild for bidirectional linking
        parent.AppendChild(child);
        parent.Children.Should().Contain(child);
    }

    [Fact(DisplayName = "HtmlNode.CreateText creates text node")]
    public void HtmlNode_CreateText_CreatesTextNode()
    {
        var text = HtmlNode.CreateText("Hello World");

        text.NodeType.Should().Be(HtmlNodeType.Text);
        text.Text.Should().Be("Hello World");
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

    private static List<HtmlNode> FindAllByTag(HtmlNode root, string tag)
    {
        var results = new List<HtmlNode>();
        CollectByTag(root, tag, results);
        return results;
    }

    private static void CollectByTag(HtmlNode node, string tag, List<HtmlNode> results)
    {
        if (node.Tag == tag)
        {
            results.Add(node);
        }

        foreach (var child in node.Children)
        {
            CollectByTag(child, tag, results);
        }
    }
}
