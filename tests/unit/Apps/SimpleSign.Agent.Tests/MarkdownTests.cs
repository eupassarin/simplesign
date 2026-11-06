using Shouldly;
using SimpleSign.Agent.Docs;

namespace SimpleSign.Agent.Tests;

[Trait("Category", "Unit")]
public sealed class MarkdownTests
{
    [Fact]
    public void Parse_HeadingsParagraphsAndNotes()
    {
        var blocks = Markdown.Parse("# Title\n\nFirst line\nsecond line.\n\n## Part\n\n> A note\n> in two lines.");

        blocks.Count.ShouldBe(4);
        blocks[0].ShouldBeOfType<MdHeading>().Level.ShouldBe(1);
        blocks[1].ShouldBeOfType<MdParagraph>().Inlines.Single().Text.ShouldBe("First line second line.");
        blocks[2].ShouldBeOfType<MdHeading>().Level.ShouldBe(2);
        blocks[3].ShouldBeOfType<MdNote>().Inlines.Single().Text.ShouldBe("A note in two lines.");
    }

    [Fact]
    public void Parse_FencedCode_KeepsTheTextAsItIs()
    {
        var code = Markdown.Parse("```js\nconst a = `x`;\n  // **not bold**\n```\nAfter").First().ShouldBeOfType<MdCode>();

        code.Language.ShouldBe("js");
        code.Text.ShouldBe("const a = `x`;\n  // **not bold**");
    }

    [Fact]
    public void Parse_Lists_BulletsNumbersAndWrappedItems()
    {
        var blocks = Markdown.Parse("- one\n- two\n  continues\n\n1. first\n2. second");

        var bullets = blocks[0].ShouldBeOfType<MdList>();
        bullets.Ordered.ShouldBeFalse();
        bullets.Items.Count.ShouldBe(2);
        string.Concat(bullets.Items[1].Select(i => i.Text)).ShouldBe("two continues");
        var numbers = blocks[1].ShouldBeOfType<MdList>();
        numbers.Ordered.ShouldBeTrue();
        numbers.Items.Count.ShouldBe(2);
    }

    [Fact]
    public void Parse_Table_SkipsTheSeparatorRow()
    {
        var table = Markdown.Parse("| Call | What |\n| --- | --- |\n| `GET /a` | A \\| B |\n| `GET /b` | C |").Single().ShouldBeOfType<MdTable>();

        table.Header.Select(c => c.Single().Text).ShouldBe(["Call", "What"]);
        table.Rows.Count.ShouldBe(2);
        table.Rows[0][0].Single().Style.ShouldBe(MdStyle.Code);
        table.Rows[0][1].Single().Text.ShouldBe("A | B");
    }

    [Fact]
    public void Inlines_CodeBoldItalicAndLinks()
    {
        var inlines = Markdown.Inlines("Call `fetch` on **this** *computer*, see [Security](#security).");

        inlines.Select(i => i.Style).ShouldBe([MdStyle.Text, MdStyle.Code, MdStyle.Text, MdStyle.Bold, MdStyle.Text, MdStyle.Italic, MdStyle.Text, MdStyle.Link, MdStyle.Text]);
        inlines[1].Text.ShouldBe("fetch");
        inlines[7].Text.ShouldBe("Security");
        inlines[7].Url.ShouldBe("#security");
    }

    [Fact]
    public void Inlines_UnclosedMarkers_StayAsText() =>
        string.Concat(Markdown.Inlines("2 * 3 and a ` alone").Select(i => i.Text)).ShouldBe("2 * 3 and a ` alone");
}
