using Shouldly;
using SimpleSign.HtmlToPdf.Parsing;
using Xunit;

namespace SimpleSign.HtmlToPdf.Tests;

[Trait("Category", "Unit")]
public class CssParserTests
{
    // ── Stylesheet parsing ──────────────────────────────────────────────

    [Fact(DisplayName = "ParseStylesheet: single rule")]
    public void ParseStylesheet_SingleRule_ParsesCorrectly()
    {
        var rules = CssParser.ParseStylesheet("p { color: red; font-size: 14px; }");

        rules.Count().ShouldBe(1);
        rules[0].Selector.ShouldBe("p");
        rules[0].Properties.ShouldContainKey("color");
        rules[0].Properties["color"].ShouldBe("red");
        rules[0].Properties["font-size"].ShouldBe("14px");
    }

    [Fact(DisplayName = "ParseStylesheet: multiple rules")]
    public void ParseStylesheet_MultipleRules_ParsesAll()
    {
        var rules = CssParser.ParseStylesheet(
            "h1 { font-size: 24px; } p { color: blue; }");

        rules.Count().ShouldBe(2);
        rules[0].Selector.ShouldBe("h1");
        rules[1].Selector.ShouldBe("p");
    }

    [Fact(DisplayName = "ParseStylesheet: class selector")]
    public void ParseStylesheet_ClassSelector_ParsesCorrectly()
    {
        var rules = CssParser.ParseStylesheet(".highlight { background: yellow; }");

        rules.Count().ShouldBe(1);
        rules[0].Selector.ShouldBe(".highlight");
    }

    [Fact(DisplayName = "ParseStylesheet: id selector")]
    public void ParseStylesheet_IdSelector_ParsesCorrectly()
    {
        var rules = CssParser.ParseStylesheet("#main { width: 100%; }");

        rules.Count().ShouldBe(1);
        rules[0].Selector.ShouldBe("#main");
    }

    [Fact(DisplayName = "ParseStylesheet: empty input")]
    public void ParseStylesheet_EmptyString_ReturnsEmpty()
    {
        var rules = CssParser.ParseStylesheet("");

        rules.ShouldBeEmpty();
    }

    [Fact(DisplayName = "ParseStylesheet: grouped selectors")]
    public void ParseStylesheet_GroupedSelectors_ParsesBoth()
    {
        var rules = CssParser.ParseStylesheet("h1, h2 { font-weight: bold; }");

        rules.Count().ShouldBeGreaterThanOrEqualTo(1);
    }

    // ── Inline style parsing ────────────────────────────────────────────

    [Fact(DisplayName = "ParseInlineStyle: single property")]
    public void ParseInlineStyle_SingleProperty_ParsesCorrectly()
    {
        var props = CssParser.ParseInlineStyle("color: red");

        props.ShouldContainKey("color");
        props["color"].ShouldBe("red");
    }

    [Fact(DisplayName = "ParseInlineStyle: multiple properties (shorthand expanded)")]
    public void ParseInlineStyle_MultipleProperties_ParsesAll()
    {
        var props = CssParser.ParseInlineStyle("color: red; font-size: 16px; margin: 10px");

        props.ShouldContainKey("color");
        props.ShouldContainKey("font-size");
        // margin shorthand is expanded to individual properties
        props.ShouldContainKey("margin-top");
    }

    [Fact(DisplayName = "ParseInlineStyle: empty input")]
    public void ParseInlineStyle_EmptyString_ReturnsEmpty()
    {
        var props = CssParser.ParseInlineStyle("");

        props.ShouldBeEmpty();
    }

    // ── Length parsing ──────────────────────────────────────────────────

    [Theory(DisplayName = "ParseLength: various units")]
    [InlineData("12pt", 12f)]
    [InlineData("1in", 72f)]
    [InlineData("2.54cm", 72f)]
    [InlineData("25.4mm", 72f)]
    [InlineData("1em", 12f)]
    public void ParseLength_VariousUnits_ParsesCorrectly(string input, float expected)
    {
        var result = CssParser.ParseLength(input, 12f);

        result.ShouldNotBeNull();
        result!.Value.ShouldBe(expected, 1f);
    }

    [Fact(DisplayName = "ParseLength: px applies 0.75 conversion factor")]
    public void ParseLength_Px_AppliesConversionFactor()
    {
        var result = CssParser.ParseLength("12px", 12f);

        result.ShouldNotBeNull();
        // 12px * 0.75 = 9pt
        result!.Value.ShouldBe(9f, 0.1f);
    }

    [Fact(DisplayName = "ParseLength: invalid input returns null")]
    public void ParseLength_InvalidInput_ReturnsNull()
    {
        var result = CssParser.ParseLength("abc");

        result.ShouldBeNull();
    }

    [Fact(DisplayName = "ParseLength: percentage does not throw")]
    public void ParseLength_Percentage_DoesNotThrow()
    {
        // Percentages need a container width which ParseLength doesn't support
        // The important thing is it doesn't throw
        var act = () => CssParser.ParseLength("50%");

        Should.NotThrow(act);
    }

    // ── Specificity calculation ─────────────────────────────────────────

    [Theory(DisplayName = "CalculateSpecificity: various selectors")]
    [InlineData("p", 1)]
    [InlineData(".class", 10)]
    [InlineData("#id", 100)]
    public void CalculateSpecificity_VariousSelectors_ReturnsCorrectValue(string selector, int expected)
    {
        var specificity = CssParser.CalculateSpecificity(selector);

        specificity.ShouldBe(expected);
    }

    [Fact(DisplayName = "CalculateSpecificity: compound selector")]
    public void CalculateSpecificity_CompoundSelector_SumsCorrectly()
    {
        // div.class = 1 (element) + 10 (class) = 11
        var specificity = CssParser.CalculateSpecificity("div.class");

        specificity.ShouldBe(11);
    }

    [Fact(DisplayName = "CalculateSpecificity: descendant selector")]
    public void CalculateSpecificity_DescendantSelector_SumsCorrectly()
    {
        // div p = 1 + 1 = 2
        var specificity = CssParser.CalculateSpecificity("div p");

        specificity.ShouldBe(2);
    }
}
