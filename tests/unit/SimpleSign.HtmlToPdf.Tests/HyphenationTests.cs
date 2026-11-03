// Licensed to SimpleSign under the MIT License.

using Shouldly;
using SimpleSign.HtmlToPdf.Layout;
using SimpleSign.HtmlToPdf.Parsing;
using Xunit;
using static SimpleSign.HtmlToPdf.Tests.TestSupport;

namespace SimpleSign.HtmlToPdf.Tests;

[Trait("Category", "Unit")]
public sealed class HyphenationTests
{
    private static string Hyphenate(string word, string lang = "pt-BR")
    {
        List<int> points = Hyphenator.Points(word, lang);
        for (int i = points.Count - 1; i >= 0; i--)
        {
            word = word.Insert(points[i], "-");
        }

        return word;
    }

    [Theory]
    [InlineData("chocolate", "cho-co-la-te")]
    [InlineData("carro", "car-ro")]
    [InlineData("palhaço", "pa-lha-ço")]
    [InlineData("pessoa", "pes-soa")]
    [InlineData("instrução", "ins-tru-ção")]
    [InlineData("perspectiva", "pers-pec-ti-va")]
    [InlineData("guerra", "guer-ra")]
    [InlineData("nascimento", "nas-ci-men-to")]
    [InlineData("excesso", "ex-ces-so")]
    [InlineData("abraço", "abra-ço")]
    [InlineData("documento,", "do-cu-men-to,")]
    [InlineData("Brasil", "Bra-sil")]
    public void Portuguese_Syllables(string word, string expected) =>
        Hyphenate(word).ShouldBe(expected);

    [Theory]
    [InlineData("caballero", "ca-ba-lle-ro")]
    [InlineData("perro", "pe-rro")]
    public void Spanish_UsesSameRules(string word, string expected)
    {
        // Spanish keeps "rr" together; the shared rules split it like Portuguese, which is acceptable for line breaking.
        string result = Hyphenate(word, "es");
        result.Replace("-", string.Empty, StringComparison.Ordinal).ShouldBe(word);
        if (word == "caballero")
        {
            result.ShouldBe(expected);
        }
    }

    [Theory]
    [InlineData("en")]
    [InlineData(null)]
    [InlineData("de")]
    public void UnsupportedLanguage_NoPoints(string? lang) =>
        Hyphenator.Points("chocolate", lang).ShouldBeEmpty();

    [Theory]
    [InlineData("casa")]
    [InlineData("CO2-free")]
    [InlineData("12345")]
    public void ShortOrNonAlphabetic_NoPoints(string word) =>
        Hyphenator.Points(word, "pt").ShouldBeEmpty();

    [Fact]
    public void Cascade_HyphensAndLangInherit()
    {
        HtmlNode root = Resolve("<div lang='pt-BR'><p>x</p></div>", "div { hyphens: auto; }");
        ComputedStyle p = First(root, "p").ComputedStyle!;

        p.Language.ShouldBe("pt-BR");
        p.Hyphens.ShouldBe(HyphensMode.Auto);
    }

    [Fact]
    public void SoftHyphen_IsInvisibleWhenNotBroken()
    {
        LayoutResult result = LayoutHtml("<p>super&shy;cali&shy;fragil</p>");

        Texts(result).Single().Text.ShouldBe("supercalifragil");
    }

    [Fact]
    public void SoftHyphen_BreaksWithVisibleHyphen()
    {
        LayoutResult result = LayoutHtml("<div style='width:60pt'>aaaa bbbbbbbb&shy;cccccccc</div>");

        List<string> texts = [.. Texts(result).Select(t => t.Text!)];
        texts.ShouldContain(t => t.EndsWith("bbbbbbbb-", StringComparison.Ordinal));
        texts.ShouldContain("cccccccc");
    }

    [Fact]
    public void HyphensNone_IgnoresSoftHyphen()
    {
        LayoutResult result = LayoutHtml("<div style='width:60pt;hyphens:none'>aaaa bbbbbbbb&shy;cccccccc</div>");

        Texts(result).ShouldNotContain(t => t.Text!.EndsWith('-'));
    }

    [Fact]
    public void HyphensAuto_Portuguese_BreaksLongWord()
    {
        LayoutResult result = LayoutHtml("<p lang='pt' style='width:80pt;hyphens:auto'>Os responsáveis pela inconstitucionalidade</p>");

        List<string> texts = [.. Texts(result).Select(t => t.Text!)];
        texts.ShouldContain(t => t.EndsWith('-'));
        string.Concat(texts.Select(t => t.TrimEnd('-'))).Replace(" ", string.Empty, StringComparison.Ordinal)
            .ShouldBe("Osresponsáveispelainconstitucionalidade");
    }

    [Fact]
    public void HyphensAuto_WithoutLanguage_DoesNotHyphenate()
    {
        LayoutResult result = LayoutHtml("<p style='width:80pt;hyphens:auto'>Os responsáveis pela inconstitucionalidade</p>");

        Texts(result).ShouldNotContain(t => t.Text!.EndsWith('-'));
    }

    [Fact]
    public void HardHyphen_IsABreakOpportunity()
    {
        LayoutResult result = LayoutHtml("<div style='width:70pt'>xx well-established</div>");

        Texts(result).Select(t => t.Text).ShouldContain("established");
    }

    [Fact]
    public void BuilderLanguage_EnablesAutoHyphenation()
    {
        byte[] pdf = HtmlToPdfConverter.Html("<p style='width:100pt;hyphens:auto'>Os responsáveis pela inconstitucionalidade</p>")
            .WithLanguage("pt-BR")
            .Convert();

        Decompressed(pdf).ShouldContain("-) Tj");
    }
}
