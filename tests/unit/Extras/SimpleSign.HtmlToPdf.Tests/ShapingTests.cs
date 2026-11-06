// Licensed to SimpleSign under the MIT License.

using System.Text;
using Shouldly;
using SimpleSign.HtmlToPdf.Fonts;
using SimpleSign.HtmlToPdf.Fonts.OpenType;
using Xunit;
using static SimpleSign.HtmlToPdf.Tests.TestSupport;

namespace SimpleSign.HtmlToPdf.Tests;

[Trait("Category", "Unit")]
public sealed class ShapingTests
{
    private static readonly EmbeddedFont Arabic = new("TestArabic", LoadFont("TestArabic"));
    private static readonly EmbeddedFont Devanagari = new("TestDevanagari", LoadFont("TestDevanagari"));
    private static readonly EmbeddedFont Kerning = new("TestKerning", LoadFont("TestKerning"));

    private static ushort Cmap(EmbeddedFont font, char c) => font.GetGlyphId(new Rune(c));

    private static List<PositionedGlyph> Shape(EmbeddedFont font, string text, bool rtl = false) => font.Shaper.Shape(text, rtl).Glyphs;

    // ── Script detection ─────────────────────────────────────────────────

    [Theory]
    [InlineData("hello", "Default")]
    [InlineData("שלום", "Default")]
    [InlineData("سلام", "Arabic")]
    [InlineData("abc نص", "Arabic")]
    [InlineData("नमस्ते", "Devanagari")]
    public void DetectScript(string text, string expected) =>
        TextShaper.DetectScript(text).ShouldBe(Enum.Parse<ShapingScript>(expected));

    // ── Arabic ───────────────────────────────────────────────────────────

    [Fact]
    public void Arabic_JoiningFormsReplaceNominalGlyphs()
    {
        List<PositionedGlyph> glyphs = Shape(Arabic, "سلام");

        glyphs.Count.ShouldBe(4);
        glyphs[0].Glyph.ShouldNotBe(Cmap(Arabic, 'س'));   // initial form
        glyphs[1].Glyph.ShouldNotBe(Cmap(Arabic, 'ل'));   // medial form
        glyphs[2].Glyph.ShouldNotBe(Cmap(Arabic, 'ا'));   // final form

        // Alef does not join to the left, so the meem after it stays isolated.
        glyphs[3].Glyph.ShouldBe(Cmap(Arabic, 'م'));
    }

    [Fact]
    public void Arabic_IsolatedLetterKeepsNominalGlyph() =>
        Shape(Arabic, "م").Single().Glyph.ShouldBe(Cmap(Arabic, 'م'));

    [Fact]
    public void Arabic_RightJoiningLetterBreaksTheJoin()
    {
        // Alef (right-joining) does not connect to the following letter, so "ب" after it is initial-or-isolated, not medial.
        List<PositionedGlyph> joined = Shape(Arabic, "بب");
        List<PositionedGlyph> broken = Shape(Arabic, "ابب");

        broken[1].Glyph.ShouldBe(joined[0].Glyph);
    }

    [Fact]
    public void Arabic_LamAlef_UsesRequiredForms()
    {
        // Naskh draws lam-alef with two contextual glyphs (rlig) rather than one ligature.
        List<PositionedGlyph> glyphs = Shape(Arabic, "لا");

        glyphs.Count.ShouldBe(2);
        glyphs[0].Glyph.ShouldNotBe(Cmap(Arabic, 'ل'));
        glyphs[1].Glyph.ShouldNotBe(Cmap(Arabic, 'ا'));
    }

    [Fact]
    public void Arabic_ShaddaOrderedBeforeFatha()
    {
        // Both orders of the same marks shape identically (marks are normalized first).
        List<ushort> a = [.. Shape(Arabic, "مَّ").Select(g => g.Glyph)];
        List<ushort> b = [.. Shape(Arabic, "مَّ".Normalize(NormalizationForm.FormD)).Select(g => g.Glyph)];

        a.ShouldBe(b);
    }

    [Fact]
    public void Arabic_RightToLeftReversesGlyphOrder()
    {
        List<ushort> ltr = [.. Shape(Arabic, "مرحبا").Select(g => g.Glyph)];
        List<ushort> rtl = [.. Shape(Arabic, "مرحبا", rtl: true).Select(g => g.Glyph)];

        rtl.ShouldBe(Enumerable.Reverse(ltr));
    }

    [Fact]
    public void Arabic_RightToLeftPositionsDecreaseInLogicalOrder()
    {
        List<PositionedGlyph> rtl = Shape(Arabic, "سلام", rtl: true);

        // Visual order: the last logical letter is drawn leftmost.
        rtl[0].Text.ShouldBe("م");
        rtl.Select(g => g.X).ShouldBeInOrder();
    }

    [Fact]
    public void Arabic_MarkHasNoAdvanceAndIsAnchored()
    {
        ShapedRun withMark = Arabic.Shaper.Shape("بَ", false);
        ShapedRun bare = Arabic.Shaper.Shape("ب", false);

        withMark.Advance.ShouldBe(bare.Advance);
        PositionedGlyph mark = withMark.Glyphs.Single(g => g.Text == "\u064E");
        mark.Y.ShouldNotBe(0);
    }

    // ── Devanagari ───────────────────────────────────────────────────────

    [Fact]
    public void Devanagari_PreBaseMatraIsDrawnFirst() =>
        Shape(Devanagari, "कि")[0].Text.ShouldBe("ि");

    [Fact]
    public void Devanagari_RephMovesAfterBase()
    {
        List<PositionedGlyph> glyphs = Shape(Devanagari, "कर्म");

        glyphs[^1].Text.ShouldBe("र्");
        glyphs.Select(g => g.Text).ShouldContain("म");
    }

    [Fact]
    public void Devanagari_KssaConjunctIsOneGlyph() =>
        Shape(Devanagari, "क्ष").Count.ShouldBe(1);

    [Fact]
    public void Devanagari_HalfFormsReduceGlyphCount()
    {
        List<PositionedGlyph> glyphs = Shape(Devanagari, "स्त्री");

        glyphs.Count.ShouldBeLessThan("स्त्री".Length);
        string.Concat(glyphs.Select(g => g.Text)).Length.ShouldBe("स्त्री".Length);
    }

    [Fact]
    public void Devanagari_ZwnjKeepsExplicitVirama() =>
        Shape(Devanagari, "क्\u200Cष").Count.ShouldBeGreaterThan(Shape(Devanagari, "क्ष").Count);

    [Fact]
    public void Devanagari_PreBaseMatraBeforeConjunct() =>
        // In "क्ति" the i-matra precedes the whole क्त cluster.
        Shape(Devanagari, "क्ति")[0].Text.ShouldBe("ि");

    // ── Latin ────────────────────────────────────────────────────────────

    [Fact]
    public void Kerning_TightensAV()
    {
        ShapedRun pair = Kerning.Shaper.Shape("AV", false);
        int plain = Kerning.AdvanceOf(Cmap(Kerning, 'A')) + Kerning.AdvanceOf(Cmap(Kerning, 'V'));

        pair.Advance.ShouldBeLessThan(plain);
    }

    [Fact]
    public void Ligature_ffiIsOneGlyph()
    {
        List<PositionedGlyph> glyphs = Shape(Kerning, "office");

        glyphs.Count.ShouldBeLessThan(6);
        glyphs.ShouldContain(g => g.Text == "ffi" || g.Text == "ff" || g.Text == "fi");
    }

    [Fact]
    public void Measure_UsesShapedWidth()
    {
        var font = new ResolvedFont(Kerning, string.Empty, false, false);
        float shaped = TextMeasurer.MeasureResolved("AV", font, null, 12, 0, 0);
        float unshaped = TextMeasurer.MeasureResolved("AV", font, null, 12, 0.001f, 0) - 0.001f;

        shaped.ShouldBeLessThan(unshaped);
    }

    [Fact]
    public void LetterSpacing_DisablesShapingForLatin() =>
        TextMeasurer.UsesShaping(new ResolvedFont(Kerning, string.Empty, false, false), "office", 1).ShouldBeFalse();

    [Fact]
    public void ComplexScripts_AlwaysShaped() =>
        TextMeasurer.UsesShaping(new ResolvedFont(Arabic, string.Empty, false, false), "سلام", 1).ShouldBeTrue();

    [Fact]
    public void FontWithoutLayoutTables_IsNotShaped() =>
        TextMeasurer.UsesShaping(new ResolvedFont(new EmbeddedFont("Plain", LoadTestFont()), string.Empty, false, false), "office", 0)
            .ShouldBe(new EmbeddedFont("Plain", LoadTestFont()).Shaper.HasLayout);

    // ── PDF output ───────────────────────────────────────────────────────

    [Fact]
    public void Pdf_LigatureMapsBackToTextInToUnicode()
    {
        byte[] pdf = HtmlToPdfConverter.Html("<p>office</p>")
            .WithFont("Test Kerning", LoadFont("TestKerning"))
            .WithStylesheet("p { font-family: 'Test Kerning'; }")
            .Convert();

        string text = Decompressed(pdf);
        text.ShouldContain("] TJ");
        text.ShouldMatch("<[0-9A-F]{4}> <(006600660069|00660066|00660069)>");
    }

    [Fact]
    public void Pdf_KerningEmitsTjAdjustment() =>
        Decompressed(HtmlToPdfConverter.Html("<p>AVATAR</p>")
            .WithFont("Test Kerning", LoadFont("TestKerning"))
            .WithStylesheet("p { font-family: 'Test Kerning'; }")
            .Convert()).ShouldMatch(@"\[<[0-9A-F]{4}>\d+(\.\d+)? <");

    [Fact]
    public void Pdf_ArabicMarkUsesTextRise() =>
        Decompressed(HtmlToPdfConverter.Html("<p>بَ</p>")
            .WithFont("Test Arabic", LoadFont("TestArabic"))
            .WithStylesheet("p { font-family: 'Test Arabic'; }")
            .Convert()).ShouldContain(" Ts\n");

    [Fact]
    public void Pdf_ShapedTextIsPdfACompatible() =>
        Should.NotThrow(() => HtmlToPdfConverter.Html("<p dir='rtl'>مرحبا بالعالم</p><p>हिन्दी भाषा</p>")
            .WithFont("Test Arabic", LoadFont("TestArabic"))
            .WithFont("Test Devanagari", LoadFont("TestDevanagari"))
            .WithStylesheet("p { font-family: 'Test Arabic', 'Test Devanagari'; }")
            .WithPdfA()
            .Convert());
}
