// Licensed to SimpleSign under the MIT License.

using Shouldly;
using SimpleSign.HtmlToPdf.Fonts;
using SimpleSign.HtmlToPdf.Fonts.OpenType;
using Xunit;
using static SimpleSign.HtmlToPdf.Tests.TestSupport;

namespace SimpleSign.HtmlToPdf.Tests;

/// <summary>
/// Compares the shaper with reference output produced by HarfBuzz (uharfbuzz) for the same test fonts:
/// glyph ids in visual order with absolute x and y positions in font units.
/// </summary>
[Trait("Category", "Unit")]
public sealed class ShapingReferenceTests
{
    private static readonly Dictionary<string, EmbeddedFont> Fonts = new(StringComparer.Ordinal);

    [Theory]
    [InlineData("TestArabic", "مرحبا بالعالم", "41@0,0 36@528,0 3@740,0 30@993,0 36@1407,0 3@1619,0 84@1942,-31 10@1872,0 1@2147,0 3@2368,0 84@2711,-31 8@2621,0 15@2913,0 19@3549,0 43@3953,0")]
    [InlineData("TestArabic", "مُحَمَّد", "17@0,0 90@581,-64 86@583,-186 42@474,0 90@1087,-172 14@887,0 91@1696,-196 43@1553,0")]
    [InlineData("TestArabic", "العربية", "83@91,-294 47@0,0 85@506,-17 9@452,0 84@882,-31 10@812,0 19@1087,0 30@1491,0 36@1905,0 2@2117,0")]
    [InlineData("TestArabic", "لا الله", "47@0,0 34@452,0 36@697,0 2@909,0 1@1147,0 4@1368,0 37@1668,0")]
    [InlineData("TestDevanagari", "हिन्दी भाषा", "113@0,0 21@259,0 30@790,0 9@1099,0 4@1630,0 1@1889,0 13@2149,0 2@2852,0 19@3111,0 2@3689,0")]
    [InlineData("TestDevanagari", "क्षत्रिय", "22@0,0 114@717,0 43@976,0 15@1528,0")]
    [InlineData("TestDevanagari", "कर्म", "7@0,0 14@768,0 102@1366,0")]
    [InlineData("TestDevanagari", "स्त्री", "39@0,0 43@389,0 4@941,0")]
    [InlineData("TestDevanagari", "प्रेम श्री", "46@0,0 6@569,0 14@569,0 1@1167,0 52@1427,0 4@2135,0")]
    [InlineData("TestDevanagari", "विद्या किताब", "114@0,0 17@259,0 81@815,0 2@1445,0 1@1704,0 114@1964,0 7@2223,0 8@2991,0 2@3561,0 12@3820,0")]
    [InlineData("TestKerning", "AVATAR Wave To", "21@0,0 24@1270,0 21@2540,0 23@3782,0 21@4874,0 22@6275,0 1@7698,0 25@8349,0 26@10243,0 34@11498,0 28@12710,0 1@13970,0 23@14621,0 32@15524,0")]
    [InlineData("TestKerning", "office fluffy", "32@0,0 50@1253,0 27@3233,0 28@4359,0 1@5619,0 49@6270,0 33@7560,0 47@8858,0 35@10269,0")]
    public void Shape_MatchesHarfBuzz(string font, string text, string expected)
    {
        if (!Fonts.TryGetValue(font, out EmbeddedFont? face))
        {
            face = new EmbeddedFont(font, LoadFont(font));
            Fonts[font] = face;
        }

        bool rtl = TextShaper.DetectScript(text) == ShapingScript.Arabic;
        List<PositionedGlyph> glyphs = face.Shaper.Shape(text, rtl).Glyphs;
        string[] reference = expected.Split(' ');

        glyphs.Count.ShouldBe(reference.Length, $"glyphs: {string.Join(' ', glyphs.Select(g => g.Glyph))}");
        for (int i = 0; i < reference.Length; i++)
        {
            string[] parts = reference[i].Split('@', ',');
            glyphs[i].Glyph.ShouldBe(ushort.Parse(parts[0], System.Globalization.CultureInfo.InvariantCulture), $"glyph {i}");
            Math.Abs(glyphs[i].X - int.Parse(parts[1], System.Globalization.CultureInfo.InvariantCulture)).ShouldBeLessThanOrEqualTo(2, $"x of glyph {i}");
            Math.Abs(glyphs[i].Y - int.Parse(parts[2], System.Globalization.CultureInfo.InvariantCulture)).ShouldBeLessThanOrEqualTo(2, $"y of glyph {i}");
        }
    }
}
