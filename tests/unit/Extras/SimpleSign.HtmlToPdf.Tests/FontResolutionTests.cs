// Licensed to SimpleSign under the MIT License.

using System.Buffers.Binary;
using System.IO.Compression;
using System.Text;
using System.Text.RegularExpressions;
using Shouldly;
using SimpleSign.HtmlToPdf.Fonts;
using Xunit;
using static SimpleSign.HtmlToPdf.Tests.TestSupport;

namespace SimpleSign.HtmlToPdf.Tests;

[Trait("Category", "Unit")]
public sealed partial class FontResolutionTests
{
    private static FontCollection Collection(params (string Family, FontVariant Variant)[] faces) =>
        new(faces.Select(f => new FontRegistration(f.Family, f.Variant, LoadTestFont())));

    [Fact]
    public void Resolve_FamilyList_SkipsUnregisteredNames()
    {
        FontCollection fonts = Collection(("Brand", FontVariant.Regular));

        ResolvedFont font = FontCollection.Resolve(fonts, ["Roboto", "Brand", "sans-serif"], false, false);

        font.Embedded!.Family.ShouldBe("Brand");
    }

    [Fact]
    public void Resolve_GenericSerif_MapsToTimes()
    {
        ResolvedFont font = FontCollection.Resolve(null, ["Unknown Font", "serif"], true, false);

        font.StandardName.ShouldBe("Times-Bold");
    }

    [Fact]
    public void Resolve_OnlyUnknownFamilies_FallsBackToHelvetica()
    {
        ResolvedFont font = FontCollection.Resolve(null, ["Nope"], false, true);

        font.StandardName.ShouldBe("Helvetica-Oblique");
    }

    [Fact]
    public void Resolve_RegisteredBoldFace_IsUsedWithoutSynthesis()
    {
        FontCollection fonts = Collection(("Brand", FontVariant.Regular), ("Brand", FontVariant.Bold));

        ResolvedFont font = FontCollection.Resolve(fonts, ["Brand"], true, false);

        font.Embedded!.Variant.ShouldBe(FontVariant.Bold);
        font.SyntheticBold.ShouldBeFalse();
    }

    [Fact]
    public void Resolve_MissingBoldFace_SynthesizesBold()
    {
        FontCollection fonts = Collection(("Brand", FontVariant.Regular));

        ResolvedFont font = FontCollection.Resolve(fonts, ["Brand"], true, true);

        font.Embedded!.Variant.ShouldBe(FontVariant.Regular);
        font.SyntheticBold.ShouldBeTrue();
        font.SyntheticItalic.ShouldBeTrue();
    }

    [Fact]
    public void Resolve_BoldItalicRequest_PrefersBoldFaceAndSynthesizesItalic()
    {
        FontCollection fonts = Collection(("Brand", FontVariant.Regular), ("Brand", FontVariant.Bold));

        ResolvedFont font = FontCollection.Resolve(fonts, ["Brand"], true, true);

        font.Embedded!.Variant.ShouldBe(FontVariant.Bold);
        font.SyntheticBold.ShouldBeFalse();
        font.SyntheticItalic.ShouldBeTrue();
    }

    [Fact]
    public void Resolve_EmbeddedOnly_NeverReturnsStandardFont()
    {
        FontCollection fonts = Collection(("Brand", FontVariant.Regular));
        fonts.EmbeddedOnly = true;

        ResolvedFont font = FontCollection.Resolve(fonts, ["Helvetica"], false, false);

        font.IsEmbedded.ShouldBeTrue();
    }

    [Fact]
    public void SplitRuns_CharacterMissingFromStandardFont_FallsBackToRegisteredFont()
    {
        byte[] emojiFont = WithSupplementaryCmap(LoadTestFont(), 0x1F600, 1);
        var fonts = new FontCollection([new FontRegistration("Emoji", FontVariant.Regular, emojiFont)]);

        List<(string Text, ResolvedFont Font)> runs = FontCollection.SplitRuns("ok \U0001F600 ok", ResolvedFont.Standard("Helvetica"), fonts);

        runs.Count.ShouldBe(3);
        runs[1].Text.ShouldBe("\U0001F600");
        runs[1].Font.Embedded!.Family.ShouldBe("Emoji");
        runs[0].Font.StandardName.ShouldBe("Helvetica");
    }

    [Fact]
    public void MeasureWidth_UnmappableStandardCharacter_MeasuresAsQuestionMark()
    {
        float cyrillic = TextMeasurer.MeasureWidth("Ж", "Helvetica", 10);
        float question = TextMeasurer.MeasureWidth("?", "Helvetica", 10);

        cyrillic.ShouldBe(question, 0.001f);
    }

    [Fact]
    public void Convert_SyntheticStyles_EmitStrokeModeAndSkewMatrix()
    {
        byte[] pdf = HtmlToPdfConverter.Html("<p><b>Bold</b> <i>Ital</i></p>")
            .WithFont("Brand", LoadTestFont())
            .WithStylesheet("p { font-family: Brand; }")
            .Convert();

        string text = Decompressed(pdf);
        text.ShouldContain("2 Tr");
        text.ShouldContain("1 0 0.21 1 ");
    }

    [Fact]
    public void Convert_MultiPageDocument_EmbedsFontProgramOnce()
    {
        string body = string.Concat(Enumerable.Range(0, 150).Select(i => $"<p>Paragraph {i}</p>"));
        byte[] pdf = HtmlToPdfConverter.Html(body).WithFont("Brand", LoadTestFont()).WithStylesheet("p { font-family: Brand; }").Convert();

        PageCount(pdf).ShouldBeGreaterThan(1);
        string raw = Encoding.Latin1.GetString(pdf);
        CountRegex().Count(raw).ShouldBe(1);
    }

    [Fact]
    public void Convert_EmbeddedFont_IsSubsetToUsedGlyphs()
    {
        byte[] original = LoadTestFont();
        byte[] pdf = HtmlToPdfConverter.Html("<p>AAA</p>").WithFont("Brand", original).WithStylesheet("p { font-family: Brand; }").Convert();

        byte[] program = ExtractFontProgram(pdf);
        program.Length.ShouldBeLessThan(original.Length / 2);

        var source = new EmbeddedFont("Brand", original);
        ushort glyphA = source.GetGlyphId(new Rune('A'));
        ushort glyphZ = source.GetGlyphId(new Rune('Z'));
        GlyphLength(program, glyphA).ShouldBeGreaterThan(0);
        GlyphLength(program, glyphZ).ShouldBe(0);
    }

    [Fact]
    public void Convert_EmbeddedFont_HasSubsetTagAndToUnicode()
    {
        byte[] pdf = HtmlToPdfConverter.Html("<p>Olá</p>").WithFont("Brand", LoadTestFont()).WithStylesheet("p { font-family: Brand; }").Convert();

        string raw = Encoding.Latin1.GetString(pdf);
        SubsetTagRegex().IsMatch(raw).ShouldBeTrue();
        Decompressed(pdf).ShouldContain("<00E1>"); // á in the ToUnicode CMap
    }

    [Fact]
    public void WithFont_Variants_ResolveThroughCss()
    {
        byte[] pdf = HtmlToPdfConverter.Html("<p>regular <b>bold</b></p>")
            .WithFont("Brand", LoadTestFont())
            .WithFont("Brand", LoadTestFont(), FontVariant.Bold)
            .WithStylesheet("p { font-family: Brand; }")
            .Convert();

        string raw = Encoding.Latin1.GetString(pdf);
        raw.ShouldContain("+Brand-Bold");
        Decompressed(pdf).ShouldNotContain("2 Tr");
    }

    [Fact]
    public void FontFace_BoldWeight_RegistersBoldVariant()
    {
        string data = Convert.ToBase64String(LoadTestFont());
        string css = $"@font-face {{ font-family: X; src: url(data:font/ttf;base64,{data}); }} @font-face {{ font-family: X; font-weight: 700; src: url(data:font/ttf;base64,{data}); }} p {{ font-family: X; }}";
        byte[] pdf = HtmlToPdfConverter.Html($"<style>{css}</style><p><strong>bold</strong></p>").Convert();

        Encoding.Latin1.GetString(pdf).ShouldContain("+X-Bold");
    }

    [Fact]
    public void EmbeddedFont_Woff_IsRejectedWithClearMessage()
    {
        byte[] woff = [0x77, 0x4F, 0x46, 0x46, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

        Should.Throw<ArgumentException>(() => new EmbeddedFont("W", woff)).Message.ShouldContain("WOFF");
    }

    [Fact]
    public void EmbeddedFont_Collection_IsRejectedWithClearMessage()
    {
        byte[] ttc = [0x74, 0x74, 0x63, 0x66, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0];

        Should.Throw<ArgumentException>(() => new EmbeddedFont("C", ttc)).Message.ShouldContain(".ttc");
    }

    private static byte[] ExtractFontProgram(byte[] pdf)
    {
        string raw = Encoding.Latin1.GetString(pdf);
        Match match = FontFileRegex().Match(raw);
        match.Success.ShouldBeTrue();
        int length = int.Parse(match.Groups[1].Value, System.Globalization.CultureInfo.InvariantCulture);
        int start = raw.IndexOf("stream\n", match.Index, StringComparison.Ordinal) + "stream\n".Length;
        using var input = new MemoryStream(pdf, start, length);
        using var zlib = new ZLibStream(input, CompressionMode.Decompress);
        using var output = new MemoryStream();
        zlib.CopyTo(output);
        return output.ToArray();
    }

    private static int GlyphLength(byte[] font, ushort glyph)
    {
        int tables = BinaryPrimitives.ReadUInt16BigEndian(font.AsSpan(4));
        int loca = -1;
        for (int i = 0; i < tables; i++)
        {
            int entry = 12 + (i * 16);
            if (Encoding.ASCII.GetString(font, entry, 4) == "loca")
            {
                loca = (int)BinaryPrimitives.ReadUInt32BigEndian(font.AsSpan(entry + 8));
            }
        }

        loca.ShouldBeGreaterThan(0);
        uint start = BinaryPrimitives.ReadUInt32BigEndian(font.AsSpan(loca + (glyph * 4)));
        uint end = BinaryPrimitives.ReadUInt32BigEndian(font.AsSpan(loca + ((glyph + 1) * 4)));
        return (int)(end - start);
    }

    private static byte[] WithSupplementaryCmap(byte[] source, uint codepoint, ushort glyphId)
    {
        // Appends a format-12 cmap containing only the given codepoint and points the table directory at it.
        ushort tableCount = BinaryPrimitives.ReadUInt16BigEndian(source.AsSpan(4, 2));
        int cmapRecord = -1;
        for (int i = 0; i < tableCount; i++)
        {
            int entry = 12 + (i * 16);
            if (Encoding.ASCII.GetString(source, entry, 4) == "cmap")
            {
                cmapRecord = entry;
            }
        }

        byte[] cmap = new byte[40];
        BinaryPrimitives.WriteUInt16BigEndian(cmap.AsSpan(2, 2), 1);
        BinaryPrimitives.WriteUInt16BigEndian(cmap.AsSpan(4, 2), 3);
        BinaryPrimitives.WriteUInt16BigEndian(cmap.AsSpan(6, 2), 10);
        BinaryPrimitives.WriteUInt32BigEndian(cmap.AsSpan(8, 4), 12);
        BinaryPrimitives.WriteUInt16BigEndian(cmap.AsSpan(12, 2), 12);
        BinaryPrimitives.WriteUInt32BigEndian(cmap.AsSpan(16, 4), 28);
        BinaryPrimitives.WriteUInt32BigEndian(cmap.AsSpan(24, 4), 1);
        BinaryPrimitives.WriteUInt32BigEndian(cmap.AsSpan(28, 4), codepoint);
        BinaryPrimitives.WriteUInt32BigEndian(cmap.AsSpan(32, 4), codepoint);
        BinaryPrimitives.WriteUInt32BigEndian(cmap.AsSpan(36, 4), glyphId);
        byte[] result = [.. source, .. cmap];
        BinaryPrimitives.WriteUInt32BigEndian(result.AsSpan(cmapRecord + 8, 4), (uint)source.Length);
        BinaryPrimitives.WriteUInt32BigEndian(result.AsSpan(cmapRecord + 12, 4), (uint)cmap.Length);
        return result;
    }

    [GeneratedRegex("/FontFile2")]
    private static partial Regex CountRegex();

    [GeneratedRegex(@"/BaseFont /[A-Z]{6}\+Brand")]
    private static partial Regex SubsetTagRegex();

    [GeneratedRegex(@"/Length1 \d+ /Filter /FlateDecode /Length (\d+)")]
    private static partial Regex FontFileRegex();
}
