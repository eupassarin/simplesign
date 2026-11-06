using System.Buffers.Binary;
using System.Reflection;
using System.Text;
using Shouldly;
using SimpleSign.HtmlToPdf.Fonts;
using Xunit;

namespace SimpleSign.HtmlToPdf.Tests;

[Trait("Category", "Unit")]
public sealed class P0FontEmbeddingTests
{
    private static byte[] LoadTestFont()
    {
        using Stream stream = Assembly.GetExecutingAssembly()
            .GetManifestResourceStream("SimpleSign.HtmlToPdf.Tests.LiberationSans-subset.ttf")!;
        using var output = new MemoryStream();
        stream.CopyTo(output);
        return output.ToArray();
    }

    [Fact]
    public void EmbeddedFont_MapsUnicodeGlyphsAndMeasuresUsingTtfMetrics()
    {
        var font = new EmbeddedFont("Brand Sans", LoadTestFont());
        Rune eAcute = new('é');
        ushort cid = font.GetCid(eAcute);

        font.GetGlyphId(eAcute).ShouldBeGreaterThan((ushort)0);
        font.Measure(eAcute, 12).ShouldBeGreaterThan(0);
        Encoding.ASCII.GetString(font.BuildToUnicodeCMap()).ShouldContain($"<{cid:X4}> <00E9>");
    }

    [Fact]
    public void EmbeddedFont_CmapFormat12_PreservesSupplementaryUnicode()
    {
        byte[] fontBytes = AddSupplementaryCmap(LoadTestFont(), 0x1F600, 1);
        var font = new EmbeddedFont("Unicode Test", fontBytes);
        Rune emoji = new(0x1F600);
        ushort cid = font.GetCid(emoji);

        font.GetGlyphId(emoji).ShouldBe((ushort)1);
        Encoding.ASCII.GetString(font.BuildToUnicodeCMap()).ShouldContain($"<{cid:X4}> <D83DDE00>");
    }

    [Fact]
    public void WithFont_EmbedsType0FontAndUnicodeToUnicodeMap()
    {
        byte[] font = LoadTestFont();
        byte[] pdf = HtmlToPdfConverter.Html("<p>café — déjà vu</p>")
            .WithFont("Brand Sans", font)
            .WithStylesheet("p { font-family: 'Brand Sans'; font-size: 18px; }")
            .Convert();
        string text = Encoding.Latin1.GetString(pdf);

        text.ShouldContain("/Subtype /Type0");
        text.ShouldContain("/Subtype /CIDFontType2");
        text.ShouldContain("/ToUnicode");
        text.ShouldContain("/FontFile2");
        text.ShouldContain("/Length1");
    }

    [Fact]
    public void WithFont_SnapshotsCallerFontData()
    {
        byte[] source = LoadTestFont();
        var builder = HtmlToPdfConverter.Html("<p>café</p>")
            .WithFont("Brand Sans", source)
            .WithStylesheet("p { font-family: 'Brand Sans'; }");
        Array.Clear(source);

        byte[] pdf = builder.Convert();

        Encoding.Latin1.GetString(pdf).ShouldContain("/Subtype /Type0");
    }

    private static byte[] AddSupplementaryCmap(byte[] source, uint codepoint, ushort glyphId)
    {
        ushort tableCount = BinaryPrimitives.ReadUInt16BigEndian(source.AsSpan(4, 2));
        int cmapRecord = -1;
        for (int i = 0; i < tableCount; i++)
        {
            int entry = 12 + (i * 16);
            if (Encoding.ASCII.GetString(source, entry, 4) == "cmap")
            {
                cmapRecord = entry;
                break;
            }
        }

        cmapRecord.ShouldBeGreaterThanOrEqualTo(0);
        byte[] cmap = new byte[40];
        BinaryPrimitives.WriteUInt16BigEndian(cmap.AsSpan(0, 2), 0); // cmap version
        BinaryPrimitives.WriteUInt16BigEndian(cmap.AsSpan(2, 2), 1); // one encoding record
        BinaryPrimitives.WriteUInt16BigEndian(cmap.AsSpan(4, 2), 3); // Windows platform
        BinaryPrimitives.WriteUInt16BigEndian(cmap.AsSpan(6, 2), 10); // UCS-4 encoding
        BinaryPrimitives.WriteUInt32BigEndian(cmap.AsSpan(8, 4), 12); // subtable offset
        BinaryPrimitives.WriteUInt16BigEndian(cmap.AsSpan(12, 2), 12); // format 12
        BinaryPrimitives.WriteUInt32BigEndian(cmap.AsSpan(16, 4), 28); // subtable length
        BinaryPrimitives.WriteUInt32BigEndian(cmap.AsSpan(24, 4), 1); // one group
        BinaryPrimitives.WriteUInt32BigEndian(cmap.AsSpan(28, 4), codepoint);
        BinaryPrimitives.WriteUInt32BigEndian(cmap.AsSpan(32, 4), codepoint);
        BinaryPrimitives.WriteUInt32BigEndian(cmap.AsSpan(36, 4), glyphId);

        int newOffset = source.Length;
        byte[] result = [.. source, .. cmap];
        BinaryPrimitives.WriteUInt32BigEndian(result.AsSpan(cmapRecord + 8, 4), (uint)newOffset);
        BinaryPrimitives.WriteUInt32BigEndian(result.AsSpan(cmapRecord + 12, 4), (uint)cmap.Length);
        return result;
    }
}
