// Licensed to SimpleSign under the MIT License.

using System.Buffers.Binary;
using System.IO.Compression;
using System.Reflection;
using System.Text;
using System.Text.RegularExpressions;
using SimpleSign.HtmlToPdf.Layout;
using SimpleSign.HtmlToPdf.Parsing;

namespace SimpleSign.HtmlToPdf.Tests;

/// <summary>Shared helpers for layout/PDF assertions in the HtmlToPdf tests.</summary>
internal static partial class TestSupport
{
    private static readonly uint[] CrcTable = BuildCrcTable();

    /// <summary>Parses and styles a document the way the converter does (document styles first, then <paramref name="css"/>).</summary>
    internal static HtmlNode Resolve(string html, string css = "")
    {
        HtmlNode dom = HtmlTokenizer.Parse(html);
        ConversionPipeline.EnsureBody(dom);
        List<CssRule> rules = ConversionPipeline.CollectDocumentStyles(dom, Rendering.ResourceLoader.DataUriOnly);
        rules.AddRange(CssParser.ParseStylesheet(css));
        StyleResolver.Resolve(dom, rules);
        return dom;
    }

    internal static LayoutResult LayoutHtml(string html, string css = "", PageSettings? settings = null)
    {
        HtmlNode dom = Resolve(html, css);
        return new LayoutEngine(settings ?? new PageSettings()).Layout(dom);
    }

    internal static IEnumerable<LayoutBox> AllBoxes(LayoutResult result) => result.Pages.SelectMany(p => p.Boxes);

    internal static List<LayoutBox> Texts(LayoutResult result) =>
        [.. AllBoxes(result).Where(b => b.Type == LayoutBoxType.InlineText)];

    internal static LayoutBox Text(LayoutResult result, string contains) =>
        Texts(result).First(b => b.Text!.Contains(contains, StringComparison.Ordinal));

    internal static int PageOf(LayoutResult result, string contains) =>
        result.Pages.FindIndex(p => p.Boxes.Any(b => b.Type == LayoutBoxType.InlineText && b.Text!.Contains(contains, StringComparison.Ordinal)));

    internal static HtmlNode First(HtmlNode root, string tag) => root.Descendants(tag).First();

    internal static string Decompressed(byte[] pdf) => PdfTextHelper.GetDecompressedPdfText(pdf);

    internal static int PageCount(byte[] pdf) => PageRegex().Count(Encoding.Latin1.GetString(pdf));

    internal static byte[] LoadTestFont()
    {
        using Stream stream = Assembly.GetExecutingAssembly()
            .GetManifestResourceStream("SimpleSign.HtmlToPdf.Tests.LiberationSans-subset.ttf")!;
        using var output = new MemoryStream();
        stream.CopyTo(output);
        return output.ToArray();
    }

    /// <summary>Loads one of the shaping test fonts from <c>Fonts/</c> (TestArabic, TestDevanagari, TestKerning).</summary>
    internal static byte[] LoadFont(string name)
    {
        using Stream stream = Assembly.GetExecutingAssembly()
            .GetManifestResourceStream($"SimpleSign.HtmlToPdf.Tests.Fonts.{name}.ttf")!;
        using var output = new MemoryStream();
        stream.CopyTo(output);
        return output.ToArray();
    }

    /// <summary>Encodes a PNG from raw (unfiltered) scanlines.</summary>
    internal static byte[] Png(int width, int height, int colorType, int bitDepth, byte[] pixels,
        byte[]? palette = null, byte[]? transparency = null)
    {
        int channels = colorType switch { 0 => 1, 2 => 3, 3 => 1, 4 => 2, _ => 4 };
        int stride = ((width * channels * bitDepth) + 7) / 8;
        using var raw = new MemoryStream();
        for (int y = 0; y < height; y++)
        {
            raw.WriteByte(0); // filter: none
            raw.Write(pixels, y * stride, stride);
        }

        using var compressed = new MemoryStream();
        using (var zlib = new ZLibStream(compressed, CompressionLevel.Optimal, leaveOpen: true))
        {
            raw.Position = 0;
            raw.CopyTo(zlib);
        }

        using var png = new MemoryStream();
        png.Write([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]);
        byte[] ihdr = new byte[13];
        BinaryPrimitives.WriteInt32BigEndian(ihdr, width);
        BinaryPrimitives.WriteInt32BigEndian(ihdr.AsSpan(4), height);
        ihdr[8] = (byte)bitDepth;
        ihdr[9] = (byte)colorType;
        WriteChunk(png, "IHDR", ihdr);
        if (palette is not null)
        {
            WriteChunk(png, "PLTE", palette);
        }

        if (transparency is not null)
        {
            WriteChunk(png, "tRNS", transparency);
        }

        WriteChunk(png, "IDAT", compressed.ToArray());
        WriteChunk(png, "IEND", []);
        return png.ToArray();
    }

    internal static string DataUri(byte[] png) => "data:image/png;base64," + Convert.ToBase64String(png);

    /// <summary>A 2x2 opaque RGB PNG.</summary>
    internal static byte[] RgbPng() => Png(2, 2, 2, 8, [255, 0, 0, 0, 255, 0, 0, 0, 255, 255, 255, 255]);

    private static void WriteChunk(Stream stream, string type, byte[] data)
    {
        Span<byte> length = stackalloc byte[4];
        BinaryPrimitives.WriteInt32BigEndian(length, data.Length);
        stream.Write(length);
        byte[] typeBytes = Encoding.ASCII.GetBytes(type);
        stream.Write(typeBytes);
        stream.Write(data);
        uint crc = Crc([.. typeBytes, .. data]);
        Span<byte> crcBytes = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(crcBytes, crc);
        stream.Write(crcBytes);
    }

    private static uint Crc(byte[] data)
    {
        uint c = 0xFFFFFFFF;
        foreach (byte b in data)
        {
            c = CrcTable[(c ^ b) & 0xFF] ^ (c >> 8);
        }

        return c ^ 0xFFFFFFFF;
    }

    private static uint[] BuildCrcTable()
    {
        var table = new uint[256];
        for (uint n = 0; n < 256; n++)
        {
            uint c = n;
            for (int k = 0; k < 8; k++)
            {
                c = (c & 1) != 0 ? 0xEDB88320 ^ (c >> 1) : c >> 1;
            }

            table[n] = c;
        }

        return table;
    }

    [GeneratedRegex(@"/Type /Page\b(?!s)")]
    private static partial Regex PageRegex();
}
