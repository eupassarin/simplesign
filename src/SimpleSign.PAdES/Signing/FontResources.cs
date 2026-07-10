using System.IO.Compression;

namespace SimpleSign.PAdES.Signing;

/// <summary>
/// Provides embedded font data for appearance XObject generation.
/// Uses LiberationSans (metric-compatible with Helvetica/Arial) subsetted
/// to the WinAnsiEncoding character range (U+0020–U+00FF, ~200 glyphs).
/// Required for PDF/A-1 compliance (ISO 19005-1 §6.3.4) which mandates
/// font program embedding for all fonts, including the standard 14.
/// </summary>
internal static class FontResources
{
    private static byte[]? _ttfData;
    private static readonly Lazy<byte[]> s_compressedTtf = new(CompressTtf, LazyThreadSafetyMode.ExecutionAndPublication);

    private const string ResourceName = "SimpleSign.PAdES.Signing.LiberationSans-subset.ttf";

    private static byte[] LoadTtf()
    {
        var assembly = typeof(FontResources).Assembly;
        using var stream = assembly.GetManifestResourceStream(ResourceName)
            ?? throw new InvalidOperationException($"Embedded font resource '{ResourceName}' not found.");
        var data = new byte[stream.Length];
        stream.ReadExactly(data);
        return data;
    }

    /// <summary>Raw TTF font data for LiberationSans (WinAnsi subset).</summary>
    internal static byte[] TtfData => _ttfData ??= LoadTtf();

    /// <summary>TTF data compressed with FlateDecode (ready for PDF stream).</summary>
    internal static byte[] CompressedTtf => s_compressedTtf.Value;

    private static byte[] CompressTtf()
    {
        var raw = TtfData;
        using var ms = new MemoryStream();
        using (var zs = new ZLibStream(ms, CompressionLevel.SmallestSize))
        {
            zs.Write(raw, 0, raw.Length);
        }
        return ms.ToArray();
    }

    internal const int UnitsPerEm = 2048;
    internal const int Ascent = 1491;
    internal const int Descent = -431;
    internal const int CapHeight = 1409;
    internal const int Flags = 32;
    internal const int StemV = 59;
    internal const int ItalicAngle = 0;
    internal const int FirstChar = 32;
    internal const int LastChar = 255;

    internal static readonly int[] FontBBox = [-416, -434, 1960, 1798];

    /// <summary>
    /// Advance widths for WinAnsi characters (32–255) in PDF glyph space
    /// (units of 1/1000 of a unit of text space, per ISO 32000-1 §9.2.2).
    /// Derived from the LiberationSans hmtx table (2048 UPM) and scaled
    /// to 1000 UPM via the formula: width_1000 = round(width_2048 * 1000 / 2048).
    /// </summary>
    internal static readonly ushort[] Widths =
    [
        278, 278, 355, 556, 556, 889, 667, 191, 333, 333, 389, 584, 278, 333, 278, 278,
        556, 556, 556, 556, 556, 556, 556, 556, 556, 556, 278, 278, 584, 584, 584, 556,
        1015, 667, 667, 722, 722, 667, 611, 778, 722, 278, 500, 667, 556, 833, 722, 778,
        667, 778, 722, 667, 611, 722, 667, 944, 667, 667, 611, 278, 278, 278, 469, 556,
        333, 556, 556, 500, 556, 556, 278, 556, 556, 222, 222, 500, 222, 833, 556, 556,
        556, 556, 333, 500, 278, 556, 500, 722, 500, 500, 500, 334, 260, 334, 584, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        278, 333, 556, 556, 556, 556, 260, 556, 333, 737, 370, 556, 584, 333, 737, 552,
        400, 549, 333, 333, 333, 576, 537, 278, 333, 333, 365, 556, 834, 834, 834, 611,
        667, 667, 667, 667, 667, 667, 1000, 722, 667, 667, 667, 667, 278, 278, 278, 278,
        722, 722, 778, 778, 778, 778, 778, 584, 778, 722, 722, 722, 722, 667, 667, 611,
        556, 556, 556, 556, 556, 556, 889, 500, 556, 556, 556, 556, 278, 278, 278, 278,
        556, 556, 556, 556, 556, 556, 556, 549, 611, 556, 556, 556, 556, 500, 556, 500,
    ];
}
