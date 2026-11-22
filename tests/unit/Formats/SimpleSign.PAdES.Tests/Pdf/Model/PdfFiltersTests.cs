using System.IO.Compression;
using System.Reflection;
using System.Text;
using Microsoft.Extensions.Logging;
using Shouldly;
using SimpleSign.PAdES.Pdf;
using SimpleSign.PAdES.Pdf.Model;
using SimpleSign.TestHelpers;
using Xunit;

namespace SimpleSign.PAdES.Tests.Pdf.Model;

/// <summary>
/// The stream filters of ISO 32000-1 §7.4 for the PDF object model (ADR 0032): FlateDecode with its size limit,
/// ASCII85Decode, ASCIIHexDecode, the filter chain, the filters refused as unsupported, and parity of inflate
/// with the old reader's on every stream of the integration fixtures.
/// </summary>
[Trait("Category", "Unit")]
public sealed class PdfFiltersTests
{
    private static readonly byte[] Text = Encoding.ASCII.GetBytes("Hello, PDF! Hello, PDF! Hello, PDF!");

    private static byte[] Ascii(string s) => Encoding.ASCII.GetBytes(s);

    private static byte[] Zlib(byte[] data)
    {
        using var ms = new MemoryStream();
        using (var zlib = new ZLibStream(ms, CompressionLevel.Optimal, leaveOpen: true))
        {
            zlib.Write(data);
        }

        return ms.ToArray();
    }

    // ── FlateDecode ─────────────────────────────────────────────────────────────

    [Fact]
    public void Inflate_ZlibData_ReturnsOriginal() => PdfFilters.Inflate(Zlib(Text)).ShouldBe(Text);

    [Fact]
    public void Inflate_PresetDictionaryFlag_SkipsDictionaryId()
    {
        byte[] zlib = Zlib(Text);
        // 0x78 0xBB: FDICT (bit 5 of FLG) set, header check (0x78BB % 31 == 0) kept; then a 4-byte dictionary id.
        byte[] withDict = [0x78, 0xBB, 0xDE, 0xAD, 0xBE, 0xEF, .. zlib.AsSpan(2)];

        PdfFilters.Inflate(withDict).ShouldBe(Text);
    }

    [Fact]
    public void Inflate_Empty_ReturnsEmpty() => PdfFilters.Inflate([]).ShouldBeEmpty();

    [Fact]
    public void Inflate_HeaderOnly_ReturnsEmpty() => PdfFilters.Inflate([0x78, 0x9C]).ShouldBeEmpty();

    [Fact]
    public void Inflate_SingleByte_Throws() =>
        Should.Throw<PdfFilterException>(() => PdfFilters.Inflate([0x78])).FilterName.ShouldBe("FlateDecode");

    [Theory]
    [InlineData(new byte[] { 0x6E, 0x6F, 0x74, 0x20 })] // "not ": method 14
    [InlineData(new byte[] { 0x78, 0x9D, 0x03, 0x00 })] // method 8, but 0x789D is not a multiple of 31
    public void Inflate_NotAZlibHeader_Throws(byte[] data) =>
        Should.Throw<PdfFilterException>(() => PdfFilters.Inflate(data)).Message.ShouldContain("zlib header");

    [Fact]
    public void Inflate_Truncated_ReturnsWhatWasInflated()
    {
        byte[] original = new byte[64 * 1024];
        new Random(42).NextBytes(original);
        byte[] zlib = Zlib(original);

        byte[] result = PdfFilters.Inflate(zlib.AsSpan(0, zlib.Length / 2));

        result.Length.ShouldBeGreaterThan(0);
        result.Length.ShouldBeLessThan(original.Length);
        result.ShouldBe(original.AsSpan(0, result.Length).ToArray());
    }

    [Fact]
    public void Inflate_CorruptDeflateData_Throws()
    {
        // BFINAL=1, BTYPE=11: a reserved block type.
        byte[] corrupt = [0x78, 0x9C, 0xFF, 0xFF, 0xFF, 0xFF];

        var ex = Should.Throw<PdfFilterException>(() => PdfFilters.Inflate(corrupt));
        ex.InnerException.ShouldBeOfType<InvalidDataException>();
    }

    [Fact]
    public void Inflate_OverLimit_ThrowsSizeLimitException()
    {
        byte[] bomb = Zlib(new byte[2 * 1024 * 1024]);

        var ex = Should.Throw<PdfDecodedSizeLimitException>(() => PdfFilters.Inflate(bomb, maxDecodedBytes: 1024 * 1024));
        ex.MaxDecodedBytes.ShouldBe(1024 * 1024);
        ex.FilterName.ShouldBe("FlateDecode");
    }

    [Fact]
    public void Inflate_ExactlyAtLimit_Succeeds() =>
        PdfFilters.Inflate(Zlib(new byte[100_000]), maxDecodedBytes: 100_000).Length.ShouldBe(100_000);

    [Fact]
    public void Inflate_OverDefaultLimit_ThrowsSizeLimitException()
    {
        // About 50 KB of zlib that would inflate to 50 MB + 1 byte.
        byte[] bomb = Zlib(new byte[PdfFilters.DefaultMaxDecodedBytes + 1]);

        Should.Throw<PdfDecodedSizeLimitException>(() => PdfFilters.Inflate(bomb))
            .MaxDecodedBytes.ShouldBe(50 * 1024 * 1024);
    }

    [Fact]
    public void Inflate_NonPositiveLimit_ThrowsArgumentOutOfRange() =>
        Should.Throw<ArgumentOutOfRangeException>(() => PdfFilters.Inflate(Zlib(Text), maxDecodedBytes: 0));

    [Fact]
    public void DecodeFlate_WithPngPredictor_InflatesThenReversesRows()
    {
        // Two xref-stream-like rows of 3 bytes: None 1 0 5, Up 0 0 3 → 1 0 5, 1 0 8.
        byte[] encoded = Zlib([0, 1, 0, 5, 2, 0, 0, 3]);

        PdfFilters.DecodeFlate(encoded, new PdfDecodeParams { Predictor = 12, Columns = 3 })
            .ShouldBe([1, 0, 5, 1, 0, 8]);
    }

    [Fact]
    public void DecodeFlate_NullParams_OnlyInflates() => PdfFilters.DecodeFlate(Zlib(Text), null).ShouldBe(Text);

    // ── ASCII85Decode ───────────────────────────────────────────────────────────

    [Theory]
    [InlineData("9jqo^", "Man ")]
    [InlineData("FCfN8", "test")]
    [InlineData("9jqo~>", "Man")]
    [InlineData("87cURD_*#-6q/=~>", "Hello, PDF!")]
    [InlineData("<~87cURD_*#-6q/=~>", "Hello, PDF!")]
    [InlineData("  87cU RD_*\r\n#-6q\t/=\f~>", "Hello, PDF!")]
    [InlineData("87cURD_*#-6q/=", "Hello, PDF!")]
    [InlineData("9jqo^~>garbage after the end", "Man ")]
    [InlineData("~>", "")]
    [InlineData("", "")]
    public void DecodeAscii85_ValidInput_Decodes(string encoded, string expected) =>
        PdfFilters.DecodeAscii85(Ascii(encoded)).ShouldBe(Ascii(expected));

    [Fact]
    public void DecodeAscii85_ZShorthand_ExpandsToFourZeros() =>
        PdfFilters.DecodeAscii85(Ascii("z!<~>")).ShouldBe([0, 0, 0, 0, 1]);

    [Theory]
    [InlineData("9jqv^~>")]   // 'v' is past 'u'
    [InlineData("9jz~>")]     // 'z' inside a group
    [InlineData("9jqo^9~>")]  // one character left in the final group
    [InlineData("uuuuu~>")]   // 85^5 − 1 > 2^32 − 1
    [InlineData("9jqo^~x")]   // '~' not followed by '>'
    [InlineData("9jqo^~")]    // '~' at the very end
    public void DecodeAscii85_CorruptInput_Throws(string encoded) =>
        Should.Throw<PdfFilterException>(() => PdfFilters.DecodeAscii85(Ascii(encoded))).FilterName.ShouldBe("ASCII85Decode");

    [Fact]
    public void DecodeAscii85_LargestGroup_DecodesToAllOnes() =>
        PdfFilters.DecodeAscii85(Ascii("s8W-!~>")).ShouldBe([0xFF, 0xFF, 0xFF, 0xFF]);

    [Fact]
    public void DecodeAscii85_OverLimit_ThrowsSizeLimitException() =>
        Should.Throw<PdfDecodedSizeLimitException>(() => PdfFilters.DecodeAscii85(Ascii("zzz~>"), maxDecodedBytes: 8));

    // ── ASCIIHexDecode ──────────────────────────────────────────────────────────

    [Theory]
    [InlineData("48656C6C6F>", "Hello")]
    [InlineData("48656c6c6f>", "Hello")]
    [InlineData(" 48 65\r\n6C\t6C 6F >", "Hello")]
    [InlineData("48656C6C6F", "Hello")]
    [InlineData("4865>6C6C6F", "He")]
    [InlineData("414>", "A@")]
    [InlineData(">", "")]
    [InlineData("", "")]
    public void DecodeAsciiHex_ValidInput_Decodes(string encoded, string expected) =>
        PdfFilters.DecodeAsciiHex(Ascii(encoded)).ShouldBe(Ascii(expected));

    [Theory]
    [InlineData("48G5>")]
    [InlineData("48-65>")]
    public void DecodeAsciiHex_InvalidCharacter_Throws(string encoded) =>
        Should.Throw<PdfFilterException>(() => PdfFilters.DecodeAsciiHex(Ascii(encoded))).FilterName.ShouldBe("ASCIIHexDecode");

    [Fact]
    public void DecodeAsciiHex_OverLimit_ThrowsSizeLimitException() =>
        Should.Throw<PdfDecodedSizeLimitException>(() => PdfFilters.DecodeAsciiHex(Ascii("010203>"), maxDecodedBytes: 2));

    // ── The chain ───────────────────────────────────────────────────────────────

    [Fact]
    public void Decode_NoFilters_ReturnsCopy()
    {
        byte[] data = [1, 2, 3];

        byte[] result = PdfFilters.Decode(data, []);

        result.ShouldBe(data);
        result.ShouldNotBeSameAs(data);
    }

    [Fact]
    public void Decode_AsciiHexThenFlate_AppliesInOrder()
    {
        byte[] hex = Ascii(Convert.ToHexString(Zlib(Text)) + ">");

        PdfFilters.Decode(hex, ["ASCIIHexDecode", "FlateDecode"]).ShouldBe(Text);
    }

    [Fact]
    public void Decode_Ascii85ThenFlateWithPredictor_UsesParamsByPosition()
    {
        byte[] a85 = [.. Encoding.ASCII.GetBytes(Ascii85Encode(Zlib([0, 1, 0, 5, 2, 0, 0, 3]))), .. "~>"u8];

        PdfFilters.Decode(a85, ["ASCII85Decode", "FlateDecode"], [null, new PdfDecodeParams { Predictor = 12, Columns = 3 }])
            .ShouldBe([1, 0, 5, 1, 0, 8]);
    }

    [Fact]
    public void Decode_FewerParamsThanFilters_UsesDefaults() =>
        PdfFilters.Decode(Zlib(Text), ["FlateDecode"], []).ShouldBe(Text);

    [Fact]
    public void Decode_AbbreviationsAndLeadingSlash_AreAccepted()
    {
        byte[] hex = Ascii(Convert.ToHexString(Zlib(Text)));

        PdfFilters.Decode(hex, ["AHx", "/Fl"]).ShouldBe(Text);
        PdfFilters.Decode(Ascii("87cURD_*#-6q/=~>"), ["A85"]).ShouldBe(Ascii("Hello, PDF!"));
    }

    [Theory]
    [InlineData("LZWDecode")]
    [InlineData("LZW")]
    [InlineData("RunLengthDecode")]
    [InlineData("RL")]
    [InlineData("DCTDecode")]
    [InlineData("JPXDecode")]
    [InlineData("CCITTFaxDecode")]
    [InlineData("JBIG2Decode")]
    [InlineData("Crypt")]
    [InlineData("flatedecode")]
    [InlineData("NoSuchDecode")]
    public void Decode_UnsupportedFilter_ThrowsUnsupported(string filter)
    {
        Should.Throw<PdfUnsupportedFilterException>(() => PdfFilters.Decode([1, 2, 3], [filter])).FilterName.ShouldBe(filter);
        PdfFilters.IsSupported(filter).ShouldBeFalse();
    }

    [Fact]
    public void Decode_UnsupportedFilterAfterCorruptData_ReportsUnsupportedBeforeDecoding() =>
        Should.Throw<PdfUnsupportedFilterException>(() => PdfFilters.Decode(Ascii("not hex at all"), ["ASCIIHexDecode", "LZWDecode"]))
            .FilterName.ShouldBe("LZWDecode");

    [Fact]
    public void Decode_LimitAppliesToEachFilter() =>
        Should.Throw<PdfDecodedSizeLimitException>(() =>
            PdfFilters.Decode(Ascii(Convert.ToHexString(Zlib(new byte[10_000]))), ["ASCIIHexDecode", "FlateDecode"], maxDecodedBytes: 5_000));

    [Theory]
    [InlineData("FlateDecode")]
    [InlineData("Fl")]
    [InlineData("ASCII85Decode")]
    [InlineData("A85")]
    [InlineData("ASCIIHexDecode")]
    [InlineData("AHx")]
    public void IsSupported_SupportedFilter_ReturnsTrue(string filter) => PdfFilters.IsSupported(filter).ShouldBeTrue();

    // ── Parity with the old reader ──────────────────────────────────────────────

    private delegate byte[] OldInflate(ReadOnlySpan<byte> data, ILogger? logger);

    [Fact]
    public void Inflate_EveryFlateStreamOfIntegrationFixtures_MatchesOldReaderInflate()
    {
        OldInflate old = typeof(PdfStructureReader)
            .GetMethod("InflateZlib", BindingFlags.NonPublic | BindingFlags.Static)
            .ShouldNotBeNull()
            .CreateDelegate<OldInflate>();

        string fixtures = RepositoryPaths.Get("tests", "integration", "SimpleSign.Integration.Tests", "Fixtures");
        int compared = 0;
        int files = 0;
        var notZlib = new SortedSet<string>(StringComparer.Ordinal);
        foreach (string path in Directory.EnumerateFiles(fixtures, "*.pdf", SearchOption.AllDirectories))
        {
            files++;
            byte[] pdf = File.ReadAllBytes(path);
            foreach ((int offset, byte[] raw) in FlateStreams(pdf))
            {
                string where = $"{Path.GetFileName(path)} @ {offset}";
                byte[]? expected = null;
                bool oldThrew = false;
                try
                {
                    expected = old(raw, null);
                }
                catch (InvalidDataException)
                {
                    oldThrew = true;
                }

                if (oldThrew)
                {
                    Should.Throw<PdfFilterException>(() => PdfFilters.Inflate(raw), where);
                }
                else if (raw.Length >= 2 && ((raw[0] & 0x0F) != 8 || ((raw[0] << 8) | raw[1]) % 31 != 0))
                {
                    // Not zlib (an encrypted stream): the old inflate skipped two bytes and returned whatever came out;
                    // the header is checked now.
                    Should.Throw<PdfFilterException>(() => PdfFilters.Inflate(raw), where).Message.ShouldContain("zlib header");
                    notZlib.Add(Path.GetFileName(path));
                }
                else
                {
                    PdfFilters.Inflate(raw).ShouldBe(expected, where);
                }

                compared++;
            }
        }

        files.ShouldBeGreaterThan(10);
        compared.ShouldBeGreaterThan(100);
        notZlib.ShouldBe(["encrypted.pdf"]);
    }

    /// <summary>
    /// The raw data of every stream whose only filter is <c>FlateDecode</c>: a scan for <c>stream</c> after
    /// <c>&gt;&gt;</c>, the dictionary read back to the <c>obj</c> keyword, the data up to <c>endstream</c>.
    /// </summary>
    private static IEnumerable<(int Offset, byte[] Raw)> FlateStreams(byte[] pdf)
    {
        ReadOnlySpan<byte> keyword = "stream"u8;
        string[] otherFilters = ["/ASCII", "/A85", "/AHx", "/LZW", "/RunLength", "/DCT", "/JPX", "/CCITT", "/JBIG2", "/Crypt"];
        var results = new List<(int, byte[])>();

        for (int i = pdf.AsSpan().IndexOf(keyword); i >= 0;)
        {
            int next = i + keyword.Length;
            if (IsStreamKeyword(pdf, i))
            {
                int objStart = pdf.AsSpan(Math.Max(0, i - 65536), Math.Min(i, 65536)).LastIndexOf(" obj"u8);
                if (objStart >= 0)
                {
                    string dict = Encoding.Latin1.GetString(pdf, Math.Max(0, i - 65536) + objStart, Math.Min(i, 65536) - objStart);
                    int dataStart = next + (pdf[next] == '\r' && next + 1 < pdf.Length && pdf[next + 1] == '\n' ? 2 : 1);
                    int end = pdf.AsSpan(dataStart).IndexOf("endstream"u8);
                    if (dict.Contains("/FlateDecode", StringComparison.Ordinal)
                        && !otherFilters.Any(f => dict.Contains(f, StringComparison.Ordinal))
                        && end > 0)
                    {
                        results.Add((i, pdf.AsSpan(dataStart, end).ToArray()));
                    }
                }
            }

            int found = pdf.AsSpan(next).IndexOf(keyword);
            i = found < 0 ? -1 : next + found;
        }

        return results;
    }

    private static bool IsStreamKeyword(byte[] pdf, int i)
    {
        int after = i + 6;
        if (after >= pdf.Length || (pdf[after] != '\r' && pdf[after] != '\n'))
        {
            return false;
        }

        int j = i - 1;
        while (j > 0 && pdf[j] is (byte)' ' or (byte)'\r' or (byte)'\n' or (byte)'\t')
        {
            j--;
        }

        return j > 0 && pdf[j] == '>' && pdf[j - 1] == '>';
    }

    /// <summary>A plain ASCII85 encoder (no <c>z</c>), only to build test input.</summary>
    private static string Ascii85Encode(byte[] data)
    {
        var sb = new StringBuilder();
        for (int i = 0; i < data.Length; i += 4)
        {
            int n = Math.Min(4, data.Length - i);
            uint value = 0;
            for (int k = 0; k < 4; k++)
            {
                value = (value << 8) | (k < n ? data[i + k] : 0u);
            }

            var digits = new char[5];
            for (int k = 4; k >= 0; k--)
            {
                digits[k] = (char)('!' + (value % 85));
                value /= 85;
            }

            sb.Append(digits, 0, n + 1);
        }

        return sb.ToString();
    }
}
