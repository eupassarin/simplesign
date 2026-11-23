using Shouldly;
using SimpleSign.PAdES.Pdf.Model;
using Xunit;

namespace SimpleSign.PAdES.Tests.Pdf.Model;

/// <summary>
/// The PNG predictors (10–15) and TIFF predictor 2 of ISO 32000-1 §7.4.4.4. Every expected value is worked
/// out by hand in the comments, not by a second implementation.
/// </summary>
[Trait("Category", "Unit")]
public sealed class PdfPredictorsTests
{
    private static PdfDecodeParams Png(int columns, int colors = 1, int bpc = 8, int predictor = 12) =>
        new() { Predictor = predictor, Columns = columns, Colors = colors, BitsPerComponent = bpc };

    private static PdfDecodeParams Tiff(int columns, int colors = 1, int bpc = 8) =>
        new() { Predictor = 2, Columns = columns, Colors = colors, BitsPerComponent = bpc };

    [Fact]
    public void Decode_Predictor1_ReturnsSameArray()
    {
        byte[] data = [1, 2, 3];

        PdfPredictors.Decode(data, PdfDecodeParams.Default).ShouldBeSameAs(data);
    }

    [Fact]
    public void Decode_PngNoneSubUpAverage_ReversesEachRowFilter()
    {
        byte[] data =
        [
            0, 10, 20, 30, // None:    10 20 30
            1, 5, 5, 5,    // Sub:     5, 5+5=10, 5+10=15
            2, 1, 2, 3,    // Up:      1+5=6, 2+10=12, 3+15=18
            3, 4, 4, 4,    // Average: 4+(0+6)/2=7, 4+(7+12)/2=13, 4+(13+18)/2=19
        ];

        PdfPredictors.Decode(data, Png(columns: 3)).ShouldBe([
            10, 20, 30,
            5, 10, 15,
            6, 12, 18,
            7, 13, 19,
        ]);
    }

    [Fact]
    public void Decode_PngPaeth_PicksLeftAboveOrUpperLeft()
    {
        byte[] data =
        [
            0, 10, 10, 20, 30,
            // i0: a=0,   b=10, c=0  → p=10:  pa=10, pb=0,   pc=10  → b=10:  190+10  = 200
            // i1: a=200, b=10, c=10 → p=200: pa=0                  → a=200: 246+200 = 446 mod 256 = 190
            // i2: a=190, b=20, c=10 → p=200: pa=10, pb=180, pc=190 → a=190: 76+190  = 266 mod 256 = 10
            // i3: a=10,  b=30, c=20 → p=20:  pa=10, pb=10,  pc=0   → c=20:  5+20    = 25
            4, 190, 246, 76, 5,
        ];

        PdfPredictors.Decode(data, Png(columns: 4)).ShouldBe([10, 10, 20, 30, 200, 190, 10, 25]);
    }

    [Fact]
    public void Decode_PngFirstRowPaeth_TreatsRowAboveAsZero()
    {
        // No row above: b = c = 0, so Paeth is a (the left byte) — the same as Sub.
        byte[] data = [4, 7, 1, 1];

        PdfPredictors.Decode(data, Png(columns: 3)).ShouldBe([7, 8, 9]);
    }

    [Fact]
    public void Decode_PngSubWithThreeColors_StepsBackOnePixel()
    {
        // Colors 3 × 8 bits: a pixel is 3 bytes, so Sub adds the byte 3 positions to the left.
        byte[] data = [1, 1, 2, 3, 10, 20, 30];

        PdfPredictors.Decode(data, Png(columns: 2, colors: 3)).ShouldBe([1, 2, 3, 11, 22, 33]);
    }

    [Fact]
    public void Decode_PngSixteenBitSub_StepsBackTwoBytesModulo256()
    {
        // 16 bits: a pixel is 2 bytes; PNG filters work on bytes: 0+1 = 1, 2+255 = 257 mod 256 = 1.
        byte[] data = [1, 0x01, 0xFF, 0x00, 0x02];

        PdfPredictors.Decode(data, Png(columns: 2, bpc: 16)).ShouldBe([0x01, 0xFF, 0x01, 0x01]);
    }

    [Fact]
    public void Decode_PngUpOverflow_WrapsModulo256()
    {
        byte[] data = [0, 250, 2, 2, 10, 255];

        PdfPredictors.Decode(data, Png(columns: 2)).ShouldBe([250, 2, 4, 1]);
    }

    [Fact]
    public void Decode_PngOneBitRows_UsesBytesPerRowRoundedUp()
    {
        // 10 columns × 1 bit = 2 bytes a row; a pixel counts as 1 byte.
        byte[] data = [0, 0xAA, 0xC0, 2, 0x01, 0x01];

        PdfPredictors.Decode(data, Png(columns: 10, bpc: 1)).ShouldBe([0xAA, 0xC0, 0xAB, 0xC1]);
    }

    [Theory]
    [InlineData(10)]
    [InlineData(11)]
    [InlineData(12)]
    [InlineData(13)]
    [InlineData(14)]
    [InlineData(15)]
    public void Decode_AnyPngPredictor_FollowsEachRowTag(int predictor)
    {
        // The value 10–15 only says "PNG"; the tag of each row decides.
        byte[] data = [2, 1, 1, 1, 9, 9];

        PdfPredictors.Decode(data, Png(columns: 2, predictor: predictor)).ShouldBe([1, 1, 9, 18]);
    }

    [Fact]
    public void Decode_PngTruncatedLastRow_DecodesWhatIsThere()
    {
        byte[] data = [0, 10, 20, 30, 2, 1];

        PdfPredictors.Decode(data, Png(columns: 3)).ShouldBe([10, 20, 30, 11]);
    }

    [Fact]
    public void Decode_PngUnknownRowTag_Throws()
    {
        byte[] data = [0, 1, 2, 5, 1, 2];

        Should.Throw<PdfFilterException>(() => PdfPredictors.Decode(data, Png(columns: 2)))
            .FilterName.ShouldBe("FlateDecode");
    }

    [Fact]
    public void Decode_PngEmptyData_ReturnsEmpty() => PdfPredictors.Decode([], Png(columns: 4)).ShouldBeEmpty();

    [Fact]
    public void Decode_TiffEightBitsThreeColors_AddsSameComponentOfLeftPixel()
    {
        byte[] data =
        [
            10, 20, 30, 1, 2, 3,      // 10 20 30 | 11 22 33
            5, 5, 5, 250, 10, 200,    // rows are independent: 5 5 5 | 255 15 205
        ];

        PdfPredictors.Decode(data, Tiff(columns: 2, colors: 3)).ShouldBe([
            10, 20, 30, 11, 22, 33,
            5, 5, 5, 255, 15, 205,
        ]);
    }

    [Fact]
    public void Decode_TiffEightBitsOverflow_WrapsModulo256()
    {
        byte[] data = [200, 100, 0];

        PdfPredictors.Decode(data, Tiff(columns: 3)).ShouldBe([200, 44, 44]);
    }

    [Fact]
    public void Decode_TiffSixteenBits_AddsBigEndianSamplesModulo65536()
    {
        // 0x0100, then 0xFF10 + 0x0100 = 0x10010 mod 0x10000 = 0x0010.
        byte[] data = [0x01, 0x00, 0xFF, 0x10];

        PdfPredictors.Decode(data, Tiff(columns: 2, bpc: 16)).ShouldBe([0x01, 0x00, 0x00, 0x10]);
    }

    [Fact]
    public void Decode_TiffFourBits_AddsNibblesModulo16()
    {
        // Samples 1 2 3 15 → 1, 1+2=3, 3+3=6, 6+15=21 mod 16=5 → 0x13 0x65.
        byte[] data = [0x12, 0x3F];

        PdfPredictors.Decode(data, Tiff(columns: 4, bpc: 4)).ShouldBe([0x13, 0x65]);
    }

    [Fact]
    public void Decode_TiffOneBit_XorsWithLeftBit()
    {
        // Bits 1 0 0 1 0 0 0 0 → running sum mod 2: 1 1 1 0 0 0 0 0.
        byte[] data = [0x90];

        PdfPredictors.Decode(data, Tiff(columns: 8, bpc: 1)).ShouldBe([0xE0]);
    }

    [Fact]
    public void Decode_TiffTwoBitsTwoColors_KeepsPaddingBits()
    {
        // Pixels (1,2) (3,3) (2,1): 01 10 11 11 | 10 01 00 00 = 0x6F 0x90.
        // Decoded (1,2) (1+3, 2+3) mod 4 = (0,1) (0+2, 1+1) = (2,2): 01 10 00 01 | 10 10 00 00 = 0x61 0xA0.
        byte[] data = [0x6F, 0x90];

        PdfPredictors.Decode(data, Tiff(columns: 3, colors: 2, bpc: 2)).ShouldBe([0x61, 0xA0]);
    }

    [Fact]
    public void Decode_TiffDoesNotChangeInput()
    {
        byte[] data = [1, 1, 1];

        PdfPredictors.Decode(data, Tiff(columns: 3)).ShouldBe([1, 2, 3]);
        data.ShouldBe([1, 1, 1]);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(3)]
    [InlineData(9)]
    [InlineData(16)]
    public void Decode_UndefinedPredictor_Throws(int predictor) =>
        Should.Throw<PdfFilterException>(() => PdfPredictors.Decode([1, 2], new PdfDecodeParams { Predictor = predictor }));

    [Theory]
    [InlineData(0, 8, 1)]
    [InlineData(1, 3, 1)]
    [InlineData(1, 32, 1)]
    [InlineData(1, 8, 0)]
    [InlineData(int.MaxValue, 16, int.MaxValue)]
    public void Decode_ParametersOutOfRange_Throws(int colors, int bpc, int columns) =>
        Should.Throw<PdfFilterException>(() => PdfPredictors.Decode([0, 1], Png(columns, colors, bpc)));
}
