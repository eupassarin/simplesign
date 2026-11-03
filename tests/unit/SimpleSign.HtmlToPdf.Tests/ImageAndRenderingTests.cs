// Licensed to SimpleSign under the MIT License.

using System.Text;
using Shouldly;
using SimpleSign.HtmlToPdf.Rendering;
using Xunit;
using static SimpleSign.HtmlToPdf.Tests.TestSupport;

namespace SimpleSign.HtmlToPdf.Tests;

[Trait("Category", "Unit")]
public sealed class ImageAndRenderingTests
{
    // ── PNG decoding ─────────────────────────────────────────────────────

    [Fact]
    public void PngDecoder_Rgb8_DecodesOpaquePixels()
    {
        DecodedPng png = PngDecoder.Decode(RgbPng())!;

        png.Width.ShouldBe(2);
        png.ColorComponents.ShouldBe(3);
        png.Alpha.ShouldBeNull();
        png.Color[..3].ShouldBe([255, 0, 0]);
    }

    [Fact]
    public void PngDecoder_Rgba_ProducesAlphaPlane()
    {
        byte[] rgba = Png(1, 1, 6, 8, [10, 20, 30, 128]);

        DecodedPng png = PngDecoder.Decode(rgba)!;

        png.Color.ShouldBe([10, 20, 30]);
        png.Alpha.ShouldBe([128]);
    }

    [Fact]
    public void PngDecoder_PaletteWithTransparency_ExpandsToRgbAndAlpha()
    {
        byte[] palette = [255, 0, 0, 0, 0, 255];
        byte[] indexed = Png(2, 1, 3, 8, [0, 1], palette, transparency: [255, 0]);

        DecodedPng png = PngDecoder.Decode(indexed)!;

        png.Color.ShouldBe([255, 0, 0, 0, 0, 255]);
        png.Alpha.ShouldBe([255, 0]);
    }

    [Fact]
    public void PngDecoder_OneBitGray_ScalesToFullRange()
    {
        byte[] gray = Png(8, 1, 0, 1, [0b1010_0000]);

        DecodedPng png = PngDecoder.Decode(gray)!;

        png.ColorComponents.ShouldBe(1);
        png.Color.ShouldBe([255, 0, 255, 0, 0, 0, 0, 0]);
    }

    [Fact]
    public void PngDecoder_SixteenBit_UsesHighByte()
    {
        byte[] gray16 = Png(1, 1, 0, 16, [0xAB, 0xCD]);

        PngDecoder.Decode(gray16)!.Color.ShouldBe([0xAB]);
    }

    [Fact]
    public void PngDecoder_Garbage_ReturnsNull() =>
        PngDecoder.Decode([0x89, 0x50, 0x4E, 0x47, 1, 2, 3]).ShouldBeNull();

    [Fact]
    public void Convert_TranslucentPng_WritesSoftMask()
    {
        string src = DataUri(Png(1, 1, 6, 8, [10, 20, 30, 128]));

        string raw = Encoding.Latin1.GetString(HtmlToPdfConverter.Html($"<img src='{src}'>").Convert());

        raw.ShouldContain("/SMask ");
    }

    [Fact]
    public void Convert_OpaquePng_HasNoSoftMask()
    {
        string raw = Encoding.Latin1.GetString(HtmlToPdfConverter.Html($"<img src='{DataUri(RgbPng())}'>").Convert());

        raw.ShouldNotContain("/SMask ");
    }

    [Fact]
    public void Convert_SameImageTwice_IsEmbeddedOnce()
    {
        string src = DataUri(RgbPng());
        string raw = Encoding.Latin1.GetString(HtmlToPdfConverter.Html($"<img src='{src}'><img src='{src}'>").Convert());

        (raw.Length - raw.Replace("/Subtype /Image", string.Empty, StringComparison.Ordinal).Length).ShouldBe("/Subtype /Image".Length);
    }

    [Fact]
    public void ImageData_AdobeCmykJpeg_IsFlaggedForInvertedDecode()
    {
        byte[] jpeg =
        [
            0xFF, 0xD8,
            0xFF, 0xEE, 0x00, 0x0E, (byte)'A', (byte)'d', (byte)'o', (byte)'b', (byte)'e', 0, 100, 0, 0, 0, 0, 2,
            0xFF, 0xC0, 0x00, 0x14, 8, 0, 1, 0, 1, 4, 1, 0x11, 0, 2, 0x11, 0, 3, 0x11, 0, 4, 0x11, 0,
            0xFF, 0xD9,
        ];

        ImageData image = ImageData.Parse("data:image/jpeg;base64," + Convert.ToBase64String(jpeg))!;

        image.Components.ShouldBe(4);
        image.AdobeInverted.ShouldBeTrue();
    }

    [Fact]
    public void ImageData_ProgressiveJpeg_IsRecognized()
    {
        byte[] jpeg = [0xFF, 0xD8, 0xFF, 0xC2, 0x00, 0x0B, 8, 0, 3, 0, 4, 1, 1, 0x11, 0, 0xFF, 0xD9];

        ImageData image = ImageData.Parse("data:image/jpeg;base64," + Convert.ToBase64String(jpeg))!;

        image.Width.ShouldBe(4);
        image.Height.ShouldBe(3);
    }

    [Fact]
    public void ResourceLoader_PercentEncodedDataUri_IsDecoded() =>
        ResourceLoader.DecodeDataUri("data:text/css,p%20%7B%20color%3A%20red%20%7D").ShouldBe(Encoding.UTF8.GetBytes("p { color: red }"));

    // ── Vector output ────────────────────────────────────────────────────

    [Fact]
    public void Render_DashedBorder_SetsDashPattern()
    {
        string text = Decompressed(HtmlToPdfConverter.Html("<div style='border:2px dashed #000'>x</div>").Convert());

        text.ShouldContain("] 0 d");
    }

    [Fact]
    public void Render_DottedBorder_UsesRoundCaps()
    {
        string text = Decompressed(HtmlToPdfConverter.Html("<div style='border-bottom:2px dotted #000'>x</div>").Convert());

        text.ShouldContain("1 J");
    }

    [Fact]
    public void Render_BorderRadius_DrawsCurves()
    {
        string text = Decompressed(HtmlToPdfConverter.Html("<div style='border:1px solid #000;border-radius:8px;background:#eee'>x</div>").Convert());

        text.ShouldContain(" c\n");
    }

    [Fact]
    public void Render_BorderIsDrawnInsideBox()
    {
        // A 10pt top border on a box at the top margin: the stroke is centered 5pt below the box top.
        string text = Decompressed(HtmlToPdfConverter.Html("<div style='border-top:10pt solid #000'>x</div>").WithMargins(0).Convert());

        text.ShouldContain("836.89 m");
    }

    [Fact]
    public void Render_DiscBullet_IsFilledPathNotGlyph()
    {
        string text = Decompressed(HtmlToPdfConverter.Html("<ul><li>item</li></ul>").Convert());

        text.ShouldContain(" c\n");
        text.ShouldNotContain("\\225) Tj"); // the WinAnsi bullet glyph
    }

    [Fact]
    public void Render_InlineBackground_IsFilledBehindText()
    {
        string text = Decompressed(HtmlToPdfConverter.Html("<p>a <span style='background:#ff0000'>marked</span></p>").Convert());

        int fill = text.IndexOf("1.00 0.00 0.00 rg", StringComparison.Ordinal);
        int glyphs = text.IndexOf("(marked) Tj", StringComparison.Ordinal);
        fill.ShouldBeGreaterThan(0);
        fill.ShouldBeLessThan(glyphs);
    }

    [Fact]
    public void Render_VisibilityHidden_DrawsNothing()
    {
        string text = Decompressed(HtmlToPdfConverter.Html("<p style='visibility:hidden'>ghost</p>").Convert());

        text.ShouldNotContain("(ghost) Tj");
    }

    [Fact]
    public void Render_LinkedImage_HasLinkAnnotation()
    {
        string raw = Encoding.Latin1.GetString(HtmlToPdfConverter.Html($"<a href='https://x.y'><img src='{DataUri(RgbPng())}'></a>").Convert());

        raw.ShouldContain("/URI (https://x.y)");
    }

    [Fact]
    public void Render_UnmappableStandardCharacters_DoNotOverlap()
    {
        string text = Decompressed(HtmlToPdfConverter.Html("<p>Привет</p>").Convert());

        text.ShouldContain("(??????) Tj");
    }

    [Fact]
    public void SrgbProfile_HasValidIccHeader()
    {
        byte[] icc = SrgbProfile.Bytes;

        System.Buffers.Binary.BinaryPrimitives.ReadUInt32BigEndian(icc).ShouldBe((uint)icc.Length);
        Encoding.ASCII.GetString(icc, 36, 4).ShouldBe("acsp");
        Encoding.ASCII.GetString(icc, 16, 4).ShouldBe("RGB ");
    }
}
