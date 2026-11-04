using System.Buffers.Binary;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using Shouldly;
using SimpleSign.Core.Crypto;
using SimpleSign.Core.Validation;
using SimpleSign.PAdES.Signing;
using SimpleSign.PAdES.Validation;
using SimpleSign.Pdf.Enums;
using Xunit;

namespace SimpleSign.PAdES.Tests.Signing;

/// <summary>
/// Tests for the customizable labels, date format, layout and image handling of <see cref="SignatureAppearance"/>.
/// </summary>
[Trait("Category", "Unit")]
public sealed class SignatureAppearanceCustomizationTests
{
    private static readonly DateTime SampleTime = new(2025, 6, 15, 14, 30, 0, DateTimeKind.Utc);
    private static readonly TimeZoneInfo Brt = TimeZoneInfo.CreateCustomTimeZone("BRT", TimeSpan.FromHours(-3), "BRT", "BRT");

    // ── Labels ──────────────────────────────────────────────────────────

    [Fact(DisplayName = "Default labels keep the English stamp text")]
    public void Render_DefaultLabels_KeepsEnglishText()
    {
        string content = Render(new SignatureAppearance { ShowReason = true, ShowLocation = true }, reason: "Approval", location: "Vitoria");

        content.ShouldContain("(Signed by) Tj");
        content.ShouldContain("(15/06/2025 14:30 UTC) Tj");
        content.ShouldContain("(Reason: Approval) Tj");
        content.ShouldContain("(Location: Vitoria) Tj");
    }

    [Fact(DisplayName = "SignedByLabel replaces 'Signed by'")]
    public void Render_CustomSignedByLabel_ReplacesDefault()
    {
        string content = Render(new SignatureAppearance { SignedByLabel = "Assinado digitalmente por" });

        content.ShouldContain("(Assinado digitalmente por) Tj");
        content.ShouldNotContain("Signed by");
    }

    [Fact(DisplayName = "Empty SignedByLabel removes the first line")]
    public void Render_EmptySignedByLabel_OmitsLine()
    {
        var app = new SignatureAppearance { SignedByLabel = string.Empty };

        app.LineCount(hasReason: false, hasLocation: false).ShouldBe(2); // name + date
        string content = Render(app);
        content.ShouldNotContain("Signed by");
        content.ShouldContain("(Maria Silva) Tj");
    }

    [Fact(DisplayName = "Reason, location and date labels are customizable")]
    public void Render_CustomFieldLabels_AreUsed()
    {
        var app = new SignatureAppearance
        {
            ShowReason = true,
            ShowLocation = true,
            ReasonLabel = "Motivo: ",
            LocationLabel = "Local: ",
            DateLabel = "Data: ",
        };

        string content = Render(app, reason: "Aprovação", location: "Vitória/ES");

        content.ShouldContain("(Motivo: Aprovação) Tj");
        content.ShouldContain("(Local: Vitória/ES) Tj");
        content.ShouldContain("(Data: 15/06/2025 14:30 UTC) Tj");
    }

    [Fact(DisplayName = "WithLabels returns a clone with the new labels and keeps other settings")]
    public void WithLabels_ReturnsCloneKeepingSettings()
    {
        var original = SignatureAppearance.Auto(showReason: true, showLocation: false);

        var clone = original.WithLabels(signedBy: "Assinado por", reason: "Motivo: ");

        clone.ShouldNotBeSameAs(original);
        clone.SignedByLabel.ShouldBe("Assinado por");
        clone.ReasonLabel.ShouldBe("Motivo: ");
        clone.LocationLabel.ShouldBe("Location: ");
        clone.AutoPosition.ShouldBeTrue();
        clone.ShowReason.ShouldBeTrue();
        original.SignedByLabel.ShouldBe("Signed by");
    }

    [Fact(DisplayName = "Clone methods copy every customization")]
    public void WithExtraLines_CopiesNewProperties()
    {
        var app = new SignatureAppearance
        {
            SignedByLabel = "Assinado por",
            SignerDisplayName = "Dra. Maria",
            ReasonLabel = "Motivo: ",
            LocationLabel = "Local: ",
            DateLabel = "Em ",
            DateFormat = "yyyy",
            TimeZone = Brt,
            MaxTextLength = 12,
            Width = 150,
            Height = 60,
            BackgroundColor = (1f, 1f, 0.9f),
            BackgroundImageFit = SignatureImageFit.Contain,
        };

        var clone = app.WithExtraLines(["CPF: ***"]);

        clone.SignedByLabel.ShouldBe("Assinado por");
        clone.SignerDisplayName.ShouldBe("Dra. Maria");
        clone.ReasonLabel.ShouldBe("Motivo: ");
        clone.LocationLabel.ShouldBe("Local: ");
        clone.DateLabel.ShouldBe("Em ");
        clone.DateFormat.ShouldBe("yyyy");
        clone.TimeZone.ShouldBe(Brt);
        clone.MaxTextLength.ShouldBe(12);
        clone.Width.ShouldBe(150);
        clone.Height.ShouldBe(60);
        clone.BackgroundColor.ShouldBe((1f, 1f, 0.9f));
        clone.BackgroundImageFit.ShouldBe(SignatureImageFit.Contain);
        clone.ExtraLines.ShouldBe(["CPF: ***"]);
    }

    [Fact(DisplayName = "SignerDisplayName overrides the name shown in the stamp")]
    public void Render_SignerDisplayName_OverridesSignerName()
    {
        string content = Render(new SignatureAppearance { SignerDisplayName = "Dra. Maria S." });

        content.ShouldContain("(Dra. Maria S.) Tj");
        content.ShouldNotContain("(Maria Silva) Tj");
    }

    // ── Date ────────────────────────────────────────────────────────────

    [Fact(DisplayName = "TimeZone converts the date and shows the UTC offset")]
    public void FormatDate_TimeZone_ShowsLocalTimeAndOffset()
    {
        var app = new SignatureAppearance { TimeZone = Brt };

        app.FormatDate(SampleTime).ShouldBe("15/06/2025 11:30 UTC-03:00");
    }

    [Fact(DisplayName = "DateFormat is applied after the time zone conversion")]
    public void FormatDate_CustomFormat_UsesFormatAndZone()
    {
        var app = new SignatureAppearance().WithDateFormat("yyyy-MM-dd HH:mm:ss zzz", Brt);

        app.FormatDate(SampleTime).ShouldBe("2025-06-15 11:30:00 -03:00");
    }

    [Fact(DisplayName = "Positive offsets are formatted with a plus sign")]
    public void FormatDate_PositiveOffset_HasPlusSign()
    {
        var zone = TimeZoneInfo.CreateCustomTimeZone("IST", new TimeSpan(5, 30, 0), "IST", "IST");
        var app = new SignatureAppearance { TimeZone = zone };

        app.FormatDate(SampleTime).ShouldBe("15/06/2025 20:00 UTC+05:30");
    }

    // ── Text handling and layout ────────────────────────────────────────

    [Fact(DisplayName = "Characters outside the font are replaced with readable equivalents")]
    public void Render_UnsupportedCharacters_AreReplaced()
    {
        var options = new SignatureFieldOptions
        {
            SignerName = "Łukasz Nowak – Őrs “dev” \U0001F600",
            Appearance = new SignatureAppearance(),
        };

        string content = Render(options);

        content.ShouldContain("(Lukasz Nowak - Ors \"dev\" ?) Tj");
    }

    [Fact(DisplayName = "Latin-1 accents are kept as they are")]
    public void ToEncodable_Latin1Accents_AreKept() =>
        AppearanceText.ToEncodable("João Conceição").ShouldBe("João Conceição");

    [Fact(DisplayName = "MaxTextLength controls truncation")]
    public void Render_MaxTextLength_ControlsTruncation()
    {
        string longName = new('A', 60);

        Render(new SignatureFieldOptions { SignerName = longName, Appearance = new SignatureAppearance { MaxTextLength = 0 } })
            .ShouldContain($"({longName}) Tj");
        Render(new SignatureFieldOptions { SignerName = longName, Appearance = new SignatureAppearance { MaxTextLength = 10 } })
            .ShouldContain("(AAAAAAA...) Tj");
    }

    [Fact(DisplayName = "Stamp width follows the font size")]
    public void ComputeWidth_LargerFont_IsWider()
    {
        float normal = new SignatureAppearance().ComputeWidth("Maria da Silva Pereira", null, null, SampleTime);
        float large = new SignatureAppearance { CustomFontSize = 14 }.ComputeWidth("Maria da Silva Pereira", null, null, SampleTime);

        large.ShouldBeGreaterThan(normal * 1.5f);
    }

    [Fact(DisplayName = "Stamp width fits the measured text")]
    public void ComputeWidth_MatchesMeasuredText()
    {
        var app = new SignatureAppearance { ShowDate = false, SignedByLabel = string.Empty };

        // "WWWW" in Helvetica 7pt = 4 × 944/1000 × 7 = 26.43pt, plus 4pt padding on each side.
        app.ComputeWidth("WWWW", null, null, SampleTime).ShouldBe(34.43f, 0.01f);
    }

    [Fact(DisplayName = "Courier is measured as a monospaced font")]
    public void Measure_Courier_IsMonospaced()
    {
        AppearanceText.Measure("iiii", "Courier", 10).ShouldBe(AppearanceText.Measure("WWWW", "Courier", 10));
        AppearanceText.Measure("iiii", "Helvetica", 10).ShouldBeLessThan(AppearanceText.Measure("WWWW", "Helvetica", 10));
    }

    [Fact(DisplayName = "Line height grows with large fonts so lines do not overlap")]
    public void ComputeHeight_LargeFont_GrowsLineHeight()
    {
        float normal = new SignatureAppearance().ComputeHeight(false, false);
        float large = new SignatureAppearance { CustomFontSize = 20, CustomLabelFontSize = 16 }.ComputeHeight(false, false);

        normal.ShouldBe(34f); // 3 lines × 10pt + 4pt padding (unchanged default)
        large.ShouldBe(4f + 20f + 25f + 20f);
    }

    [Fact(DisplayName = "Fixed Width and Height override the computed size")]
    public void ComputeSize_FixedWidthAndHeight_AreUsed()
    {
        var app = new SignatureAppearance { Width = 200, Height = 70, VerificationUrl = "https://example.com/v" };

        app.ComputeWidth("Maria", null, null, SampleTime).ShouldBe(200f);
        app.ComputeHeight(false, false).ShouldBe(70f);
    }

    [Fact(DisplayName = "Reason and extra lines use the label font size even without the date")]
    public void Render_NoDate_ReasonUsesLabelFont()
    {
        var app = new SignatureAppearance { ShowDate = false, ShowReason = true, CustomFontSize = 9, CustomLabelFontSize = 5 };

        string content = Render(app, reason: "Ok");

        int reason = content.IndexOf("(Reason: Ok) Tj", StringComparison.Ordinal);
        int lastFont = content.LastIndexOf("/F1 ", reason, StringComparison.Ordinal);
        content[lastFont..reason].ShouldStartWith("/F1 5.00 Tf");
    }

    // ── Background, border and images ───────────────────────────────────

    [Fact(DisplayName = "BackgroundColor fills the stamp and the border is drawn last")]
    public void Render_BackgroundColorAndBorder_DrawOrder()
    {
        var app = new SignatureAppearance { BackgroundColor = (0.9f, 0.95f, 1f), BorderColor = (0f, 0f, 0.5f), Width = 120, Height = 40 };

        string content = Render(app);

        int fill = content.IndexOf("0.90 0.95 1.00 rg\n0 0 120.00 40.00 re f", StringComparison.Ordinal);
        int text = content.IndexOf("BT", StringComparison.Ordinal);
        int border = content.IndexOf(" re S", StringComparison.Ordinal);
        fill.ShouldBeGreaterThan(0);
        text.ShouldBeGreaterThan(fill);
        border.ShouldBeGreaterThan(content.IndexOf("ET", StringComparison.Ordinal));
    }

    [Fact(DisplayName = "Border is drawn over the background image")]
    public void Render_BorderWithImage_BorderAfterImage()
    {
        var app = new SignatureAppearance { BorderColor = (0f, 0f, 0f), BackgroundImagePng = TestPng.Rgb(2, 2) };

        string content = Render(app, imageObjNum: 11);

        content.IndexOf(" re S", StringComparison.Ordinal).ShouldBeGreaterThan(content.IndexOf("/Img0 Do", StringComparison.Ordinal));
    }

    [Theory(DisplayName = "Image fit modes place the image correctly")]
    [InlineData(SignatureImageFit.Stretch, "200.00 0 0 50.00 0.00 0.00 cm", false)]
    [InlineData(SignatureImageFit.Contain, "100.00 0 0 50.00 50.00 0.00 cm", false)]
    [InlineData(SignatureImageFit.Cover, "200.00 0 0 100.00 0.00 -25.00 cm", true)]
    public void Render_ImageFit_PlacesImage(SignatureImageFit fit, string expectedMatrix, bool clipped)
    {
        var app = new SignatureAppearance { Width = 200, Height = 50, BackgroundImageFit = fit, BackgroundImagePng = TestPng.Rgb(4, 2) };

        string content = Render(app, imageObjNum: 11);

        content.ShouldContain(expectedMatrix);
        content.Contains("re W n", StringComparison.Ordinal).ShouldBe(clipped);
    }

    [Fact(DisplayName = "RGBA PNG is embedded with a soft mask holding the alpha channel")]
    public void Render_RgbaPng_EmbedsSoftMask()
    {
        byte[] png = TestPng.Rgba(3, 2, (x, y) => ((byte)(x * 80), (byte)(y * 100), 7, (byte)((x * 100) + y)));
        var app = new SignatureAppearance { BackgroundImagePng = png };

        byte[] bytes = RenderBytes(app, imageObjNum: 11, softMaskObjNum: 14);
        string content = Encoding.Latin1.GetString(bytes);

        content.ShouldContain("/SMask 14 0 R");
        content.ShouldContain("14 0 obj");
        content.ShouldNotContain("/Predictor");
        Inflate(StreamOf(bytes, 11)).ShouldBe([0, 0, 7, 80, 0, 7, 160, 0, 7, 0, 100, 7, 80, 100, 7, 160, 100, 7]);
        Inflate(StreamOf(bytes, 14)).ShouldBe([0, 100, 200, 1, 101, 201]);
    }

    [Fact(DisplayName = "Gray+alpha PNG is embedded as DeviceGray with a soft mask")]
    public void Render_GrayAlphaPng_EmbedsSoftMask()
    {
        byte[] png = TestPng.GrayAlpha(2, 1, [10, 255, 20, 0]);

        byte[] bytes = RenderBytes(new SignatureAppearance { BackgroundImagePng = png }, imageObjNum: 11, softMaskObjNum: 14);

        Encoding.Latin1.GetString(bytes).ShouldContain("/ColorSpace /DeviceGray");
        Inflate(StreamOf(bytes, 11)).ShouldBe([10, 20]);
        Inflate(StreamOf(bytes, 14)).ShouldBe([255, 0]);
    }

    [Fact(DisplayName = "Palette PNG with tRNS uses an Indexed color space and a soft mask")]
    public void Render_PalettePngWithTransparency_IndexedWithSoftMask()
    {
        byte[] png = TestPng.Palette(width: 3, height: 1, bitDepth: 4, palette: [255, 0, 0, 0, 0, 255], trns: [0], indices: [1, 0, 1]);

        byte[] bytes = RenderBytes(new SignatureAppearance { BackgroundImagePng = png }, imageObjNum: 11, softMaskObjNum: 14);
        string content = Encoding.Latin1.GetString(bytes);

        content.ShouldContain("/ColorSpace [/Indexed /DeviceRGB 1 <FF00000000FF>]");
        content.ShouldContain("/BitsPerComponent 4");
        content.ShouldContain("/SMask 14 0 R");
        Inflate(StreamOf(bytes, 14)).ShouldBe([255, 0, 255]);
    }

    [Fact(DisplayName = "Palette PNG without tRNS has no soft mask")]
    public void Render_PalettePngOpaque_NoSoftMask()
    {
        byte[] png = TestPng.Palette(width: 2, height: 2, bitDepth: 8, palette: [1, 2, 3], trns: null, indices: [0, 0, 0, 0]);

        string content = Encoding.Latin1.GetString(RenderBytes(new SignatureAppearance { BackgroundImagePng = png }, imageObjNum: 11, softMaskObjNum: 14));

        content.ShouldContain("/Indexed");
        content.ShouldNotContain("/SMask");
    }

    [Fact(DisplayName = "16-bit PNG is still rejected")]
    public void Render_SixteenBitPng_Throws()
    {
        byte[] png = TestPng.Raw(1, 1, bitDepth: 16, colorType: 2, scanlines: [0, 0, 0, 0, 0, 0, 0]);

        Should.Throw<NotSupportedException>(() => RenderBytes(new SignatureAppearance { BackgroundImagePng = png }, imageObjNum: 11));
    }

    [Fact(DisplayName = "Truncated PNG image data throws ArgumentException")]
    public void Render_TruncatedAlphaPng_Throws()
    {
        byte[] png = TestPng.Raw(4, 4, bitDepth: 8, colorType: 6, scanlines: [0, 1, 2, 3, 4]);

        Should.Throw<ArgumentException>(() => RenderBytes(new SignatureAppearance { BackgroundImagePng = png }, imageObjNum: 11));
    }

    [Fact(DisplayName = "Grayscale JPEG uses DeviceGray")]
    public void ReadJpegInfo_Grayscale_HasOneComponent()
    {
        byte[] jpeg = TestJpeg.Header(width: 40, height: 20, components: 1, adobe: false);

        AppearanceImage.ReadJpegInfo(jpeg).ShouldBe((40, 20, 1, false));
        Encoding.Latin1.GetString(RenderBytes(new SignatureAppearance { BackgroundImageJpeg = jpeg }, imageObjNum: 11))
            .ShouldContain("/ColorSpace /DeviceGray");
    }

    [Fact(DisplayName = "Adobe CMYK JPEG uses DeviceCMYK with an inverted Decode array")]
    public void Render_AdobeCmykJpeg_DeviceCmykInverted()
    {
        byte[] jpeg = TestJpeg.Header(width: 8, height: 8, components: 4, adobe: true);

        string content = Encoding.Latin1.GetString(RenderBytes(new SignatureAppearance { BackgroundImageJpeg = jpeg }, imageObjNum: 11));

        content.ShouldContain("/ColorSpace /DeviceCMYK");
        content.ShouldContain("/Decode [1 0 1 0 1 0 1 0]");
        content.ShouldContain("/Width 8");
    }

    [Fact(DisplayName = "SOF marker bytes inside an earlier segment are not mistaken for the frame header")]
    public void ReadJpegInfo_SofBytesInsideAppSegment_AreSkipped()
    {
        byte[] header = TestJpeg.Header(width: 300, height: 200, components: 3, adobe: false);
        byte[] app1 = [0xFF, 0xE1, 0x00, 0x0B, 0xFF, 0xC0, 0x00, 0x11, 0x08, 0x00, 0x01, 0x00, 0x01];
        byte[] jpeg = [.. header[..2], .. app1, .. header[2..]];

        AppearanceImage.ReadJpegInfo(jpeg).ShouldBe((300, 200, 3, false));
    }

    // ── Fonts, alignment and shrink-to-fit ──────────────────────────────

    [Fact(DisplayName = "Times and Helvetica-Bold use their own character widths")]
    public void Measure_Base14Fonts_UseOwnWidths()
    {
        const string text = "Maria da Silva";
        float helvetica = AppearanceText.Measure(text, "Helvetica", 10);

        AppearanceText.Measure(text, "Times-Roman", 10).ShouldBeLessThan(helvetica);
        AppearanceText.Measure(text, "Helvetica-Bold", 10).ShouldBeGreaterThan(helvetica);
        AppearanceText.Measure(text, "Times-Bold", 10).ShouldBeGreaterThan(AppearanceText.Measure(text, "Times-Roman", 10));

        // "M" is 889/1000 in Times-Roman and 833/1000 in Helvetica-Bold (Adobe AFM).
        AppearanceText.Measure("M", "Times-Roman", 10).ShouldBe(8.89f, 0.001f);
        AppearanceText.Measure("M", "Helvetica-Bold", 10).ShouldBe(8.33f, 0.001f);
    }

    [Theory(DisplayName = "Text alignment places each line in the text area")]
    [InlineData(SignatureTextAlignment.Left)]
    [InlineData(SignatureTextAlignment.Center)]
    [InlineData(SignatureTextAlignment.Right)]
    public void Layout_TextAlignment_PositionsLines(SignatureTextAlignment alignment)
    {
        var app = new SignatureAppearance { Width = 200, Height = 40, TextAlignment = alignment, ShowDate = false };

        var lines = app.Layout("Maria", null, null, SampleTime, 200, 40);

        var name = lines.Single(l => l.Text == "Maria");
        float width = AppearanceText.Measure("Maria", "Helvetica", 7);
        float expected = alignment switch
        {
            SignatureTextAlignment.Center => 3 + ((192 - width) / 2),
            SignatureTextAlignment.Right => 195 - width,
            _ => 3,
        };
        name.X.ShouldBe(expected, 0.01f);
    }

    [Theory(DisplayName = "Vertical alignment places the text block in a tall stamp")]
    [InlineData(SignatureVerticalAlignment.Top, 90f)]
    [InlineData(SignatureVerticalAlignment.Middle, 52f)]
    [InlineData(SignatureVerticalAlignment.Bottom, 14f)]
    public void Layout_VerticalAlignment_PositionsBlock(SignatureVerticalAlignment alignment, float firstBaseline)
    {
        // 2 lines of 10pt in a 100pt stamp with 4pt bottom padding: free space is 76pt.
        var app = new SignatureAppearance { Height = 100, VerticalAlignment = alignment, ShowDate = false };

        var lines = app.Layout("Maria", null, null, SampleTime, 120, 100);

        lines[0].Y.ShouldBe(firstBaseline, 0.01f);
        lines[1].Y.ShouldBe(firstBaseline - 10, 0.01f);
    }

    [Fact(DisplayName = "Text is centered next to the QR code")]
    public void Layout_CenterWithQr_StaysRightOfQr()
    {
        var app = new SignatureAppearance { Width = 220, VerificationUrl = "https://example.com/v", TextAlignment = SignatureTextAlignment.Center };
        float height = app.ComputeHeight(false, false);

        var lines = app.Layout("Maria", null, null, SampleTime, 220, height);

        float qrRight = SignatureAppearance.QrSize(height) + 2;
        lines.ShouldAllBe(l => l.X > qrRight);
    }

    [Fact(DisplayName = "ShrinkToFit scales long text down to a fixed width")]
    public void Layout_ShrinkToFit_FitsFixedWidth()
    {
        string name = "Maria da Conceição Pereira dos Santos";
        var app = new SignatureAppearance { Width = 90, Height = 40 };

        var lines = app.Layout(name, null, null, SampleTime, 90, 40);

        var nameLine = lines.Single(l => l.Text == name);
        nameLine.FontSize.ShouldBeLessThan(7f);
        (nameLine.X + AppearanceText.Measure(name, "Helvetica", nameLine.FontSize)).ShouldBeLessThanOrEqualTo(85.01f);
        lines.ShouldAllBe(l => l.Y >= 0);
    }

    [Fact(DisplayName = "ShrinkToFit scales text down to a fixed height")]
    public void Layout_ShrinkToFit_FitsFixedHeight()
    {
        var app = new SignatureAppearance { Width = 300, Height = 20 };

        var lines = app.Layout("Maria", null, null, SampleTime, 300, 20);

        lines[^1].Y.ShouldBeGreaterThanOrEqualTo(3.99f);
        lines[0].FontSize.ShouldBeLessThan(6f);
    }

    [Fact(DisplayName = "ShrinkToFit=false keeps the font size and lets the stamp clip")]
    public void Layout_ShrinkToFitDisabled_KeepsSize()
    {
        var app = new SignatureAppearance { Width = 40, Height = 20, ShrinkToFit = false };

        var lines = app.Layout("Maria da Conceição Pereira", null, null, SampleTime, 40, 20);

        lines.Select(l => l.FontSize).ShouldBe([6f, 7f, 6f]);
    }

    [Fact(DisplayName = "Computed stamps are not shrunk")]
    public void Layout_ComputedSize_KeepsFontSizes()
    {
        var app = new SignatureAppearance { ShowReason = true, ExtraLines = ["CPF: ***.456.789-**"] };
        string signer = "Maria da Conceição Pereira";
        float width = app.ComputeWidth(signer, "Aprovação", null, SampleTime);
        float height = app.ComputeHeight(true, false);

        var lines = app.Layout(signer, "Aprovação", null, SampleTime, width, height);

        lines.Select(l => l.FontSize).ShouldBe([6f, 7f, 6f, 6f, 6f]);
    }

    // ── PDF text strings ────────────────────────────────────────────────

    [Theory(DisplayName = "PDFDocEncoding-safe text is written as a literal string")]
    [InlineData("Maria Silva", "(Maria Silva)")]
    [InlineData("João (Diretor)", "(João \\(Diretor\\))")]
    public void PdfTextString_LiteralSafe_WritesLiteral(string text, string expected) =>
        PdfTextString.Encode(text).ShouldBe(expected);

    [Theory(DisplayName = "Text outside PDFDocEncoding is written as UTF-16BE")]
    [InlineData("Łukasz", "<FEFF01410075006B00610073007A>")]
    [InlineData("10 €", "<FEFF00310030002020AC>")]
    [InlineData("a\u00ADb", "<FEFF006100AD0062>")]
    public void PdfTextString_NonLatin_WritesUtf16(string text, string expected) =>
        PdfTextString.Encode(Regex.Unescape(text)).ShouldBe(expected);

    [Fact(DisplayName = "Signer name, reason, location and field name with non-Latin characters survive a round trip")]
    public async Task SignAsync_NonLatinTextEntries_RoundTrip()
    {
        using X509Certificate2 cert = CreateRsaCert();
        const string name = "Łukasz Żółć";
        const string reason = "Zatwierdzenie – wersja «final» €";
        const string location = "Kraków, Ελλάδα";

        byte[] signed = await PadesSigner.Document(BuildPdfWithPage()).WithCertificate(cert)
            .WithTestFieldOptions(name, reason, location)
            .WithFieldName("Podpis-Ł")
            .WithAppearance(new SignatureAppearance { ShowReason = true, ShowLocation = true })
            .SignAsync();

        using var stream = new MemoryStream(signed);
        var fields = await Pdf.PdfStructureReader.ReadSignatureFieldsAsync(stream);
        fields.Count.ShouldBe(1);
        fields[0].SignerName.ShouldBe(name);
        fields[0].Reason.ShouldBe(reason);
        fields[0].Location.ShouldBe(location);
        fields[0].FieldName.ShouldBe("Podpis-Ł");

        // The stamp itself falls back to Latin-1 text.
        Encoding.Latin1.GetString(signed).ShouldContain("(Lukasz Zólc) Tj");
    }

    // ── PDF/A ───────────────────────────────────────────────────────────

    [Fact(DisplayName = "PDF/A-1 accepts an opaque PNG and rejects one with alpha")]
    public void PdfAValidator_PdfA1_OnlyRejectsTransparentPng()
    {
        var opaque = new SignatureFieldOptions { SubFilter = PdfSignatureSubFilter.AdbePkcs7Detached, Appearance = new SignatureAppearance { BackgroundImagePng = TestPng.Rgb(2, 2) } };
        var alpha = new SignatureFieldOptions { SubFilter = PdfSignatureSubFilter.AdbePkcs7Detached, Appearance = new SignatureAppearance { BackgroundImagePng = TestPng.Rgba(1, 1, (_, _) => (0, 0, 0, 0)) } };

        PdfAPreservationValidator.Validate(PdfALevel.A1b, opaque).ShouldBeEmpty();
        PdfAPreservationValidator.Validate(PdfALevel.A1b, alpha).ShouldContain(i => i.Severity == PdfAIssueSeverity.Error);
        PdfAPreservationValidator.Validate(PdfALevel.A2b, alpha).ShouldBeEmpty();
    }

    // ── End to end ──────────────────────────────────────────────────────

    [Fact(DisplayName = "Signed PDF with custom labels and a transparent PNG is valid and its xref points at the soft mask")]
    public async Task SignAsync_CustomLabelsAndTransparentPng_IsValid()
    {
        using X509Certificate2 cert = CreateRsaCert();
        byte[] png = TestPng.Rgba(8, 4, (x, y) => (0, 0, 128, (byte)(x * 30)));

        byte[] signed = await PadesSigner.Document(BuildPdfWithPage()).WithCertificate(cert)
            .WithTestFieldOptions("Maria Silva", "Aprovação")
            .WithAppearance(new SignatureAppearance
            {
                X = 30,
                Y = 30,
                ShowReason = true,
                BackgroundImagePng = png,
                BackgroundImageFit = SignatureImageFit.Contain,
                BackgroundColor = (1f, 1f, 1f),
                TimeZone = Brt,
            }.WithLabels("Assinado digitalmente por", "Motivo: "))
            .SignAsync();

        string text = Encoding.Latin1.GetString(signed);
        text.ShouldContain("(Assinado digitalmente por) Tj");
        text.ShouldContain("(Motivo: Aprovação) Tj");
        text.ShouldContain("/Name (Maria Silva)");

        var smask = Regex.Match(text, @"/SMask (\d+) 0 R");
        smask.Success.ShouldBeTrue();
        int smaskObj = int.Parse(smask.Groups[1].Value, System.Globalization.CultureInfo.InvariantCulture);
        long offset = XrefOffset(text, smaskObj);
        text.Substring((int)offset, $"{smaskObj} 0 obj".Length).ShouldBe($"{smaskObj} 0 obj");

        using var stream = new MemoryStream(signed);
        var results = await new PdfSignatureValidator(new ValidationOptions { CheckRevocation = false, TrustedRoots = [cert] }).ValidateAsync(stream);
        results.Count.ShouldBe(1);
        results[0].IsIntegrityValid.ShouldBeTrue();
        results[0].IsSignatureValid.ShouldBeTrue();
    }

    // ── Helpers ─────────────────────────────────────────────────────────

    private static string Render(SignatureAppearance appearance, string? reason = null, string? location = null, int imageObjNum = 0) =>
        Render(new SignatureFieldOptions { SignerName = "Maria Silva", Reason = reason, Location = location, Appearance = appearance }, imageObjNum);

    private static string Render(SignatureFieldOptions options, int imageObjNum = 0) =>
        Encoding.Latin1.GetString(RenderBytes(options, imageObjNum, 0));

    private static byte[] RenderBytes(SignatureAppearance appearance, int imageObjNum, int softMaskObjNum = 0) =>
        RenderBytes(new SignatureFieldOptions { SignerName = "Maria Silva", Appearance = appearance }, imageObjNum, softMaskObjNum);

    private static byte[] RenderBytes(SignatureFieldOptions options, int imageObjNum, int softMaskObjNum)
    {
        var app = options.Appearance!;
        float width = app.ComputeWidth(options.SignerName ?? "Signer", options.Reason, options.Location, SampleTime);
        float height = app.ComputeHeight(!string.IsNullOrEmpty(options.Reason), !string.IsNullOrEmpty(options.Location));
        return SignatureAppearanceRenderer.BuildAppearanceXObject(10, options, SampleTime, width, height, imageObjNum, softMaskObjNum: softMaskObjNum);
    }

    private static byte[] StreamOf(byte[] bytes, int objNum)
    {
        string text = Encoding.Latin1.GetString(bytes);
        int obj = text.IndexOf($"{objNum} 0 obj", StringComparison.Ordinal);
        var length = Regex.Match(text[obj..], @"/Length (\d+)");
        int start = text.IndexOf("stream\n", obj, StringComparison.Ordinal) + "stream\n".Length;
        return bytes[start..(start + int.Parse(length.Groups[1].Value, System.Globalization.CultureInfo.InvariantCulture))];
    }

    private static byte[] Inflate(byte[] data)
    {
        using var input = new MemoryStream(data);
        using var zlib = new ZLibStream(input, CompressionMode.Decompress);
        using var output = new MemoryStream();
        zlib.CopyTo(output);
        return output.ToArray();
    }

    private static long XrefOffset(string pdf, int objNum)
    {
        int xref = pdf.LastIndexOf("\nxref\n", StringComparison.Ordinal) + "\nxref\n".Length;
        var lines = pdf[xref..].Split('\n');
        int i = 0;
        while (i < lines.Length && !lines[i].StartsWith("trailer", StringComparison.Ordinal))
        {
            var header = lines[i].Split(' ');
            int first = int.Parse(header[0], System.Globalization.CultureInfo.InvariantCulture);
            int count = int.Parse(header[1], System.Globalization.CultureInfo.InvariantCulture);
            if (objNum >= first && objNum < first + count)
            {
                return long.Parse(lines[i + 1 + objNum - first][..10], System.Globalization.CultureInfo.InvariantCulture);
            }

            i += count + 1;
        }

        throw new InvalidOperationException($"Object {objNum} not in last xref section.");
    }

    private static byte[] BuildPdfWithPage() => Encoding.Latin1.GetBytes("%PDF-1.7\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] >>\nendobj\nxref\n0 4\n0000000000 65535 f \n0000000009 00000 n \n0000000058 00000 n \n0000000115 00000 n \ntrailer\n<< /Size 4 /Root 1 0 R >>\nstartxref\n181\n%%EOF");

    private static X509Certificate2 CreateRsaCert()
    {
        using RSA key = RSA.Create(2048);
        var request = new CertificateRequest("CN=Maria Silva, C=BR", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, critical: false));
        using X509Certificate2 cert = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        return CertificateLoader.LoadPkcs12(cert.Export(X509ContentType.Pfx, "test-export"), "test-export");
    }

    /// <summary>Builds small PNG files for tests.</summary>
    private static class TestPng
    {
        public static byte[] Rgb(int width, int height)
        {
            var rows = new List<byte>();
            for (int y = 0; y < height; y++)
            {
                rows.Add(0);
                for (int x = 0; x < width * 3; x++)
                {
                    rows.Add((byte)(x * 20));
                }
            }

            return Raw(width, height, 8, 2, [.. rows]);
        }

        public static byte[] Rgba(int width, int height, Func<int, int, (byte R, byte G, byte B, byte A)> pixel)
        {
            var rows = new List<byte>();
            for (int y = 0; y < height; y++)
            {
                // Alternate filters (Sub on even rows, Up on odd rows) to exercise unfiltering.
                byte filter = (byte)(y % 2 == 0 ? 1 : 2);
                rows.Add(filter);
                for (int x = 0; x < width; x++)
                {
                    var p = pixel(x, y);
                    byte[] cur = [p.R, p.G, p.B, p.A];
                    byte[] reference = filter == 1
                        ? (x > 0 ? Bytes(pixel(x - 1, y)) : [0, 0, 0, 0])
                        : (y > 0 ? Bytes(pixel(x, y - 1)) : [0, 0, 0, 0]);
                    for (int c = 0; c < 4; c++)
                    {
                        rows.Add((byte)(cur[c] - reference[c]));
                    }
                }
            }

            return Raw(width, height, 8, 6, [.. rows]);

            static byte[] Bytes((byte R, byte G, byte B, byte A) p) => [p.R, p.G, p.B, p.A];
        }

        public static byte[] GrayAlpha(int width, int height, byte[] pixels)
        {
            var rows = new List<byte>();
            for (int y = 0; y < height; y++)
            {
                rows.Add(0);
                rows.AddRange(pixels.AsSpan(y * width * 2, width * 2).ToArray());
            }

            return Raw(width, height, 8, 4, [.. rows]);
        }

        public static byte[] Palette(int width, int height, int bitDepth, byte[] palette, byte[]? trns, byte[] indices)
        {
            int rowBytes = ((width * bitDepth) + 7) / 8;
            var rows = new List<byte>();
            for (int y = 0; y < height; y++)
            {
                rows.Add(0);
                byte[] row = new byte[rowBytes];
                for (int x = 0; x < width; x++)
                {
                    int bit = x * bitDepth;
                    row[bit >> 3] |= (byte)(indices[(y * width) + x] << (8 - bitDepth - (bit & 7)));
                }

                rows.AddRange(row);
            }

            var chunks = new List<(string, byte[])> { ("PLTE", palette) };
            if (trns is not null)
            {
                chunks.Add(("tRNS", trns));
            }

            return Raw(width, height, (byte)bitDepth, 3, [.. rows], chunks);
        }

        public static byte[] Raw(int width, int height, byte bitDepth, byte colorType, byte[] scanlines, List<(string Type, byte[] Data)>? extra = null)
        {
            using var ms = new MemoryStream();
            ms.Write([137, 80, 78, 71, 13, 10, 26, 10]);
            byte[] ihdr = new byte[13];
            BinaryPrimitives.WriteInt32BigEndian(ihdr, width);
            BinaryPrimitives.WriteInt32BigEndian(ihdr.AsSpan(4), height);
            ihdr[8] = bitDepth;
            ihdr[9] = colorType;
            WriteChunk(ms, "IHDR", ihdr);
            foreach (var (type, data) in extra ?? [])
            {
                WriteChunk(ms, type, data);
            }

            using var compressed = new MemoryStream();
            using (var zlib = new ZLibStream(compressed, CompressionLevel.Optimal))
            {
                zlib.Write(scanlines);
            }

            WriteChunk(ms, "IDAT", compressed.ToArray());
            WriteChunk(ms, "IEND", []);
            return ms.ToArray();
        }

        private static void WriteChunk(MemoryStream ms, string type, byte[] data)
        {
            byte[] length = new byte[4];
            BinaryPrimitives.WriteInt32BigEndian(length, data.Length);
            ms.Write(length);
            ms.Write(Encoding.ASCII.GetBytes(type));
            ms.Write(data);
            ms.Write(new byte[4]); // CRC is not checked by the reader
        }
    }

    /// <summary>Builds JPEG marker headers (enough for dimension and color space detection).</summary>
    private static class TestJpeg
    {
        public static byte[] Header(int width, int height, byte components, bool adobe)
        {
            var bytes = new List<byte> { 0xFF, 0xD8 };
            if (adobe)
            {
                bytes.AddRange([0xFF, 0xEE, 0x00, 0x0E, (byte)'A', (byte)'d', (byte)'o', (byte)'b', (byte)'e', 0, 100, 0, 0, 0, 0, 2]);
            }

            int sofLength = 8 + (3 * components);
            bytes.AddRange([0xFF, 0xC0, (byte)(sofLength >> 8), (byte)sofLength, 8, (byte)(height >> 8), (byte)height, (byte)(width >> 8), (byte)width, components]);
            for (int c = 0; c < components; c++)
            {
                bytes.AddRange([(byte)(c + 1), 0x11, 0]);
            }

            bytes.AddRange([0xFF, 0xD9]);
            return [.. bytes];
        }
    }
}
