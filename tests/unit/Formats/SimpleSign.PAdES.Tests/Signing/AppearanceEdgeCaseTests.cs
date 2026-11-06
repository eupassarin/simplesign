using Shouldly;
using SimpleSign.PAdES.Signing;
using Xunit;

namespace SimpleSign.PAdES.Tests.Signing;

/// <summary>
/// Edge-case tests for <see cref="SignatureAppearance"/> and <see cref="SignatureAppearanceRenderer"/>.
/// </summary>
[Trait("Category", "Unit")]
public sealed class AppearanceEdgeCaseTests
{
    private static readonly DateTime SampleTime = new(2025, 6, 15, 14, 30, 0, DateTimeKind.Utc);
    private static readonly byte[] TinyPngRgb1x1 =
    [
        0x89,0x50,0x4E,0x47,0x0D,0x0A,0x1A,0x0A,
        0x00,0x00,0x00,0x0D,0x49,0x48,0x44,0x52,
        0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x01,
        0x08,0x02,0x00,0x00,0x00,0x90,0x77,0x53,0xDE,
        0x00,0x00,0x00,0x0A,0x49,0x44,0x41,0x54,
        0x78,0x9C,0x63,0x60,0x00,0x00,0x00,0x02,0x00,0x01,0xE5,0x27,0xD4,0xA2,
        0x00,0x00,0x00,0x00,0x49,0x45,0x4E,0x44,0xAE,0x42,0x60,0x82
    ];

    // ── SignatureAppearance property edge cases ─────────────────────────

    [Fact(DisplayName = "Minimal appearance (no date, reason, location) calculates height correctly")]
    public void MinimalAppearance_NoDateReasonLocation_LineCountIsTwo()
    {
        var app = new SignatureAppearance
        {
            ShowDate = false,
            ShowReason = false,
            ShowLocation = false,
        };

        app.LineCount(hasReason: false, hasLocation: false).ShouldBe(2);
        var height = app.ComputeHeight(hasReason: false, hasLocation: false);
        height.ShouldBeGreaterThan(0);
    }

    [Fact(DisplayName = "ShowReason=true but null Reason does not add a line")]
    public void ShowReasonTrue_ReasonNull_LineCountDoesNotIncludeReason()
    {
        var app = new SignatureAppearance { ShowReason = true, ShowDate = false };

        // hasReason=false simulates null reason
        app.LineCount(hasReason: false, hasLocation: false).ShouldBe(2);
    }

    [Fact(DisplayName = "ShowLocation=true but null Location does not add a line")]
    public void ShowLocationTrue_LocationNull_LineCountDoesNotIncludeLocation()
    {
        var app = new SignatureAppearance { ShowLocation = true, ShowDate = false };

        app.LineCount(hasReason: false, hasLocation: false).ShouldBe(2);
    }

    [Fact(DisplayName = "CustomFontSize=0 returns 0 as font size")]
    public void CustomFontSizeZero_ReturnsZero()
    {
        var app = new SignatureAppearance { CustomFontSize = 0f };
        app.GetFontSizeValue().ShouldBe(0f);
    }

    [Fact(DisplayName = "CustomFontSize=72 (very large) is stored without error")]
    public void CustomFontSizeVeryLarge_IsStored()
    {
        var app = new SignatureAppearance { CustomFontSize = 72f };
        app.GetFontSizeValue().ShouldBe(72f);
    }

    [Fact(DisplayName = "Empty SignerName renders without exception")]
    public void EmptySignerName_RendersWithoutException()
    {
        var options = new SignatureFieldOptions
        {
            SignerName = "",
            Appearance = new SignatureAppearance(),
        };

        float width = options.Appearance.ComputeWidth("", null, null, SampleTime);
        float height = options.Appearance.ComputeHeight(hasReason: false, hasLocation: false);

        var act = () => SignatureAppearanceRenderer.BuildAppearanceXObject(
            10, options, SampleTime, width, height);

        Should.NotThrow(act);
    }

    [Fact(DisplayName = "SignerName with exactly 40 characters is not truncated")]
    public void SignerName_Exactly40Chars_NotTruncated()
    {
        string name = new('A', 40);
        var result = SignatureAppearance.Truncate(name);
        result.ShouldBe(name);
        result.Length.ShouldBe(40);
    }

    [Fact(DisplayName = "SignerName with 41 characters is truncated to 37 + '...'")]
    public void SignerName_41Chars_TruncatedWithEllipsis()
    {
        string name = new('B', 41);
        var result = SignatureAppearance.Truncate(name);
        result.Length.ShouldBe(40);
        result.ShouldEndWith("...");
        result.ShouldStartWith(new string('B', 37));
    }

    [Fact(DisplayName = "SignerName with PDF special characters is escaped")]
    public void SignerName_SpecialPdfChars_AreEscaped()
    {
        string name = @"John (Doe) \ Jr.";
        var escaped = SignatureAppearanceRenderer.EscapePdfString(name);
        escaped.ShouldNotContain("(Doe)");
        escaped.ShouldContain("\\(Doe\\)");
        escaped.ShouldContain("\\\\");
    }

    // ── ComputeAutoPosition ─────────────────────────────────────────────

    [Fact(DisplayName = "AutoPosition index 0 at first position")]
    public void ComputeAutoPosition_Index0_FirstPosition()
    {
        var (x, y) = SignatureAppearance.ComputeAutoPosition(
            pageWidth: 595f, pageBottomMargin: 0f, existingSigCount: 0,
            stampWidth: 150f, stampHeight: 40f);

        x.ShouldBe(8f); // Margin = 8
        y.ShouldBe(8f);
    }

    [Fact(DisplayName = "AutoPosition index 10 distributes across multiple lines")]
    public void ComputeAutoPosition_Index10_WrapsToMultipleRows()
    {
        var (_, y0) = SignatureAppearance.ComputeAutoPosition(
            pageWidth: 595f, pageBottomMargin: 0f, existingSigCount: 0,
            stampWidth: 150f, stampHeight: 40f);

        var (_, y10) = SignatureAppearance.ComputeAutoPosition(
            pageWidth: 595f, pageBottomMargin: 0f, existingSigCount: 10,
            stampWidth: 150f, stampHeight: 40f);

        // Must have wrapped to a row above
        y10.ShouldBeGreaterThan(y0, "índice 10 deve estar em linha acima");
    }

    [Fact(DisplayName = "AutoPosition very small page (50x50) does not fail")]
    public void ComputeAutoPosition_VerySmallPage_NoCrash()
    {
        var act = () => SignatureAppearance.ComputeAutoPosition(
            pageWidth: 50f, pageBottomMargin: 0f, existingSigCount: 0,
            stampWidth: 150f, stampHeight: 40f);

        var (x, y) = act.Invoke();
        x.ShouldBeGreaterThanOrEqualTo(0);
        y.ShouldBeGreaterThanOrEqualTo(0);
    }

    // ── Color and border edge cases ─────────────────────────────────────

    [Theory(DisplayName = "TextColor at RGB limits (black and white)")]
    [InlineData(0f, 0f, 0f)]
    [InlineData(1f, 1f, 1f)]
    public void TextColor_BoundaryValues_RenderWithoutException(float r, float g, float b)
    {
        var options = new SignatureFieldOptions
        {
            SignerName = "Teste",
            Appearance = new SignatureAppearance { TextColor = (r, g, b) },
        };
        float width = options.Appearance.ComputeWidth("Teste", null, null, SampleTime);
        float height = options.Appearance.ComputeHeight(hasReason: false, hasLocation: false);

        var result = SignatureAppearanceRenderer.BuildAppearanceXObject(
            10, options, SampleTime, width, height);

        result.ShouldNotBeEmpty();
    }

    [Fact(DisplayName = "BorderColor with BorderWidth=0 renders without error")]
    public void BorderColor_WithZeroBorderWidth_RendersWithoutException()
    {
        var options = new SignatureFieldOptions
        {
            SignerName = "Teste",
            Appearance = new SignatureAppearance
            {
                BorderColor = (0.5f, 0.5f, 0.5f),
                BorderWidth = 0f,
            },
        };
        float width = options.Appearance.ComputeWidth("Teste", null, null, SampleTime);
        float height = options.Appearance.ComputeHeight(hasReason: false, hasLocation: false);

        var result = SignatureAppearanceRenderer.BuildAppearanceXObject(
            10, options, SampleTime, width, height);

        result.ShouldNotBeEmpty();
    }

    [Fact(DisplayName = "BackgroundColor with full opacity renders without error")]
    public void TextColor_FullOpacity_RendersWithoutException()
    {
        var options = new SignatureFieldOptions
        {
            SignerName = "Teste",
            Appearance = new SignatureAppearance { TextColor = (1f, 0f, 0f) },
        };
        float width = options.Appearance.ComputeWidth("Teste", null, null, SampleTime);
        float height = options.Appearance.ComputeHeight(hasReason: false, hasLocation: false);

        var result = SignatureAppearanceRenderer.BuildAppearanceXObject(
            10, options, SampleTime, width, height);

        var content = System.Text.Encoding.Latin1.GetString(result);
        content.ShouldContain("1.00 0.00 0.00 rg");
    }

    // ── Image edge cases ────────────────────────────────────────────────

    [Fact(DisplayName = "Null BackgroundImageJpeg renders text only")]
    public void BackgroundImageNull_RendersTextOnly()
    {
        var options = new SignatureFieldOptions
        {
            SignerName = "Teste",
            Appearance = new SignatureAppearance { BackgroundImageJpeg = null },
        };
        float width = options.Appearance.ComputeWidth("Teste", null, null, SampleTime);
        float height = options.Appearance.ComputeHeight(hasReason: false, hasLocation: false);

        var result = SignatureAppearanceRenderer.BuildAppearanceXObject(
            10, options, SampleTime, width, height);

        result.ShouldNotBeEmpty();
        var content = System.Text.Encoding.Latin1.GetString(result);
        content.ShouldNotContain("/Img0");
    }

    [Fact(DisplayName = "Empty BackgroundImageJpeg does not cause exception")]
    public void BackgroundImageEmpty_DoesNotCrash()
    {
        var options = new SignatureFieldOptions
        {
            SignerName = "Teste",
            Appearance = new SignatureAppearance { BackgroundImageJpeg = Array.Empty<byte>() },
        };
        float width = options.Appearance.ComputeWidth("Teste", null, null, SampleTime);
        float height = options.Appearance.ComputeHeight(hasReason: false, hasLocation: false);

        var act = () => SignatureAppearanceRenderer.BuildAppearanceXObject(
            10, options, SampleTime, width, height);

        Should.NotThrow(act);
    }

    [Fact(DisplayName = "BackgroundImageJpeg with 1 byte does not cause exception")]
    public void BackgroundImageOneByte_DoesNotCrash()
    {
        var options = new SignatureFieldOptions
        {
            SignerName = "Teste",
            Appearance = new SignatureAppearance { BackgroundImageJpeg = new byte[] { 0xFF } },
        };
        float width = options.Appearance.ComputeWidth("Teste", null, null, SampleTime);
        float height = options.Appearance.ComputeHeight(hasReason: false, hasLocation: false);

        var act = () => SignatureAppearanceRenderer.BuildAppearanceXObject(
            10, options, SampleTime, width, height);

        Should.NotThrow(act);
    }

    [Fact(DisplayName = "Valid BackgroundImagePng renders with FlateDecode and /Img0")]
    public void BackgroundImagePng_ValidPng_RendersWithImageXObject()
    {
        var options = new SignatureFieldOptions
        {
            SignerName = "Teste",
            Appearance = new SignatureAppearance { BackgroundImagePng = TinyPngRgb1x1 },
        };
        float width = options.Appearance.ComputeWidth("Teste", null, null, SampleTime);
        float height = options.Appearance.ComputeHeight(hasReason: false, hasLocation: false);

        var bytes = SignatureAppearanceRenderer.BuildAppearanceXObject(
            10, options, SampleTime, width, height, imageObjNum: 11);

        var content = System.Text.Encoding.Latin1.GetString(bytes);
        content.ShouldContain("/Filter /FlateDecode");
        content.ShouldContain("/Img0 11 0 R");
    }

    [Fact(DisplayName = "Invalid BackgroundImagePng throws ArgumentException")]
    public void BackgroundImagePng_InvalidPng_ThrowsArgumentException()
    {
        var options = new SignatureFieldOptions
        {
            SignerName = "Teste",
            Appearance = new SignatureAppearance { BackgroundImagePng = new byte[] { 1, 2, 3, 4 } },
        };
        float width = options.Appearance.ComputeWidth("Teste", null, null, SampleTime);
        float height = options.Appearance.ComputeHeight(hasReason: false, hasLocation: false);

        var act = () => SignatureAppearanceRenderer.BuildAppearanceXObject(
            10, options, SampleTime, width, height, imageObjNum: 11);

        Should.Throw<ArgumentException>(act);
    }

    [Fact(DisplayName = "Custom BaseFontName appears in font dictionary")]
    public void BaseFontName_CustomFont_IsUsedInXObject()
    {
        var options = new SignatureFieldOptions
        {
            SignerName = "Teste",
            Appearance = new SignatureAppearance { BaseFontName = "Courier-Bold" },
        };
        float width = options.Appearance.ComputeWidth("Teste", null, null, SampleTime);
        float height = options.Appearance.ComputeHeight(hasReason: false, hasLocation: false);

        var bytes = SignatureAppearanceRenderer.BuildAppearanceXObject(
            10, options, SampleTime, width, height);

        var content = System.Text.Encoding.Latin1.GetString(bytes);
        content.ShouldContain("/BaseFont /Courier-Bold");
    }

    [Fact(DisplayName = "Invalid BaseFontName falls back to Helvetica")]
    public void BaseFontName_InvalidFontName_FallsBackToHelvetica()
    {
        var options = new SignatureFieldOptions
        {
            SignerName = "Teste",
            Appearance = new SignatureAppearance { BaseFontName = "Font With Space" },
        };
        float width = options.Appearance.ComputeWidth("Teste", null, null, SampleTime);
        float height = options.Appearance.ComputeHeight(hasReason: false, hasLocation: false);

        var bytes = SignatureAppearanceRenderer.BuildAppearanceXObject(
            10, options, SampleTime, width, height);

        var content = System.Text.Encoding.Latin1.GetString(bytes);
        content.ShouldContain("/BaseFont /Helvetica");
    }

    // ── EscapePdfString edge cases ──────────────────────────────────────

    [Fact(DisplayName = "EscapePdfString with unbalanced parenthesis escapes correctly")]
    public void EscapePdfString_UnbalancedParenthesis_Escapes()
    {
        var result = SignatureAppearanceRenderer.EscapePdfString("(test");
        result.ShouldBe("\\(test");
    }

    [Fact(DisplayName = "EscapePdfString with backslashes escapes correctly")]
    public void EscapePdfString_Backslashes_Escapes()
    {
        var result = SignatureAppearanceRenderer.EscapePdfString(@"test\path");
        result.ShouldBe("test\\\\path");
    }

    [Fact(DisplayName = "EscapePdfString with line break preserves content")]
    public void EscapePdfString_Newlines_PreservesContent()
    {
        var result = SignatureAppearanceRenderer.EscapePdfString("line1\nline2");
        // Newlines are not among the escaped chars; they pass through
        result.ShouldContain("line1");
        result.ShouldContain("line2");
    }
}
