using Shouldly;
using SimpleSign.HtmlToPdf.Parsing;
using Xunit;

namespace SimpleSign.HtmlToPdf.Tests;

[Trait("Category", "Unit")]
public class ComputedStyleTests
{
    // ── PdfColor ────────────────────────────────────────────────────────

    [Fact(DisplayName = "PdfColor.Parse: hex 6-digit")]
    public void PdfColor_Parse_Hex6Digit()
    {
        var color = PdfColor.Parse("#FF0000");

        color.R.ShouldBe(1.0f, 0.01f);
        color.G.ShouldBe(0.0f, 0.01f);
        color.B.ShouldBe(0.0f, 0.01f);
    }

    [Fact(DisplayName = "PdfColor.Parse: hex 3-digit")]
    public void PdfColor_Parse_Hex3Digit()
    {
        var color = PdfColor.Parse("#F00");

        color.R.ShouldBe(1.0f, 0.01f);
        color.G.ShouldBe(0.0f, 0.01f);
        color.B.ShouldBe(0.0f, 0.01f);
    }

    [Fact(DisplayName = "PdfColor.Parse: named colors")]
    public void PdfColor_Parse_NamedColors()
    {
        PdfColor.Parse("black").ShouldBe(PdfColor.Black);
        PdfColor.Parse("white").ShouldBe(PdfColor.White);
    }

    [Fact(DisplayName = "PdfColor.Parse: rgb() function")]
    public void PdfColor_Parse_RgbFunction()
    {
        var color = PdfColor.Parse("rgb(255, 0, 128)");

        color.R.ShouldBe(1.0f, 0.01f);
        color.G.ShouldBe(0.0f, 0.01f);
        color.B.ShouldBe(0.5f, 0.02f);
    }

    [Fact(DisplayName = "PdfColor statics are correct")]
    public void PdfColor_Statics_AreCorrect()
    {
        PdfColor.Black.R.ShouldBe(0);
        PdfColor.Black.G.ShouldBe(0);
        PdfColor.Black.B.ShouldBe(0);

        PdfColor.White.R.ShouldBe(1);
        PdfColor.White.G.ShouldBe(1);
        PdfColor.White.B.ShouldBe(1);

        PdfColor.Transparent.IsTransparent.ShouldBeTrue();
    }

    [Fact(DisplayName = "PdfColor.IsTransparent for non-transparent color")]
    public void PdfColor_IsTransparent_ReturnsFalseForNonTransparent()
    {
        PdfColor.Black.IsTransparent.ShouldBeFalse();
        PdfColor.White.IsTransparent.ShouldBeFalse();
    }

    // ── Thickness ───────────────────────────────────────────────────────

    [Fact(DisplayName = "Thickness.Zero has all zeros")]
    public void Thickness_Zero_AllZeros()
    {
        var t = Thickness.Zero;

        t.Top.ShouldBe(0);
        t.Right.ShouldBe(0);
        t.Bottom.ShouldBe(0);
        t.Left.ShouldBe(0);
    }

    [Fact(DisplayName = "Thickness.Uniform creates equal sides")]
    public void Thickness_Uniform_CreatesEqualSides()
    {
        var t = Thickness.Uniform(10);

        t.Top.ShouldBe(10);
        t.Right.ShouldBe(10);
        t.Bottom.ShouldBe(10);
        t.Left.ShouldBe(10);
    }

    [Fact(DisplayName = "Thickness constructor with 4 values")]
    public void Thickness_FourValues_SetsCorrectly()
    {
        var t = new Thickness(1, 2, 3, 4);

        t.Top.ShouldBe(1);
        t.Right.ShouldBe(2);
        t.Bottom.ShouldBe(3);
        t.Left.ShouldBe(4);
    }

    [Fact(DisplayName = "Thickness constructor with 2 values (vertical, horizontal)")]
    public void Thickness_TwoValues_SetsSymmetrically()
    {
        var t = new Thickness(10, 20);

        t.Top.ShouldBe(10);
        t.Bottom.ShouldBe(10);
        t.Right.ShouldBe(20);
        t.Left.ShouldBe(20);
    }

    // ── BorderStyle ─────────────────────────────────────────────────────

    [Fact(DisplayName = "BorderStyle.None has no border")]
    public void BorderStyle_None_HasNoBorder()
    {
        var border = BorderStyle.None;

        border.HasBorder.ShouldBeFalse();
    }

    [Fact(DisplayName = "BorderStyle.Clone creates independent copy")]
    public void BorderStyle_Clone_CreatesIndependentCopy()
    {
        var original = new BorderStyle
        {
            TopWidth = 2,
            TopColor = PdfColor.Black,
        };

        var clone = original.Clone();
        clone.TopWidth = 5;

        original.TopWidth.ShouldBe(2);
        clone.TopWidth.ShouldBe(5);
    }

    [Fact(DisplayName = "BorderStyle.HasBorder detects non-zero widths")]
    public void BorderStyle_HasBorder_DetectsNonZeroWidths()
    {
        var border = new BorderStyle { TopWidth = 1 };

        border.HasBorder.ShouldBeTrue();
    }

    // ── ComputedStyle defaults ──────────────────────────────────────────

    [Fact(DisplayName = "ComputedStyle defaults are reasonable")]
    public void ComputedStyle_Defaults_AreReasonable()
    {
        var style = new ComputedStyle();

        style.FontFamily.ShouldBe("Helvetica");
        style.FontSize.ShouldBe(12f);
        style.IsBold.ShouldBeFalse();
        style.IsItalic.ShouldBeFalse();
        style.Color.ShouldBe(PdfColor.Black);
        style.TextAlign.ShouldBe(TextAlign.Left);
        style.LineHeight.ShouldBe(1.4f, 0.01f);
        style.Display.ShouldBe(DisplayType.Block);
        style.Margin.ShouldBe(Thickness.Zero);
        style.Padding.ShouldBe(Thickness.Zero);
        style.Border.HasBorder.ShouldBeFalse();
    }

    // ── Enums ───────────────────────────────────────────────────────────

    [Fact(DisplayName = "DisplayType enum has expected values")]
    public void DisplayType_HasExpectedValues()
    {
        Enum.IsDefined(DisplayType.Block).ShouldBeTrue();
        Enum.IsDefined(DisplayType.Inline).ShouldBeTrue();
        Enum.IsDefined(DisplayType.None).ShouldBeTrue();
        Enum.IsDefined(DisplayType.Table).ShouldBeTrue();
        Enum.IsDefined(DisplayType.TableRow).ShouldBeTrue();
        Enum.IsDefined(DisplayType.TableCell).ShouldBeTrue();
        Enum.IsDefined(DisplayType.ListItem).ShouldBeTrue();
    }

    [Fact(DisplayName = "TextAlign enum has expected values")]
    public void TextAlign_HasExpectedValues()
    {
        Enum.IsDefined(TextAlign.Left).ShouldBeTrue();
        Enum.IsDefined(TextAlign.Center).ShouldBeTrue();
        Enum.IsDefined(TextAlign.Right).ShouldBeTrue();
    }

    // ── HSL colors ──────────────────────────────────────────────────────

    [Fact(DisplayName = "PdfColor.Parse: hsl red (0, 100%, 50%)")]
    public void PdfColor_Parse_HslRed()
    {
        var color = PdfColor.Parse("hsl(0, 100%, 50%)");

        color.R.ShouldBe(1.0f, 0.01f);
        color.G.ShouldBe(0.0f, 0.01f);
        color.B.ShouldBe(0.0f, 0.01f);
    }

    [Fact(DisplayName = "PdfColor.Parse: hsl green (120, 100%, 50%)")]
    public void PdfColor_Parse_HslGreen()
    {
        var color = PdfColor.Parse("hsl(120, 100%, 50%)");

        color.R.ShouldBe(0.0f, 0.01f);
        color.G.ShouldBe(1.0f, 0.01f);
        color.B.ShouldBe(0.0f, 0.01f);
    }

    [Fact(DisplayName = "PdfColor.Parse: hsl blue (240, 100%, 50%)")]
    public void PdfColor_Parse_HslBlue()
    {
        var color = PdfColor.Parse("hsl(240, 100%, 50%)");

        color.R.ShouldBe(0.0f, 0.01f);
        color.G.ShouldBe(0.0f, 0.01f);
        color.B.ShouldBe(1.0f, 0.01f);
    }

    [Fact(DisplayName = "PdfColor.Parse: hsla with alpha does not throw")]
    public void PdfColor_Parse_HslaWithAlpha_DoesNotThrow()
    {
        var act = () => PdfColor.Parse("hsla(0, 100%, 50%, 0.5)");

        var color = act.Invoke();
        color.R.ShouldBe(1.0f, 0.01f);
    }
}
