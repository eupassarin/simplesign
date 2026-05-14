using FluentAssertions;
using SimpleSign.HtmlToPdf.Parsing;
using Xunit;

namespace SimpleSign.HtmlToPdf.Tests;

public class ComputedStyleTests
{
    // ── PdfColor ────────────────────────────────────────────────────────

    [Fact(DisplayName = "PdfColor.Parse: hex 6-digit")]
    public void PdfColor_Parse_Hex6Digit()
    {
        var color = PdfColor.Parse("#FF0000");

        color.R.Should().BeApproximately(1.0f, 0.01f);
        color.G.Should().BeApproximately(0.0f, 0.01f);
        color.B.Should().BeApproximately(0.0f, 0.01f);
    }

    [Fact(DisplayName = "PdfColor.Parse: hex 3-digit")]
    public void PdfColor_Parse_Hex3Digit()
    {
        var color = PdfColor.Parse("#F00");

        color.R.Should().BeApproximately(1.0f, 0.01f);
        color.G.Should().BeApproximately(0.0f, 0.01f);
        color.B.Should().BeApproximately(0.0f, 0.01f);
    }

    [Fact(DisplayName = "PdfColor.Parse: named colors")]
    public void PdfColor_Parse_NamedColors()
    {
        PdfColor.Parse("black").Should().Be(PdfColor.Black);
        PdfColor.Parse("white").Should().Be(PdfColor.White);
    }

    [Fact(DisplayName = "PdfColor.Parse: rgb() function")]
    public void PdfColor_Parse_RgbFunction()
    {
        var color = PdfColor.Parse("rgb(255, 0, 128)");

        color.R.Should().BeApproximately(1.0f, 0.01f);
        color.G.Should().BeApproximately(0.0f, 0.01f);
        color.B.Should().BeApproximately(0.5f, 0.02f);
    }

    [Fact(DisplayName = "PdfColor statics are correct")]
    public void PdfColor_Statics_AreCorrect()
    {
        PdfColor.Black.R.Should().Be(0);
        PdfColor.Black.G.Should().Be(0);
        PdfColor.Black.B.Should().Be(0);

        PdfColor.White.R.Should().Be(1);
        PdfColor.White.G.Should().Be(1);
        PdfColor.White.B.Should().Be(1);

        PdfColor.Transparent.IsTransparent.Should().BeTrue();
    }

    [Fact(DisplayName = "PdfColor.IsTransparent for non-transparent color")]
    public void PdfColor_IsTransparent_ReturnsFalseForNonTransparent()
    {
        PdfColor.Black.IsTransparent.Should().BeFalse();
        PdfColor.White.IsTransparent.Should().BeFalse();
    }

    // ── Thickness ───────────────────────────────────────────────────────

    [Fact(DisplayName = "Thickness.Zero has all zeros")]
    public void Thickness_Zero_AllZeros()
    {
        var t = Thickness.Zero;

        t.Top.Should().Be(0);
        t.Right.Should().Be(0);
        t.Bottom.Should().Be(0);
        t.Left.Should().Be(0);
    }

    [Fact(DisplayName = "Thickness.Uniform creates equal sides")]
    public void Thickness_Uniform_CreatesEqualSides()
    {
        var t = Thickness.Uniform(10);

        t.Top.Should().Be(10);
        t.Right.Should().Be(10);
        t.Bottom.Should().Be(10);
        t.Left.Should().Be(10);
    }

    [Fact(DisplayName = "Thickness constructor with 4 values")]
    public void Thickness_FourValues_SetsCorrectly()
    {
        var t = new Thickness(1, 2, 3, 4);

        t.Top.Should().Be(1);
        t.Right.Should().Be(2);
        t.Bottom.Should().Be(3);
        t.Left.Should().Be(4);
    }

    [Fact(DisplayName = "Thickness constructor with 2 values (vertical, horizontal)")]
    public void Thickness_TwoValues_SetsSymmetrically()
    {
        var t = new Thickness(10, 20);

        t.Top.Should().Be(10);
        t.Bottom.Should().Be(10);
        t.Right.Should().Be(20);
        t.Left.Should().Be(20);
    }

    // ── BorderStyle ─────────────────────────────────────────────────────

    [Fact(DisplayName = "BorderStyle.None has no border")]
    public void BorderStyle_None_HasNoBorder()
    {
        var border = BorderStyle.None;

        border.HasBorder.Should().BeFalse();
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

        original.TopWidth.Should().Be(2);
        clone.TopWidth.Should().Be(5);
    }

    [Fact(DisplayName = "BorderStyle.HasBorder detects non-zero widths")]
    public void BorderStyle_HasBorder_DetectsNonZeroWidths()
    {
        var border = new BorderStyle { TopWidth = 1 };

        border.HasBorder.Should().BeTrue();
    }

    // ── ComputedStyle defaults ──────────────────────────────────────────

    [Fact(DisplayName = "ComputedStyle defaults are reasonable")]
    public void ComputedStyle_Defaults_AreReasonable()
    {
        var style = new ComputedStyle();

        style.FontFamily.Should().Be("Helvetica");
        style.FontSize.Should().Be(12f);
        style.IsBold.Should().BeFalse();
        style.IsItalic.Should().BeFalse();
        style.Color.Should().Be(PdfColor.Black);
        style.TextAlign.Should().Be(TextAlign.Left);
        style.LineHeight.Should().BeApproximately(1.4f, 0.01f);
        style.Display.Should().Be(DisplayType.Block);
        style.Margin.Should().Be(Thickness.Zero);
        style.Padding.Should().Be(Thickness.Zero);
        style.Border.HasBorder.Should().BeFalse();
    }

    // ── Enums ───────────────────────────────────────────────────────────

    [Fact(DisplayName = "DisplayType enum has expected values")]
    public void DisplayType_HasExpectedValues()
    {
        Enum.IsDefined(DisplayType.Block).Should().BeTrue();
        Enum.IsDefined(DisplayType.Inline).Should().BeTrue();
        Enum.IsDefined(DisplayType.None).Should().BeTrue();
        Enum.IsDefined(DisplayType.Table).Should().BeTrue();
        Enum.IsDefined(DisplayType.TableRow).Should().BeTrue();
        Enum.IsDefined(DisplayType.TableCell).Should().BeTrue();
        Enum.IsDefined(DisplayType.ListItem).Should().BeTrue();
    }

    [Fact(DisplayName = "TextAlign enum has expected values")]
    public void TextAlign_HasExpectedValues()
    {
        Enum.IsDefined(TextAlign.Left).Should().BeTrue();
        Enum.IsDefined(TextAlign.Center).Should().BeTrue();
        Enum.IsDefined(TextAlign.Right).Should().BeTrue();
    }

    // ── HSL colors ──────────────────────────────────────────────────────

    [Fact(DisplayName = "PdfColor.Parse: hsl red (0, 100%, 50%)")]
    public void PdfColor_Parse_HslRed()
    {
        var color = PdfColor.Parse("hsl(0, 100%, 50%)");

        color.R.Should().BeApproximately(1.0f, 0.01f);
        color.G.Should().BeApproximately(0.0f, 0.01f);
        color.B.Should().BeApproximately(0.0f, 0.01f);
    }

    [Fact(DisplayName = "PdfColor.Parse: hsl green (120, 100%, 50%)")]
    public void PdfColor_Parse_HslGreen()
    {
        var color = PdfColor.Parse("hsl(120, 100%, 50%)");

        color.R.Should().BeApproximately(0.0f, 0.01f);
        color.G.Should().BeApproximately(1.0f, 0.01f);
        color.B.Should().BeApproximately(0.0f, 0.01f);
    }

    [Fact(DisplayName = "PdfColor.Parse: hsl blue (240, 100%, 50%)")]
    public void PdfColor_Parse_HslBlue()
    {
        var color = PdfColor.Parse("hsl(240, 100%, 50%)");

        color.R.Should().BeApproximately(0.0f, 0.01f);
        color.G.Should().BeApproximately(0.0f, 0.01f);
        color.B.Should().BeApproximately(1.0f, 0.01f);
    }

    [Fact(DisplayName = "PdfColor.Parse: hsla with alpha does not throw")]
    public void PdfColor_Parse_HslaWithAlpha_DoesNotThrow()
    {
        var act = () => PdfColor.Parse("hsla(0, 100%, 50%, 0.5)");

        var color = act.Should().NotThrow().Subject;
        color.R.Should().BeApproximately(1.0f, 0.01f);
    }
}
