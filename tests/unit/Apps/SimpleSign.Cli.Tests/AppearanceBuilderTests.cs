using Shouldly;
using SimpleSign.Cli.Rendering;

namespace SimpleSign.Cli.Tests;

[Trait("Category", "Unit")]
public sealed class AppearanceBuilderTests
{
    [Fact]
    public void Build_NonVisible_ReturnsNull()
    {
        var result = AppearanceBuilder.Build(false, null, null, null, null, null, false, false);
        result.ShouldBeNull();
    }

    [Fact]
    public void Build_VisibleAutoPosition_SetsDefaults()
    {
        var result = AppearanceBuilder.Build(true, null, null, null, null, null, false, false);

        result.ShouldNotBeNull();
        result.AutoPosition.ShouldBeTrue();
        result.Page.ShouldBe(1);
        result.X.ShouldBe(20f);
        result.Y.ShouldBe(20f);
        result.ShowReason.ShouldBeFalse();
        result.ShowLocation.ShouldBeFalse();
        result.VerificationUrl.ShouldBeNull();
    }

    [Fact]
    public void Build_WithCoordinates_DisablesAutoPosition()
    {
        var result = AppearanceBuilder.Build(true, null, null, 3, 100f, 200f, true, true);

        result.ShouldNotBeNull();
        result.AutoPosition.ShouldBeFalse();
        result.Page.ShouldBe(3);
        result.X.ShouldBe(100f);
        result.Y.ShouldBe(200f);
        result.ShowReason.ShouldBeTrue();
        result.ShowLocation.ShouldBeTrue();
    }

    [Fact]
    public void Build_WithQrUrl_SetsVerificationUrl()
    {
        var result = AppearanceBuilder.Build(true, null, "https://verify.example.com", null, null, null, false, false);

        result.ShouldNotBeNull();
        result.VerificationUrl.ShouldBe("https://verify.example.com");
    }

    [Fact]
    public void Build_WithPngBackground_SetsBackgroundImagePng()
    {
        var tempPng = Path.GetTempFileName() + ".png";
        try
        {
            File.WriteAllBytes(tempPng, [0x89, 0x50, 0x4E, 0x47]);

            var result = AppearanceBuilder.Build(true, tempPng, null, null, null, null, false, false);

            result.ShouldNotBeNull();
            result.BackgroundImagePng.HasValue.ShouldBeTrue();
            result.BackgroundImagePng!.Value.ToArray().ShouldBe([0x89, 0x50, 0x4E, 0x47]);
            result.BackgroundImageJpeg.HasValue.ShouldBeFalse();
        }
        finally
        {
            File.Delete(tempPng);
        }
    }

    [Fact]
    public void Build_WithJpgBackground_SetsBackgroundImageJpeg()
    {
        var tempJpg = Path.GetTempFileName() + ".jpg";
        try
        {
            File.WriteAllBytes(tempJpg, [0xFF, 0xD8, 0xFF, 0xE0]);

            var result = AppearanceBuilder.Build(true, tempJpg, null, null, null, null, false, false);

            result.ShouldNotBeNull();
            result.BackgroundImageJpeg.HasValue.ShouldBeTrue();
            result.BackgroundImageJpeg!.Value.ToArray().ShouldBe([0xFF, 0xD8, 0xFF, 0xE0]);
            result.BackgroundImagePng.HasValue.ShouldBeFalse();
        }
        finally
        {
            File.Delete(tempJpg);
        }
    }

    [Fact]
    public void Build_WithFontSize_SetsCustomFontSize()
    {
        var result = AppearanceBuilder.Build(true, null, null, null, null, null, false, false, fontSize: 12f);

        result.ShouldNotBeNull();
        result.CustomFontSize.ShouldBe(12f);
    }

    [Fact]
    public void Build_WithLabelFontSize_SetsCustomLabelFontSize()
    {
        var result = AppearanceBuilder.Build(true, null, null, null, null, null, false, false, labelFontSize: 10f);

        result.ShouldNotBeNull();
        result.CustomLabelFontSize.ShouldBe(10f);
    }

    [Fact]
    public void Build_WithTextColor_SetsTextColor()
    {
        var result = AppearanceBuilder.Build(true, null, null, null, null, null, false, false, textColor: "0.5,0.5,0.5");

        result.ShouldNotBeNull();
        result.TextColor.ShouldNotBeNull();
        (result.TextColor!.Value.R, result.TextColor!.Value.G, result.TextColor!.Value.B)
            .ShouldBe((0.5f, 0.5f, 0.5f));
    }

    [Fact]
    public void Build_WithFont_SetsBaseFontName()
    {
        var result = AppearanceBuilder.Build(true, null, null, null, null, null, false, false, font: "Times-Roman");

        result.ShouldNotBeNull();
        result.BaseFontName.ShouldBe("Times-Roman");
    }

    [Fact]
    public void Build_WithBorderColor_SetsBorderColor()
    {
        var result = AppearanceBuilder.Build(true, null, null, null, null, null, false, false,
            borderColor: "0.2,0.2,0.2", borderWidth: 1f);

        result.ShouldNotBeNull();
        result.BorderColor.ShouldNotBeNull();
        (result.BorderColor!.Value.R, result.BorderColor!.Value.G, result.BorderColor!.Value.B)
            .ShouldBe((0.2f, 0.2f, 0.2f));
        result.BorderWidth.ShouldBe(1f);
    }

    [Fact]
    public void Build_WithNoDate_HidesDate()
    {
        var result = AppearanceBuilder.Build(true, null, null, null, null, null, false, false, noDate: true);

        result.ShouldNotBeNull();
        result.ShowDate.ShouldBeFalse();
    }

    [Theory]
    [InlineData("0.5,0.5,0.5", 0.5f, 0.5f, 0.5f)]
    [InlineData("1,0,0", 1f, 0f, 0f)]
    [InlineData("0,0,0", 0f, 0f, 0f)]
    [InlineData("0.25,0.5,0.75", 0.25f, 0.5f, 0.75f)]
    public void ParseColor_ValidInput_ReturnsColor(string input, float r, float g, float b)
    {
        var result = AppearanceBuilder.ParseColor(input);
        result.ShouldNotBeNull();
        (result!.Value.R, result!.Value.G, result!.Value.B).ShouldBe((r, g, b));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("invalid")]
    [InlineData("1,2")]
    [InlineData("1,2,3,4")]
    [InlineData("abc,def,ghi")]
    public void ParseColor_InvalidInput_ReturnsNull(string? input) =>
        AppearanceBuilder.ParseColor(input).ShouldBeNull();

    [Fact]
    public void ParseColor_OutOfRange_ClampsToZeroOne() =>
        AppearanceBuilder.ParseColor("2,-1,0.5").ShouldBe((1f, 0f, 0.5f));

    [Fact]
    public void AddAeaExtraLines_AddsNameAndMaskedCpf()
    {
        var baseAppearance = AppearanceBuilder.Build(true, null, null, 1, 50f, 60f, true, false);

        var result = AppearanceBuilder.AddAeaExtraLines(baseAppearance, "André Almeida", "12345678901");

        result.ShouldNotBeNull();
        result.ExtraLines.ShouldNotBeNull();
        result.ExtraLines.Count.ShouldBe(2);
        result.ExtraLines[0].ShouldBe("André Almeida");
        result.ExtraLines[1].ShouldBe("CPF: ***.456.789-**");
        result.Page.ShouldBe(1);
        result.X.ShouldBe(50f);
        result.Y.ShouldBe(60f);
        result.AutoPosition.ShouldBeFalse();
    }

    [Fact]
    public void Build_WithTextOptions_SetsLabelsAndDate()
    {
        var text = new AppearanceTextOptions("Assinado por", "Motivo: ", "Local: ", "Data: ", "dd/MM/yyyy HH:mm zzz", "-03:00");

        var result = AppearanceBuilder.Build(true, null, null, null, null, null, true, true, text: text, backgroundColor: "1,1,0.9", imageFit: "contain");

        result.SignedByLabel.ShouldBe("Assinado por");
        result.ReasonLabel.ShouldBe("Motivo: ");
        result.LocationLabel.ShouldBe("Local: ");
        result.DateLabel.ShouldBe("Data: ");
        result.DateFormat.ShouldBe("dd/MM/yyyy HH:mm zzz");
        result.TimeZone!.BaseUtcOffset.ShouldBe(TimeSpan.FromHours(-3));
        result.BackgroundColor.ShouldBe((1f, 1f, 0.9f));
        result.BackgroundImageFit.ShouldBe(PAdES.Signing.SignatureImageFit.Contain);
        result.AutoPosition.ShouldBeTrue();
    }

    [Fact]
    public void Build_WithoutTextOptions_KeepsDefaultLabels()
    {
        var result = AppearanceBuilder.Build(true, null, null, null, null, null, false, false);

        result.SignedByLabel.ShouldBe("Signed by");
        result.TimeZone.ShouldBeNull();
        result.BackgroundImageFit.ShouldBe(PAdES.Signing.SignatureImageFit.Stretch);
    }

    [Theory]
    [InlineData("UTC", 0)]
    [InlineData("+05:30", 330)]
    [InlineData("-0300", -180)]
    [InlineData("-03", -180)]
    public void ParseTimeZone_Offsets_AreParsed(string value, int minutes) =>
        AppearanceBuilder.ParseTimeZone(value)!.BaseUtcOffset.ShouldBe(TimeSpan.FromMinutes(minutes));

    [Theory]
    [InlineData("Not/AZone")]
    [InlineData("+25:00")]
    [InlineData("-")]
    public void ParseTimeZone_Invalid_ReturnsNull(string value) =>
        AppearanceBuilder.ParseTimeZone(value).ShouldBeNull();

    [Theory]
    [InlineData("Stretch", PAdES.Signing.SignatureImageFit.Stretch)]
    [InlineData("contain", PAdES.Signing.SignatureImageFit.Contain)]
    [InlineData(" COVER ", PAdES.Signing.SignatureImageFit.Cover)]
    public void ParseImageFit_KnownModes_AreParsed(string value, PAdES.Signing.SignatureImageFit expected) =>
        AppearanceBuilder.ParseImageFit(value).ShouldBe(expected);

    [Fact]
    public void ParseImageFit_Unknown_ReturnsNull() =>
        AppearanceBuilder.ParseImageFit("tile").ShouldBeNull();

    [Fact]
    public void Build_WithLayoutOptions_SetsSizeAndAlignment()
    {
        var result = AppearanceBuilder.Build(true, null, null, null, null, null, false, false,
            layout: new AppearanceLayoutOptions(200f, 60f, "center"));

        result.Width.ShouldBe(200f);
        result.Height.ShouldBe(60f);
        result.TextAlignment.ShouldBe(PAdES.Signing.SignatureTextAlignment.Center);
    }

    [Theory]
    [InlineData("left", PAdES.Signing.SignatureTextAlignment.Left)]
    [InlineData("Center", PAdES.Signing.SignatureTextAlignment.Center)]
    [InlineData(" RIGHT", PAdES.Signing.SignatureTextAlignment.Right)]
    public void ParseTextAlignment_KnownValues_AreParsed(string value, PAdES.Signing.SignatureTextAlignment expected) =>
        AppearanceBuilder.ParseTextAlignment(value).ShouldBe(expected);

    [Fact]
    public void ParseTextAlignment_Unknown_ReturnsNull() =>
        AppearanceBuilder.ParseTextAlignment("justify").ShouldBeNull();

    [Fact]
    public void Build_WithExtraOptions_SetsEveryOne()
    {
        var result = AppearanceBuilder.Build(true, null, null, null, null, null, hasReason: true, hasLocation: true,
            text: new AppearanceTextOptions(null, null, null, null, "dd/MM/yyyy", null),
            extra: new AppearanceExtraOptions("middle", NoShrinkToFit: true, MaxTextLength: 120, DateCulture: "pt-BR",
                SignerDisplayName: "Dra. Ana", ExtraLines: ["CRM 12345", "São Paulo"], HideReason: true, HideLocation: false));

        result.VerticalAlignment.ShouldBe(PAdES.Signing.SignatureVerticalAlignment.Middle);
        result.ShrinkToFit.ShouldBeFalse();
        result.MaxTextLength.ShouldBe(120);
        result.DateCulture!.Name.ShouldBe("pt-BR");
        result.SignerDisplayName.ShouldBe("Dra. Ana");
        result.ExtraLines.ShouldBe(["CRM 12345", "São Paulo"]);
        result.ShowReason.ShouldBeFalse();
        result.ShowLocation.ShouldBeTrue();
    }

    [Fact]
    public void Build_WithoutExtraOptions_KeepsTheLibraryDefaults()
    {
        var result = AppearanceBuilder.Build(true, null, null, null, null, null, false, false);

        result.VerticalAlignment.ShouldBe(PAdES.Signing.SignatureVerticalAlignment.Top);
        result.ShrinkToFit.ShouldBeTrue();
        result.MaxTextLength.ShouldBe(new PAdES.Signing.SignatureAppearance().MaxTextLength);
    }

    [Fact]
    public void AddAeaExtraLines_AfterExtraLines_KeepsThem()
    {
        var result = AppearanceBuilder.AddAeaExtraLines(
            new PAdES.Signing.SignatureAppearance().WithExtraLines(["Linha"]), "Ana", "12345678901");

        result.ExtraLines![0].ShouldBe("Linha");
        result.ExtraLines.Count.ShouldBe(3);
    }

    [Theory]
    [InlineData("top", PAdES.Signing.SignatureVerticalAlignment.Top)]
    [InlineData(" Middle", PAdES.Signing.SignatureVerticalAlignment.Middle)]
    [InlineData("BOTTOM", PAdES.Signing.SignatureVerticalAlignment.Bottom)]
    public void ParseVerticalAlignment_KnownValues_AreParsed(string value, PAdES.Signing.SignatureVerticalAlignment expected) =>
        AppearanceBuilder.ParseVerticalAlignment(value).ShouldBe(expected);

    [Theory]
    [InlineData("pt-BR", true)]
    [InlineData("xx-NOPE", false)]
    public void IsValidCulture_Name_SaysWhetherItIsKnown(string name, bool expected) =>
        AppearanceBuilder.IsValidCulture(name).ShouldBe(expected);
}
