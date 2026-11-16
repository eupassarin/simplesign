using Shouldly;
using SimpleSign.PAdES.Signing;
using SimpleSign.PAdES.Pdf.Enums;
using Xunit;

namespace SimpleSign.PAdES.Tests.Signing;

[Trait("Category", "Unit")]
public sealed class PdfAPreservationValidatorTests
{
    [Fact]
    public void Validate_NonPdfA_ReturnsNoIssues()
    {
        var options = new SignatureFieldOptions();
        var issues = PdfAPreservationValidator.Validate(PdfALevel.None, options);
        issues.ShouldBeEmpty();
    }

    [Fact]
    public void Validate_PdfA1_WithEtsiCades_ReturnsError()
    {
        var options = new SignatureFieldOptions { SubFilter = PdfSignatureSubFilter.EtsiCadesDetached };
        var issues = PdfAPreservationValidator.Validate(PdfALevel.A1b, options);
        issues.Count().ShouldBe(1);
        issues.First().Severity.ShouldBe(PdfAIssueSeverity.Error);
    }

    [Fact]
    public void Validate_PdfA1a_WithEtsiCades_ReturnsError()
    {
        var options = new SignatureFieldOptions { SubFilter = PdfSignatureSubFilter.EtsiCadesDetached };
        var issues = PdfAPreservationValidator.Validate(PdfALevel.A1a, options);
        issues.Count().ShouldBe(1);
        issues.First().Severity.ShouldBe(PdfAIssueSeverity.Error);
    }

    [Fact]
    public void Validate_PdfA2_WithEtsiCades_ReturnsNoIssues()
    {
        var options = new SignatureFieldOptions { SubFilter = PdfSignatureSubFilter.EtsiCadesDetached };
        var issues = PdfAPreservationValidator.Validate(PdfALevel.A2b, options);
        issues.ShouldBeEmpty();
    }

    [Fact]
    public void Validate_PdfA1_WithPngAppearance_ReturnsWarning()
    {
        var options = new SignatureFieldOptions
        {
            SubFilter = PdfSignatureSubFilter.AdbePkcs7Detached,
            Appearance = new SignatureAppearance
            {
                BackgroundImagePng = new byte[] { 0x89, 0x50, 0x4E, 0x47 }, // PNG header
            },
        };
        var issues = PdfAPreservationValidator.Validate(PdfALevel.A1b, options);
        issues.Count().ShouldBe(1);
        issues.First().Severity.ShouldBe(PdfAIssueSeverity.Error);
    }

    [Fact]
    public void Validate_PdfA2_WithPngAppearance_ReturnsNoIssues()
    {
        var options = new SignatureFieldOptions
        {
            Appearance = new SignatureAppearance
            {
                BackgroundImagePng = new byte[] { 0x89, 0x50, 0x4E, 0x47 },
            },
        };
        var issues = PdfAPreservationValidator.Validate(PdfALevel.A2b, options);
        issues.ShouldBeEmpty();
    }

    [Fact]
    public void Validate_PdfA3_WithDefaultOptions_ReturnsNoIssues()
    {
        var options = new SignatureFieldOptions();
        var issues = PdfAPreservationValidator.Validate(PdfALevel.A3b, options);
        issues.ShouldBeEmpty();
    }

    [Fact]
    public void Validate_PdfA1_WithJpegAppearance_ReturnsNoIssues()
    {
        var options = new SignatureFieldOptions
        {
            SubFilter = PdfSignatureSubFilter.AdbePkcs7Detached,
            Appearance = new SignatureAppearance
            {
                BackgroundImageJpeg = new byte[] { 0xFF, 0xD8, 0xFF },
            },
        };
        var issues = PdfAPreservationValidator.Validate(PdfALevel.A1b, options);
        issues.ShouldBeEmpty("JPEG images don't have transparency issues in PDF/A-1");
    }

    [Fact]
    public void Validate_Unknown_WithEtsiCades_ReturnsNoIssues()
    {
        var options = new SignatureFieldOptions { SubFilter = PdfSignatureSubFilter.EtsiCadesDetached };
        var issues = PdfAPreservationValidator.Validate(PdfALevel.Unknown, options);
        issues.ShouldBeEmpty("Unknown PDF/A level should not trigger errors");
    }

    [Theory(DisplayName = "CMYK JPEG stamp on a PDF/A document: a warning (DeviceCMYK needs a CMYK OutputIntent)")]
    [InlineData(PdfALevel.A1b)]
    [InlineData(PdfALevel.A2b)]
    [InlineData(PdfALevel.A3u)]
    public void Validate_PdfAWithCmykJpeg_ReturnsWarning(PdfALevel level)
    {
        var options = new SignatureFieldOptions
        {
            SubFilter = PdfSignatureSubFilter.AdbePkcs7Detached,
            Appearance = new SignatureAppearance { BackgroundImageJpeg = Jpeg(components: 4) },
        };

        var issues = PdfAPreservationValidator.Validate(level, options);

        var issue = issues.ShouldHaveSingleItem();
        issue.Severity.ShouldBe(PdfAIssueSeverity.Warning);
        issue.Message.ShouldContain("CMYK");
    }

    [Theory(DisplayName = "RGB or grayscale JPEG stamp on a PDF/A document: no issue (mapped to sRGB)")]
    [InlineData(1)]
    [InlineData(3)]
    public void Validate_PdfAWithRgbOrGrayJpeg_ReturnsNoIssues(byte components)
    {
        var options = new SignatureFieldOptions { Appearance = new SignatureAppearance { BackgroundImageJpeg = Jpeg(components) } };

        PdfAPreservationValidator.Validate(PdfALevel.A2b, options).ShouldBeEmpty();
    }

    [Fact(DisplayName = "CMYK JPEG stamp on a document that is not PDF/A: no issue")]
    public void Validate_NonPdfAWithCmykJpeg_ReturnsNoIssues()
    {
        var options = new SignatureFieldOptions { Appearance = new SignatureAppearance { BackgroundImageJpeg = Jpeg(components: 4) } };

        PdfAPreservationValidator.Validate(PdfALevel.None, options).ShouldBeEmpty();
    }

    [Fact(DisplayName = "CMYK JPEG next to a PNG: the PNG is drawn, so no CMYK warning")]
    public void Validate_PdfAWithPngAndCmykJpeg_ReturnsNoIssues()
    {
        var options = new SignatureFieldOptions
        {
            Appearance = new SignatureAppearance
            {
                BackgroundImagePng = new byte[] { 0x89, 0x50, 0x4E, 0x47 },
                BackgroundImageJpeg = Jpeg(components: 4),
            },
        };

        PdfAPreservationValidator.Validate(PdfALevel.A2b, options).ShouldBeEmpty();
    }

    [Fact]
    public void PdfACompatibilityIssue_RecordEquality()
    {
        var a = new PdfACompatibilityIssue(PdfAIssueSeverity.Error, "test");
        var b = new PdfACompatibilityIssue(PdfAIssueSeverity.Error, "test");
        a.ShouldBe(b);
    }

    /// <summary>A JPEG header (SOI, SOF0, EOI) with the given number of colour components.</summary>
    private static byte[] Jpeg(byte components)
    {
        var bytes = new List<byte> { 0xFF, 0xD8 };
        int sofLength = 8 + (3 * components);
        bytes.AddRange([0xFF, 0xC0, (byte)(sofLength >> 8), (byte)sofLength, 8, 0, 8, 0, 8, components]);
        for (int c = 0; c < components; c++)
        {
            bytes.AddRange([(byte)(c + 1), 0x11, 0]);
        }

        bytes.AddRange([0xFF, 0xD9]);
        return [.. bytes];
    }
}
