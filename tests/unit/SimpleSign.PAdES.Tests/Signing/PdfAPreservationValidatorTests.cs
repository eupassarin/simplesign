using FluentAssertions;
using SimpleSign.PAdES.Signing;
using SimpleSign.Pdf.Enums;
using Xunit;

namespace SimpleSign.PAdES.Tests.Signing;

public sealed class PdfAPreservationValidatorTests
{
    [Fact]
    public void Validate_NonPdfA_ReturnsNoIssues()
    {
        var options = new SignatureFieldOptions();
        var issues = PdfAPreservationValidator.Validate(PdfALevel.None, options);
        issues.Should().BeEmpty();
    }

    [Fact]
    public void Validate_PdfA1_WithEtsiCades_ReturnsError()
    {
        var options = new SignatureFieldOptions { SubFilter = PdfSignatureSubFilter.EtsiCadesDetached };
        var issues = PdfAPreservationValidator.Validate(PdfALevel.A1b, options);
        issues.Should().ContainSingle()
            .Which.Severity.Should().Be(PdfAIssueSeverity.Error);
    }

    [Fact]
    public void Validate_PdfA1a_WithEtsiCades_ReturnsError()
    {
        var options = new SignatureFieldOptions { SubFilter = PdfSignatureSubFilter.EtsiCadesDetached };
        var issues = PdfAPreservationValidator.Validate(PdfALevel.A1a, options);
        issues.Should().ContainSingle()
            .Which.Severity.Should().Be(PdfAIssueSeverity.Error);
    }

    [Fact]
    public void Validate_PdfA2_WithEtsiCades_ReturnsNoIssues()
    {
        var options = new SignatureFieldOptions { SubFilter = PdfSignatureSubFilter.EtsiCadesDetached };
        var issues = PdfAPreservationValidator.Validate(PdfALevel.A2b, options);
        issues.Should().BeEmpty();
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
        issues.Should().ContainSingle()
            .Which.Severity.Should().Be(PdfAIssueSeverity.Warning);
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
        issues.Should().BeEmpty();
    }

    [Fact]
    public void Validate_PdfA3_WithDefaultOptions_ReturnsNoIssues()
    {
        var options = new SignatureFieldOptions();
        var issues = PdfAPreservationValidator.Validate(PdfALevel.A3b, options);
        issues.Should().BeEmpty();
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
        issues.Should().BeEmpty("JPEG images don't have transparency issues in PDF/A-1");
    }

    [Fact]
    public void Validate_Unknown_WithEtsiCades_ReturnsNoIssues()
    {
        var options = new SignatureFieldOptions { SubFilter = PdfSignatureSubFilter.EtsiCadesDetached };
        var issues = PdfAPreservationValidator.Validate(PdfALevel.Unknown, options);
        issues.Should().BeEmpty("Unknown PDF/A level should not trigger errors");
    }

    [Fact]
    public void PdfACompatibilityIssue_RecordEquality()
    {
        var a = new PdfACompatibilityIssue(PdfAIssueSeverity.Error, "test");
        var b = new PdfACompatibilityIssue(PdfAIssueSeverity.Error, "test");
        a.Should().Be(b);
    }
}
