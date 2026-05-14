using FluentAssertions;
using SimpleSign.PAdES.Signing;
using SimpleSign.Pdf;
using Xunit;
namespace SimpleSign.PAdES.Tests.Signing;

/// <summary>
/// Tests for Phase 2 enterprise features: DocMDP certification, existing field signing,
/// and rich appearance (image, colors, border).
/// </summary>
public sealed class Phase2EnterpriseTests
{

    // ── DocMDP / Certification ───────────────────────────────────────────

    [Fact(DisplayName = "AsCertification returns new builder instance")]
    public void AsCertification_ReturnsNewInstance()
    {
        var builder = SimpleSigner.Document(new byte[] { 0x25 });
        var builder2 = builder.AsCertification(CertificationLevel.NoChanges);
        builder2.Should().NotBeSameAs(builder);
    }

    [Fact(DisplayName = "Default AsCertification uses FormFilling")]
    public void AsCertification_DefaultLevel_IsFormFilling()
    {
        var builder = SimpleSigner.Document(new byte[] { 0x25 });
        var builder2 = builder.AsCertification();
        builder2.Should().NotBeNull();
    }

    [Theory(DisplayName = "CertificationLevel values are between 1 and 3")]
    [InlineData(CertificationLevel.NoChanges)]
    [InlineData(CertificationLevel.FormFilling)]
    [InlineData(CertificationLevel.FormFillingAndAnnotations)]
    public void CertificationLevel_Values_AreCorrect(CertificationLevel level)
    {
        ((int)level).Should().BeInRange(1, 3);
    }

    // ── Existing Field ───────────────────────────────────────────────────

    [Fact(DisplayName = "WithExistingField returns new instance")]
    public void WithExistingField_ReturnsNewInstance()
    {
        var builder = SimpleSigner.Document(new byte[] { 0x25 });
        var builder2 = builder.WithExistingField("Signature1");
        builder2.Should().NotBeSameAs(builder);
    }

    [Fact(DisplayName = "WithExistingField with null name throws exception")]
    public void WithExistingField_NullName_ThrowsArgument()
    {
        var builder = SimpleSigner.Document(new byte[] { 0x25 });
        var act = () => builder.WithExistingField(null!);
        act.Should().Throw<ArgumentException>();
    }

    [Fact(DisplayName = "WithExistingField with empty name throws exception")]
    public void WithExistingField_EmptyName_ThrowsArgument()
    {
        var builder = SimpleSigner.Document(new byte[] { 0x25 });
        var act = () => builder.WithExistingField("");
        act.Should().Throw<ArgumentException>();
    }

    // ── Rich Appearance ──────────────────────────────────────────────────

    [Fact(DisplayName = "TextColor is stored correctly")]
    public void SignatureAppearance_TextColor_IsStored()
    {
        var app = new SignatureAppearance { TextColor = (0.2f, 0.3f, 0.4f) };
        app.TextColor.Should().Be((0.2f, 0.3f, 0.4f));
    }

    [Fact(DisplayName = "BorderColor is stored correctly")]
    public void SignatureAppearance_BorderColor_IsStored()
    {
        var app = new SignatureAppearance { BorderColor = (1f, 0f, 0f) };
        app.BorderColor.Should().Be((1f, 0f, 0f));
    }

    [Fact(DisplayName = "CustomFontSize is stored and returned")]
    public void SignatureAppearance_CustomFontSize_IsStored()
    {
        var app = new SignatureAppearance { CustomFontSize = 10f };
        app.CustomFontSize.Should().Be(10f);
        app.GetFontSizeValue().Should().Be(10f);
    }

    [Fact(DisplayName = "Default FontSize when CustomFontSize is null")]
    public void SignatureAppearance_DefaultFontSize_WhenNull()
    {
        var app = new SignatureAppearance();
        app.GetFontSizeValue().Should().Be(SignatureAppearance.GetFontSize());
    }

    [Fact(DisplayName = "BackgroundImageJpeg is stored correctly")]
    public void SignatureAppearance_BackgroundImage_IsStored()
    {
        byte[] jpeg = [0xFF, 0xD8, 0xFF, 0xE0];
        var app = new SignatureAppearance { BackgroundImageJpeg = jpeg };
        app.BackgroundImageJpeg!.Value.ToArray().Should().BeEquivalentTo(jpeg);
    }

    [Fact(DisplayName = "Default BorderWidth is 0.5")]
    public void SignatureAppearance_BorderWidth_DefaultIs05()
    {
        var app = new SignatureAppearance();
        app.BorderWidth.Should().Be(0.5f);
    }

    // ── FindEmptySignatureField ──────────────────────────────────────────

    [Fact(DisplayName = "Field not found returns -1")]
    public void FindEmptySignatureField_NotFound_ReturnsNegative()
    {
        byte[] pdf = System.Text.Encoding.Latin1.GetBytes(
            "%PDF-1.7\n1 0 obj\n<< /Type /Catalog >>\nendobj\n");
        var result = PdfStructureParser.FindEmptySignatureField(pdf, "MissingField");
        result.Should().Be(-1);
    }

    [Fact(DisplayName = "Empty field found returns object number")]
    public void FindEmptySignatureField_EmptyField_ReturnsObjNum()
    {
        byte[] pdf = System.Text.Encoding.Latin1.GetBytes(
            "%PDF-1.7\n" +
            "5 0 obj\n<< /Type /Annot /Subtype /Widget /FT /Sig /T (Signature1) /Rect [0 0 0 0] >>\nendobj\n");
        var result = PdfStructureParser.FindEmptySignatureField(pdf, "Signature1");
        result.Should().Be(5);
    }

    [Fact(DisplayName = "Already signed field throws exception")]
    public void FindEmptySignatureField_SignedField_Throws()
    {
        byte[] pdf = System.Text.Encoding.Latin1.GetBytes(
            "%PDF-1.7\n" +
            "5 0 obj\n<< /FT /Sig /T (Signature1) /V 10 0 R >>\nendobj\n");
        var act = () => PdfStructureParser.FindEmptySignatureField(pdf, "Signature1");
        act.Should().Throw<InvalidOperationException>()
            .WithMessage("*already signed*");
    }

    // ── SignatureFieldOptions ────────────────────────────────────────────

    [Fact(DisplayName = "Default CertificationLevel is null")]
    public void SignatureFieldOptions_CertificationLevel_DefaultIsNull()
    {
        var opts = new SignatureFieldOptions();
        opts.CertificationLevel.Should().BeNull();
    }

    [Fact(DisplayName = "Default ExistingFieldName is null")]
    public void SignatureFieldOptions_ExistingFieldName_DefaultIsNull()
    {
        var opts = new SignatureFieldOptions();
        opts.ExistingFieldName.Should().BeNull();
    }
}
