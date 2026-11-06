using Shouldly;
using SimpleSign.Cli.Rendering;
using SimpleSign.PAdES.Inspection;

namespace SimpleSign.Cli.Tests;

public sealed class ExtractOutputRendererTests
{
    [Fact]
    public void Render_NoSignatures_ReturnsMessage()
    {
        var result = ExtractOutputRenderer.Render([], false);
        result.ShouldBe("No signatures found.");
    }

    [Fact]
    public void Render_SingleSignature_IncludesFileNames()
    {
        var sigs = new[] { CreateSignature("Signature1", "adbe.pkcs7.detached") };
        var result = ExtractOutputRenderer.Render(sigs, false);

        result.ShouldContain("Signature1");
        result.ShouldContain("adbe.pkcs7.detached");
        result.ShouldContain("Signature1.bin");
        result.ShouldContain("Signature1.p7s");
        result.ShouldContain("Signature1.pdf");
        result.ShouldNotContain("(skipped)");
    }

    [Fact]
    public void Render_NoRevision_ShowsSkipped()
    {
        var sigs = new[] { CreateSignature("Sig1", "ETSI.CAdES.detached") };
        var result = ExtractOutputRenderer.Render(sigs, true);

        result.ShouldContain("(skipped)");
        result.ShouldNotContain("Sig1.pdf");
    }

    [Fact]
    public void SanitizeFieldName_RemovesSpecialChars() =>
        ExtractOutputRenderer.SanitizeFieldName("Hello World!@#$").ShouldBe("Hello_World____");

    [Fact]
    public void SanitizeFieldName_EmptyReturnsDefault()
    {
        ExtractOutputRenderer.SanitizeFieldName("").ShouldBe("Signature");
        ExtractOutputRenderer.SanitizeFieldName(null!).ShouldBe("Signature");
    }

    [Fact]
    public void SanitizeFieldName_PreservesValidChars() =>
        ExtractOutputRenderer.SanitizeFieldName("Sig-1_ABC").ShouldBe("Sig-1_ABC");

    private static PadesSignatureData CreateSignature(string fieldName, string subFilter)
    {
        return new PadesSignatureData
        {
            FieldName = fieldName,
            SubFilter = subFilter,
            SignedData = [0x01, 0x02, 0x03],
            CmsSignature = [0x04, 0x05, 0x06],
            PdfRevision = [0x07, 0x08, 0x09],
            ByteRange = new SimpleSign.PAdES.Pdf.PdfByteRange { Offset1 = 0, Length1 = 100, Offset2 = 200, Length2 = 50 },
        };
    }
}
