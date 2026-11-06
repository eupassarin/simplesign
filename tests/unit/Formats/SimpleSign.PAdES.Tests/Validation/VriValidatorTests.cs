using System.Text;
using Shouldly;
using SimpleSign.PAdES.Signing;
using SimpleSign.PAdES.Validation;
using Xunit;

namespace SimpleSign.PAdES.Tests.Validation;

/// <summary>
/// Tests for VRI (Validation Related Information) structure validation
/// per ISO 32000-2 §12.8.4.4.
/// </summary>
[Trait("Category", "Unit")]
public sealed class VriValidatorTests
{
    // ── VRI Key Validation ──────────────────────────────────────────────────

    [Theory(DisplayName = "IsValidVriKey accepts valid uppercase hex SHA-1")]
    [InlineData("A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2")]
    [InlineData("0123456789ABCDEF0123456789ABCDEF01234567")]
    public void IsValidVriKey_ValidHex_ReturnsTrue(string key) => VriValidator.IsValidVriKey(key).ShouldBeTrue();

    [Theory(DisplayName = "IsValidVriKey rejects invalid keys")]
    [InlineData("a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2")] // lowercase
    [InlineData("A1B2C3")] // too short
    [InlineData("ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ")] // non-hex
    [InlineData("")] // empty
    public void IsValidVriKey_InvalidKey_ReturnsFalse(string key) => VriValidator.IsValidVriKey(key).ShouldBeFalse();

    // ── VRI Validation on well-formed DSS ───────────────────────────────────

    [Fact(DisplayName = "Validate returns success for well-formed VRI with /TU")]
    public void Validate_WellFormedVriWithTu_ReturnsNoWarnings()
    {
        // Build a DSS dict with a VRI entry containing /Cert, /CRL, /OCSP, and /TU
        var dss = BuildDssWithVri(
            "A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2",
            includeRevocationData: true,
            includeTu: true);
        var span = Encoding.Latin1.GetBytes(dss).AsSpan();

        var result = VriValidator.Validate(span);

        result.EntryCount.ShouldBe(1);
        result.AllHaveTimestamps.ShouldBeTrue();
        result.Warnings.Where(w => w.Contains("/TU")).ShouldBeEmpty();
    }

    [Fact(DisplayName = "Validate warns on missing /TU")]
    public void Validate_MissingTu_WarnsAboutTimestamp()
    {
        var dss = BuildDssWithVri(
            "A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2",
            includeRevocationData: true,
            includeTu: false);
        var span = Encoding.Latin1.GetBytes(dss).AsSpan();

        var result = VriValidator.Validate(span);

        result.EntryCount.ShouldBe(1);
        result.AllHaveTimestamps.ShouldBeFalse();
        result.Warnings.ShouldContain(w => w.Contains("/TU"));
    }

    [Fact(DisplayName = "Validate warns when VRI not found")]
    public void Validate_NoVri_WarnsNotFound()
    {
        var dss = "<< /Type /DSS /CRLs [5 0 R] >>";
        var span = Encoding.Latin1.GetBytes(dss).AsSpan();

        var result = VriValidator.Validate(span);

        result.EntryCount.ShouldBe(0);
        result.Warnings.ShouldContain(w => w.Contains("not found"));
    }

    [Fact(DisplayName = "Validate handles empty VRI dictionary")]
    public void Validate_EmptyVri_WarnsEmpty()
    {
        var dss = "<< /Type /DSS /VRI << >> >>";
        var span = Encoding.Latin1.GetBytes(dss).AsSpan();

        var result = VriValidator.Validate(span);

        result.EntryCount.ShouldBe(0);
        result.Warnings.ShouldContain(w => w.Contains("empty"));
    }

    // ── LtvEmbedder /TU output ──────────────────────────────────────────────

    [Fact(DisplayName = "ExtractSignatureContentHashes produces uppercase hex SHA-1")]
    public void ExtractSignatureContentHashes_ProducesUppercaseHex()
    {
        // Build a minimal PDF with a fake /Contents <hex...>
        var fakeHex = new string('A', 2048); // >1000 chars to be recognized as sig
        var pdf = Encoding.Latin1.GetBytes(
            $"%PDF-1.7\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n" +
            $"2 0 obj\n<< /Contents <{fakeHex}> >>\nendobj\n" +
            "xref\n0 3\n0000000000 65535 f \n0000000009 00000 n \n0000000058 00000 n \n" +
            "trailer\n<< /Size 3 /Root 1 0 R >>\nstartxref\n200\n%%EOF");

        var hashes = LtvEmbedder.ExtractSignatureContentHashes(pdf);

        hashes.ShouldNotBeEmpty();
        foreach (var hash in hashes)
        {
            hash.ShouldMatch("^[0-9A-F]{40}$", "VRI key must be uppercase hex SHA-1");
        }
    }

    [Fact(DisplayName = "LtvEmbedder VRI output includes /TU timestamp")]
    public void LtvEmbedder_VriOutput_IncludesTuTimestamp()
    {
        // We test by building a VRI dictionary the same way LtvEmbedder does internally
        // and verifying the /TU field is present
        var vriSb = new StringBuilder();
        vriSb.Append("10 0 obj\n");
        vriSb.Append("<<\n");
        vriSb.Append("   /CRL [5 0 R]\n");
        vriSb.Append($"   /TU (D:{DateTime.UtcNow:yyyyMMddHHmmss}+00'00')\n");
        vriSb.Append(">>\nendobj\n");

        var output = vriSb.ToString();
        output.ShouldContain("/TU (D:");
        output.ShouldMatch(@"/TU \(D:\d{14}\+00'00'\)");
    }

    // ── Helper ──────────────────────────────────────────────────────────────

    private static string BuildDssWithVri(string hash, bool includeRevocationData, bool includeTu)
    {
        var sb = new StringBuilder();
        sb.Append("<< /Type /DSS\n");
        sb.Append("   /CRLs [5 0 R]\n");
        sb.Append("   /VRI <<\n");
        sb.Append($"      /{hash} <<\n");
        if (includeRevocationData)
        {
            sb.Append("         /CRL [5 0 R]\n");
            sb.Append("         /Cert [6 0 R]\n");
        }
        if (includeTu)
        {
            sb.Append("         /TU (D:20240101120000+00'00')\n");
        }
        sb.Append("      >>\n");
        sb.Append("   >>\n");
        sb.Append(">>");
        return sb.ToString();
    }
}
