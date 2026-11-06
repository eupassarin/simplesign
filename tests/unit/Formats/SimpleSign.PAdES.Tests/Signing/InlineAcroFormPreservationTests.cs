using System.Security.Cryptography.X509Certificates;
using System.Text;
using Shouldly;
using SimpleSign.Core.Validation;
using SimpleSign.PAdES.Signing;
using SimpleSign.PAdES.Validation;
using SimpleSign.TestHelpers;
using Xunit;

namespace SimpleSign.PAdES.Tests.Signing;

/// <summary>
/// Regression tests for adding signatures to PDFs whose Catalog contains an inline
/// /AcroForm dictionary. The inline representation must be preserved (only /Fields
/// gains the new reference), otherwise Acrobat's modification analysis invalidates
/// the earlier signature.
/// </summary>
[Trait("Category", "Unit")]
public sealed class InlineAcroFormPreservationTests
{
    /// <summary>
    /// Builds a PDF whose Catalog has an inline /AcroForm dictionary with /Fields,
    /// /DA and /DR entries, plus an existing (empty) signature field on page 1.
    /// </summary>
    internal static byte[] BuildPdfWithInlineAcroForm()
    {
        var sb = new StringBuilder();
        sb.Append("%PDF-1.7\n");

        int obj1Offset = sb.Length;
        sb.Append("1 0 obj\n<< /Type /Catalog /Pages 2 0 R\n");
        sb.Append("   /AcroForm << /SigFlags 3 /Fields [5 0 R] /DA (/Helv 0 Tf 0 g)\n");
        sb.Append("               /DR << /Font << /Helv 4 0 R /ZaDb 4 0 R >> /XObject << /FRM 4 0 R >> >> >>\n");
        sb.Append(">>\nendobj\n");

        int obj2Offset = sb.Length;
        sb.Append("2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n");

        int obj3Offset = sb.Length;
        sb.Append("3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Annots [5 0 R] >>\nendobj\n");

        int obj4Offset = sb.Length;
        sb.Append("4 0 obj\n<< /Type /Font >>\nendobj\n");

        int obj5Offset = sb.Length;
        sb.Append("5 0 obj\n<< /Type /Annot /Subtype /Widget /FT /Sig /T (Existing) /P 3 0 R /Rect [0 0 0 0] /F 132 >>\nendobj\n");

        long xrefOffset = sb.Length;
        sb.Append("xref\n0 6\n");
        sb.Append("0000000000 65535 f \n");
        sb.Append($"{obj1Offset:D10} 00000 n \n");
        sb.Append($"{obj2Offset:D10} 00000 n \n");
        sb.Append($"{obj3Offset:D10} 00000 n \n");
        sb.Append($"{obj4Offset:D10} 00000 n \n");
        sb.Append($"{obj5Offset:D10} 00000 n \n");
        sb.Append("trailer\n<< /Size 6 /Root 1 0 R >>\n");
        sb.Append($"startxref\n{xrefOffset}\n%%EOF\n");

        return Encoding.Latin1.GetBytes(sb.ToString());
    }

    private static PdfSignatureValidator ValidatorTrusting(params X509Certificate2[] certs)
    {
        return new PdfSignatureValidator(new ValidationOptions
        {
            CheckRevocation = false,
            TrustedRoots = [.. certs]
        });
    }

    private static string LatestAcroFormSection(byte[] pdf)
    {
        string text = Encoding.Latin1.GetString(pdf);
        int lastAcroForm = text.LastIndexOf("/AcroForm", StringComparison.Ordinal);
        lastAcroForm.ShouldBeGreaterThanOrEqualTo(0, "output must contain an /AcroForm entry");
        return text[lastAcroForm..];
    }

    [Fact(DisplayName = "Adding a signature preserves an inline AcroForm and keeps earlier signature valid")]
    public async Task SignAsync_InlineAcroForm_PreservedAndBothSignaturesValid()
    {
        using X509Certificate2 cert1 = TestCertificateFactory.CreateSelfSignedCert("CN=First Signer, O=Tests");
        using X509Certificate2 cert2 = TestCertificateFactory.CreateSelfSignedCert("CN=Second Signer, O=Tests");

        byte[] source = BuildPdfWithInlineAcroForm();
        byte[] signed1 = await PadesSigner.Document(source)
            .WithCertificate(cert1)
            .WithFieldOptions(new SignatureFieldOptions { FieldName = "SigA", SignerName = "First" })
            .WithAppearance(new SignatureAppearance { X = 30, Y = 30, AutoPosition = false })
            .SignAsync();

        // First signing must keep the inline AcroForm and append only the new field.
        string firstSection = LatestAcroFormSection(signed1);
        firstSection.ShouldContain("/Fields [5 0 R 7 0 R]");
        firstSection.ShouldContain("/DA (/Helv 0 Tf 0 g)");
        firstSection.ShouldContain("/DR <<");

        byte[] signed2 = await PadesSigner.Document(signed1)
            .WithCertificate(cert2)
            .WithFieldOptions(new SignatureFieldOptions { FieldName = "SigB", SignerName = "Second" })
            .WithAppearance(new SignatureAppearance { X = 150, Y = 30, AutoPosition = false })
            .SignAsync();

        // The first revision must remain an exact byte prefix (single incremental update).
        signed2.AsSpan(0, signed1.Length).SequenceEqual(signed1).ShouldBeTrue(
            "the first signed revision must be preserved byte-for-byte");

        // The latest Catalog must still use an inline /AcroForm dictionary with all
        // original entries and the appended field references.
        string latestSection = LatestAcroFormSection(signed2);
        latestSection.ShouldStartWith("/AcroForm <<");
        latestSection.ShouldContain("/Fields [5 0 R 7 0 R 13 0 R]");
        latestSection.ShouldContain("/DA (/Helv 0 Tf 0 g)");
        latestSection.ShouldContain("/DR <<");
        latestSection.ShouldContain("/SigFlags 3");

        // Both signatures must validate.
        using MemoryStream ms = new(signed2);
        IReadOnlyList<SignatureValidationResult> results = await ValidatorTrusting(cert1, cert2).ValidateAsync(ms);
        results.Count.ShouldBe(2);
        foreach (var r in results)
        {
            r.IsIntegrityValid.ShouldBeTrue();
            r.IsSignatureValid.ShouldBeTrue();
        }
    }
}
