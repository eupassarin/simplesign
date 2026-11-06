using System.Text;
using Shouldly;
using SimpleSign.PAdES.Inspection;
using Xunit;

namespace SimpleSign.PAdES.Tests.Inspection;

[Trait("Category", "Unit")]
public sealed class PdfStructureDumperTests
{
    /// <summary>
    /// Builds a minimal PDF containing a /Sig dictionary so we can test object extraction.
    /// </summary>
    private static byte[] BuildMinimalSignedPdf()
    {
        // Synthetic PDF with: Catalog (obj 1), Pages (obj 2), Page (obj 3), AcroForm (obj 4), SigField (obj 5), Sig dict (obj 6)
        var sb = new StringBuilder();
        sb.AppendLine("%PDF-1.7");
        sb.AppendLine("1 0 obj");
        sb.AppendLine("<< /Type /Catalog /Pages 2 0 R /AcroForm 4 0 R >>");
        sb.AppendLine("endobj");
        sb.AppendLine("2 0 obj");
        sb.AppendLine("<< /Type /Pages /Kids [3 0 R] /Count 1 >>");
        sb.AppendLine("endobj");
        sb.AppendLine("3 0 obj");
        sb.AppendLine("<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>");
        sb.AppendLine("endobj");
        sb.AppendLine("4 0 obj");
        sb.AppendLine("<< /SigFlags 3 /Fields [5 0 R] >>");
        sb.AppendLine("endobj");
        sb.AppendLine("5 0 obj");
        sb.AppendLine("<< /Type /Annot /Subtype /Widget /FT /Sig /T (Sig1) /V 6 0 R >>");
        sb.AppendLine("endobj");
        sb.AppendLine("6 0 obj");
        sb.AppendLine("<< /Type /Sig /SubFilter /ETSI.CAdES.detached /ByteRange [0 100 200 50] /Contents <AABB> >>");
        sb.AppendLine("endobj");
        sb.AppendLine("%%EOF");
        return Encoding.Latin1.GetBytes(sb.ToString());
    }

    /// <summary>
    /// Builds a minimal PDF with DSS dictionary.
    /// </summary>
    private static byte[] BuildPdfWithDss()
    {
        var sb = new StringBuilder();
        sb.AppendLine("%PDF-1.7");
        sb.AppendLine("1 0 obj");
        sb.AppendLine("<< /Type /Catalog /Pages 2 0 R /AcroForm 4 0 R /DSS 7 0 R >>");
        sb.AppendLine("endobj");
        sb.AppendLine("2 0 obj");
        sb.AppendLine("<< /Type /Pages /Kids [3 0 R] /Count 1 >>");
        sb.AppendLine("endobj");
        sb.AppendLine("3 0 obj");
        sb.AppendLine("<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>");
        sb.AppendLine("endobj");
        sb.AppendLine("4 0 obj");
        sb.AppendLine("<< /SigFlags 3 /Fields [5 0 R] >>");
        sb.AppendLine("endobj");
        sb.AppendLine("5 0 obj");
        sb.AppendLine("<< /Type /Annot /Subtype /Widget /FT /Sig /T (Sig1) /V 6 0 R >>");
        sb.AppendLine("endobj");
        sb.AppendLine("6 0 obj");
        sb.AppendLine("<< /Type /Sig /SubFilter /ETSI.CAdES.detached /ByteRange [0 100 200 50] /Contents <AABB> >>");
        sb.AppendLine("endobj");
        sb.AppendLine("7 0 obj");
        sb.AppendLine("<< /Type /DSS /CRLs [8 0 R] /Certs [9 0 R] >>");
        sb.AppendLine("endobj");
        sb.AppendLine("8 0 obj");
        sb.AppendLine("<< /Length 10 >>");
        sb.AppendLine("stream");
        sb.Append("0123456789");
        sb.AppendLine();
        sb.AppendLine("endstream");
        sb.AppendLine("endobj");
        sb.AppendLine("9 0 obj");
        sb.AppendLine("<< /Length 5 >>");
        sb.AppendLine("stream");
        sb.Append("ABCDE");
        sb.AppendLine();
        sb.AppendLine("endstream");
        sb.AppendLine("endobj");
        sb.AppendLine("%%EOF");
        return Encoding.Latin1.GetBytes(sb.ToString());
    }

    [Fact(DisplayName = "ExtractSignatureObjects finds Catalog, AcroForm, Sig field, and Sig dict")]
    public void ExtractSignatureObjects_MinimalPdf_FindsSignatureObjects()
    {
        byte[] pdf = BuildMinimalSignedPdf();

        var objects = PdfStructureDumper.ExtractSignatureObjects(pdf);

        objects.ShouldNotBeEmpty();
        objects.ShouldContain(o => o.Label == "Catalog");
        objects.ShouldContain(o => o.Label == "AcroForm");
        objects.ShouldContain(o => o.Label == "Signature Field");
        objects.ShouldContain(o => o.Label == "Signature");
    }

    [Fact(DisplayName = "ExtractSignatureObjects recognizes DocTimeStamp")]
    public void ExtractSignatureObjects_DocTimeStamp_RecognizedAsTimestamp()
    {
        var sb = new StringBuilder();
        sb.AppendLine("%PDF-1.7");
        sb.AppendLine("1 0 obj");
        sb.AppendLine("<< /Type /Catalog /Pages 2 0 R >>");
        sb.AppendLine("endobj");
        sb.AppendLine("2 0 obj");
        sb.AppendLine("<< /Type /Sig /SubFilter /ETSI.RFC3161 /ByteRange [0 10 20 5] /Contents <FF> >>");
        sb.AppendLine("endobj");
        sb.AppendLine("%%EOF");
        var pdf = Encoding.Latin1.GetBytes(sb.ToString());

        var objects = PdfStructureDumper.ExtractSignatureObjects(pdf);

        objects.ShouldContain(o => o.Label == "DocTimeStamp");
    }

    [Fact(DisplayName = "ExtractSignatureObjects skips non-signature objects")]
    public void ExtractSignatureObjects_IgnoresIrrelevantObjects()
    {
        byte[] pdf = BuildMinimalSignedPdf();

        var objects = PdfStructureDumper.ExtractSignatureObjects(pdf);

        // Pages and Page objects should not be extracted
        objects.ShouldNotContain(o => o.ObjectNumber == 2, "Pages object is not signature-related");
        objects.ShouldNotContain(o => o.ObjectNumber == 3, "Page object is not signature-related");
    }

    [Fact(DisplayName = "ExtractSignatureObjects with DSS finds DSS and referenced streams")]
    public void ExtractSignatureObjects_WithDss_FindsDssAndStreams()
    {
        byte[] pdf = BuildPdfWithDss();

        var objects = PdfStructureDumper.ExtractSignatureObjects(pdf);

        objects.ShouldContain(o => o.Label == "DSS");
        // DSS-referenced streams (obj 8, 9) should be included
        objects.ShouldContain(o => o.ObjectNumber == 8 || o.ObjectNumber == 9,
            "DSS-referenced stream objects should be extracted");
    }

    [Fact(DisplayName = "Format produces non-empty text with object headers")]
    public void Format_ProducesReadableOutput()
    {
        byte[] pdf = BuildMinimalSignedPdf();
        var objects = PdfStructureDumper.ExtractSignatureObjects(pdf);

        string output = PdfStructureDumper.Format(objects);

        output.ShouldNotBeNullOrWhiteSpace();
        output.ShouldContain("Catalog");
        output.ShouldContain("0 obj");
        output.ShouldContain("/Type /Sig");
    }

    [Fact(DisplayName = "With explanations adds inline % comments")]
    public void ExtractWithExplanations_AddsComments()
    {
        byte[] pdf = BuildMinimalSignedPdf();

        var objects = PdfStructureDumper.ExtractSignatureObjects(pdf, includeExplanations: true);

        string output = PdfStructureDumper.Format(objects);
        output.ShouldContain("%");
    }

    [Fact(DisplayName = "Throws ArgumentNullException for null input")]
    public void ExtractSignatureObjects_NullInput_Throws()
    {
        var act = () => PdfStructureDumper.ExtractSignatureObjects(null!);
        Should.Throw<ArgumentNullException>(act);
    }

    [Fact(DisplayName = "Returns empty for non-PDF input")]
    public void ExtractSignatureObjects_NonPdf_ReturnsEmpty()
    {
        byte[] notPdf = Encoding.Latin1.GetBytes("This is not a PDF file at all.");

        var objects = PdfStructureDumper.ExtractSignatureObjects(notPdf);

        objects.ShouldBeEmpty();
    }

    [Fact(DisplayName = "Objects are sorted by object number")]
    public void ExtractSignatureObjects_SortedByObjectNumber()
    {
        byte[] pdf = BuildMinimalSignedPdf();

        var objects = PdfStructureDumper.ExtractSignatureObjects(pdf);

        var objectNumbers = objects.Select(o => o.ObjectNumber).ToList();
        objectNumbers.SequenceEqual(objectNumbers.OrderBy(x => x)).ShouldBeTrue();
    }

    [Fact(DisplayName = "/Contents value is truncated in output")]
    public void Format_ContentsFieldIsTruncated()
    {
        byte[] pdf = BuildMinimalSignedPdf();

        var objects = PdfStructureDumper.ExtractSignatureObjects(pdf);
        string output = PdfStructureDumper.Format(objects);

        // The sig dict has /Contents <AABB> which is short, but the formatting should work
        output.ShouldContain("/Contents");
    }

    [Fact(DisplayName = "Detects sig dict without /Type /Sig via /Adobe.PPKLite + /ByteRange")]
    public void ExtractObjects_DetectsSignatureWithoutTypeSig()
    {
        var sb = new StringBuilder();
        sb.AppendLine("%PDF-1.3");
        sb.AppendLine("1 0 obj");
        sb.AppendLine("<< /Type /Catalog /Pages 2 0 R >>");
        sb.AppendLine("endobj");
        sb.AppendLine("2 0 obj");
        sb.AppendLine("<< /Type /Pages /Kids [3 0 R] /Count 1 >>");
        sb.AppendLine("endobj");
        sb.AppendLine("3 0 obj");
        sb.AppendLine("<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>");
        sb.AppendLine("endobj");
        sb.AppendLine("4 0 obj");
        sb.AppendLine("<< /SigFlags 3 /Fields [5 0 R] >>");
        sb.AppendLine("endobj");
        sb.AppendLine("5 0 obj");
        sb.AppendLine("<< /Subtype /Widget /T (Sig1) /V 6 0 R >>");
        sb.AppendLine("endobj");
        // No /Type /Sig — only /Filter + /ByteRange
        sb.AppendLine("6 0 obj");
        sb.AppendLine("<< /Filter /Adobe.PPKLite /SubFilter /adbe.pkcs7.detached /ByteRange [0 100 200 50] /Contents <AABB> >>");
        sb.AppendLine("endobj");
        sb.AppendLine("%%EOF");

        byte[] pdf = Encoding.Latin1.GetBytes(sb.ToString());
        var objects = PdfStructureDumper.ExtractSignatureObjects(pdf);

        objects.ShouldContain(o => o.Label == "Signature" && o.ObjectNumber == 6);
        objects.ShouldContain(o => o.Label == "Signature Field" && o.ObjectNumber == 5);
    }

    [Fact(DisplayName = "Discovers sig dict via /V reference when not self-identifying")]
    public void ExtractObjects_FollowsVReferenceToDiscoverSigDict()
    {
        var sb = new StringBuilder();
        sb.AppendLine("%PDF-1.3");
        sb.AppendLine("1 0 obj");
        sb.AppendLine("<< /Type /Catalog /Pages 2 0 R >>");
        sb.AppendLine("endobj");
        sb.AppendLine("2 0 obj");
        sb.AppendLine("<< /Type /Pages /Kids [3 0 R] /Count 1 >>");
        sb.AppendLine("endobj");
        sb.AppendLine("3 0 obj");
        sb.AppendLine("<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 10 0 R >>");
        sb.AppendLine("endobj");
        sb.AppendLine("4 0 obj");
        sb.AppendLine("<< /SigFlags 3 /Fields [5 0 R] >>");
        sb.AppendLine("endobj");
        // Field without /FT /Sig
        sb.AppendLine("5 0 obj");
        sb.AppendLine("<< /Subtype /Widget /T (Signature1) /V 6 0 R >>");
        sb.AppendLine("endobj");
        // Sig dict without /Type /Sig or /Filter
        sb.AppendLine("6 0 obj");
        sb.AppendLine("<< /SubFilter /adbe.pkcs7.detached /ByteRange [0 100 200 50] /Contents <AABB> >>");
        sb.AppendLine("endobj");
        // Page content stream (should NOT be picked up)
        sb.AppendLine("10 0 obj");
        sb.AppendLine("<< /Length 5 >>");
        sb.AppendLine("stream");
        sb.AppendLine("hello");
        sb.AppendLine("endstream");
        sb.AppendLine("endobj");
        sb.AppendLine("%%EOF");

        byte[] pdf = Encoding.Latin1.GetBytes(sb.ToString());
        var objects = PdfStructureDumper.ExtractSignatureObjects(pdf);

        // Should find field via AcroForm /Fields reference, then sig dict via /V reference
        objects.ShouldContain(o => o.Label == "Signature Field" && o.ObjectNumber == 5);
        objects.ShouldContain(o => o.Label == "Signature" && o.ObjectNumber == 6);
        // Page content stream should NOT be included
        objects.ShouldNotContain(o => o.ObjectNumber == 10);
        // Page object should NOT be included
        objects.ShouldNotContain(o => o.ObjectNumber == 3);
    }

    [Fact(DisplayName = "Parses compact /T(name) /V ref notation correctly")]
    public void ExtractObjects_CompactFieldNotation()
    {
        var sb = new StringBuilder();
        sb.AppendLine("%PDF-1.3");
        sb.AppendLine("1 0 obj");
        sb.AppendLine("<< /Type /Catalog /Pages 2 0 R >>");
        sb.AppendLine("endobj");
        sb.AppendLine("2 0 obj");
        sb.AppendLine("<< /Type /Pages /Kids [3 0 R] /Count 1 >>");
        sb.AppendLine("endobj");
        sb.AppendLine("3 0 obj");
        sb.AppendLine("<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>");
        sb.AppendLine("endobj");
        sb.AppendLine("4 0 obj");
        sb.AppendLine("<< /SigFlags 3 /Fields [5 0 R] >>");
        sb.AppendLine("endobj");
        // Compact: /T(Sig1) with no space, then /V 6 0 R
        sb.AppendLine("5 0 obj");
        sb.AppendLine("<< /Subtype /Widget /T(Signature1) /V 6 0 R /F 132 /Rect [0 0 100 50] /P 3 0 R >>");
        sb.AppendLine("endobj");
        sb.AppendLine("6 0 obj");
        sb.AppendLine("<< /Filter /Adobe.PPKLite /SubFilter /adbe.pkcs7.detached /ByteRange [0 100 200 50] /Contents <AABB> >>");
        sb.AppendLine("endobj");
        sb.AppendLine("%%EOF");

        byte[] pdf = Encoding.Latin1.GetBytes(sb.ToString());
        var objects = PdfStructureDumper.ExtractSignatureObjects(pdf);

        // Field should be detected with /T parsed correctly (not swallowing /V)
        objects.ShouldContain(o => o.Label == "Signature Field" && o.ObjectNumber == 5);
        // Sig dict must be found via /V reference
        objects.ShouldContain(o => o.Label == "Signature" && o.ObjectNumber == 6);

        // Verify /T and /V are separate entries
        var field = objects.First(o => o.ObjectNumber == 5);
        field.Entries.ShouldContain(e => e.Key == "/T");
        field.Entries.ShouldContain(e => e.Key == "/V");
    }

    [Fact(DisplayName = "Sig dict with large /Contents hex is properly parsed into entries")]
    public void ExtractObjects_LargeContentsHex_ParsedCorrectly()
    {
        // Build a sig dict with a huge /Contents hex (simulating 32KB+ signature)
        string largeHex = new string('A', 65536); // 32KB of data

        var sb = new StringBuilder();
        sb.AppendLine("%PDF-1.3");
        sb.AppendLine("1 0 obj");
        sb.AppendLine("<< /Type /Catalog /Pages 2 0 R /AcroForm << /Fields [4 0 R] /SigFlags 3 >> >>");
        sb.AppendLine("endobj");
        sb.AppendLine("2 0 obj");
        sb.AppendLine("<< /Type /Pages /Kids [3 0 R] /Count 1 >>");
        sb.AppendLine("endobj");
        sb.AppendLine("3 0 obj");
        sb.AppendLine("<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>");
        sb.AppendLine("endobj");
        sb.AppendLine("4 0 obj");
        sb.AppendLine("<< /FT /Sig /T (Sig1) /V 5 0 R /Subtype /Widget /Rect [0 0 0 0] /P 3 0 R >>");
        sb.AppendLine("endobj");
        sb.Append("5 0 obj\n");
        sb.Append($"<< /ByteRange [0 100 200 50] /Filter /Adobe.PPKLite /SubFilter /adbe.pkcs7.detached /Contents <{largeHex}> /M (D:20250101120000+00'00') /Reason (Test) >>\n");
        sb.AppendLine("endobj");
        sb.AppendLine("%%EOF");

        byte[] pdf = Encoding.Latin1.GetBytes(sb.ToString());
        var objects = PdfStructureDumper.ExtractSignatureObjects(pdf);

        // Sig dict (obj 5) must be found and have parsed entries (not raw dump)
        var sigDict = objects.FirstOrDefault(o => o.ObjectNumber == 5);
        sigDict.ShouldNotBeNull("sig dict should be discovered via /V reference");
        sigDict!.Label.ShouldBe("Signature");
        sigDict.Entries.ShouldNotBeEmpty("entries should be parsed despite large /Contents hex");

        // Key entries should be present
        sigDict.Entries.ShouldContain(e => e.Key == "/ByteRange");
        sigDict.Entries.ShouldContain(e => e.Key == "/Filter");
        sigDict.Entries.ShouldContain(e => e.Key == "/SubFilter");
        sigDict.Entries.ShouldContain(e => e.Key == "/Contents");
        sigDict.Entries.ShouldContain(e => e.Key == "/M");
        sigDict.Entries.ShouldContain(e => e.Key == "/Reason");

        // /Contents value should be truncated (not full 65K hex)
        var contents = sigDict.Entries.First(e => e.Key == "/Contents");
        contents.RawValue.Length.ShouldBeLessThan(1000);
        contents.RawValue.ShouldContain("data");
    }
}
