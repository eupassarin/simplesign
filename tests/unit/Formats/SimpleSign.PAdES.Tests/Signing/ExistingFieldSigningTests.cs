using System.Text;
using Shouldly;
using SimpleSign.PAdES.Signing;
using Xunit;

namespace SimpleSign.PAdES.Tests.Signing;

/// <summary>
/// Regression tests for signing into an existing (empty) signature field whose /V
/// entry uses variants other than "/V " with a space (newlines, names, absent keys).
/// The previous line-oriented replacement inserted a duplicate /V key for such PDFs.
/// </summary>
[Trait("Category", "Unit")]
public sealed class ExistingFieldSigningTests
{
    /// <summary>
    /// Builds a PDF with an empty signature field (object 5, /T (Sig1)) whose
    /// dictionary body includes the given /V entry text (e.g. "/V null").
    /// </summary>
    private static byte[] BuildPdfWithEmptyField(string vEntry)
    {
        var sb = new StringBuilder();
        sb.Append("%PDF-1.7\n");
        sb.Append("1 0 obj\n<< /Type /Catalog /Pages 2 0 R /AcroForm 4 0 R >>\nendobj\n");
        sb.Append("2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n");
        sb.Append("3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Annots [5 0 R] >>\nendobj\n");
        sb.Append("4 0 obj\n<< /Fields [5 0 R] /SigFlags 3 >>\nendobj\n");
        sb.Append($"5 0 obj\n<< /Type /Annot /Subtype /Widget /FT /Sig /T (Sig1) /P 3 0 R {vEntry} /Rect [0 0 0 0] /F 132 >>\nendobj\n");
        sb.Append("xref\n0 6\n");
        sb.Append("0000000000 65535 f \n");
        sb.Append("0000000009 00000 n \n");
        sb.Append("0000000058 00000 n \n");
        sb.Append("0000000115 00000 n \n");
        sb.Append("0000000172 00000 n \n");
        sb.Append("0000000238 00000 n \n");
        sb.Append("trailer\n<< /Size 6 /Root 1 0 R >>\n");
        sb.Append("startxref\n300\n%%EOF\n");
        return Encoding.Latin1.GetBytes(sb.ToString());
    }

    private static SignatureFieldOptions ExistingFieldOptions() => new()
    {
        FieldName = "Sig1",
        ExistingFieldName = "Sig1",
        ContentsReservedBytes = 1024,
    };

    private static int CountOccurrences(string text, string token)
    {
        int count = 0;
        int pos = 0;
        while ((pos = text.IndexOf(token, pos, StringComparison.Ordinal)) >= 0)
        {
            count++;
            pos += token.Length;
        }

        return count;
    }

    [Fact(DisplayName = "Signing a field with an empty literal /V replaces the value")]
    public async Task PrepareAsync_ExistingFieldEmptyLiteralV_ReplacesValue()
    {
        byte[] pdf = BuildPdfWithEmptyField("/V ()");
        using var input = new MemoryStream(pdf);
        using var output = new MemoryStream();

        await PdfSignatureWriter.PrepareAsync(input, output, ExistingFieldOptions());

        string text = Encoding.Latin1.GetString(output.ToArray());
        int lastFieldPos = text.LastIndexOf("/T (Sig1)", StringComparison.Ordinal);
        string updatedField = text[lastFieldPos..];

        CountOccurrences(updatedField, "/V 6 0 R").ShouldBe(1);
        updatedField.ShouldNotContain("/V ()");
    }

    [Fact(DisplayName = "Signing a field with /V null replaces the value with the new reference")]
    public async Task PrepareAsync_ExistingFieldVNull_ReplacesValue()
    {
        byte[] pdf = BuildPdfWithEmptyField("/V null");
        using var input = new MemoryStream(pdf);
        using var output = new MemoryStream();

        await PdfSignatureWriter.PrepareAsync(input, output, ExistingFieldOptions());

        string text = Encoding.Latin1.GetString(output.ToArray());
        int lastFieldPos = text.LastIndexOf("/T (Sig1)", StringComparison.Ordinal);
        string updatedField = text[lastFieldPos..];

        CountOccurrences(updatedField, "/V 6 0 R").ShouldBe(1);
        updatedField.ShouldNotContain("null");
    }

    [Fact(DisplayName = "Signing a field with /V on the next line replaces the value")]
    public async Task PrepareAsync_ExistingFieldVOnNextLine_ReplacesValue()
    {
        byte[] pdf = BuildPdfWithEmptyField("/V\nnull");
        using var input = new MemoryStream(pdf);
        using var output = new MemoryStream();

        await PdfSignatureWriter.PrepareAsync(input, output, ExistingFieldOptions());

        string text = Encoding.Latin1.GetString(output.ToArray());
        int lastFieldPos = text.LastIndexOf("/T (Sig1)", StringComparison.Ordinal);
        string updatedField = text[lastFieldPos..];

        CountOccurrences(updatedField, "/V 6 0 R").ShouldBe(1);
        updatedField.ShouldNotContain("null");
    }

    [Fact(DisplayName = "Signing a field with a name-valued /V replaces the value")]
    public async Task PrepareAsync_ExistingFieldVName_ReplacesValue()
    {
        byte[] pdf = BuildPdfWithEmptyField("/V /SigEmpty");
        using var input = new MemoryStream(pdf);
        using var output = new MemoryStream();

        await PdfSignatureWriter.PrepareAsync(input, output, ExistingFieldOptions());

        string text = Encoding.Latin1.GetString(output.ToArray());
        int lastFieldPos = text.LastIndexOf("/T (Sig1)", StringComparison.Ordinal);
        string updatedField = text[lastFieldPos..];

        CountOccurrences(updatedField, "/V 6 0 R").ShouldBe(1);
        updatedField.ShouldNotContain("/SigEmpty");
    }

    [Fact(DisplayName = "Signing a field without /V inserts a single new /V")]
    public async Task PrepareAsync_ExistingFieldNoV_InsertsSingleValue()
    {
        byte[] pdf = BuildPdfWithEmptyField("");
        using var input = new MemoryStream(pdf);
        using var output = new MemoryStream();

        await PdfSignatureWriter.PrepareAsync(input, output, ExistingFieldOptions());

        string text = Encoding.Latin1.GetString(output.ToArray());
        int lastFieldPos = text.LastIndexOf("/T (Sig1)", StringComparison.Ordinal);
        string updatedField = text[lastFieldPos..];

        CountOccurrences(updatedField, "/V 6 0 R").ShouldBe(1);
    }
}
