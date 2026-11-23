using Shouldly;
using SimpleSign.PAdES.Pdf.Model;
using SimpleSign.PAdES.Signing;
using SimpleSign.PAdES.Tests.Pdf.Parity;
using Xunit;
using Xunit.Abstractions;

namespace SimpleSign.PAdES.Tests.Signing;

/// <summary>
/// Signing an existing field on the PDF object model (ADR 0032), with the time fixed: invisible, visible and certifying,
/// on documents built for each case the field search and the field update handle. Each update reads back with the
/// signature on the field asked for, and is its snapshot (SHA-256, per framework). The snapshots were taken when each
/// update had been checked against the writer before the model: the same bytes, the field's CRLF kept, or a document
/// that writer could not sign at all (the reason is the case's own).
/// </summary>
[Trait("Category", "Unit")]
public sealed class ExistingFieldGoldenTests(ITestOutputHelper output)
{
    private static readonly DateTimeOffset s_now = new(2026, 11, 23, 9, 15, 0, TimeSpan.Zero);

    private const string Page = "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Annots [5 0 R] >>";
    private const string Widget = "/Type /Annot /Subtype /Widget /P 3 0 R /Rect [100 100 300 160] /F 4";

    /// <summary>Each document, the name of its field, and why the legacy writer could not sign it (null when it could).</summary>
    private static readonly Dictionary<string, (Func<byte[]> Build, string Field, string? LegacyFails)> s_documents = new(StringComparer.Ordinal)
    {
        ["merged"] = (() => Document($"<< {Widget} /FT /Sig /T (Sig1) >>"), "Sig1", null),
        ["v-null"] = (() => Document($"<< {Widget} /FT /Sig /T (Sig1) /V null >>"), "Sig1", null),
        ["v-empty-string"] = (() => Document($"<< {Widget} /FT /Sig /T (Sig1) /V () >>"), "Sig1", null),
        ["v-name"] = (() => Document($"<< {Widget} /FT /Sig /T (Sig1) /V /Off >>"), "Sig1", null),
        ["multiline"] = (() => Document($"<<\n/Type /Annot\n/Subtype /Widget\n/FT /Sig\n/T (Sig1)\n/P 3 0 R\n/Rect [100 100 300 160]\n>>"), "Sig1", null),
        ["crlf"] = (() => Document($"<<\r\n/Type /Annot /Subtype /Widget\r\n/FT /Sig /T (Sig1)\r\n/P 3 0 R /Rect [100 100 300 160]\r\n>>"), "Sig1", null),
        ["inline-acroform"] = (() => Document($"<< {Widget} /FT /Sig /T (Sig1) >>", acroForm: "<< /Fields [5 0 R] /SigFlags 3 /DA (/Helv 0 Tf 0 g) >>"), "Sig1", null),
        ["catalog-perms"] = (() => Document($"<< {Widget} /FT /Sig /T (Sig1) >>", catalogExtra: "/Perms << /DocMDP 9 0 R >>"), "Sig1", null),
        ["xref-stream"] = (() => Document($"<< {Widget} /FT /Sig /T (Sig1) >>", style: XrefStyle.Stream), "Sig1", null),
        ["utf16-name"] = (() => Document($"<< {Widget} /FT /Sig /T <FEFF00530069006700E7> >>"), "Sigç", null),
        ["ft-sig-without-space"] = (() => Document($"<< {Widget} /FT/Sig /T (Sig1) >>"), "Sig1",
            "LegacyFieldNotFound: it looked for '/FT /Sig' written with a space."),
        ["field-in-object-stream"] = (() => Document($"<< {Widget} /FT /Sig /T (Sig1) >>", compressField: true), "Sig1",
            "LegacyFieldNotFound: it searched the file's text, and the field is in an object stream."),
        ["inherited-ft"] = (() => Document("<< /FT /Sig /T (Parent) /Kids [6 0 R] >>", kid: $"<< {Widget} /T (Sig1) /Parent 5 0 R >>"), "Parent.Sig1",
            "LegacyFieldNotFound: it looked for /T and /FT in the same object, and the field inherits /FT from its parent."),
        ["nested-name"] = (() => Document("<< /T (Parent) /Kids [6 0 R] >>", kid: $"<< {Widget} /FT /Sig /T (Child) /Parent 5 0 R >>"), "Parent.Child",
            "LegacyFieldNotFound: it compared the name with /T only, not the fully qualified name."),
    };

    /// <summary>A field whose widget is a kid of its own: signed invisible as before, visible only on the model (drawn on the widget).</summary>
    private static byte[] SeparateWidget() =>
        Document("<< /FT /Sig /T (Sig1) /Kids [6 0 R] >>", kid: $"<< {Widget} /Parent 5 0 R >>");

    private static readonly Dictionary<string, Func<string, SignatureFieldOptions>> s_options = new(StringComparer.Ordinal)
    {
        ["invisible"] = name => new() { FieldName = name, ExistingFieldName = name, ContentsReservedBytes = 1024 },
        ["visible"] = name => new() { FieldName = name, ExistingFieldName = name, ContentsReservedBytes = 1024, SignerName = "Fulano", Appearance = new SignatureAppearance() },
        ["certified"] = name => new()
        {
            FieldName = name,
            ExistingFieldName = name,
            ContentsReservedBytes = 1024,
            SubFilter = PdfSignatureSubFilter.PbadPades,
            Reason = "Aprovação",
            CertificationLevel = CertificationLevel.FormFillingAndAnnotations,
        },
    };

    public static TheoryData<string, string> Cases()
    {
        var data = new TheoryData<string, string>();
        foreach (string document in s_documents.Keys.Append("separate-widget"))
        {
            foreach (string options in s_options.Keys)
            {
                data.Add(document, options);
            }
        }

        return data;
    }

    /// <summary>A one-page document whose object 5 is the field (and 6 its kid, when given).</summary>
    private static byte[] Document(
        string field, string? kid = null, string acroForm = "4 0 R", string catalogExtra = "", XrefStyle style = XrefStyle.Table, bool compressField = false)
    {
        string fields = acroForm == "4 0 R" ? "" : acroForm;
        var builder = new PdfFileBuilder()
            .Object(1, $"<< /Type /Catalog /Pages 2 0 R /AcroForm {(acroForm == "4 0 R" ? "4 0 R" : fields)} {catalogExtra} >>")
            .Object(2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
            .Object(3, kid is null ? Page : Page.Replace("[5 0 R]", "[6 0 R]", StringComparison.Ordinal))
            .Object(4, "<< /Fields [5 0 R] /SigFlags 3 /DA (/Helv 0 Tf 0 g) >>");
        builder = compressField ? builder.Compressed(5, field) : builder.Object(5, field);
        if (kid is not null)
        {
            builder.Object(6, kid);
        }

        return compressField
            ? builder.EndRevision(XrefStyle.Stream, new RevisionOptions { ObjectStreamNumber = 7, XrefStreamNumber = 8 }).ToArray()
            : builder.EndRevision(style, style == XrefStyle.Stream ? new RevisionOptions { XrefStreamNumber = 7 } : null).ToArray();
    }

    [Theory]
    [MemberData(nameof(Cases))]
    public async Task PrepareAsync_ExistingField_IsItsSnapshot(string document, string optionsKind)
    {
        var (build, field, legacyFails) = document == "separate-widget"
            ? (SeparateWidget, "Sig1", optionsKind == "visible" ? "LegacyNoRectangle: it read /Rect from the field, and the rectangle is its widget's." : null)
            : s_documents[document];
        byte[] original = build();
        var options = s_options[optionsKind](field);

        using var modelOutput = new MemoryStream();
        var modelResult = await PdfSignatureWriter.PrepareAsync(new MemoryStream(original), modelOutput, options, null, null, s_now, null, CancellationToken.None);
        byte[] model = modelOutput.ToArray();

        // The update reads back: the field asked for holds the new signature, its byte range the whole file
        // but the contents; a visible one has its appearance on the widget.
        var updated = PdfDocument.Open(model);
        var view = updated.View();
        var signature = view.Signatures.ShouldHaveSingleItem();
        signature.Field.ShouldNotBeNull().FullName.ShouldEndWith(field.Split('.')[^1]);
        signature.ByteRange.ShouldBe([0, modelResult.ByteRange.Length1, modelResult.ByteRange.Offset2, modelResult.ByteRange.Length2]);
        (modelResult.ByteRange.Offset2 + modelResult.ByteRange.Length2).ShouldBe(model.Length);
        if (optionsKind == "visible")
        {
            var widget = signature.Field.Widgets.First()!.Value;
            ((PdfDictionary)updated.GetObject(widget)!.Value).Get("AP").ShouldNotBeNull();
        }

        if (legacyFails is not null)
        {
            output.WriteLine($"the writer before the model could not sign it: {legacyFails}");
        }

        Snapshot.MatchCompressed("writers/existing-field", $"{document}|{optionsKind}", model);
    }

    [Fact]
    public async Task PrepareAsync_SignedField_ThrowsAsBefore()
    {
        byte[] pdf = Document($"<< {Widget} /FT /Sig /T (Sig1) /V 9 0 R >>");
        var options = s_options["invisible"]("Sig1");

        var error = await Should.ThrowAsync<InvalidOperationException>(() => PdfSignatureWriter.PrepareAsync(new MemoryStream(pdf), new MemoryStream(), options));

        error.Message.ShouldBe("Signature field 'Sig1' is already signed (has /V value).");
    }

    [Fact]
    public async Task PrepareAsync_MissingField_ThrowsAsBefore()
    {
        byte[] pdf = Document($"<< {Widget} /FT /Sig /T (Sig1) >>");
        var options = s_options["invisible"]("Other");

        var error = await Should.ThrowAsync<InvalidOperationException>(() => PdfSignatureWriter.PrepareAsync(new MemoryStream(pdf), new MemoryStream(), options));

        error.Message.ShouldBe("Signature field 'Other' not found in the PDF. Ensure the field exists with /FT /Sig and has an empty /V value.");
    }
}
