using System.Text;
using Shouldly;
using SimpleSign.PAdES.Pdf;
using SimpleSign.PAdES.Pdf.Model;
using SimpleSign.PAdES.Signing;
using SimpleSign.PAdES.Tests.Pdf.Parity;
using Xunit;
using Xunit.Abstractions;

namespace SimpleSign.PAdES.Tests.Signing;

/// <summary>
/// Signing a new field on the PDF object model (ADR 0032) writes what the writer before it wrote, byte for byte, with
/// the time fixed: on the writers' corpus, invisible, named, visible (placed automatically, or on page 2), certifying,
/// and with document information. Each document whose output differs shows a legacy defect, found from the document
/// itself, and every new object the defect does not concern is the same object in both.
/// </summary>
[Trait("Category", "Unit")]
public sealed class NewFieldParityTests(ITestOutputHelper output)
{
    private static readonly DateTimeOffset s_now = new(2026, 11, 23, 11, 0, 0, TimeSpan.Zero);

    private static readonly Dictionary<string, string> s_info = new(StringComparer.Ordinal) { ["Producer"] = "SimpleSign", ["Title"] = "Contrato nº 7" };

    [ThreadStatic]
    private static SignatureFieldOptions? s_lastInfoOptions;

    private static readonly Dictionary<string, Func<SignatureFieldOptions>> s_options = new(StringComparer.Ordinal)
    {
        ["invisible"] = () => new() { ContentsReservedBytes = 1024 },
        ["named"] = () => new()
        {
            FieldName = "Assinatura",
            ContentsReservedBytes = 1024,
            SubFilter = PdfSignatureSubFilter.PbadPades,
            Reason = "Aprovação",
            Location = "São Paulo",
        },
        ["visible-auto"] = () => new() { ContentsReservedBytes = 1024, SignerName = "Fulano", Appearance = SignatureAppearance.Auto() },
        ["visible-page-2"] = () => new() { ContentsReservedBytes = 1024, SignerName = "Fulano", Appearance = new SignatureAppearance { Page = 2, X = 50, Y = 60 } },
        ["certified"] = () => new() { ContentsReservedBytes = 1024, CertificationLevel = CertificationLevel.FormFillingAndAnnotations },
        ["info"] = () => new() { ContentsReservedBytes = 1024 },
    };

    public static TheoryData<string, string> Cases()
    {
        var data = new TheoryData<string, string>();
        foreach (string document in WriterCorpus.Documents.Keys)
        {
            foreach (string options in s_options.Keys)
            {
                data.Add(document, options);
            }
        }

        return data;
    }

    [Theory]
    [MemberData(nameof(Cases))]
    public async Task PrepareAsync_NewField_IsWhatTheLegacyWriterWrote(string document, string optionsKind)
    {
        byte[] original = await WriterCorpus.Documents[document]();
        var source = PdfDocument.Open(original);
        if (source.IsEncrypted || source.Catalog is null || !original.AsSpan().StartsWith("%PDF-"u8))
        {
            output.WriteLine("skipped: encrypted, no catalog or not a PDF");
            return;
        }

        var options = s_options[optionsKind]();
        var info = optionsKind == "info" ? s_info : null;
        s_lastInfoOptions = info is null ? null : options;
        using var modelOutput = new MemoryStream();
        var modelResult = await PdfSignatureWriter.PrepareAsync(new MemoryStream(original), modelOutput, options, null, null, s_now, info, CancellationToken.None);
        byte[] model = modelOutput.ToArray();
        using var legacyOutput = new MemoryStream();
        var legacyResult = await PdfSignatureWriter.PrepareLegacyAsync(new MemoryStream(original), legacyOutput, options, null, null, s_now, info, CancellationToken.None);
        byte[] legacy = legacyOutput.ToArray();

        // The model's update reads back: one more signature, on a field of its own, its byte range the whole file but
        // the contents, the earlier fields all there.
        var before = source.View();
        var after = PdfDocument.Open(model).View();
        after.Signatures.Count.ShouldBe(before.Signatures.Count + 1);
        var signature = after.Signatures.Single(s => s.Id?.Number == modelResult.SigDictObjectNumber);
        (modelResult.ByteRange.Offset2 + modelResult.ByteRange.Length2).ShouldBe(model.Length);
        signature.ByteRange.ShouldBe([0, modelResult.ByteRange.Length1, modelResult.ByteRange.Offset2, modelResult.ByteRange.Length2]);
        before.Fields.Select(f => f.FullName).Except(after.Fields.Select(f => f.FullName)).ShouldBeEmpty();
        after.Fields.Count(f => f.FullName == signature.Field!.FullName).ShouldBe(1);

        var rules = ExpectedDifferences(original, source, options, legacy, model);
        WriterParity.Compare(output, original, legacy, model, rules, [modelResult.SigDictObjectNumber]);
        if (rules.Count == 0)
        {
            (modelResult.ByteRange.Length1, modelResult.ByteRange.Offset2, modelResult.ByteRange.Length2)
                .ShouldBe((legacyResult.ByteRange.Length1, legacyResult.ByteRange.Offset2, legacyResult.ByteRange.Length2));
            modelResult.SigDictObjectNumber.ShouldBe(legacyResult.SigDictObjectNumber);
        }
    }

    /// <summary>The legacy writer's defects a document shows, each found from the document itself.</summary>
    private static List<WriterDifference> ExpectedDifferences(byte[] original, PdfDocument source, SignatureFieldOptions options, byte[] legacy, byte[] model)
    {
        var rules = new List<WriterDifference>();
        var view = source.View();
        int root = source.RootId!.Value.Number;
        int next = view.NextObjectNumber;
        int field = next + 1;
        var acroFormValue = source.Catalog!.Get(PdfName.AcroForm);
        int acroForm = acroFormValue is PdfReference reference ? reference.Id.Number : next + 2;
        bool Compressed(int number) => source.Lookup(number) is { Type: PdfXrefEntryType.Compressed };

        if (PdfStructureParser.DetermineNextObjectNumber(original) != next)
        {
            rules.Add(new("NextObjectNumberFromTheCrossReference: it numbered the new objects from the text.", [], Renumbered: true));
        }

        // The page: the legacy writer took the first /Type /Page of the file, or the Nth kid of the root /Pages.
        int pageNumber = options.Appearance?.Page ?? 1;
        int legacyPage = pageNumber > 1 ? PdfStructureParser.FindNthPageObjNum(original, pageNumber) : PdfStructureParser.FindFirstPageObject(original).ObjNum;
        int page = view.Pages.Count >= pageNumber ? view.Pages[pageNumber - 1].Id?.Number ?? -1 : -1;
        if (legacyPage != page && !(legacyPage <= 0 && page <= 0))
        {
            rules.Add(new(
                $"PageOfThePageTree: it took page {legacyPage} (the file's first /Type /Page, or a kid of the root /Pages only), the page tree's is {page}.",
                [field, legacyPage, page], OtherObjects: true));
        }

        if (Compressed(root) && acroFormValue is not null)
        {
            rules.Add(new("LegacyCatalogInObjectStream: with the catalog in an object stream it found no AcroForm, and wrote a new one without the existing fields.", [], Renumbered: true));
        }
        else if (!Compressed(root))
        {
            if (acroFormValue is PdfDictionary inline && inline.Get(PdfName.Fields) is PdfReference)
            {
                rules.Add(new("LegacyInlineAcroFormIndirectFields: moving an inline AcroForm whose /Fields is a reference out, it lost the fields and entries.", [acroForm]));
            }

            if ((source.Resolve(acroFormValue) as PdfDictionary)?.Get(PdfName.Type) is PdfName && acroFormValue is PdfReference)
            {
                rules.Add(new("LegacyAcroFormTypeAsKey: rebuilding the AcroForm it took the value of /Type /AcroForm for a key of its own.", [acroForm]));
            }

            var catalog = source.GetObject(root)!;
            bool catalogWritten = acroFormValue is not PdfReference || options.CertificationLevel is not null;
            if (catalogWritten && Encoding.Latin1.GetString(original, (int)catalog.Source.Offset, catalog.Source.Length).Contains("\r\n", StringComparison.Ordinal))
            {
                rules.Add(new("CrLfPreserved: its text edits turned the catalog's CRLF into LF.", []));
            }
        }

        foreach (int number in new[] { root, acroFormValue is PdfReference ? acroForm : 0, page }.Distinct().Where(n => n > 0))
        {
            int legacyAt = PdfStructureParser.FindObjectBytes(original, number).Start;
            var legacyCopy = legacyAt >= 0 ? PdfParser.ParseIndirectObject(original, legacyAt, new PdfParseContext()) : null;
            if (legacyCopy is not null && source.GetObject(number) is { } current && !PdfObject.SemanticEquals(legacyCopy.Value, current.Value))
            {
                rules.Add(new($"LegacyLastCopyOfObject: it rewrote the last '{number} 0 obj' of the file, not the object the cross-reference lists.", [number]));
            }
        }

        if (page > 0 && !Compressed(page) && source.GetObject(page) is { } pageObject
            && Encoding.Latin1.GetString(original, (int)pageObject.Source.Offset, pageObject.Source.Length).Contains("\r\n", StringComparison.Ordinal)
            && (pageObject.Value as PdfDictionary)?.Get("Annots") is null)
        {
            rules.Add(new("CrLfPreserved: adding /Annots it turned the page's CRLF into LF.", []));
        }

        if (options.Appearance is not null && page <= 0)
        {
            rules.Add(new("LegacyAppearanceWithoutPage: with no page to draw on it still wrote /Rect and an /AP to an appearance it never wrote.", [field]));
        }

        if (ReferenceEquals(options, s_lastInfoOptions) && !InfoBytes(legacy).AsSpan().SequenceEqual(InfoBytes(model)))
        {
            rules.Add(new("InfoEditsOnTheOriginal: it removed and inserted the entries one after another on text whose CRLF it had turned into LF (removing a key took the space of one inserted before); the patch edits the original's bytes.", []));
        }

        // The default name and the automatic place come from what the document holds: the legacy writer counted
        // '/FT /Sig' in the file's text (every copy of a field written again included).
        if (FieldName(legacy, field) is { } legacyName && FieldName(model, field) is { } modelName && legacyName != modelName && options.FieldName == "Signature1")
        {
            bool taken = view.Fields.Any(f => f.FullName == legacyName);
            rules.Add(new($"DefaultFieldNameFromTheFieldTree: it named the field {legacyName}{(taken ? ", a name a field has already" : "")}; the field tree gives {modelName}.", [field]));
        }

        if (options.Appearance is { AutoPosition: true } && page > 0
            && PdfStructureParser.CountVisibleSignatureAnnotations(original) != VisibleSignatures(source, view))
        {
            rules.Add(new("VisibleSignaturesFromTheFieldTree: it placed the stamp after the '/FT /Sig' widgets of the file's text, every copy included.", [field]));
        }

        return rules;
    }

    /// <summary>The bytes of the Info object an update wrote (empty when there is none).</summary>
    private static byte[] InfoBytes(byte[] pdf)
    {
        var document = PdfDocument.Open(pdf);
        return document.Trailer.Get(PdfName.Info) is PdfReference reference && document.GetObject(reference.Id) is { } info
            ? pdf.AsSpan((int)info.Source.Offset, info.Source.Length).ToArray()
            : [];
    }

    private static string? FieldName(byte[] pdf, int number) =>
        PdfDocument.Open(pdf).GetObject(number)?.Value is PdfDictionary { } field && field.Get(PdfName.T) is PdfString name ? name.Text : null;

    private static int VisibleSignatures(PdfDocument document, PdfRevisionView view) =>
        view.Fields.Where(f => f.IsSignature)
            .SelectMany(f => f.Widgets.Select(w => w is null || w == f.Id ? f.Dictionary : document.GetObject(w.Value)?.Value as PdfDictionary))
            .Count(widget => document.Resolve(widget?.Get("Rect")) is PdfArray rect
                && rect.Any(v => document.Resolve(v) is PdfInteger { Value: not 0 } or PdfReal { Value: not 0 }));
}
