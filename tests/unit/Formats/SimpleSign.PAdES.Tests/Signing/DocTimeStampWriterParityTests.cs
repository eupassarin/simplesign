using System.Security.Cryptography;
using Microsoft.Extensions.Logging.Abstractions;
using Shouldly;
using SimpleSign.Core.Crypto;
using SimpleSign.PAdES.Pdf;
using SimpleSign.PAdES.Pdf.Model;
using SimpleSign.PAdES.Signing;
using SimpleSign.PAdES.Tests.Pdf.Parity;
using Xunit;
using Xunit.Abstractions;

namespace SimpleSign.PAdES.Tests.Signing;

/// <summary>
/// The document timestamp writer on the PDF object model (ADR 0032) writes what the writer before it wrote, byte for
/// byte, with the clock and the token fixed: on every committed PDF, the generated ones, documents signed by the current
/// signer and the cases the writer handles apart (inline AcroForm, <c>/Annots</c> as a reference, CRLF). Each document
/// whose output differs is listed with the reason, and must differ.
/// </summary>
[Trait("Category", "Unit")]
public sealed class DocTimeStampWriterParityTests(ITestOutputHelper output)
{
    private static readonly DateTimeOffset s_now = new(2026, 11, 22, 10, 20, 30, TimeSpan.Zero);

    public static TheoryData<string> Documents() => WriterCorpus.Names(WriterCorpus.Documents.Keys);

    [Theory]
    [MemberData(nameof(Documents))]
    public async Task AppendDocTimeStampAsync_Document_IsWhatTheLegacyWriterWrote(string name)
    {
        byte[] original = await WriterCorpus.Documents[name]();
        var source = PdfDocument.Open(original);
        if (source.IsEncrypted || source.Catalog is null || !original.AsSpan().StartsWith("%PDF-"u8))
        {
            output.WriteLine("skipped: encrypted, no catalog or not a PDF");
            return;
        }

        byte[] legacy = await DocTimeStampWriterLegacy.AppendDocTimeStampAsync(
            original, "https://tsa.test", s_http, NullLogger.Instance, tsaFactory: s_tsa, timeProvider: s_clock);
        byte[] model = await DocTimeStampWriter.AppendDocTimeStampAsync(
            original, "https://tsa.test", s_http, NullLogger.Instance, tsaFactory: s_tsa, timeProvider: s_clock);

        // Whatever the legacy writer wrote, the update reads back: a new revision holding the document timestamp,
        // its byte range the whole file but the token.
        var updated = PdfDocument.Open(model);
        updated.Revisions.Count.ShouldBe(source.Revisions.Count + 1);
        var timestamp = updated.View().Signatures.Where(s => s.IsDocumentTimestamp).Last();
        timestamp.ByteRange.ShouldNotBeNull();
        (timestamp.ByteRange[2] + timestamp.ByteRange[3]).ShouldBe(model.Length);
        updated.View().Fields.ShouldContain(f => f.FullName == $"DocTimeStamp_{s_now:yyyyMMddHHmmss}");

        WriterParity.Compare(output, original, legacy, model, ExpectedDifferences(original, source), [timestamp.Id!.Value.Number]);
    }

    /// <summary>The legacy writer's defects a document shows, each found from the document itself.</summary>
    private static List<WriterDifference> ExpectedDifferences(byte[] original, PdfDocument source)
    {
        var rules = new List<WriterDifference>();
        var view = source.View();
        int root = source.RootId!.Value.Number;
        var acroForm = source.Catalog!.Get(PdfName.AcroForm);
        int acroFormNumber = acroForm is PdfReference reference ? reference.Id.Number : view.NextObjectNumber + 2;
        bool Compressed(int number) => source.Lookup(number) is { Type: PdfXrefEntryType.Compressed };

        if (Compressed(root) && acroForm is not null)
        {
            rules.Add(new WriterDifference("LegacyCatalogInObjectStream: it cannot read a catalog in an object stream, so the AcroForm it writes loses the existing fields and entries.", [acroFormNumber]));
        }
        else if (!Compressed(root))
        {
            if (acroForm is null || acroForm is PdfDictionary { } inline && inline.Get(PdfName.Fields) is PdfReference)
            {
                rules.Add(new WriterDifference("LegacyCatalogWithoutLineEnd: the catalog it writes ends at endobj, the next object or xref straight after.", []));
            }

            if (acroForm is PdfDictionary inlineWithIndirectFields && inlineWithIndirectFields.Get(PdfName.Fields) is PdfReference)
            {
                rules.Add(new WriterDifference("LegacyInlineAcroFormIndirectFields: moving an inline AcroForm whose /Fields is a reference out, it loses the fields and entries.", [acroFormNumber]));
            }

            if ((source.Resolve(acroForm) as PdfDictionary)?.Get(PdfName.Type) is PdfName && acroForm is PdfReference)
            {
                rules.Add(new WriterDifference("LegacyAcroFormTypeAsKey: rebuilding the AcroForm it takes the value of /Type /AcroForm for a key of its own.", [acroFormNumber]));
            }
        }

        int legacyPage = PdfStructureParser.FindFirstPageObject(original).ObjNum;
        int page = view.Pages.Count > 0 ? view.Pages[0].Id?.Number ?? 0 : 0;
        if (legacyPage != page)
        {
            rules.Add(new WriterDifference("FirstPageOfThePageTree: it takes the first /Type /Page of the file for the first page.", [view.NextObjectNumber + 1, legacyPage, page], OtherObjects: true));
        }
        else if (page > 0 && !Compressed(page) && source.GetObject(page) is { } pageObject
            && original.AsSpan((int)pageObject.Source.Offset, pageObject.Source.Length).IndexOf("\r\n"u8) >= 0
            && (pageObject.Value as PdfDictionary)?.Get("Annots") is null)
        {
            rules.Add(new WriterDifference("CrLfPreserved: adding /Annots it turned every CRLF of the page into LF; the patch keeps them.", []));
        }

        foreach (int number in new[] { root, acroForm is PdfReference ? acroFormNumber : 0, page }.Distinct().Where(n => n > 0))
        {
            int legacyAt = PdfStructureParser.FindObjectBytes(original, number).Start;
            var legacyCopy = legacyAt >= 0 ? PdfParser.ParseIndirectObject(original, legacyAt, new PdfParseContext()) : null;
            if (legacyCopy is not null && source.GetObject(number) is { } current && !PdfObject.SemanticEquals(legacyCopy.Value, current.Value))
            {
                rules.Add(new WriterDifference($"LegacyLastCopyOfObject: it rewrites the last '{number} 0 obj' of the file, not the object the cross-reference lists (an older copy, or a stray one), losing what changed since.", [number]));
            }
        }

        return rules;
    }

    private static readonly HttpClient s_http = new();

    private static readonly WriterParity.FixedClock s_clock = new(s_now);

    private static readonly DigestTokenFactory s_tsa = new();

    /// <summary>A "token" that is the digest of what it covers, so a different byte range gives a different file.</summary>
    private sealed class DigestTokenFactory : ITimestampClientFactory, ITimestampClient
    {
        public ITimestampClient Create(string tsaUrl) => this;

        public Task<byte[]> GetTimestampAsync(ReadOnlyMemory<byte> dataToTimestamp, HashAlgorithmName hashAlgorithm, CancellationToken cancellationToken = default) =>
            Task.FromResult<byte[]>([0x30, 0x22, .. SHA256.HashData(dataToTimestamp.Span)]);
    }
}
