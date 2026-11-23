using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Logging.Abstractions;
using Shouldly;
using SimpleSign.Core.Crypto;
using SimpleSign.PAdES.Pdf;
using SimpleSign.PAdES.Pdf.Model;
using SimpleSign.PAdES.Signing;
using SimpleSign.PAdES.Tests.Pdf.Parity;
using SimpleSign.TestHelpers;
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

    public static TheoryData<string> Documents()
    {
        var data = new TheoryData<string>();
        foreach (string name in Corpus.Keys)
        {
            data.Add(name);
        }

        return data;
    }

    private static Dictionary<string, Func<Task<byte[]>>> Corpus { get; } = BuildCorpus();

    private static Dictionary<string, Func<Task<byte[]>>> BuildCorpus()
    {
        var corpus = new Dictionary<string, Func<Task<byte[]>>>(StringComparer.Ordinal);
        foreach (var (name, path) in ParityCorpus.Fixtures)
        {
            corpus["fixture:" + name] = () => Task.FromResult(File.ReadAllBytes(path));
        }

        foreach (var (name, build) in ParityCorpus.Generated)
        {
            corpus["generated:" + name] = () => Task.FromResult(build());
        }

        foreach (string name in new[] { "table", "stream", "objstm" })
        {
            corpus["signed:" + name] = async () =>
            {
                using var cert = TestCertificateFactory.CreateSelfSignedCert();
                return await PadesSigner.Document(ParityCorpus.Generated[name]()).WithCertificate(cert).WithFieldName("Sig1").SignAsync();
            };
        }

        corpus["minimal-with-page"] = () => Task.FromResult(TestPdfFactory.CreateMinimalPdfWithPage());
        corpus["three-pages"] = () => Task.FromResult(TestPdfFactory.CreateThreePagePdf());
        corpus["inline-acroform-fields"] = () => Task.FromResult(Catalog("/AcroForm << /Fields [5 0 R] /DA (/Helv 0 Tf 0 g) /SigFlags 1 >>", "/Annots [5 0 R]"));
        corpus["inline-acroform-empty"] = () => Task.FromResult(Catalog("/AcroForm << /Fields [] /NeedAppearances true >>", ""));
        corpus["inline-acroform-no-fields"] = () => Task.FromResult(Catalog("/AcroForm << /DR << /Font << /Helv 6 0 R >> >> >>", ""));
        corpus["indirect-acroform-extras"] = () => Task.FromResult(Catalog("/AcroForm 7 0 R", "/Annots [5 0 R]"));
        corpus["indirect-annots"] = () => Task.FromResult(Catalog("/AcroForm 7 0 R", "/Annots 8 0 R"));
        corpus["page-crlf"] = () => Task.FromResult(Catalog("/AcroForm 7 0 R", "", crlf: true));
        return corpus;
    }

    /// <summary>A one-page document with a field, its catalog and page carrying the entries given.</summary>
    private static byte[] Catalog(string catalogExtra, string pageExtra, bool crlf = false)
    {
        string page = crlf
            ? $"<<\r\n/Type /Page\r\n/Parent 2 0 R\r\n/MediaBox [0 0 612 792]\r\n{pageExtra}\r\n>>"
            : $"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] {pageExtra} >>";
        return new PdfFileBuilder()
            .Object(1, $"<< /Type /Catalog /Pages 2 0 R {catalogExtra} >>")
            .Object(2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
            .Object(3, page)
            .Object(5, "<< /FT /Tx /T (Name) /Subtype /Widget /Rect [10 10 100 30] /P 3 0 R >>")
            .Object(6, "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")
            .Object(7, "<< /Type /AcroForm /Fields [5 0 R]\n/DA (/Helv 0 Tf 0 g)\n/DR << /Font << /Helv 6 0 R >> >> /SigFlags 1 >>")
            .Object(8, "[ 5 0 R ]")
            .EndRevision()
            .ToArray();
    }

    [Theory]
    [MemberData(nameof(Documents))]
    public async Task AppendDocTimeStampAsync_Document_IsWhatTheLegacyWriterWrote(string name)
    {
        byte[] original = await Corpus[name]();
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

        var rules = ExpectedDifferences(original, source);
        if (rules.Count > 0)
        {
            // A legacy defect the document shows: the output differs, and every new object the defect does not
            // concern is the same object in both.
            foreach (var rule in rules)
            {
                output.WriteLine($"differs: {rule.Why}");
            }

            model.ShouldNotBe(legacy);
            AssertSameObjects(PdfDocument.Open(legacy), updated, timestamp.Id!.Value.Number, rules);
            return;
        }

        if (!model.AsSpan().SequenceEqual(legacy))
        {
            // The byte range and the token follow from the rest: the first difference elsewhere is the one that counts.
            byte[] l = Masked(legacy, original.Length), m = Masked(model, original.Length);
            int at = m.AsSpan().CommonPrefixLength(l);
            int from = Math.Max(original.Length, at - 80);
            output.WriteLine($"first difference at {at} (original {original.Length}, legacy {legacy.Length}, model {model.Length})");
            output.WriteLine("legacy: " + Visible(Encoding.Latin1.GetString(l, from, Math.Min(260, l.Length - from))));
            output.WriteLine("model : " + Visible(Encoding.Latin1.GetString(m, from, Math.Min(260, m.Length - from))));
        }

        model.ShouldBe(legacy);
        output.WriteLine("identical");
    }

    /// <summary>A defect of the legacy writer, and the new objects it makes different.</summary>
    private sealed record Difference(string Why, int[] Unequal, bool OtherObjects = false);

    /// <summary>The legacy writer's defects a document shows, each found from the document itself.</summary>
    private static List<Difference> ExpectedDifferences(byte[] original, PdfDocument source)
    {
        var rules = new List<Difference>();
        var view = source.View();
        int root = source.RootId!.Value.Number;
        var acroForm = source.Catalog!.Get(PdfName.AcroForm);
        int acroFormNumber = acroForm is PdfReference reference ? reference.Id.Number : view.NextObjectNumber + 2;
        bool Compressed(int number) => source.Lookup(number) is { Type: PdfXrefEntryType.Compressed };

        if (Compressed(root) && acroForm is not null)
        {
            rules.Add(new("LegacyCatalogInObjectStream: it cannot read a catalog in an object stream, so the AcroForm it writes loses the existing fields and entries.", [acroFormNumber]));
        }
        else if (!Compressed(root))
        {
            if (acroForm is null || acroForm is PdfDictionary { } inline && inline.Get(PdfName.Fields) is PdfReference)
            {
                rules.Add(new("LegacyCatalogWithoutLineEnd: the catalog it writes ends at endobj, the next object or xref straight after.", []));
            }

            if (acroForm is PdfDictionary inlineWithIndirectFields && inlineWithIndirectFields.Get(PdfName.Fields) is PdfReference)
            {
                rules.Add(new("LegacyInlineAcroFormIndirectFields: moving an inline AcroForm whose /Fields is a reference out, it loses the fields and entries.", [acroFormNumber]));
            }

            if ((source.Resolve(acroForm) as PdfDictionary)?.Get(PdfName.Type) is PdfName && acroForm is PdfReference)
            {
                rules.Add(new("LegacyAcroFormTypeAsKey: rebuilding the AcroForm it takes the value of /Type /AcroForm for a key of its own.", [acroFormNumber]));
            }
        }

        int legacyPage = PdfStructureParser.FindFirstPageObject(original).ObjNum;
        int page = view.Pages.Count > 0 ? view.Pages[0].Id?.Number ?? 0 : 0;
        if (legacyPage != page)
        {
            rules.Add(new("FirstPageOfThePageTree: it takes the first /Type /Page of the file for the first page.", [view.NextObjectNumber + 1, legacyPage, page], OtherObjects: true));
        }
        else if (page > 0 && !Compressed(page) && source.GetObject(page) is { } pageObject
            && original.AsSpan((int)pageObject.Source.Offset, pageObject.Source.Length).IndexOf("\r\n"u8) >= 0
            && (pageObject.Value as PdfDictionary)?.Get("Annots") is null)
        {
            rules.Add(new("CrLfPreserved: adding /Annots it turned every CRLF of the page into LF; the patch keeps them.", []));
        }

        foreach (int number in new[] { root, acroForm is PdfReference ? acroFormNumber : 0, page }.Distinct().Where(n => n > 0))
        {
            int legacyAt = PdfStructureParser.FindObjectBytes(original, number).Start;
            var legacyCopy = legacyAt >= 0 ? PdfParser.ParseIndirectObject(original, legacyAt, new PdfParseContext()) : null;
            if (legacyCopy is not null && source.GetObject(number) is { } current && !PdfObject.SemanticEquals(legacyCopy.Value, current.Value))
            {
                rules.Add(new($"LegacyLastCopyOfObject: it rewrites the last '{number} 0 obj' of the file, not the object the cross-reference lists (an older copy, or a stray one), losing what changed since.", [number]));
            }
        }

        return rules;
    }

    /// <summary>The new objects of both updates (but the signature dictionary and the cross-reference stream) are the same objects, but those the rules name.</summary>
    private static void AssertSameObjects(PdfDocument legacy, PdfDocument model, int signature, List<Difference> rules)
    {
        static HashSet<int> Written(PdfDocument document) => [.. document.Latest.Sections.SelectMany(s => s.Entries.Keys)];

        var unequal = rules.SelectMany(r => r.Unequal).Append(signature).ToHashSet();
        var legacyObjects = Written(legacy);
        var modelObjects = Written(model);
        if (!rules.Any(r => r.OtherObjects))
        {
            modelObjects.ShouldBe(legacyObjects, ignoreOrder: true);
        }

        foreach (int number in modelObjects.Intersect(legacyObjects).Where(n => !unequal.Contains(n)))
        {
            var a = legacy.GetObject(number)!.Value;
            var b = model.GetObject(number)!.Value;
            if (a is PdfStream { } xref && xref.Dictionary.Get(PdfName.Type) is PdfName { Value: "XRef" })
            {
                continue;
            }

            PdfObject.SemanticEquals(a, b).ShouldBeTrue($"object {number}");
        }
    }

    private static string Visible(string text) => text.Replace("\r", "\\r", StringComparison.Ordinal).Replace("\n", "\\n", StringComparison.Ordinal);

    private static byte[] Masked(byte[] pdf, int from)
    {
        byte[] copy = [.. pdf];
        foreach (var (open, close) in new[] { ("/ByteRange [", (byte)']'), ("/Contents <", (byte)'>') })
        {
            int at = copy.AsSpan(from).IndexOf(Encoding.Latin1.GetBytes(open));
            if (at >= 0)
            {
                for (int i = from + at + open.Length; i < copy.Length && copy[i] != close; i++)
                {
                    copy[i] = (byte)'x';
                }
            }
        }

        return copy;
    }

    private static readonly HttpClient s_http = new();

    private static readonly FixedClock s_clock = new();

    private static readonly DigestTokenFactory s_tsa = new();

    private sealed class FixedClock : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => s_now;
    }

    /// <summary>A "token" that is the digest of what it covers, so a different byte range gives a different file.</summary>
    private sealed class DigestTokenFactory : ITimestampClientFactory, ITimestampClient
    {
        public ITimestampClient Create(string tsaUrl) => this;

        public Task<byte[]> GetTimestampAsync(ReadOnlyMemory<byte> dataToTimestamp, HashAlgorithmName hashAlgorithm, CancellationToken cancellationToken = default) =>
            Task.FromResult<byte[]>([0x30, 0x22, .. SHA256.HashData(dataToTimestamp.Span)]);
    }
}
