using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using Shouldly;
using SimpleSign.PAdES.Pdf;
using SimpleSign.PAdES.Pdf.Model;
using SimpleSign.PAdES.Signing;
using SimpleSign.PAdES.Tests.Pdf.Parity;
using SimpleSign.PAdES.Validation;
using SimpleSign.TestHelpers;
using Xunit;
using Xunit.Abstractions;

namespace SimpleSign.PAdES.Tests.Signing;

/// <summary>
/// The DSS the LTV embedder writes on the PDF object model (ADR 0032) is what it wrote before, byte for byte, with the
/// clock and the validation data fixed: on the writers' corpus, and on documents that already have a DSS (the merge, a
/// signature that already has its VRI). Each document whose output differs shows a legacy defect, found from the
/// document itself, and every new object the defect does not concern is the same object in both.
/// </summary>
[Trait("Category", "Unit")]
public sealed partial class LtvEmbedderParityTests(ITestOutputHelper output)
{
    private static readonly WriterParity.FixedClock s_clock = new(new DateTimeOffset(2026, 11, 22, 10, 20, 30, TimeSpan.Zero));

    private static readonly X509Certificate2 s_ca = TestCertificateFactory.CreateCaCert();
    private static readonly X509Certificate2 s_leaf = TestCertificateFactory.CreateLeafCert(s_ca);

    private static readonly List<byte[]> s_crls = [Encoding.ASCII.GetBytes("crl one"), Encoding.ASCII.GetBytes("crl two")];
    private static readonly List<byte[]> s_ocsps = [Encoding.ASCII.GetBytes("ocsp response")];
    private static readonly byte[] s_timestamp = Encoding.ASCII.GetBytes("timestamp token");
    private static readonly PdfDssArtifact[] s_artifacts =
    [
        new("Evidence", "EvidenceRef", Encoding.ASCII.GetBytes("evidence a")),
        new("Evidence", "EvidenceRef", Encoding.ASCII.GetBytes("evidence a")),
        new("Notes", "NotesRef", Encoding.ASCII.GetBytes("note b")),
    ];

    public static TheoryData<string> Documents() => WriterCorpus.Names(WriterCorpus.Documents.Keys.Concat(s_withDss.Keys));

    /// <summary>Documents with a DSS already: signed once with its VRI; then signed again, without one.</summary>
    private static readonly Dictionary<string, Func<Task<byte[]>>> s_withDss = new(StringComparer.Ordinal)
    {
        ["dss:signed-once"] = async () => LegacyDss(await WriterCorpus.Documents["signed:table"]()),
        ["dss:signed-twice"] = async () =>
        {
            using var cert = TestCertificateFactory.CreateSelfSignedCert();
            return await PadesSigner.Document(LegacyDss(await WriterCorpus.Documents["signed:stream"]())).WithCertificate(cert).WithFieldName("Sig2").SignAsync();
        },
    };

    private static byte[] LegacyDss(byte[] pdf)
    {
        using var cert = TestCertificateFactory.CreateSelfSignedCert();
        return LtvEmbedderLegacy.AppendDssDictionary(
            pdf, [Encoding.ASCII.GetBytes("old crl")], [], [cert], LtvEmbedderLegacy.ExtractSignatureContentHashes(pdf),
            DssExtractor.ParseExistingDss(pdf), Encoding.ASCII.GetBytes("old token"), [], s_clock);
    }

    [Theory]
    [MemberData(nameof(Documents))]
    public async Task AppendDss_Document_IsWhatTheLegacyEmbedderWrote(string name)
    {
        byte[] original = await (WriterCorpus.Documents.TryGetValue(name, out var build) ? build : s_withDss[name])();
        var source = PdfDocument.Open(original);
        if (source.IsEncrypted || source.Catalog is null || !original.AsSpan().StartsWith("%PDF-"u8))
        {
            output.WriteLine("skipped: encrypted, no catalog or not a PDF");
            return;
        }

        X509Certificate2[] certs = [s_ca, s_leaf, s_ca];
        byte[] legacy = LtvEmbedderLegacy.AppendDssDictionary(
            original, s_crls, s_ocsps, certs, LtvEmbedderLegacy.ExtractSignatureContentHashes(original),
            DssExtractor.ParseExistingDss(original), s_timestamp, s_artifacts, s_clock);
        byte[] model = LtvEmbedder.AppendDss(original, s_crls, s_ocsps, certs, s_timestamp, s_artifacts, s_clock);

        // Whatever the legacy embedder wrote, the update reads back: a new revision whose DSS holds the existing data
        // and the new, and, for the signature made last, a VRI.
        var updated = PdfDocument.Open(model);
        updated.Revisions.Count.ShouldBe(source.Revisions.Count + 1);
        updated.View().Pages.Count.ShouldBe(source.View().Pages.Count);
        var before = DssExtractor.ParseExistingDss(original);
        var after = DssExtractor.ParseExistingDss(model);
        after.CrlObjRefs.Count.ShouldBe(before.CrlObjRefs.Distinct().Count() + s_crls.Count);
        after.CertObjRefs.Count.ShouldBe(before.CertObjRefs.Distinct().Count() + 2);
        after.VriEntries.Keys.ShouldBeSubsetOf(before.VriEntries.Keys.Concat(LtvEmbedder.ExtractSignatureContentHashes(original)));
        if (LtvEmbedder.ExtractSignatureContentHashes(original) is [.., string current])
        {
            after.VriEntries.ContainsKey(current).ShouldBeTrue();
        }

        WriterParity.Compare(output, original, legacy, model, ExpectedDifferences(original, source), []);
    }

    /// <summary>The legacy embedder's defects a document shows, each found from the document itself.</summary>
    private static List<WriterDifference> ExpectedDifferences(byte[] original, PdfDocument source)
    {
        var rules = new List<WriterDifference>();
        var view = source.View();
        int root = source.RootId!.Value.Number;
        var catalog = source.GetObject(root)!;
        bool compressed = source.Lookup(root) is { Type: PdfXrefEntryType.Compressed };

        // The legacy numbering (the text's highest 'N 0 obj', its last /Size) agrees with the cross-reference's on the corpus.
        LtvEmbedderLegacy.FindNextObjectNumber(original).ShouldBe(view.NextObjectNumber);

        var legacyHashes = LtvEmbedderLegacy.ExtractSignatureContentHashes(original);
        var modelHashes = LtvEmbedder.ExtractSignatureContentHashes(original);
        if (legacyHashes is [] && modelHashes is not [])
        {
            rules.Add(new("LegacySignatureNotFound: it looked for '/Contents <' with more than 1000 hex digits and found none of the signatures (/Contents< without a space, in an object stream, or short), so it wrote no VRI.", [], Renumbered: true));
        }
        else
        {
            legacyHashes.LastOrDefault().ShouldBe(modelHashes.LastOrDefault(), "the signature the VRI is for");
        }

        int legacyAt = PdfStructureParser.FindObjectBytes(original, root).Start;
        if (legacyAt < 0)
        {
            rules.Add(new("LegacyCatalogNotFound: with no 'N 0 obj' of the catalog in the file (an object stream), it wrote a catalog of /Type and /DSS only.", [root]));
        }
        else if (!PdfObject.SemanticEquals(PdfParser.ParseIndirectObject(original, legacyAt, new PdfParseContext())?.Value, catalog.Value))
        {
            rules.Add(new("LegacyLastCopyOfObject: it rewrote the last 'N 0 obj' of the catalog in the file, not the one the cross-reference lists.", [root]));
        }

        string catalogText = compressed ? "" : Encoding.Latin1.GetString(original, (int)catalog.Source.Offset, catalog.Source.Length);
        if ((catalog.Value as PdfDictionary)?.Get("DSS") is not null && !compressed)
        {
            rules.Add(new("DssSetInPlace: it removed /DSS and the rest of its line and wrote it again before >>; the patch sets it where it is.", []));
            if (DssWithKeysAfter().IsMatch(catalogText))
            {
                rules.Add(new("LegacyDssLineRemoved: removing the rest of /DSS's line, it removed what followed it there (other keys, the catalog's >>).", [root]));
            }
        }

        if (catalogText.Contains("\r\n", StringComparison.Ordinal))
        {
            rules.Add(new("CrLfPreserved: it turned the catalog's CRLF line ends into LF; the patch keeps them.", []));
        }

        return rules;
    }

    [GeneratedRegex(@"/DSS\s+\d+\s+\d+\s+R[ \t\r]*[^ \t\r\n]")]
    private static partial Regex DssWithKeysAfter();
}
