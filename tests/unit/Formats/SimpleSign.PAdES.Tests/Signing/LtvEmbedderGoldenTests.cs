using System.Security.Cryptography.X509Certificates;
using System.Text;
using Shouldly;
using SimpleSign.PAdES.Pdf.Model;
using SimpleSign.PAdES.Signing;
using SimpleSign.PAdES.Tests.Pdf.Parity;
using SimpleSign.PAdES.Validation;
using SimpleSign.TestHelpers;
using Xunit;
using Xunit.Abstractions;

namespace SimpleSign.PAdES.Tests.Signing;

/// <summary>
/// The DSS the LTV embedder writes on the PDF object model (ADR 0032), with the clock and the validation data fixed, on
/// the writers' corpus and on documents that already have a DSS (the merge; a signature with its VRI already): each
/// update reads back with the existing data and the new, and a VRI for the signature made last; and is its snapshot
/// (SHA-256, per framework). The snapshots were taken when each update had been checked against the embedder before
/// the model: the same bytes, or a difference that embedder's defect explained (catalogued in the ADR).
/// </summary>
[Trait("Category", "Unit")]
public sealed class LtvEmbedderGoldenTests(ITestOutputHelper output)
{
    private static readonly FixedClock s_clock = new(new DateTimeOffset(2026, 11, 22, 10, 20, 30, TimeSpan.Zero));

    // Captured public certificates: the same bytes on every run, so the DSS is (a new key each run would not be).
    private static readonly X509Certificate2 s_ca = SimpleSign.Core.Crypto.CertificateLoader.LoadCertificate(SimpleSign.TestFixtures.RecordedFixtures.DigiCertIssuerCertDer);
    private static readonly X509Certificate2 s_leaf = SimpleSign.Core.Crypto.CertificateLoader.LoadCertificate(SimpleSign.TestFixtures.RecordedFixtures.DigiCertPublicCertDer);

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
        ["dss:signed-once"] = async () => WithDss(await WriterCorpus.Documents["signed:table"]()),
        ["dss:signed-twice"] = async () =>
        {
            using var cert = TestCertificateFactory.CreateSelfSignedCert();
            return await PadesSigner.Document(WithDss(await WriterCorpus.Documents["signed:stream"]())).WithCertificate(cert).WithFieldName("Sig2").SignAsync();
        },
    };

    private static byte[] WithDss(byte[] pdf)
    {
        using var cert = TestCertificateFactory.CreateSelfSignedCert();
        return LtvEmbedder.AppendDss(pdf, [Encoding.ASCII.GetBytes("old crl")], [], [cert], Encoding.ASCII.GetBytes("old token"), [], s_clock);
    }

    [Theory]
    [MemberData(nameof(Documents))]
    public async Task AppendDss_Document_IsItsSnapshot(string name)
    {
        byte[] original = await (WriterCorpus.Documents.TryGetValue(name, out var build) ? build : s_withDss[name])();
        var source = PdfDocument.Open(original);
        if (source.IsEncrypted || source.Catalog is null || !original.AsSpan().StartsWith("%PDF-"u8))
        {
            output.WriteLine("skipped: encrypted, no catalog or not a PDF");
            return;
        }

        X509Certificate2[] certs = [s_ca, s_leaf, s_ca];
        byte[] model = LtvEmbedder.AppendDss(original, s_crls, s_ocsps, certs, s_timestamp, s_artifacts, s_clock);

        // The update reads back: a new revision whose DSS holds the existing data
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

        if (WriterCorpus.IsDeterministic(name))
        {
            Snapshot.MatchCompressed("writers/dss", name, model);
        }
    }
}
