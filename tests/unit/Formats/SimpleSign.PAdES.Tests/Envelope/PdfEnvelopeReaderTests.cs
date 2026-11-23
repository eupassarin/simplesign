using System.Text;
using Shouldly;
using SimpleSign.PAdES.Envelope;
using SimpleSign.TestHelpers;
using Xunit;
using static SimpleSign.PAdES.Tests.Envelope.EnvelopeTestData;

namespace SimpleSign.PAdES.Tests.Envelope;

[Trait("Category", "Unit")]
public sealed class PdfEnvelopeReaderTests
{
    [Fact]
    public void Read_NoEnvelope_ReturnsNull() => PdfEnvelopeReader.Read(TwoPagePdf()).ShouldBeNull();

    [Fact]
    public async Task Read_Prepared_GivesTheManifestFieldsAndNext()
    {
        using var first = TestCertificateFactory.CreateSelfSignedCert("CN=One");
        using var second = TestCertificateFactory.CreateSelfSignedCert("CN=Two");
        byte[] prepared = await PdfEnvelope.Prepare(TwoPagePdf()).WithId("id-1").WithTimeProvider(new FixedTime())
            .WithTimestampUrl(new Uri("http://tsa.example/"))
            .AddSigner(Signer("One", first, role: "Diretora", level: EnvelopeLevel.PadesT))
            .AddSigner(Signer("Two", second, page: 2, y: 300))
            .PrepareAsync();

        var envelope = PdfEnvelopeReader.Read(prepared).ShouldNotBeNull();

        envelope.Status.ShouldBe(EnvelopeStatus.Prepared);
        envelope.Problems.ShouldBeEmpty();
        var manifest = envelope.Manifest.ShouldNotBeNull();
        manifest.Id.ShouldBe("id-1");
        manifest.PreparedAt.ShouldBe(PreparedAt);
        manifest.Signers[0].Role.ShouldBe("Diretora");
        manifest.Signers[0].Level.Id.ShouldBe("pades-t");
        manifest.Signers[0].Level.Timestamp.ShouldBeTrue();
        envelope.Fields.Select(f => f.Name).ShouldBe(["SimpleSign_1", "SimpleSign_2"]);
        envelope.Fields[1].Placement.ShouldBe(new EnvelopePlacement(2, 72, 300, 200, 50));
        envelope.Fields[0].SeedValue!.TimestampRequired.ShouldBeTrue();
        envelope.Fields[0].SeedValue!.TimestampUrl.ShouldBe(new Uri("http://tsa.example/"));
        envelope.Fields[0].Lock.ShouldBe(new EnvelopeFieldLock("Exclude", ["SimpleSign_2"], null), new LockComparer());
        envelope.Next!.Name.ShouldBe("SimpleSign_1");
        envelope.Pending.Count.ShouldBe(2);
    }

    [Fact]
    public async Task Read_OneSigned_InProgressAndNextIsTheSecond()
    {
        using var first = TestCertificateFactory.CreateSelfSignedCert("CN=One");
        using var second = TestCertificateFactory.CreateSelfSignedCert("CN=Two");
        byte[] signed = await PadesSigner.Document(await PrepareAsync(TwoPagePdf(), first, second))
            .WithCertificate(first).WithEnvelopeField("SimpleSign_1").SignAsync();

        var envelope = PdfEnvelopeReader.Read(signed)!;

        envelope.Status.ShouldBe(EnvelopeStatus.InProgress);
        envelope.Fields[0].IsSigned.ShouldBeTrue();
        envelope.Fields[0].SignerName.ShouldBe("One");
        envelope.Fields[0].SignerCertificate!.Thumbprint.ShouldBe(first.Thumbprint);
        envelope.Next!.Name.ShouldBe("SimpleSign_2");
    }

    [Fact]
    public async Task Read_ParallelOrder_HasNoNext()
    {
        using var first = TestCertificateFactory.CreateSelfSignedCert("CN=One");
        byte[] prepared = await PdfEnvelope.Prepare(TwoPagePdf()).WithOrder(EnvelopeOrder.Parallel).AddSigner(Signer("One", first)).PrepareAsync();

        PdfEnvelopeReader.Read(prepared)!.Next.ShouldBeNull();
    }

    [Fact]
    public async Task Read_FieldRenamed_IsInconsistent()
    {
        using var first = TestCertificateFactory.CreateSelfSignedCert("CN=One");
        byte[] prepared = await PrepareAsync(TwoPagePdf(), first);
        byte[] renamed = Replace(prepared, "(SimpleSign_1)", "(SimpleSign_7)");

        var envelope = PdfEnvelopeReader.Read(renamed)!;

        envelope.Status.ShouldBe(EnvelopeStatus.Inconsistent);
        envelope.Problems.ShouldContain(p => p.Contains("SimpleSign_1", StringComparison.Ordinal));
        envelope.Problems.ShouldContain(p => p.Contains("SimpleSign_7", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Read_LockChanged_IsInconsistent()
    {
        using var first = TestCertificateFactory.CreateSelfSignedCert("CN=One");
        using var second = TestCertificateFactory.CreateSelfSignedCert("CN=Two");
        byte[] prepared = await PrepareAsync(TwoPagePdf(), first, second);
        byte[] unlocked = Replace(prepared, "/Action /Exclude", "/Action /Include");

        PdfEnvelopeReader.Read(unlocked)!.Status.ShouldBe(EnvelopeStatus.Inconsistent);
    }

    [Fact]
    public async Task Read_ManifestChangedAfterTheFirstSignature_IsInconsistent()
    {
        using var first = TestCertificateFactory.CreateSelfSignedCert("CN=One");
        using var second = TestCertificateFactory.CreateSelfSignedCert("CN=Two");
        byte[] signed = await PadesSigner.Document(await PrepareAsync(TwoPagePdf(), first, second))
            .WithCertificate(first).WithEnvelopeField("SimpleSign_1").SignAsync();

        // A later revision that replaces the manifest's embedded file stream.
        var file = SimpleSign.PAdES.Pdf.PdfEmbeddedFiles.Read(signed).Single();
        string json = Encoding.UTF8.GetString(file.Data.Span).Replace("Signer 2", "Mallory", StringComparison.Ordinal);
        byte[] tampered = AppendEmbeddedFileRevision(signed, json);

        var envelope = PdfEnvelopeReader.Read(tampered)!;

        envelope.Status.ShouldBe(EnvelopeStatus.Inconsistent);
        envelope.Problems.ShouldContain("The manifest changed after the first signature.");
    }

    private static byte[] Replace(byte[] pdf, string from, string to)
    {
        from.Length.ShouldBe(to.Length);
        string text = Encoding.Latin1.GetString(pdf);
        text.ShouldContain(from);
        return Encoding.Latin1.GetBytes(text.Replace(from, to, StringComparison.Ordinal));
    }

    /// <summary>An update that writes the manifest's embedded file stream again, unfiltered, under the same number.</summary>
    private static byte[] AppendEmbeddedFileRevision(byte[] pdf, string json)
    {
        var document = SimpleSign.PAdES.Pdf.Model.PdfDocument.Open(pdf);
        var view = document.View();
        var tree = view.NameTree("EmbeddedFiles").Single();
        var spec = (SimpleSign.PAdES.Pdf.Model.PdfDictionary)view.Resolve(tree.Value)!;
        var ef = (SimpleSign.PAdES.Pdf.Model.PdfDictionary)spec.Get("EF")!;
        int number = ((SimpleSign.PAdES.Pdf.Model.PdfReference)ef.Get("F")!).Id.Number;
        var update = new SimpleSign.PAdES.Pdf.Writing.PdfIncrementalUpdate(document);
        byte[] data = Encoding.UTF8.GetBytes(json);
        update.Add(number, new SimpleSign.PAdES.Pdf.Model.PdfStream(
            new SimpleSign.PAdES.Pdf.Model.PdfDictionary(("Type", SimpleSign.PAdES.Pdf.Model.PdfName.Of("EmbeddedFile")), ("Length", new SimpleSign.PAdES.Pdf.Model.PdfInteger(data.Length))),
            data));
        return update.Finish(view.NextObjectNumber, document.RootId!.Value.Number);
    }

    private sealed class LockComparer : IEqualityComparer<EnvelopeFieldLock?>
    {
        public bool Equals(EnvelopeFieldLock? x, EnvelopeFieldLock? y) =>
            x is not null && y is not null && x.Action == y.Action && x.Fields.SequenceEqual(y.Fields) && x.Permissions == y.Permissions;

        public int GetHashCode(EnvelopeFieldLock? obj) => obj?.Action.GetHashCode(StringComparison.Ordinal) ?? 0;
    }
}
