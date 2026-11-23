using System.Text;
using Shouldly;
using SimpleSign.Core.Signing;
using SimpleSign.PAdES.Envelope;
using SimpleSign.PAdES.Pdf;
using SimpleSign.PAdES.Pdf.Model;
using SimpleSign.PAdES.Signing;
using SimpleSign.TestHelpers;
using Xunit;
using static SimpleSign.PAdES.Tests.Envelope.EnvelopeTestData;

namespace SimpleSign.PAdES.Tests.Envelope;

[Trait("Category", "Unit")]
public sealed class PdfEnvelopeBuilderTests
{
    [Fact]
    public async Task PrepareAsync_TwoSigners_WritesFieldsSeedValuesLocksAndTheAssociatedManifest()
    {
        using var first = TestCertificateFactory.CreateSelfSignedCert("CN=One");
        using var second = TestCertificateFactory.CreateSelfSignedCert("CN=Two");
        byte[] pdf = TwoPagePdf();
        byte[] prepared = await PdfEnvelope.Prepare(pdf).WithId("abc").WithTimeProvider(new FixedTime())
            .WithTimestampUrl(new Uri("http://tsa.example/tsa"))
            .WithCertification(CertificationLevel.FormFilling)
            .AddSigner(Signer("One", first, level: EnvelopeLevel.PadesT) with { Reasons = ["Aprovo"] })
            .AddSigner(Signer("Two", second, page: 2))
            .PrepareAsync();

        prepared.AsSpan(0, pdf.Length).SequenceEqual(pdf).ShouldBeTrue();
        var view = PdfDocument.Open(prepared).View();
        var fields = view.Fields.Where(f => f.IsSignature).ToList();
        fields.Select(f => f.FullName).ShouldBe(["SimpleSign_1", "SimpleSign_2"]);
        fields.ShouldAllBe(f => f.Value == null);

        var seed = fields[0].SeedValue.ShouldNotBeNull();
        seed.ContainsKey(PdfName.Of("SubFilter")).ShouldBeFalse();
        seed.ContainsKey(PdfName.Of("Filter")).ShouldBeFalse();
        var timestamp = (PdfDictionary)view.Resolve(seed.Get("TimeStamp"))!;
        ((PdfString)timestamp.Get("URL")!).Text.ShouldBe("http://tsa.example/tsa");
        ((PdfInteger)timestamp.Get("Ff")!).Value.ShouldBe(1);
        ((PdfInteger)((PdfDictionary)seed.Get("MDP")!).Get("P")!).Value.ShouldBe(2);
        fields[1].SeedValue!.ContainsKey(PdfName.Of("MDP")).ShouldBeFalse();
        fields[1].SeedValue!.ContainsKey(PdfName.Of("TimeStamp")).ShouldBeFalse();

        var fieldLock = fields[0].Lock.ShouldNotBeNull();
        ((PdfName)fieldLock.Get("Action")!).Value.ShouldBe("Exclude");
        ((PdfArray)fieldLock.Get("Fields")!).OfType<PdfString>().Select(s => s.Text).ShouldBe(["SimpleSign_2"]);

        var file = PdfEmbeddedFiles.Read(prepared).ShouldHaveSingleItem();
        file.Name.ShouldBe(EnvelopeManifest.FileName);
        file.IsAssociated.ShouldBeTrue();
        file.Relationship.ShouldBe("Data");
        file.MediaType.ShouldBe("application/json");
        file.Size.ShouldBe(file.Data.Length);
        file.ModDate.ShouldBe(PreparedAt);
        string json = Encoding.UTF8.GetString(file.Data.Span);
        json.ShouldContain("\"order\": \"sequential\"");
        json.ShouldContain("\"field\": \"SimpleSign_2\"");
        json.ShouldContain("\"baseline\": \"B-T\"");
    }

    [Fact]
    public async Task PrepareAsync_OneSigner_LocksEveryField()
    {
        using var first = TestCertificateFactory.CreateSelfSignedCert("CN=One");
        byte[] prepared = await PrepareAsync(TwoPagePdf(), first);

        var field = PdfDocument.Open(prepared).View().Fields.Single(f => f.IsSignature);
        ((PdfName)field.Lock!.Get("Action")!).Value.ShouldBe("All");
    }

    [Fact]
    public async Task PrepareAsync_DocumentLock_LastFieldLocksTheDocument()
    {
        using var first = TestCertificateFactory.CreateSelfSignedCert("CN=One");
        using var second = TestCertificateFactory.CreateSelfSignedCert("CN=Two");
        byte[] prepared = await PdfEnvelope.Prepare(TwoPagePdf()).WithDocumentLock()
            .AddSigner(Signer("One", first)).AddSigner(Signer("Two", second, y: 200)).PrepareAsync();

        var fields = PdfDocument.Open(prepared).View().Fields.Where(f => f.IsSignature).ToList();
        fields[0].Lock!.ContainsKey(PdfName.Of("P")).ShouldBeFalse();
        ((PdfInteger)fields[1].Lock!.Get("P")!).Value.ShouldBe(1);
    }

    [Fact]
    public async Task PrepareAsync_ExistingFormAndFiles_KeepsThemAndAddsTheManifestInOrder()
    {
        byte[] pdf = TestPdfFactory.CreatePdfWithAttachments(("zeta.txt", "z"u8.ToArray()), ("alpha.txt", "a"u8.ToArray()));
        using var first = TestCertificateFactory.CreateSelfSignedCert("CN=One");

        byte[] prepared = await PrepareAsync(pdf, first);

        // Keys are ordered by their bytes: the UTF-16 names (FE FF…) come after the manifest's.
        PdfEmbeddedFiles.Read(prepared).Select(f => f.Name).ShouldBe([EnvelopeManifest.FileName, "alpha.txt", "zeta.txt"]);
    }

    [Fact]
    public async Task PrepareAsync_SignedDocument_RefusesNotSignable()
    {
        using var first = TestCertificateFactory.CreateSelfSignedCert("CN=One");
        byte[] signed = await PadesSigner.Document(TwoPagePdf()).WithCertificate(first).SignAsync();

        var ex = await Should.ThrowAsync<SigningException>(PrepareAsync(signed, first));

        ex.Reason.ShouldBe(SigningErrorReason.DocumentNotSignable);
    }

    [Fact]
    public async Task PrepareAsync_EnvelopeAlready_RefusesNotSignable()
    {
        using var first = TestCertificateFactory.CreateSelfSignedCert("CN=One");
        byte[] prepared = await PrepareAsync(TwoPagePdf(), first);

        var ex = await Should.ThrowAsync<SigningException>(PrepareAsync(prepared, first));

        ex.Reason.ShouldBe(SigningErrorReason.DocumentNotSignable);
    }

    [Fact]
    public async Task PrepareAsync_Encrypted_RefusesEncrypted()
    {
        using var first = TestCertificateFactory.CreateSelfSignedCert("CN=One");
        byte[] encrypted = "%PDF-1.7\n1 0 obj\n<< /Type /Catalog >>\nendobj\ntrailer\n<< /Root 1 0 R /Encrypt 5 0 R >>\n%%EOF"u8.ToArray();

        var ex = await Should.ThrowAsync<SigningException>(PrepareAsync(encrypted, first));

        ex.Reason.ShouldBe(SigningErrorReason.DocumentEncrypted);
    }

    [Theory]
    [InlineData(2, "3")]
    [InlineData(3, "3")]
    public async Task PrepareAsync_PdfA2Or3_DeclaresPdfA3(int part, string expected)
    {
        using var first = TestCertificateFactory.CreateSelfSignedCert("CN=One");
        byte[] prepared = await PrepareAsync(PdfA(part), first);

        var view = PdfDocument.Open(prepared).View();
        var metadata = (PdfStream)view.Resolve(view.Catalog!.Get("Metadata"))!;
        Encoding.ASCII.GetString(view.Document.DecodeStream(metadata)).ShouldContain($"<pdfaid:part>{expected}</pdfaid:part>");
    }

    [Fact]
    public async Task PrepareAsync_PdfA1_RefusesNotSignable()
    {
        using var first = TestCertificateFactory.CreateSelfSignedCert("CN=One");

        var ex = await Should.ThrowAsync<SigningException>(PrepareAsync(PdfA(1), first));

        ex.Reason.ShouldBe(SigningErrorReason.DocumentNotSignable);
    }

    [Fact]
    public async Task PrepareAsync_PageOutsideTheDocument_Throws()
    {
        using var first = TestCertificateFactory.CreateSelfSignedCert("CN=One");

        await Should.ThrowAsync<ArgumentException>(PdfEnvelope.Prepare(TwoPagePdf()).AddSigner(Signer("One", first, page: 3)).PrepareAsync());
    }

    [Fact]
    public void PrepareAsync_NoSigner_Throws() =>
        Should.Throw<InvalidOperationException>(() => PdfEnvelope.Prepare(TwoPagePdf()).PrepareAsync());

    [Fact]
    public void AddSigner_PlacementWithoutSize_Throws()
    {
        var signer = new EnvelopeSigner { Name = "One", Placement = new EnvelopePlacement(1, 0, 0, 0, 10) };

        Should.Throw<ArgumentException>(() => PdfEnvelope.Prepare(TwoPagePdf()).AddSigner(signer));
    }

    [Fact]
    public void BuildManifest_NoChangesWithTwoSigners_Throws()
    {
        var builder = PdfEnvelope.Prepare(TwoPagePdf()).WithCertification(CertificationLevel.NoChanges)
            .AddSigner(new EnvelopeSigner { Name = "One", Placement = new EnvelopePlacement(1, 0, 0, 10, 10) })
            .AddSigner(new EnvelopeSigner { Name = "Two", Placement = new EnvelopePlacement(1, 0, 20, 10, 10) });

        Should.Throw<InvalidOperationException>(builder.BuildManifest);
    }

    /// <summary>A one-page document whose XMP declares PDF/A part <paramref name="part"/>, conformance B.</summary>
    private static byte[] PdfA(int part)
    {
        string xmp = $"<x:xmpmeta xmlns:x=\"adobe:ns:meta/\"><rdf:RDF xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\"><rdf:Description rdf:about=\"\" xmlns:pdfaid=\"http://www.aiim.org/pdfa/ns/id/\"><pdfaid:part>{part}</pdfaid:part><pdfaid:conformance>B</pdfaid:conformance></rdf:Description></rdf:RDF></x:xmpmeta>";
        return Encoding.Latin1.GetBytes(
            "%PDF-1.7\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R /Metadata 4 0 R >>\nendobj\n" +
            "2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n" +
            "3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>\nendobj\n" +
            $"4 0 obj\n<< /Type /Metadata /Subtype /XML /Length {xmp.Length} >>\nstream\n{xmp}\nendstream\nendobj\n" +
            "trailer\n<< /Size 5 /Root 1 0 R >>\n%%EOF\n");
    }
}
