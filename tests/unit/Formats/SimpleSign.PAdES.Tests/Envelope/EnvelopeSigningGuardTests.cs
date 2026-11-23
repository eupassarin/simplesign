using Shouldly;
using SimpleSign.Core.Signing;
using SimpleSign.Core.Validation;
using SimpleSign.PAdES.Envelope;
using SimpleSign.PAdES.Signing;
using SimpleSign.TestHelpers;
using Xunit;
using static SimpleSign.PAdES.Tests.Envelope.EnvelopeTestData;

namespace SimpleSign.PAdES.Tests.Envelope;

[Trait("Category", "Unit")]
public sealed class EnvelopeSigningGuardTests
{
    private const string Basic = "SignatureConstraints/BasicSignatureConstraints";

    [Fact]
    public async Task Ensure_ThreeSignersInTurnWithCertification_EverySignatureValidWithNoUndefinedChange()
    {
        using var first = TestCertificateFactory.CreateSelfSignedCert("CN=Envelope One");
        using var second = TestCertificateFactory.CreateSelfSignedCert("CN=Envelope Two");
        using var third = TestCertificateFactory.CreateSelfSignedCert("CN=Envelope Three");
        byte[] prepared = await PdfEnvelope.Prepare(TwoPagePdf()).WithId("flow").WithTimeProvider(new FixedTime())
            .WithCertification(CertificationLevel.FormFilling)
            .AddSigner(Signer("One", first, role: "Diretora"))
            .AddSigner(Signer("Two", second, page: 2))
            .AddSigner(Signer("Three", third, y: 200))
            .PrepareAsync();

        byte[] signed = await PadesSigner.Document(prepared).WithCertificate(first).WithEnvelopeField("SimpleSign_1")
            .AsCertification(CertificationLevel.FormFilling).SignAsync();
        signed = await PadesSigner.Document(signed).WithCertificate(second).WithEnvelopeField("SimpleSign_2").SignAsync();
        signed = await PadesSigner.Document(signed).WithCertificate(third).WithEnvelopeField("SimpleSign_3").SignAsync();

        var envelope = PdfEnvelopeReader.Read(signed).ShouldNotBeNull();
        envelope.Status.ShouldBe(EnvelopeStatus.Completed, string.Join(" ", envelope.Problems));
        envelope.Fields.Select(f => f.SignatureOrder).ShouldBe([1, 2, 3]);
        envelope.Fields[0].ClaimedRoles.ShouldBe(["Diretora"]);

        using var stream = new MemoryStream(signed, writable: false);
        var results = await Validator(first, second, third).ValidateAsync(stream);
        results.Count.ShouldBe(3);
        foreach (var result in results)
        {
            foreach (string id in new[] { "DocMDP", "FieldMDP", "SigFieldLock", "UndefinedChanges" })
            {
                result.Constraints.ShouldContain(c => c.Id == Basic + "/" + id && c.Status == ConstraintStatus.Passed,
                    $"{result.FieldName} {id}: " + string.Join(" | ", result.Constraints.Where(c => c.Id.EndsWith(id, StringComparison.Ordinal)).Select(c => c.Message)));
            }
        }
    }

    [Fact]
    public async Task Ensure_SecondBeforeFirst_RefusesNotYourTurn()
    {
        using var first = TestCertificateFactory.CreateSelfSignedCert("CN=Envelope One");
        using var second = TestCertificateFactory.CreateSelfSignedCert("CN=Envelope Two");
        byte[] prepared = await PrepareAsync(TwoPagePdf(), first, second);

        var ex = await Should.ThrowAsync<SigningException>(
            PadesSigner.Document(prepared).WithCertificate(second).WithEnvelopeField("SimpleSign_2").SignAsync());

        ex.Reason.ShouldBe(SigningErrorReason.NotYourTurn);
    }

    [Fact]
    public async Task Ensure_AnotherCertificate_RefusesUnexpectedSigner()
    {
        using var first = TestCertificateFactory.CreateSelfSignedCert("CN=Envelope One");
        using var intruder = TestCertificateFactory.CreateSelfSignedCert("CN=Intruder");
        byte[] prepared = await PrepareAsync(TwoPagePdf(), first);

        var ex = await Should.ThrowAsync<SigningException>(
            PadesSigner.Document(prepared).WithCertificate(intruder).WithEnvelopeField("SimpleSign_1").SignAsync());

        ex.Reason.ShouldBe(SigningErrorReason.UnexpectedSigner);
    }

    [Fact]
    public async Task Ensure_FieldSignedTwice_RefusesAlreadySigned()
    {
        using var first = TestCertificateFactory.CreateSelfSignedCert("CN=Envelope One");
        using var second = TestCertificateFactory.CreateSelfSignedCert("CN=Envelope Two");
        byte[] signed = await PadesSigner.Document(await PrepareAsync(TwoPagePdf(), first, second))
            .WithCertificate(first).WithEnvelopeField("SimpleSign_1").SignAsync();

        var ex = await Should.ThrowAsync<SigningException>(
            PadesSigner.Document(signed).WithCertificate(first).WithEnvelopeField("SimpleSign_1").SignAsync());

        ex.Reason.ShouldBe(SigningErrorReason.EnvelopeFieldAlreadySigned);
    }

    [Fact]
    public async Task Ensure_UnknownField_RefusesFieldNotFound()
    {
        using var first = TestCertificateFactory.CreateSelfSignedCert("CN=Envelope One");
        byte[] prepared = await PrepareAsync(TwoPagePdf(), first);

        var ex = await Should.ThrowAsync<SigningException>(
            PadesSigner.Document(prepared).WithCertificate(first).WithEnvelopeField("SimpleSign_9").SignAsync());

        ex.Reason.ShouldBe(SigningErrorReason.EnvelopeFieldNotFound);
    }

    [Fact]
    public async Task Ensure_LevelNeedsTimestamp_RefusesTimestampRequired()
    {
        using var first = TestCertificateFactory.CreateSelfSignedCert("CN=Envelope One");
        byte[] prepared = await PdfEnvelope.Prepare(TwoPagePdf())
            .AddSigner(Signer("One", first, level: EnvelopeLevel.PadesT))
            .PrepareAsync();

        var ex = await Should.ThrowAsync<SigningException>(
            PadesSigner.Document(prepared).WithCertificate(first).WithEnvelopeField("SimpleSign_1").SignAsync());

        ex.Reason.ShouldBe(SigningErrorReason.TimestampRequired);
    }

    [Fact]
    public async Task Ensure_LevelNeedsSubFilter_RefusesLevelNotMet()
    {
        using var first = TestCertificateFactory.CreateSelfSignedCert("CN=Envelope One");
        var level = new EnvelopeLevel { Id = "pbad-only", SubFilters = ["PBAD.PAdES"] };
        byte[] prepared = await PdfEnvelope.Prepare(TwoPagePdf()).AddSigner(Signer("One", first, level: level)).PrepareAsync();

        var ex = await Should.ThrowAsync<SigningException>(
            PadesSigner.Document(prepared).WithCertificate(first).WithEnvelopeField("SimpleSign_1").SignAsync());

        ex.Reason.ShouldBe(SigningErrorReason.LevelNotMet);
    }

    [Fact]
    public async Task Ensure_CertificationAskedButNotMade_RefusesSeedValueViolated()
    {
        using var first = TestCertificateFactory.CreateSelfSignedCert("CN=Envelope One");
        using var second = TestCertificateFactory.CreateSelfSignedCert("CN=Envelope Two");
        byte[] prepared = await PdfEnvelope.Prepare(TwoPagePdf()).WithCertification(CertificationLevel.FormFilling)
            .AddSigner(Signer("One", first)).AddSigner(Signer("Two", second, y: 200)).PrepareAsync();

        var ex = await Should.ThrowAsync<SigningException>(
            PadesSigner.Document(prepared).WithCertificate(first).WithEnvelopeField("SimpleSign_1").SignAsync());

        ex.Reason.ShouldBe(SigningErrorReason.SeedValueViolated);
    }

    [Fact]
    public async Task Ensure_Deferred_ChecksTheSignerBeforeTheHash()
    {
        using var first = TestCertificateFactory.CreateSelfSignedCert("CN=Envelope One");
        using var intruder = TestCertificateFactory.CreateSelfSignedCert("CN=Intruder");
        byte[] prepared = await PrepareAsync(TwoPagePdf(), first);

        var ex = await Should.ThrowAsync<SigningException>(
            DeferredSigner.Document(prepared).WithCertificate(intruder).WithSessionIntegrityKey(new byte[32])
                .WithEnvelopeField("SimpleSign_1").PrepareAsync());

        ex.Reason.ShouldBe(SigningErrorReason.UnexpectedSigner);
    }

    [Fact]
    public async Task Ensure_Parallel_AnyOrder()
    {
        using var first = TestCertificateFactory.CreateSelfSignedCert("CN=Envelope One");
        using var second = TestCertificateFactory.CreateSelfSignedCert("CN=Envelope Two");
        byte[] prepared = await PdfEnvelope.Prepare(TwoPagePdf()).WithOrder(EnvelopeOrder.Parallel)
            .AddSigner(Signer("One", first)).AddSigner(Signer("Two", second, y: 200)).PrepareAsync();

        byte[] signed = await PadesSigner.Document(prepared).WithCertificate(second).WithEnvelopeField("SimpleSign_2").SignAsync();
        signed = await PadesSigner.Document(signed).WithCertificate(first).WithEnvelopeField("SimpleSign_1").SignAsync();

        PdfEnvelopeReader.Read(signed)!.Status.ShouldBe(EnvelopeStatus.Completed);
    }
}
