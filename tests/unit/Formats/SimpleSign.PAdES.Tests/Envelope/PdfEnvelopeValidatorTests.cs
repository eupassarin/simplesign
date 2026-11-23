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
public sealed class PdfEnvelopeValidatorTests
{
    [Fact]
    public async Task ValidateAsync_EverySignerSigned_IsComplete()
    {
        using var first = TestCertificateFactory.CreateSelfSignedCert("CN=One");
        using var second = TestCertificateFactory.CreateSelfSignedCert("CN=Two");
        byte[] signed = await PadesSigner.Document(await PdfEnvelope.Prepare(TwoPagePdf()).WithCertification(CertificationLevel.FormFilling)
                .AddSigner(Signer("One", first)).AddSigner(Signer("Two", second, y: 200)).PrepareAsync())
            .WithCertificate(first).WithEnvelopeField("SimpleSign_1").AsCertification(CertificationLevel.FormFilling).SignAsync();
        signed = await PadesSigner.Document(signed).WithCertificate(second).WithEnvelopeField("SimpleSign_2").SignAsync();

        var report = await new PdfEnvelopeValidator(Validator(first, second)).ValidateAsync(signed);

        report.Signatures.ShouldAllBe(s => s.IsSigned && s.SignerMatches && s.LevelMet && s.InOrder);
        report.Signatures.ShouldAllBe(s => s.Validation!.Indication == SignatureIndication.Valid,
            string.Join(" | ", report.Signatures.Select(s => $"{s.Field}: {s.Validation!.Indication} {s.Validation.SubIndication} {string.Join(" ", s.Validation.Errors)}")));
        report.IsComplete.ShouldBeTrue();
        report.MissingFields.ShouldBeEmpty();
        string json = report.ToJson();
        json.ShouldContain("\"isComplete\": true");
        json.ShouldContain("\"field\": \"SimpleSign_2\"");
        json.ShouldContain("\"match\": \"Matched\"");
    }

    [Fact]
    public async Task ValidateAsync_OneMissing_IsNotCompleteAndSaysWhich()
    {
        using var first = TestCertificateFactory.CreateSelfSignedCert("CN=One");
        using var second = TestCertificateFactory.CreateSelfSignedCert("CN=Two");
        byte[] signed = await PadesSigner.Document(await PrepareAsync(TwoPagePdf(), first, second))
            .WithCertificate(first).WithEnvelopeField("SimpleSign_1").SignAsync();

        var report = await new PdfEnvelopeValidator(Validator(first, second)).ValidateAsync(signed);

        report.IsComplete.ShouldBeFalse();
        report.MissingFields.ShouldBe(["SimpleSign_2"]);
    }

    [Fact]
    public async Task ValidateAsync_FieldSignedWithoutTheChecks_ReportsTheWrongSignerAndLevel()
    {
        using var first = TestCertificateFactory.CreateSelfSignedCert("CN=One");
        using var intruder = TestCertificateFactory.CreateSelfSignedCert("CN=Intruder");
        byte[] prepared = await PdfEnvelope.Prepare(TwoPagePdf()).AddSigner(Signer("One", first, level: EnvelopeLevel.PadesT)).PrepareAsync();

        // WithExistingField does not check the envelope: the validator still finds what is wrong.
        byte[] signed = await PadesSigner.Document(prepared).WithCertificate(intruder).WithExistingField("SimpleSign_1").SignAsync();
        var report = await new PdfEnvelopeValidator(Validator(intruder)).ValidateAsync(signed);

        var signature = report.Signatures.ShouldHaveSingleItem();
        signature.SignerMatches.ShouldBeFalse();
        signature.Identifiers.Single().Match.ShouldBe(EnvelopeIdentifierMatch.Mismatch);
        signature.LevelMet.ShouldBeFalse();
        signature.ReachedLevel.ShouldBe(AdesBaselineLevel.Basic);
        report.IsComplete.ShouldBeFalse();
    }

    [Fact]
    public async Task ValidateAsync_SequentialSignedOutOfOrder_IsNotInOrder()
    {
        using var first = TestCertificateFactory.CreateSelfSignedCert("CN=One");
        using var second = TestCertificateFactory.CreateSelfSignedCert("CN=Two");
        byte[] signed = await PadesSigner.Document(await PrepareAsync(TwoPagePdf(), first, second))
            .WithCertificate(second).WithExistingField("SimpleSign_2").SignAsync();
        signed = await PadesSigner.Document(signed).WithCertificate(first).WithExistingField("SimpleSign_1").SignAsync();

        var report = await new PdfEnvelopeValidator(Validator(first, second)).ValidateAsync(signed);

        report.Signatures[0].InOrder.ShouldBeTrue();
        report.Signatures[1].InOrder.ShouldBeFalse();
        report.OrderRespected.ShouldBeFalse();
    }

    [Fact]
    public async Task ValidateAsync_NoEnvelope_Throws()
    {
        var ex = await Should.ThrowAsync<SigningException>(new PdfEnvelopeValidator().ValidateAsync(TwoPagePdf()));

        ex.Reason.ShouldBe(SigningErrorReason.EnvelopeFieldNotFound);
    }
}
