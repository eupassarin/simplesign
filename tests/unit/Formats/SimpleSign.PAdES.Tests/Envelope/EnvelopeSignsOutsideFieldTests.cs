using System.Security.Cryptography.X509Certificates;
using Shouldly;
using SimpleSign.Core.Extensions;
using SimpleSign.Core.Signing;
using SimpleSign.Core.Validation;
using SimpleSign.PAdES.Envelope;
using SimpleSign.PAdES.Signing;
using SimpleSign.TestHelpers;
using Xunit;
using static SimpleSign.PAdES.Tests.Envelope.EnvelopeTestData;

namespace SimpleSign.PAdES.Tests.Envelope;

/// <summary>A signer who signs outside their field, with a tool that makes its own (the gov.br signer).</summary>
[Trait("Category", "Unit")]
public sealed class EnvelopeSignsOutsideFieldTests
{
    [Fact]
    public async Task Prepare_OutsideSigner_HasAHiddenFieldAndTheManifestSaysSo()
    {
        using var gov = TestCertificateFactory.CreateSelfSignedCert("CN=Gov");
        byte[] prepared = await PdfEnvelope.Prepare(TwoPagePdf()).AddSigner(Outside("Gov", gov)).PrepareAsync();

        var envelope = PdfEnvelopeReader.Read(prepared).ShouldNotBeNull();

        envelope.Problems.ShouldBeEmpty();
        envelope.Manifest!.Signers[0].SignsOutsideField.ShouldBeTrue();
        envelope.Fields[0].Exists.ShouldBeTrue();
        envelope.Fields[0].Placement.ShouldBe(new EnvelopePlacement(1, 0, 0, 0, 0));
        envelope.Manifest.ToJson().ShouldContain("\"signsOutsideField\": true");
    }

    [Fact]
    public void Manifest_WithoutOutsideSigner_HasNoKeyAndReadsTheSame()
    {
        var manifest = new EnvelopeManifest
        {
            Id = "m",
            PreparedAt = PreparedAt,
            Signers = [new EnvelopeManifestSigner { Field = "SimpleSign_1", Name = "One" }],
        };

        string json = manifest.ToJson();

        json.ShouldNotContain("signsOutsideField");
        EnvelopeManifest.Parse(json).Signers[0].SignsOutsideField.ShouldBeFalse();
        EnvelopeManifest.Parse(json.Replace("\"name\": \"One\"", "\"name\": \"One\", \"signsOutsideField\": true", StringComparison.Ordinal))
            .Signers[0].SignsOutsideField.ShouldBeTrue();
    }

    [Fact]
    public async Task Read_SignedOutsideByTheSigner_CountsAsTheirs()
    {
        using var gov = TestCertificateFactory.CreateSelfSignedCert("CN=Gov");
        using var second = TestCertificateFactory.CreateSelfSignedCert("CN=Two");
        byte[] prepared = await PdfEnvelope.Prepare(TwoPagePdf()).WithOrder(EnvelopeOrder.Parallel)
            .AddSigner(Outside("Gov", gov)).AddSigner(Signer("Two", second)).PrepareAsync();

        byte[] signed = await PadesSigner.Document(prepared).WithCertificate(gov).SignAsync();
        var envelope = PdfEnvelopeReader.Read(signed)!;

        envelope.Status.ShouldBe(EnvelopeStatus.InProgress);
        envelope.Problems.ShouldBeEmpty();
        var field = envelope.Fields[0];
        field.IsSigned.ShouldBeTrue();
        field.SignatureField.ShouldNotBeNull().ShouldNotStartWith("SimpleSign_");
        field.SignerName.ShouldBe("Gov");
        field.SignerCertificate!.Thumbprint.ShouldBe(gov.Thumbprint);
        field.SignatureOrder.ShouldBe(1);

        signed = await PadesSigner.Document(signed).WithCertificate(second).WithEnvelopeField("SimpleSign_2").SignAsync();
        envelope = PdfEnvelopeReader.Read(signed)!;

        envelope.Status.ShouldBe(EnvelopeStatus.Completed);
        envelope.Fields[1].SignatureField.ShouldBe("SimpleSign_2");
        envelope.Fields[1].SignatureOrder.ShouldBe(2);
    }

    [Fact]
    public async Task Read_SignedOutsideBySomeoneElse_StaysPending()
    {
        using var gov = TestCertificateFactory.CreateSelfSignedCert("CN=Gov");
        using var other = TestCertificateFactory.CreateSelfSignedCert("CN=Other");
        byte[] prepared = await PdfEnvelope.Prepare(TwoPagePdf()).AddSigner(Outside("Gov", gov)).PrepareAsync();

        byte[] signed = await PadesSigner.Document(prepared).WithCertificate(other).SignAsync();
        var envelope = PdfEnvelopeReader.Read(signed)!;

        envelope.Status.ShouldBe(EnvelopeStatus.Prepared);
        envelope.Pending.Select(f => f.Name).ShouldBe(["SimpleSign_1"]);
    }

    [Fact]
    public async Task Read_IdentifierOnlyAReaderKnows_IsFoundWithTheReaders()
    {
        using var gov = TestCertificateFactory.CreateSelfSignedCert("CN=Gov");
        byte[] prepared = await PdfEnvelope.Prepare(TwoPagePdf())
            .AddSigner(new EnvelopeSigner { Name = "Gov", SignsOutsideField = true, Identifiers = [new EnvelopeIdentifier(CommonNameReader.Type, "Gov")] })
            .PrepareAsync();
        byte[] signed = await PadesSigner.Document(prepared).WithCertificate(gov).SignAsync();

        PdfEnvelopeReader.Read(signed)!.Status.ShouldBe(EnvelopeStatus.Prepared);
        PdfEnvelopeReader.Read(signed, [new CommonNameReader()])!.Status.ShouldBe(EnvelopeStatus.Completed);
    }

    [Fact]
    public async Task CheckSigner_Sequential_TheNextWaitsForTheSignatureOutside()
    {
        using var gov = TestCertificateFactory.CreateSelfSignedCert("CN=Gov");
        using var second = TestCertificateFactory.CreateSelfSignedCert("CN=Two");
        byte[] prepared = await PdfEnvelope.Prepare(TwoPagePdf()).AddSigner(Outside("Gov", gov)).AddSigner(Signer("Two", second)).PrepareAsync();

        PdfEnvelope.CheckSigner(prepared, "SimpleSign_2", second).Reason.ShouldBe(SigningErrorReason.NotYourTurn);
        PdfEnvelope.CheckSigner(prepared, "SimpleSign_1", gov).Reason.ShouldBe(SigningErrorReason.EnvelopeFieldSignedOutside);

        byte[] signed = await PadesSigner.Document(prepared).WithCertificate(gov).SignAsync();

        PdfEnvelope.CheckSigner(signed, "SimpleSign_2", second).Allowed.ShouldBeTrue();
        signed = await PadesSigner.Document(signed).WithCertificate(second).WithEnvelopeField("SimpleSign_2").SignAsync();
        PdfEnvelopeReader.Read(signed)!.Status.ShouldBe(EnvelopeStatus.Completed);
    }

    [Fact]
    public async Task Sign_InTheFieldOfAnOutsideSigner_IsRefused()
    {
        using var gov = TestCertificateFactory.CreateSelfSignedCert("CN=Gov");
        byte[] prepared = await PdfEnvelope.Prepare(TwoPagePdf()).AddSigner(Outside("Gov", gov)).PrepareAsync();

        var ex = await Should.ThrowAsync<SigningException>(() => PadesSigner.Document(prepared).WithCertificate(gov).WithEnvelopeField("SimpleSign_1").SignAsync());

        ex.Reason.ShouldBe(SigningErrorReason.EnvelopeFieldSignedOutside);
    }

    [Fact]
    public async Task Validate_SignatureOutside_IsTheSignersAndComplete()
    {
        using var gov = TestCertificateFactory.CreateSelfSignedCert("CN=Gov");
        using var second = TestCertificateFactory.CreateSelfSignedCert("CN=Two");
        byte[] prepared = await PdfEnvelope.Prepare(TwoPagePdf()).AddSigner(Outside("Gov", gov)).AddSigner(Signer("Two", second)).PrepareAsync();
        byte[] signed = await PadesSigner.Document(prepared).WithCertificate(gov).SignAsync();
        signed = await PadesSigner.Document(signed).WithCertificate(second).WithEnvelopeField("SimpleSign_2").SignAsync();

        var report = await new PdfEnvelopeValidator(Validator(gov, second)).ValidateAsync(signed);

        report.Signatures.ShouldAllBe(s => s.IsSigned && s.SignerMatches && s.InOrder);
        report.Signatures[0].Validation.ShouldNotBeNull().Indication.ShouldBe(SignatureIndication.Valid);
        report.IsComplete.ShouldBeTrue();
    }

    [Fact]
    public void Builder_OutsideSigner_RefusesCertificationAndLock()
    {
        using var gov = TestCertificateFactory.CreateSelfSignedCert("CN=Gov");
        var builder = PdfEnvelope.Prepare(TwoPagePdf()).AddSigner(Outside("Gov", gov));

        Should.Throw<InvalidOperationException>(() => builder.WithCertification(CertificationLevel.FormFilling).BuildManifest());
        Should.Throw<InvalidOperationException>(() => builder.WithDocumentLock().BuildManifest());
    }

    [Fact]
    public void Builder_NoPlacementOrNoIdentifier_IsRefused()
    {
        var builder = PdfEnvelope.Prepare(TwoPagePdf());

        Should.Throw<ArgumentException>(() => builder.AddSigner(new EnvelopeSigner { Name = "Nowhere" }));
        Should.Throw<ArgumentException>(() => builder.AddSigner(new EnvelopeSigner { Name = "Anyone", SignsOutsideField = true }));
    }

    private static EnvelopeSigner Outside(string name, X509Certificate2 certificate) =>
        Signer(name, certificate) with { Placement = null, SignsOutsideField = true };

    /// <summary>A reader of a type no other reader knows: the certificate's common name.</summary>
    private sealed class CommonNameReader : ISignerIdentityReader
    {
        public const string Type = "TEST-CN";

        public IReadOnlyCollection<string> IdentifierTypes => [Type];

        public IReadOnlyList<string> Read(X509Certificate2 certificate, string identifierType) =>
            string.Equals(identifierType, Type, StringComparison.OrdinalIgnoreCase) ? [certificate.GetNameInfo(X509NameType.SimpleName, false)] : [];
    }
}
