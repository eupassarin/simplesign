using System.Security.Cryptography.X509Certificates;
using Shouldly;
using SimpleSign.Core.Extensions;
using SimpleSign.Core.Signing;
using SimpleSign.PAdES.Envelope;
using SimpleSign.TestHelpers;
using Xunit;
using static SimpleSign.PAdES.Tests.Envelope.EnvelopeTestData;

namespace SimpleSign.PAdES.Tests.Envelope;

[Trait("Category", "Unit")]
public sealed class PdfEnvelopeTests
{
    [Fact]
    public async Task CheckSigner_RightCertificate_IsAllowed()
    {
        using var first = TestCertificateFactory.CreateSelfSignedCert("CN=One");
        byte[] prepared = await PrepareAsync(TwoPagePdf(), first);

        var check = PdfEnvelope.CheckSigner(prepared, "SimpleSign_1", first);

        check.Allowed.ShouldBeTrue();
        check.IsYourTurn.ShouldBeTrue();
        check.Identifiers.ShouldHaveSingleItem().Match.ShouldBe(EnvelopeIdentifierMatch.Matched);
    }

    [Fact]
    public async Task CheckSigner_EmailInAnotherCase_IsMatched()
    {
        using var certificate = TestCertificateFactory.CreateSelfSignedCert("CN=Maria, E=Maria@Example.com");
        byte[] prepared = await PdfEnvelope.Prepare(TwoPagePdf())
            .AddSigner(new EnvelopeSigner
            {
                Name = "Maria",
                Identifiers = [new EnvelopeIdentifier(SignerIdentifierTypes.Email, "maria@example.com")],
                Placement = new EnvelopePlacement(1, 10, 10, 100, 40),
            })
            .PrepareAsync();

        PdfEnvelope.CheckSigner(prepared, "SimpleSign_1", certificate).Allowed.ShouldBeTrue();
    }

    [Fact]
    public async Task CheckSigner_TypeNoReaderKnows_IsNotVerifiableAndRefused()
    {
        using var certificate = TestCertificateFactory.CreateSelfSignedCert("CN=Maria");
        byte[] prepared = await PdfEnvelope.Prepare(TwoPagePdf())
            .AddSigner(new EnvelopeSigner
            {
                Name = "Maria",
                Identifiers = [new EnvelopeIdentifier(SignerIdentifierTypes.Cpf, "123.456.789-09")],
                Placement = new EnvelopePlacement(1, 10, 10, 100, 40),
            })
            .PrepareAsync();

        var check = PdfEnvelope.CheckSigner(prepared, "SimpleSign_1", certificate);

        check.Reason.ShouldBe(SigningErrorReason.UnexpectedSigner);
        check.Identifiers.ShouldHaveSingleItem().Match.ShouldBe(EnvelopeIdentifierMatch.NotVerifiable);
    }

    [Fact]
    public async Task CheckSigner_ReaderOfTheProfile_MatchesFormattedValueAndAlsoAccept()
    {
        using var certificate = TestCertificateFactory.CreateSelfSignedCert("CN=Maria");
        byte[] prepared = await PdfEnvelope.Prepare(TwoPagePdf())
            .AddSigner(new EnvelopeSigner
            {
                Name = "Maria",
                Identifiers = [new EnvelopeIdentifier(SignerIdentifierTypes.Cpf, "123.456.789-09") { AlsoAccept = [SignerIdentifierTypes.ResponsibleCpf] }],
                Placement = new EnvelopePlacement(1, 10, 10, 100, 40),
            })
            .PrepareAsync();
        var profile = TrustProfile.Default with { SignerIdentityReaders = [new FixedReader(SignerIdentifierTypes.ResponsibleCpf, "12345678909")] };

        var check = PdfEnvelope.CheckSigner(prepared, "SimpleSign_1", certificate, profile);

        check.Allowed.ShouldBeTrue(check.Message);
        check.Identifiers.Single().Found.ShouldBe(["12345678909"]);
    }

    [Fact]
    public async Task CheckSigner_EveryIdentifierMustMatch()
    {
        using var certificate = TestCertificateFactory.CreateSelfSignedCert("CN=Maria, E=maria@example.com");
        byte[] prepared = await PdfEnvelope.Prepare(TwoPagePdf())
            .AddSigner(new EnvelopeSigner
            {
                Name = "Maria",
                Identifiers =
                [
                    new EnvelopeIdentifier(SignerIdentifierTypes.Email, "maria@example.com"),
                    new EnvelopeIdentifier(SignerIdentifierTypes.CertificateSha256, "00"),
                ],
                Placement = new EnvelopePlacement(1, 10, 10, 100, 40),
            })
            .PrepareAsync();

        var check = PdfEnvelope.CheckSigner(prepared, "SimpleSign_1", certificate);

        check.Reason.ShouldBe(SigningErrorReason.UnexpectedSigner);
        check.Identifiers.Select(i => i.Match).ShouldBe([EnvelopeIdentifierMatch.Matched, EnvelopeIdentifierMatch.Mismatch]);
    }

    [Fact]
    public async Task CheckSigner_NotYourTurn_SaysWhoIsBefore()
    {
        using var first = TestCertificateFactory.CreateSelfSignedCert("CN=One");
        using var second = TestCertificateFactory.CreateSelfSignedCert("CN=Two");
        byte[] prepared = await PrepareAsync(TwoPagePdf(), first, second);

        var check = PdfEnvelope.CheckSigner(prepared, "SimpleSign_2", second);

        check.Reason.ShouldBe(SigningErrorReason.NotYourTurn);
        check.IsYourTurn.ShouldBeFalse();
        check.Message!.ShouldContain("SimpleSign_1 (Signer 1)");
    }

    [Fact]
    public void CheckSigner_NoEnvelope_Throws()
    {
        using var first = TestCertificateFactory.CreateSelfSignedCert("CN=One");

        Should.Throw<SigningException>(() => PdfEnvelope.CheckSigner(TwoPagePdf(), "SimpleSign_1", first)).Reason
            .ShouldBe(SigningErrorReason.EnvelopeFieldNotFound);
    }

    [Theory]
    [InlineData("CPF", "123.456.789-09", "12345678909", true)]
    [InlineData("CNPJ", "12.ABC.345/01DE-35", "12abc34501de35", true)]
    [InlineData("EMAIL", " Ana@X.com ", "ana@x.com", true)]
    [InlineData("EMAIL", "a.b@x.com", "ab@x.com", false)]
    [InlineData("CPF", "12345678909", "12345678900", false)]
    public void SameValue_ComparesAsTheTypeSays(string type, string expected, string actual, bool same) =>
        PdfEnvelope.SameValue(type, expected, actual).ShouldBe(same);

    private sealed class FixedReader(string type, string value) : ISignerIdentityReader
    {
        public IReadOnlyCollection<string> IdentifierTypes => [type];

        public IReadOnlyList<string> Read(X509Certificate2 certificate, string identifierType) =>
            string.Equals(identifierType, type, StringComparison.OrdinalIgnoreCase) ? [value] : [];
    }
}
