using System.Security.Cryptography.X509Certificates;
using Shouldly;
using SimpleSign.Core.Extensions;
using SimpleSign.Core.Signing;
using SimpleSign.PAdES;
using SimpleSign.PAdES.Envelope;
using SimpleSign.TestHelpers;

namespace SimpleSign.Brazil.IcpBrasil.Tests;

/// <summary>An envelope whose signer is named by CPF and signs at an ICP-Brasil level.</summary>
[Trait("Category", "Unit")]
public sealed class IcpBrasilEnvelopeLevelsTests
{
    private const string Cpf = "52998224725";

    private static Task<byte[]> Prepare(EnvelopeLevel level) =>
        PdfEnvelope.Prepare(TestPdfFactory.CreateMinimalPdfWithPage())
            .AddSigner(new EnvelopeSigner
            {
                Name = "Fulano",
                Identifiers = [new EnvelopeIdentifier(SignerIdentifierTypes.Cpf, "529.982.247-25")],
                Role = "Diretor",
                Level = level,
                Placement = new EnvelopePlacement(1, 72, 72, 200, 50),
            })
            .PrepareAsync();

    [Fact]
    public async Task AdRb_CpfInTheCertificateAndPbadPolicy_SignsAndClaimsTheRole()
    {
        using var certificate = Signer(Cpf);

        byte[] signed = await PadesSigner.Document(await Prepare(IcpBrasilEnvelopeLevels.AdRb)).WithCertificate(certificate)
            .WithCountryExtension(new IcpBrasilExtension())
            .WithIcpBrasilPolicy(IcpBrasilPolicy.AdRb)
            .WithEnvelopeField("SimpleSign_1")
            .SignAsync();

        var field = PdfEnvelopeReader.Read(signed)!.Fields.Single();
        field.IsSigned.ShouldBeTrue();
        field.ClaimedRoles.ShouldBe(["Diretor"]);
        System.Text.Encoding.Latin1.GetString(signed).ShouldContain("/SubFilter /PBAD.PAdES");
    }

    [Fact]
    public async Task AdRb_WithoutThePbadPolicy_RefusesLevelNotMet()
    {
        using var certificate = Signer(Cpf);

        var ex = await Should.ThrowAsync<SigningException>(PadesSigner.Document(await Prepare(IcpBrasilEnvelopeLevels.AdRb))
            .WithCertificate(certificate).WithCountryExtension(new IcpBrasilExtension()).WithEnvelopeField("SimpleSign_1").SignAsync());

        ex.Reason.ShouldBe(SigningErrorReason.LevelNotMet);
    }

    [Fact]
    public async Task AdRt_WithoutATimestamp_RefusesTimestampRequired()
    {
        using var certificate = Signer(Cpf);

        var ex = await Should.ThrowAsync<SigningException>(PadesSigner.Document(await Prepare(IcpBrasilEnvelopeLevels.AdRt))
            .WithCertificate(certificate).WithCountryExtension(new IcpBrasilExtension())
            .WithIcpBrasilPolicy(IcpBrasilPolicy.AdRb).WithEnvelopeField("SimpleSign_1").SignAsync());

        ex.Reason.ShouldBe(SigningErrorReason.TimestampRequired);
    }

    [Fact]
    public async Task CheckSigner_AnotherCpf_IsAMismatch()
    {
        using var certificate = Signer("11144477735");

        var check = PdfEnvelope.CheckSigner(await Prepare(IcpBrasilEnvelopeLevels.AdRb), "SimpleSign_1", certificate, IcpBrasilProfile.Create());

        check.Reason.ShouldBe(SigningErrorReason.UnexpectedSigner);
        check.Identifiers.Single().Match.ShouldBe(EnvelopeIdentifierMatch.Mismatch);
    }

    [Fact]
    public async Task CheckSigner_WithoutTheIcpBrasilReader_IsNotVerifiable()
    {
        using var certificate = Signer(Cpf);

        var check = PdfEnvelope.CheckSigner(await Prepare(IcpBrasilEnvelopeLevels.AdRb), "SimpleSign_1", certificate);

        check.Identifiers.Single().Match.ShouldBe(EnvelopeIdentifierMatch.NotVerifiable);
    }

    /// <summary>A certificate that signs, with the CPF in its SubjectAltName (2.16.76.1.3.1).</summary>
    private static X509Certificate2 Signer(string cpf) =>
        TestCertificateFactory.CreateSelfSignedCert("CN=FULANO DE TAL", SanCertificates.OtherNames(("2.16.76.1.3.1", "01011980" + cpf + "00000000000")));

    [Theory]
    [InlineData("icp-ad-rb", true)]
    [InlineData("icp-ad-rt", true)]
    [InlineData("icp-ad-ra", false)]
    public void FromId_KnownIds_GiveTheLevel(string id, bool known) =>
        (IcpBrasilEnvelopeLevels.FromId(id) is not null).ShouldBe(known);
}
