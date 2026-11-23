using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Shouldly;
using SimpleSign.Cli.Commands;
using SimpleSign.PAdES.Envelope;
using SimpleSign.TestHelpers;
using Spectre.Console;
using Spectre.Console.Cli;

namespace SimpleSign.Cli.Tests;

[Collection(CliConsoleCollection.Name)]
[Trait("Category", "Unit")]
public sealed class EnvelopeCommandsTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), $"simplesign-cli-envelope-{Guid.NewGuid():N}");

    public EnvelopeCommandsTests()
    {
        Directory.CreateDirectory(_dir);
    }

    public void Dispose()
    {
        try
        {
            Directory.Delete(_dir, recursive: true);
        }
        catch (IOException)
        {
        }
    }

    [Fact]
    public async Task PrepareStatusSignValidate_TwoSigners_TheEnvelopeIsComplete()
    {
        string pdf = Path.Combine(_dir, "contract.pdf");
        File.WriteAllBytes(pdf, TestPdfFactory.CreateMinimalPdfWithPage());
        using var first = TestCertificateFactory.CreateSelfSignedCert("CN=Ana");
        using var second = TestCertificateFactory.CreateSelfSignedCert("CN=Bruno");
        string firstPfx = Pfx(first, "ana.pfx");
        string secondPfx = Pfx(second, "bruno.pfx");
        string prepared = Path.Combine(_dir, "prepared.pdf");

        (await Run("envelope", "prepare", pdf, "-o", prepared, "--certify", "form-filling",
            "--signer", $"name=Ana;id=CERT-SHA256:{Sha256(first)};role=Diretora;page=1;rect=72,72,200,50",
            "--signer", $"name=Bruno;id=CERT-SHA256:{Sha256(second)};page=1;rect=72,200,200,50")).Code.ShouldBe(0);

        var status = await Run("envelope", "status", prepared);
        status.Code.ShouldBe(0);
        status.Output.ShouldContain("Next: SimpleSign_1 (Ana)");

        string signedOnce = Path.Combine(_dir, "signed1.pdf");
        string signed = Path.Combine(_dir, "signed2.pdf");
        (await Run("sign", prepared, "--cert", firstPfx, "--password", "p", "--output", signedOnce,
            "--envelope-field", "SimpleSign_1", "--certify", "form-filling")).Code.ShouldBe(0);
        var wrongTurn = await Run("sign", prepared, "--cert", secondPfx, "--password", "p", "--output", Path.Combine(_dir, "x.pdf"),
            "--envelope-field", "SimpleSign_2");
        wrongTurn.Code.ShouldNotBe(0);
        (await Run("sign", signedOnce, "--cert", secondPfx, "--password", "p", "--output", signed,
            "--envelope-field", "SimpleSign_2")).Code.ShouldBe(0);

        PdfEnvelopeReader.Read(File.ReadAllBytes(signed))!.Status.ShouldBe(EnvelopeStatus.Completed);
        string trust = Directory.CreateDirectory(Path.Combine(_dir, "trust")).FullName;
        File.WriteAllBytes(Path.Combine(trust, "ana.cer"), first.Export(X509ContentType.Cert));
        File.WriteAllBytes(Path.Combine(trust, "bruno.cer"), second.Export(X509ContentType.Cert));
        var validate = await Run("validate", signed, "--envelope", "--trust-dir", trust, "--no-revocation", "--json");
        validate.Output.ShouldContain("\"isComplete\": true");
        validate.Code.ShouldBe(0, validate.Output);
    }

    [Fact]
    public async Task Prepare_SignerWithoutRect_Fails()
    {
        string pdf = Path.Combine(_dir, "contract.pdf");
        File.WriteAllBytes(pdf, TestPdfFactory.CreateMinimalPdfWithPage());

        var result = await Run("envelope", "prepare", pdf, "--signer", "name=Ana");

        result.Code.ShouldBe(1);
        result.Output.ShouldContain("rect");
    }

    [Fact]
    public async Task Status_NoEnvelope_ReturnsOne()
    {
        string pdf = Path.Combine(_dir, "plain.pdf");
        File.WriteAllBytes(pdf, TestPdfFactory.CreateMinimalPdfWithPage());

        (await Run("envelope", "status", pdf)).Code.ShouldBe(1);
    }

    [Fact]
    public void Parse_EveryKey_BuildsTheSigner()
    {
        var signer = EnvelopeSignerSpec.Parse(
            "name=Maria Silva; id=cpf:529.982.247-25; also=responsible-cpf; id=EMAIL:m@x.com; role=Diretora; email=m@x.com; reason=Aprovo; level=pades-t; page=2; rect=10,20,30.5,40; external");

        signer.Name.ShouldBe("Maria Silva");
        signer.Identifiers.Select(i => i.Type).ShouldBe(["CPF", "EMAIL"]);
        signer.Identifiers[0].AlsoAccept.ShouldBe(["RESPONSIBLE-CPF"]);
        signer.Role.ShouldBe("Diretora");
        signer.Reasons.ShouldBe(["Aprovo"]);
        signer.Level.Id.ShouldBe("pades-t");
        signer.External.ShouldBeTrue();
        signer.Placement.ShouldBe(new EnvelopePlacement(2, 10, 20, 30.5f, 40));
    }

    [Theory]
    [InlineData("rect=1,2,3,4")]
    [InlineData("name=A")]
    [InlineData("name=A;rect=1,2,3")]
    [InlineData("name=A;rect=1,2,3,4;level=nope")]
    [InlineData("name=A;rect=1,2,3,4;id=CPF")]
    [InlineData("name=A;rect=1,2,3,4;also=CPF")]
    [InlineData("name=A;rect=1,2,3,4;color=red")]
    public void Parse_Wrong_Throws(string spec) => Should.Throw<FormatException>(() => EnvelopeSignerSpec.Parse(spec));

    private string Pfx(X509Certificate2 certificate, string name)
    {
        string path = Path.Combine(_dir, name);
        File.WriteAllBytes(path, certificate.Export(X509ContentType.Pfx, "p"));
        return path;
    }

    private static string Sha256(X509Certificate2 certificate) => Convert.ToHexString(SHA256.HashData(certificate.RawData));

    private static async Task<(int Code, string Output)> Run(params string[] args)
    {
        var original = AnsiConsole.Console;
        var recorder = new Recorder(AnsiConsole.Create(new AnsiConsoleSettings { Out = new AnsiConsoleOutput(TextWriter.Null) }));
        AnsiConsole.Console = recorder;
        var writer = new StringWriter();
        var originalOut = Console.Out;
        Console.SetOut(writer);
        try
        {
            CommandApp app = Program.CreateApp();
            int code = await Program.RunWithAsync(app, args);
            return (code, recorder.ExportText() + writer);
        }
        finally
        {
            AnsiConsole.Console = original;
            Console.SetOut(originalOut);
        }
    }
}
