using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using Shouldly;
using SimpleSign.TestHelpers;
using SimpleSign.XAdES;
using Spectre.Console;

namespace SimpleSign.Cli.Tests;

/// <summary><c>simplesign xmldsig sign|validate</c> and the XML-DSig session of <c>deferred complete</c>.</summary>
[Collection(CliConsoleCollection.Name)]
[Trait("Category", "Unit")]
public sealed class XmlDsigCommandTests : IDisposable
{
    private const string Password = "test";
    private const string Batch = "<lote xmlns=\"urn:test\"><doc Id=\"D1\"><v>1</v></doc><doc Id=\"D2\"><v>2</v></doc></lote>";
    private readonly string _tempDir = Directory.CreateTempSubdirectory("simplesign-xmldsig-").FullName;
    private readonly X509Certificate2 _cert = TestCertificateFactory.CreateSelfSignedCert();
    private readonly string _pfxPath;
    private readonly string _cerPath;

    public XmlDsigCommandTests()
    {
        _pfxPath = Path.Combine(_tempDir, "cert.pfx");
        _cerPath = Path.Combine(_tempDir, "cert.cer");
        File.WriteAllBytes(_pfxPath, _cert.Export(X509ContentType.Pfx, Password));
        File.WriteAllBytes(_cerPath, _cert.Export(X509ContentType.Cert));
    }

    public void Dispose()
    {
        _cert.Dispose();
        try
        {
            Directory.Delete(_tempDir, recursive: true);
        }
        catch (IOException)
        {
        }
    }

    private string Write(string name, string xml)
    {
        string path = Path.Combine(_tempDir, name);
        File.WriteAllText(path, xml);
        return path;
    }

    [Fact]
    public async Task Sign_WholeDocument_ValidatesWithTheCommand()
    {
        string input = Write("doc.xml", "<doc><v>1</v></doc>");

        var (exit, text) = await RunAsync("xmldsig", "sign", input, "--cert", _pfxPath, "--password", Password, "--json");

        exit.ShouldBe(0, text);
        text.ShouldContain("\"format\": \"xmldsig\"");
        var (validateExit, json) = await RunAsync("xmldsig", "validate", input + ".signed.xml", "--json");
        validateExit.ShouldBe(0, json);
        using var doc = JsonDocument.Parse(json);
        doc.RootElement.GetProperty("signatures")[0].GetProperty("referenceUri").GetString().ShouldBeEmpty();
    }

    [Fact]
    public async Task Sign_AllElementsOfABatch_SignsEachOnce()
    {
        string input = Write("batch.xml", Batch);
        string output = Path.Combine(_tempDir, "batch-signed.xml");

        var (exit, text) = await RunAsync("xmldsig", "sign", input, "--element", "doc", "--all", "--cert", _pfxPath, "--password", Password, "--output", output);

        exit.ShouldBe(0, text);
        var result = XmlDsigValidator.VerifySignatures(await File.ReadAllBytesAsync(output));
        result.Signatures.Select(s => s.ReferenceUri).ShouldBe(["#D1", "#D2"]);
        result.IsValid.ShouldBeTrue();
    }

    [Fact]
    public async Task Sign_Sha1UnderTheDefaultPolicy_IsRefusedWithItsReason()
    {
        string input = Write("sha1.xml", Batch);

        var (exit, text) = await RunAsync("xmldsig", "sign", input, "--element", "doc", "--id", "D1", "--hash", "SHA1",
            "--cert", _pfxPath, "--password", Password, "--json");

        exit.ShouldNotBe(0);
        text.ShouldContain("AlgorithmNotPermitted");
    }

    [Fact]
    public async Task Sign_PrepareAndDeferredComplete_WritesAValidSignature()
    {
        string input = Write("prepare.xml", Batch);
        string key = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));

        var (prepareExit, prepareOutput) = await RunAsync("xmldsig", "sign", input, "--element", "doc", "--id", "D2",
            "--cert", _cerPath, "--prepare", "--session-key", key, "--json");
        prepareExit.ShouldBe(0, prepareOutput);
        prepareOutput.ShouldContain("\"format\": \"xmldsig\"");
        byte[] toSign = await File.ReadAllBytesAsync(input + ".tbs");
        using (var rsa = _cert.GetRSAPrivateKey()!)
        {
            await File.WriteAllBytesAsync(input + ".sig", rsa.SignData(toSign, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
        }

        string signed = Path.Combine(_tempDir, "prepared-signed.xml");
        var (completeExit, completeOutput) = await RunAsync("deferred", "complete", input + ".session", "--session-key", key,
            "--signature", input + ".sig", "--output", signed);

        completeExit.ShouldBe(0, completeOutput);
        var result = XmlDsigValidator.VerifySignatures(await File.ReadAllBytesAsync(signed));
        result.Signatures.ShouldHaveSingleItem().ReferenceUri.ShouldBe("#D2");
        result.IsValid.ShouldBeTrue();
    }

    [Theory]
    [InlineData("--id-attribute", "id")]
    [InlineData("--placement", "middle")]
    [InlineData("--hash", "MD5")]
    public async Task Sign_InvalidOption_IsRefused(string option, string value)
    {
        string input = Write($"invalid-{option.TrimStart('-')}.xml", Batch);

        var (exit, _) = await RunAsync("xmldsig", "sign", input, option, value, "--cert", _pfxPath, "--password", Password);

        exit.ShouldNotBe(0);
    }

    [Fact]
    public async Task Validate_Changed_Fails()
    {
        string input = Write("changed.xml", "<doc><v>1</v></doc>");
        (await RunAsync("xmldsig", "sign", input, "--cert", _pfxPath, "--password", Password)).Exit.ShouldBe(0);
        string signedPath = input + ".signed.xml";
        await File.WriteAllTextAsync(signedPath, (await File.ReadAllTextAsync(signedPath)).Replace("<v>1</v>", "<v>2</v>", StringComparison.Ordinal));

        var (exit, text) = await RunAsync("xmldsig", "validate", signedPath);

        exit.ShouldBe(1, text);
        text.ShouldContain("The digest does not match");
    }

    private static async Task<(int Exit, string Output)> RunAsync(params string[] args)
    {
        var app = Program.CreateApp();

        IAnsiConsole originalAnsi = AnsiConsole.Console;
        TextWriter originalOut = Console.Out;
        using var ansiText = new StringWriter();
        using var stdout = new StringWriter();
        IAnsiConsole console = AnsiConsole.Create(new AnsiConsoleSettings
        {
            Ansi = AnsiSupport.No,
            ColorSystem = ColorSystemSupport.NoColors,
            Interactive = InteractionSupport.No,
            Out = new AnsiConsoleOutput(ansiText),
        });
        console.Profile.Width = 240;
        AnsiConsole.Console = console;
        Console.SetOut(stdout);
        try
        {
            int exit = await Program.RunWithAsync(app, args);
            return (exit, stdout.ToString() + ansiText);
        }
        finally
        {
            AnsiConsole.Console = originalAnsi;
            Console.SetOut(originalOut);
        }
    }
}
