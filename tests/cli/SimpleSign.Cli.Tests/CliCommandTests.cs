using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using Shouldly;
using SimpleSign.Brasil;
using SimpleSign.CAdES;
using SimpleSign.PAdES.DependencyInjection;
using SimpleSign.TestHelpers;
using SimpleSign.XAdES;
using Spectre.Console;
using Spectre.Console.Cli;

namespace SimpleSign.Cli.Tests;

/// <summary>Serializes tests that replace the process-wide console (AnsiConsole.Console, Console.Out).</summary>
[CollectionDefinition(Name, DisableParallelization = true)]
public sealed class CliConsoleCollection
{
    /// <summary>Collection name.</summary>
    public const string Name = "CLI console";
}

/// <summary>
/// End-to-end tests of CLI commands through the real command pipeline, asserting on exit codes,
/// JSON output and written files (validate, validate-dir, inspect, html-to-pdf, explain, cades).
/// </summary>
[Collection(CliConsoleCollection.Name)]
public sealed class CliCommandTests : IDisposable
{
    private const string Password = "test";
    private readonly string _tempDir = Path.Combine(Path.GetTempPath(), $"simplesign-cli-{Guid.NewGuid():N}");
    private readonly X509Certificate2 _cert = TestCertificateFactory.CreateSelfSignedCert();
    private readonly string _pfxPath;
    private readonly string _cerPath;

    public CliCommandTests()
    {
        Directory.CreateDirectory(_tempDir);
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

    // ── validate ────────────────────────────────────────────────────────

    [Fact]
    public async Task Validate_TrustedSignature_JsonReportsValid()
    {
        string signed = await SignAsync("valid.pdf");

        var (exit, output) = await RunAsync("validate", signed, "--no-revocation", "--trust", _cerPath, "--json");

        exit.ShouldBe(0);
        using var json = JsonDocument.Parse(output);
        json.RootElement.GetProperty("signatureCount").GetInt32().ShouldBe(1);
        var signature = json.RootElement.GetProperty("signatures")[0];
        signature.GetProperty("indication").GetString().ShouldBe("Valid");
        signature.GetProperty("integrity").GetBoolean().ShouldBeTrue();
    }

    [Fact]
    public async Task Validate_UntrustedSignature_IsIndeterminateWithExitCode1()
    {
        string signed = await SignAsync("untrusted.pdf");

        var (exit, output) = await RunAsync("validate", signed, "--no-revocation", "--json");

        exit.ShouldBe(1);
        using var json = JsonDocument.Parse(output);
        var signature = json.RootElement.GetProperty("signatures")[0];
        signature.GetProperty("indication").GetString().ShouldBe("Indeterminate");
        signature.GetProperty("integrity").GetBoolean().ShouldBeTrue();
    }

    [Fact]
    public async Task Validate_TamperedPdf_IsInvalid()
    {
        string signed = await SignAsync("tampered.pdf");
        byte[] bytes = await File.ReadAllBytesAsync(signed);
        int target = Encoding.Latin1.GetString(bytes).IndexOf("/Type /Catalog", StringComparison.Ordinal);
        bytes[target + 1] = (byte)'X'; // inside the first signed byte range
        await File.WriteAllBytesAsync(signed, bytes);

        var (exit, output) = await RunAsync("validate", signed, "--no-revocation", "--trust", _cerPath, "--json");

        exit.ShouldBe(1);
        using var json = JsonDocument.Parse(output);
        var signature = json.RootElement.GetProperty("signatures")[0];
        signature.GetProperty("indication").GetString().ShouldBe("Invalid");
        signature.GetProperty("integrity").GetBoolean().ShouldBeFalse();
    }

    [Fact]
    public async Task Validate_UnsignedPdf_JsonHasNoSignatures()
    {
        string path = WriteMinimalPdf("unsigned.pdf");

        var (exit, output) = await RunAsync("validate", path, "--no-revocation", "--json");

        exit.ShouldBe(0);
        using var json = JsonDocument.Parse(output);
        json.RootElement.GetProperty("signatureCount").GetInt32().ShouldBe(0);
    }

    [Fact]
    public async Task Validate_Simple_PrintsOneLinePerSignature()
    {
        string signed = await SignAsync("simple.pdf");

        var (exit, output) = await RunAsync("validate", signed, "--no-revocation", "--trust", _cerPath, "--simple");

        exit.ShouldBe(0);
        output.ShouldContain("Signature1");
    }

    [Fact]
    public async Task Validate_MissingTrustFile_ReturnsError()
    {
        string signed = await SignAsync("missing-trust.pdf");

        var (exit, _) = await RunAsync("validate", signed, "--trust", Path.Combine(_tempDir, "nope.cer"));

        exit.ShouldNotBe(0);
    }

    // ── validate-dir ────────────────────────────────────────────────────

    [Fact]
    public async Task ValidateDir_AllTrusted_ReturnsZeroAndSummarizes()
    {
        string dir = Directory.CreateDirectory(Path.Combine(_tempDir, "batch-ok")).FullName;
        await SignAsync(Path.Combine("batch-ok", "a.pdf"));
        await SignAsync(Path.Combine("batch-ok", "b.pdf"));

        var (exit, output) = await RunAsync("validate-dir", dir, "--no-revocation", "--trust", _cerPath);

        exit.ShouldBe(0);
        output.ShouldContain("a.pdf");
        output.ShouldContain("b.pdf");
        output.ShouldContain("Summary");
        output.ShouldContain("2 valid");
    }

    [Fact]
    public async Task ValidateDir_WithUntrustedSignature_ReturnsOne()
    {
        string dir = Directory.CreateDirectory(Path.Combine(_tempDir, "batch-mixed")).FullName;
        await SignAsync(Path.Combine("batch-mixed", "a.pdf"));

        var (exit, output) = await RunAsync("validate-dir", dir, "--no-revocation");

        exit.ShouldBe(1);
        output.ShouldContain("1 indeterminate");
    }

    [Fact]
    public async Task ValidateDir_NoMatchingFiles_ReturnsZero()
    {
        string dir = Directory.CreateDirectory(Path.Combine(_tempDir, "empty")).FullName;

        var (exit, output) = await RunAsync("validate-dir", dir);

        exit.ShouldBe(0);
        output.ShouldContain("No files matching");
    }

    [Fact]
    public async Task ValidateDir_MissingDirectory_ReturnsError()
    {
        var (exit, _) = await RunAsync("validate-dir", Path.Combine(_tempDir, "does-not-exist"));

        exit.ShouldNotBe(0);
    }

    // ── inspect ─────────────────────────────────────────────────────────

    [Fact]
    public async Task Inspect_Json_DescribesTheSignature()
    {
        string signed = await SignAsync("inspect.pdf");

        var (exit, output) = await RunAsync("inspect", signed, "--json");

        exit.ShouldBe(0);
        using var json = JsonDocument.Parse(output);
        json.RootElement.GetProperty("document").GetProperty("signatureCount").GetInt32().ShouldBe(1);
        var signature = json.RootElement.GetProperty("signatures")[0];
        signature.GetProperty("fieldName").GetString().ShouldBe("Signature1");
        signature.GetProperty("isDocumentTimestamp").GetBoolean().ShouldBeFalse();
    }

    [Fact]
    public async Task Inspect_Structure_PrintsTheObjectTree()
    {
        string signed = await SignAsync("structure.pdf");

        var (exit, output) = await RunAsync("inspect", signed, "--structure");

        exit.ShouldBe(0);
        output.ShouldContain("ByteRange");
        output.ShouldContain("Contents");
    }

    // ── html-to-pdf ─────────────────────────────────────────────────────

    [Fact]
    public async Task HtmlToPdf_WritesPdfWithTitleAndPdfA()
    {
        string html = Path.Combine(_tempDir, "page.html");
        await File.WriteAllTextAsync(html, "<h1>Relatório</h1><p>Olá, mundo.</p>");
        string output = Path.Combine(_tempDir, "page.pdf");

        string font = FindRepositoryFile("src", "SimpleSign.PAdES", "Signing", "LiberationSans-subset.ttf");

        var (exit, log) = await RunAsync(
            "html-to-pdf", html, "-o", output, "--font", $"Liberation Sans={font}", "--css", WriteCss("body { font-family: 'Liberation Sans'; }"),
            "--title", "Relatório anual", "--footer", "{page}/{pages}", "--pdfa");

        exit.ShouldBe(0, log);
        byte[] pdf = await File.ReadAllBytesAsync(output);
        string text = Encoding.Latin1.GetString(pdf);
        text.ShouldStartWith("%PDF-");
        text.ShouldContain("/Title");
        text.ShouldContain("pdfaid:part");
    }

    [Fact]
    public async Task HtmlToPdf_MissingInput_ReturnsError()
    {
        var (exit, _) = await RunAsync("html-to-pdf", Path.Combine(_tempDir, "missing.html"), "-o", Path.Combine(_tempDir, "x.pdf"));

        exit.ShouldNotBe(0);
    }

    // ── explain ─────────────────────────────────────────────────────────

    [Fact]
    public async Task Explain_KnownTerm_PrintsDefinition()
    {
        var (exit, output) = await RunAsync("explain", "ByteRange");

        exit.ShouldBe(0);
        output.ShouldContain("ByteRange");
    }

    [Fact]
    public async Task Explain_NoTerm_PrintsGlossary()
    {
        var (exit, output) = await RunAsync("explain");

        exit.ShouldBe(0);
        output.ShouldContain("Glossary");
    }

    // ── cades ───────────────────────────────────────────────────────────

    [Fact]
    public async Task CadesSignThenValidate_TrustedSignature_IsValid()
    {
        string data = Path.Combine(_tempDir, "data.txt");
        await File.WriteAllTextAsync(data, "contrato assinado");
        string signature = Path.Combine(_tempDir, "data.p7s");

        var (signExit, _) = await RunAsync("cades", "sign", data, "--cert", _pfxPath, "--password", Password, "-o", signature);
        signExit.ShouldBe(0);
        File.Exists(signature).ShouldBeTrue();

        var (exit, output) = await RunAsync("cades", "validate", signature, "--data", data, "--trust", _cerPath, "--json");

        exit.ShouldBe(0);
        using var json = JsonDocument.Parse(output);
        json.RootElement.GetProperty("isValid").GetBoolean().ShouldBeTrue();
        json.RootElement.GetProperty("isIntegrityValid").GetBoolean().ShouldBeTrue();
    }

    [Fact]
    public async Task CadesValidate_ModifiedData_IsInvalid()
    {
        string data = Path.Combine(_tempDir, "data.txt");
        await File.WriteAllTextAsync(data, "original");
        string signature = Path.Combine(_tempDir, "data.p7s");
        (await RunAsync("cades", "sign", data, "--cert", _pfxPath, "--password", Password, "-o", signature)).Exit.ShouldBe(0);
        await File.WriteAllTextAsync(data, "changed");

        var (exit, output) = await RunAsync("cades", "validate", signature, "--data", data, "--trust", _cerPath, "--json");

        exit.ShouldBe(1);
        using var json = JsonDocument.Parse(output);
        json.RootElement.GetProperty("isValid").GetBoolean().ShouldBeFalse();
        json.RootElement.GetProperty("isIntegrityValid").GetBoolean().ShouldBeFalse();
    }

    // ── xades ───────────────────────────────────────────────────────────

    [Fact]
    public async Task XadesValidate_DetachedWithData_IsValid()
    {
        string data = Path.Combine(_tempDir, "data.xml");
        await File.WriteAllTextAsync(data, "<?xml version=\"1.0\"?><doc>detached</doc>");
        string signature = Path.Combine(_tempDir, "data.sig.xml");
        (await RunAsync("xades", "sign", data, "--cert", _pfxPath, "--password", Password, "--output", signature,
            "--form", "detached", "--data-uri", "data.xml")).Exit.ShouldBe(0);

        var (exit, output) = await RunAsync("xades", "validate", signature, "--data", data, "--trust", _cerPath, "--json");

        exit.ShouldBe(0, output);
        using var json = JsonDocument.Parse(output);
        json.RootElement.GetProperty("isIntegrityValid").GetBoolean().ShouldBeTrue();
    }

    [Fact]
    public async Task XadesValidate_DetachedWithChangedData_IsInvalid()
    {
        string data = Path.Combine(_tempDir, "data.xml");
        await File.WriteAllTextAsync(data, "<?xml version=\"1.0\"?><doc>original</doc>");
        string signature = Path.Combine(_tempDir, "data.sig.xml");
        (await RunAsync("xades", "sign", data, "--cert", _pfxPath, "--password", Password, "--output", signature,
            "--form", "detached", "--data-uri", "data.xml")).Exit.ShouldBe(0);
        await File.WriteAllTextAsync(data, "<?xml version=\"1.0\"?><doc>changed</doc>");

        var (exit, output) = await RunAsync("xades", "validate", signature, "--data", data, "--trust", _cerPath, "--json");

        exit.ShouldBe(1);
        using var json = JsonDocument.Parse(output);
        json.RootElement.GetProperty("isIntegrityValid").GetBoolean().ShouldBeFalse();
    }

    [Fact]
    public async Task XadesValidate_MissingDataFile_ReturnsError()
    {
        string signature = Path.Combine(_tempDir, "any.xml");
        await File.WriteAllTextAsync(signature, "<x/>");

        var (exit, _) = await RunAsync("xades", "validate", signature, "--data", Path.Combine(_tempDir, "nope.xml"));

        exit.ShouldNotBe(0);
    }

    // ── helpers ─────────────────────────────────────────────────────────

    private async Task<string> SignAsync(string relativeOutput)
    {
        string input = WriteMinimalPdf(Path.GetFileNameWithoutExtension(relativeOutput) + "-input.pdf");
        string output = Path.Combine(_tempDir, relativeOutput);
        var (exit, text) = await RunAsync("sign", input, "--cert", _pfxPath, "--password", Password, "--output", output);
        exit.ShouldBe(0, text);
        return output;
    }

    private string WriteCss(string css)
    {
        string path = Path.Combine(_tempDir, "style.css");
        File.WriteAllText(path, css);
        return path;
    }

    private static string FindRepositoryFile(params string[] parts)
    {
        for (var dir = new DirectoryInfo(AppContext.BaseDirectory); dir is not null; dir = dir.Parent)
        {
            string candidate = Path.Combine([dir.FullName, .. parts]);
            if (File.Exists(candidate))
            {
                return candidate;
            }
        }

        throw new FileNotFoundException(Path.Combine(parts));
    }

    private string WriteMinimalPdf(string name)
    {
        string path = Path.Combine(_tempDir, name);
        File.WriteAllBytes(path, "%PDF-1.7\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n2 0 obj\n<< /Type /Pages /Kids [] /Count 0 >>\nendobj\nxref\n0 3\n0000000000 65535 f \n0000000009 00000 n \n0000000058 00000 n \ntrailer\n<< /Size 3 /Root 1 0 R >>\nstartxref\n110\n%%EOF"u8.ToArray());
        return path;
    }

    /// <summary>Runs the CLI and returns the exit code with everything written to both consoles.</summary>
    private static async Task<(int Exit, string Output)> RunAsync(params string[] args)
    {
        var services = new ServiceCollection();
        services.AddSimpleSign();
        services.AddSimpleSignBrasil();
        services.AddSimpleSignCades();
        services.AddSimpleSignXades();
        var app = new CommandApp(new SimpleSignServiceRegistry(services));
        Program.ConfigureApp(app);

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
