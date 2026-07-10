using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.DependencyInjection;
using SimpleSign.Brasil;
using SimpleSign.CAdES;
using SimpleSign.Core.Validation;
using SimpleSign.PAdES.DependencyInjection;
using SimpleSign.PAdES.Inspection;
using SimpleSign.PAdES.Validation;
using SimpleSign.TestHelpers;
using SimpleSign.XAdES;
using Shouldly;
using Spectre.Console;
using Spectre.Console.Cli;

namespace SimpleSign.Cli.Tests;

public sealed class CommandPipelineTests : IDisposable
{
    private readonly string _tempDir;

    public CommandPipelineTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), $"simplesign-cli-pipeline-{Guid.NewGuid():N}");
        Directory.CreateDirectory(_tempDir);
    }

    public void Dispose()
    {
        try
        {
            Directory.Delete(_tempDir, recursive: true);
        }
        catch
        {
        }
    }

    private static CommandApp CreateConfiguredApp()
    {
        var services = new ServiceCollection();
        services.AddSimpleSign();
        services.AddSimpleSignBrasil();
        services.AddSimpleSignCades();
        services.AddSimpleSignXades();
        var registry = new SimpleSignServiceRegistry(services);
        var app = new CommandApp(registry);
        Program.ConfigureApp(app);
        return app;
    }

    [Fact]
    public async Task Version_ReturnsZero()
    {
        using var capture = new ConsoleCapture();
        var app = CreateConfiguredApp();
        var result = await Program.RunWithAsync(app, ["version"]);
        result.ShouldBe(0);
    }

    [Fact]
    public async Task Extract_UnsignedPdf_ReturnsZero()
    {
        var pdfPath = Path.Combine(_tempDir, "unsigned.pdf");
        File.WriteAllBytes(pdfPath, CreateMinimalPdf());

        using var capture = new ConsoleCapture();
        var app = CreateConfiguredApp();
        var result = await Program.RunWithAsync(app, ["extract", pdfPath]);

        result.ShouldBe(0);
        Directory.GetFiles(_tempDir, "*.p7s").ShouldBeEmpty();
    }

    [Fact]
    public async Task Sign_SelfSignedCert_CreatesOutputFile()
    {
        var pdfPath = Path.Combine(_tempDir, "input.pdf");
        File.WriteAllBytes(pdfPath, CreateMinimalPdf());

        var certPath = Path.Combine(_tempDir, "cert.pfx");
        using (var cert = TestCertificateFactory.CreateSelfSignedCert())
        {
            File.WriteAllBytes(certPath, cert.Export(X509ContentType.Pfx, "test"));
        }

        var outputPath = Path.Combine(_tempDir, "signed.pdf");

        using var capture = new ConsoleCapture();
        var app = CreateConfiguredApp();
        var result = await Program.RunWithAsync(app, [
            "sign", pdfPath,
            "--cert", certPath,
            "--password", "test",
            "--output", outputPath
        ]);

        result.ShouldBe(0);
        File.Exists(outputPath).ShouldBeTrue();

        var pdfBytes = await File.ReadAllBytesAsync(outputPath);
        pdfBytes.Length.ShouldBeGreaterThan(0);
    }

    [Fact]
    public async Task SignThenInspect_SignedPdf_HasSignature()
    {
        var pdfPath = Path.Combine(_tempDir, "input.pdf");
        File.WriteAllBytes(pdfPath, CreateMinimalPdf());

        var certPath = Path.Combine(_tempDir, "cert.pfx");
        using (var cert = TestCertificateFactory.CreateSelfSignedCert())
        {
            File.WriteAllBytes(certPath, cert.Export(X509ContentType.Pfx, "test"));
        }

        var signedPath = Path.Combine(_tempDir, "signed.pdf");

        var app = CreateConfiguredApp();

        using (new ConsoleCapture())
        {
            var signResult = await Program.RunWithAsync(app, [
                "sign", pdfPath,
                "--cert", certPath,
                "--password", "test",
                "--output", signedPath
            ]);
            signResult.ShouldBe(0);
        }

        using var inspectCapture = new ConsoleCapture();
        var inspectResult = await Program.RunWithAsync(app, ["inspect", signedPath]);

        inspectResult.ShouldBe(0);
    }

    [Fact]
    public async Task Sign_NoCertOrThumbprint_ReturnsError()
    {
        var pdfPath = Path.Combine(_tempDir, "input.pdf");
        File.WriteAllBytes(pdfPath, CreateMinimalPdf());

        using var capture = new ConsoleCapture();
        var app = CreateConfiguredApp();
        var result = await Program.RunWithAsync(app, ["sign", pdfPath]);

        result.ShouldNotBe(0);
    }

    [Fact]
    public async Task Sign_InvalidSubFilter_ReturnsError()
    {
        var pdfPath = Path.Combine(_tempDir, "input.pdf");
        File.WriteAllBytes(pdfPath, CreateMinimalPdf());

        var certPath = Path.Combine(_tempDir, "cert.pfx");
        using (var cert = TestCertificateFactory.CreateSelfSignedCert())
        {
            File.WriteAllBytes(certPath, cert.Export(X509ContentType.Pfx, "test"));
        }

        using var capture = new ConsoleCapture();
        var app = CreateConfiguredApp();
        var result = await Program.RunWithAsync(app, [
            "sign", pdfPath,
            "--cert", certPath,
            "--password", "test",
            "--sub-filter", "bogus"
        ]);

        result.ShouldNotBe(0);
    }

    [Fact]
    public async Task Sign_InvalidSignatureAlgorithm_ReturnsError()
    {
        var pdfPath = Path.Combine(_tempDir, "input.pdf");
        File.WriteAllBytes(pdfPath, CreateMinimalPdf());

        var certPath = Path.Combine(_tempDir, "cert.pfx");
        using (var cert = TestCertificateFactory.CreateSelfSignedCert())
        {
            File.WriteAllBytes(certPath, cert.Export(X509ContentType.Pfx, "test"));
        }

        using var capture = new ConsoleCapture();
        var app = CreateConfiguredApp();
        var result = await Program.RunWithAsync(app, [
            "sign", pdfPath,
            "--cert", certPath,
            "--password", "test",
            "--signature-algorithm", "md5"
        ]);

        result.ShouldNotBe(0);
    }

    [Fact]
    public async Task Sign_FontSizeWithoutVisible_ReturnsError()
    {
        var pdfPath = Path.Combine(_tempDir, "input.pdf");
        File.WriteAllBytes(pdfPath, CreateMinimalPdf());

        var certPath = Path.Combine(_tempDir, "cert.pfx");
        using (var cert = TestCertificateFactory.CreateSelfSignedCert())
        {
            File.WriteAllBytes(certPath, cert.Export(X509ContentType.Pfx, "test"));
        }

        using var capture = new ConsoleCapture();
        var app = CreateConfiguredApp();
        var result = await Program.RunWithAsync(app, [
            "sign", pdfPath,
            "--cert", certPath,
            "--password", "test",
            "--font-size", "12"
        ]);

        result.ShouldNotBe(0);
    }

    [Fact]
    public async Task Sign_BrasilWithoutCpf_ReturnsError()
    {
        var pdfPath = Path.Combine(_tempDir, "input.pdf");
        File.WriteAllBytes(pdfPath, CreateMinimalPdf());

        var certPath = Path.Combine(_tempDir, "cert.pfx");
        using (var cert = TestCertificateFactory.CreateSelfSignedCert())
        {
            File.WriteAllBytes(certPath, cert.Export(X509ContentType.Pfx, "test"));
        }

        using var capture = new ConsoleCapture();
        var app = CreateConfiguredApp();
        var result = await Program.RunWithAsync(app, [
            "sign", pdfPath,
            "--cert", certPath,
            "--password", "test",
            "--brasil"
        ]);

        result.ShouldNotBe(0);
    }

    [Fact]
    public async Task Sign_WithSubFilterAdbePkcs7_SetsSubFilter()
    {
        var pdfPath = Path.Combine(_tempDir, "input.pdf");
        File.WriteAllBytes(pdfPath, CreateMinimalPdf());

        var certPath = Path.Combine(_tempDir, "cert.pfx");
        using (var cert = TestCertificateFactory.CreateSelfSignedCert())
        {
            File.WriteAllBytes(certPath, cert.Export(X509ContentType.Pfx, "test"));
        }

        var outputPath = Path.Combine(_tempDir, "signed.pdf");

        using var capture = new ConsoleCapture();
        var app = CreateConfiguredApp();
        var signResult = await Program.RunWithAsync(app, [
            "sign", pdfPath,
            "--cert", certPath,
            "--password", "test",
            "--output", outputPath,
            "--sub-filter", "adbe-pkcs7-detached"
        ]);

        signResult.ShouldBe(0);

        await using var stream = File.OpenRead(outputPath);
        var info = await PdfSignatureInspector.InspectAsync(stream);
        info.Signatures.ShouldNotBeEmpty();
        info.Signatures[0].SubFilter.ShouldBe("adbe.pkcs7.detached");
    }

    [Fact]
    public async Task Validate_UnsignedPdf_ReturnsZero()
    {
        var pdfPath = Path.Combine(_tempDir, "unsigned.pdf");
        File.WriteAllBytes(pdfPath, CreateMinimalPdf());

        using var capture = new ConsoleCapture();
        var app = CreateConfiguredApp();
        var result = await Program.RunWithAsync(app, ["validate", pdfPath]);

        result.ShouldBe(0);
    }

    [Fact]
    public async Task Validate_SignedPdf_ReturnsZero()
    {
        var pdfPath = Path.Combine(_tempDir, "input.pdf");
        File.WriteAllBytes(pdfPath, CreateMinimalPdf());

        var certPath = Path.Combine(_tempDir, "cert.pfx");
        using var trustedCert = TestCertificateFactory.CreateSelfSignedCert();
        File.WriteAllBytes(certPath, trustedCert.Export(X509ContentType.Pfx, "test"));

        var signedPath = Path.Combine(_tempDir, "signed.pdf");

        var app = CreateConfiguredApp();

        using (new ConsoleCapture())
        {
            var signResult = await Program.RunWithAsync(app, [
                "sign", pdfPath,
                "--cert", certPath,
                "--password", "test",
                "--output", signedPath
            ]);
            signResult.ShouldBe(0);
        }

        // Validate programmatically with the test cert trusted.
        // CLI validate uses ICP-Brasil trust anchors and cannot trust self-signed certs.
        var validator = new PdfSignatureValidator(new ValidationOptions
        {
            CheckRevocation = false,
            TrustedRoots = [trustedCert]
        });
        using var stream = File.OpenRead(signedPath);
        var results = await validator.ValidateAsync(stream);
        results.Count.ShouldBe(1);
        results[0].IsIntegrityValid.ShouldBeTrue();
        results[0].IsSignatureValid.ShouldBeTrue();
    }

    [Fact]
    public async Task Validate_NonExistentFile_ReturnsError()
    {
        var missingPath = Path.Combine(_tempDir, "nonexistent.pdf");

        using var capture = new ConsoleCapture();
        var app = CreateConfiguredApp();
        var result = await Program.RunWithAsync(app, ["validate", missingPath]);

        result.ShouldNotBe(0);
    }

    private static byte[] CreateMinimalPdf() =>
        "%PDF-1.7\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n2 0 obj\n<< /Type /Pages /Kids [] /Count 0 >>\nendobj\nxref\n0 3\n0000000000 65535 f \n0000000009 00000 n \n0000000058 00000 n \ntrailer\n<< /Size 3 /Root 1 0 R >>\nstartxref\n110\n%%EOF"u8.ToArray();
}

file sealed class ConsoleCapture : IDisposable
{
    private readonly IAnsiConsole _original;

    public ConsoleCapture()
    {
        _original = AnsiConsole.Console;
        AnsiConsole.Console = new Recorder(_original);
    }

    public void Dispose() =>
        AnsiConsole.Console = _original;
}
