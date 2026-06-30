using System.Security.Cryptography.X509Certificates;
using SimpleSign.TestHelpers;
using Shouldly;
using Spectre.Console;
using Spectre.Console.Cli;

namespace SimpleSign.Cli.Tests;

public sealed class XadesCommandPipelineTests : IDisposable
{
    private readonly string _tempDir;

    public XadesCommandPipelineTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), $"simplesign-xades-{Guid.NewGuid():N}");
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

    [Fact]
    public async Task Sign_WithSelfSignedCert_CreatesOutputFile()
    {
        var xmlPath = Path.Combine(_tempDir, "input.xml");
        File.WriteAllText(xmlPath, "<?xml version=\"1.0\"?><doc>hello</doc>");

        var certPath = Path.Combine(_tempDir, "cert.pfx");
        using (var cert = TestCertificateFactory.CreateSelfSignedCert("CN=CLI Test, O=Tests"))
        {
            File.WriteAllBytes(certPath, cert.Export(X509ContentType.Pfx, "test"));
        }

        var outputPath = Path.Combine(_tempDir, "signed.xml");

        using var capture = new ConsoleCapture();
        var app = new CommandApp();
        Program.ConfigureApp(app);
        var result = await Program.RunWithAsync(app, [
            "xades", "sign", xmlPath,
            "--cert", certPath,
            "--password", "test",
            "--output", outputPath
        ]);

        result.ShouldBe(0);
        File.Exists(outputPath).ShouldBeTrue();
        var bytes = await File.ReadAllBytesAsync(outputPath);
        bytes.Length.ShouldBeGreaterThan(0);
    }

    [Fact]
    public async Task Sign_WithInvalidLevel_ReturnsError()
    {
        var xmlPath = Path.Combine(_tempDir, "input.xml");
        File.WriteAllText(xmlPath, "<?xml version=\"1.0\"?><doc/>");

        var certPath = Path.Combine(_tempDir, "cert.pfx");
        using (var cert = TestCertificateFactory.CreateSelfSignedCert())
        {
            File.WriteAllBytes(certPath, cert.Export(X509ContentType.Pfx, "test"));
        }

        using var capture = new ConsoleCapture();
        var app = new CommandApp();
        Program.ConfigureApp(app);
        var result = await Program.RunWithAsync(app, [
            "xades", "sign", xmlPath,
            "--cert", certPath,
            "--password", "test",
            "--level", "bogus"
        ]);

        result.ShouldNotBe(0);
    }

    [Fact]
    public async Task Sign_WithInvalidHash_ReturnsError()
    {
        var xmlPath = Path.Combine(_tempDir, "input.xml");
        File.WriteAllText(xmlPath, "<?xml version=\"1.0\"?><doc/>");

        var certPath = Path.Combine(_tempDir, "cert.pfx");
        using (var cert = TestCertificateFactory.CreateSelfSignedCert())
        {
            File.WriteAllBytes(certPath, cert.Export(X509ContentType.Pfx, "test"));
        }

        using var capture = new ConsoleCapture();
        var app = new CommandApp();
        Program.ConfigureApp(app);
        var result = await Program.RunWithAsync(app, [
            "xades", "sign", xmlPath,
            "--cert", certPath,
            "--password", "test",
            "--hash", "MD5"
        ]);

        result.ShouldNotBe(0);
    }

    [Fact]
    public async Task Sign_WithInvalidForm_ReturnsError()
    {
        var xmlPath = Path.Combine(_tempDir, "input.xml");
        File.WriteAllText(xmlPath, "<?xml version=\"1.0\"?><doc/>");

        var certPath = Path.Combine(_tempDir, "cert.pfx");
        using (var cert = TestCertificateFactory.CreateSelfSignedCert())
        {
            File.WriteAllBytes(certPath, cert.Export(X509ContentType.Pfx, "test"));
        }

        using var capture = new ConsoleCapture();
        var app = new CommandApp();
        Program.ConfigureApp(app);
        var result = await Program.RunWithAsync(app, [
            "xades", "sign", xmlPath,
            "--cert", certPath,
            "--password", "test",
            "--form", "bogus"
        ]);

        result.ShouldNotBe(0);
    }

    [Fact]
    public async Task Sign_WithMissingInput_ReturnsError()
    {
        var missingPath = Path.Combine(_tempDir, "nonexistent.xml");

        using var capture = new ConsoleCapture();
        var app = new CommandApp();
        Program.ConfigureApp(app);
        var result = await Program.RunWithAsync(app, [
            "xades", "sign", missingPath
        ]);

        result.ShouldNotBe(0);
    }

    [Fact]
    public async Task Sign_ThenValidate_RoundTrip()
    {
        var xmlPath = Path.Combine(_tempDir, "input.xml");
        File.WriteAllText(xmlPath, "<?xml version=\"1.0\"?><doc>roundtrip</doc>");

        var certPath = Path.Combine(_tempDir, "cert.pfx");
        var trustPath = Path.Combine(_tempDir, "trust.cer");
        using (var cert = TestCertificateFactory.CreateSelfSignedCert("CN=RoundTrip, O=Tests"))
        {
            File.WriteAllBytes(certPath, cert.Export(X509ContentType.Pfx, "test"));
            File.WriteAllBytes(trustPath, cert.RawData);
        }

        var signedPath = Path.Combine(_tempDir, "signed.xml");

        var app = new CommandApp();
        Program.ConfigureApp(app);

        // Sign
        using (new ConsoleCapture())
        {
            var signResult = await Program.RunWithAsync(app, [
                "xades", "sign", xmlPath,
                "--cert", certPath,
                "--password", "test",
                "--output", signedPath
            ]);
            signResult.ShouldBe(0);
        }

        // Validate with trust anchor
        using var validateCapture = new ConsoleCapture();
        var validateResult = await Program.RunWithAsync(app, [
            "xades", "validate", signedPath,
            "--trust", trustPath
        ]);

        validateResult.ShouldBe(0);
    }

    [Fact]
    public async Task Sign_WithLevelB_T_ProducesTimestampedOutput()
    {
        var xmlPath = Path.Combine(_tempDir, "input.xml");
        File.WriteAllText(xmlPath, "<?xml version=\"1.0\"?><doc>bt</doc>");

        var certPath = Path.Combine(_tempDir, "cert.pfx");
        using (var cert = TestCertificateFactory.CreateSelfSignedCert())
        {
            File.WriteAllBytes(certPath, cert.Export(X509ContentType.Pfx, "test"));
        }

        var outputPath = Path.Combine(_tempDir, "signed.xml");

        using var capture = new ConsoleCapture();
        var app = new CommandApp();
        Program.ConfigureApp(app);
        var result = await Program.RunWithAsync(app, [
            "xades", "sign", xmlPath,
            "--cert", certPath,
            "--password", "test",
            "--output", outputPath,
            "--level", "basic"
        ]);

        result.ShouldBe(0);
        File.Exists(outputPath).ShouldBeTrue();
    }

    [Fact]
    public async Task Sign_WithSignerRole_IncludesInSignature()
    {
        var xmlPath = Path.Combine(_tempDir, "input.xml");
        File.WriteAllText(xmlPath, "<?xml version=\"1.0\"?><doc>role</doc>");

        var certPath = Path.Combine(_tempDir, "cert.pfx");
        using (var cert = TestCertificateFactory.CreateSelfSignedCert())
        {
            File.WriteAllBytes(certPath, cert.Export(X509ContentType.Pfx, "test"));
        }

        var outputPath = Path.Combine(_tempDir, "signed.xml");

        using var capture = new ConsoleCapture();
        var app = new CommandApp();
        Program.ConfigureApp(app);
        var result = await Program.RunWithAsync(app, [
            "xades", "sign", xmlPath,
            "--cert", certPath,
            "--password", "test",
            "--output", outputPath,
            "--signer-role", "Manager"
        ]);

        result.ShouldBe(0);
    }

    [Fact]
    public async Task Sign_WithCommitmentType_IncludesInSignature()
    {
        var xmlPath = Path.Combine(_tempDir, "input.xml");
        File.WriteAllText(xmlPath, "<?xml version=\"1.0\"?><doc>commit</doc>");

        var certPath = Path.Combine(_tempDir, "cert.pfx");
        using (var cert = TestCertificateFactory.CreateSelfSignedCert())
        {
            File.WriteAllBytes(certPath, cert.Export(X509ContentType.Pfx, "test"));
        }

        var outputPath = Path.Combine(_tempDir, "signed.xml");

        using var capture = new ConsoleCapture();
        var app = new CommandApp();
        Program.ConfigureApp(app);
        var result = await Program.RunWithAsync(app, [
            "xades", "sign", xmlPath,
            "--cert", certPath,
            "--password", "test",
            "--output", outputPath,
            "--commitment", "origin"
        ]);

        result.ShouldBe(0);
    }

    [Fact]
    public async Task Validate_NonExistentFile_ReturnsError()
    {
        var missingPath = Path.Combine(_tempDir, "nonexistent.xml");

        using var capture = new ConsoleCapture();
        var app = new CommandApp();
        Program.ConfigureApp(app);
        var result = await Program.RunWithAsync(app, [
            "xades", "validate", missingPath
        ]);

        result.ShouldNotBe(0);
    }

    [Fact]
    public async Task Sign_WithLevelAliases_AllSucceed()
    {
        var certPath = Path.Combine(_tempDir, "cert.pfx");
        using (var cert = TestCertificateFactory.CreateSelfSignedCert())
        {
            File.WriteAllBytes(certPath, cert.Export(X509ContentType.Pfx, "test"));
        }

        foreach (var alias in new[] { "basic", "timestamped", "longterm", "archive" })
        {
            var xmlPath = Path.Combine(_tempDir, $"input-{alias}.xml");
            File.WriteAllText(xmlPath, $"<?xml version=\"1.0\"?><doc>{alias}</doc>");
            var outputPath = Path.Combine(_tempDir, $"signed-{alias}.xml");

            using var capture = new ConsoleCapture();
            var app = new CommandApp();
            Program.ConfigureApp(app);
            var result = await Program.RunWithAsync(app, [
                "xades", "sign", xmlPath,
                "--cert", certPath,
                "--password", "test",
                "--output", outputPath,
                "--level", alias
            ]);

            result.ShouldBe(0, $"Level alias '{alias}' should succeed");
            File.Exists(outputPath).ShouldBeTrue($"Output for '{alias}' should exist");
        }
    }
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
