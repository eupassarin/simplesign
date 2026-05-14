using System.Diagnostics;
using FluentAssertions;
using SimpleSign.PAdES;
using SimpleSign.TestHelpers;
using Xunit;
using Xunit.Abstractions;

namespace SimpleSign.Interop.Tests;

/// <summary>
/// Unicode interop: signatures with international/unicode metadata (CJK, Arabic, emoji,
/// accented characters, binary data) must be handled correctly by external validators.
/// Tests are skipped when Docker or the required images are unavailable.
/// </summary>
[Trait("Category", "Interop")]
public sealed class UnicodeInteropTests(ITestOutputHelper output)
{
    [SkippableFact(DisplayName = "Unicode PAdES with CJK signer name validates under pyHanko")]
    public async Task PadesCjkSignerName_ValidatesWithPyHanko()
    {
        SkipIfDssUnavailable();

        var pdf = MinimalPdf();
        using var cert = TestCertificateFactory.CreateSelfSignedCert("CN=Unicode CJK Interop");

        var signed = await SimpleSigner.Document(pdf)
            .WithCertificate(cert)
            .WithMetadata("テスト署名者") // Japanese
            .SignAsync();

        var tmpDir = CreateTempDir();
        await File.WriteAllBytesAsync(Path.Combine(tmpDir, "signed.pdf"), signed);
        try
        {
            var (stdout, stderr, exitCode) = await DockerRun(
                $"-v {tmpDir}:/in simplesign-dss validate-pades /in/signed.pdf");
            output.WriteLine(stdout);
            if (!string.IsNullOrEmpty(stderr))
                output.WriteLine($"STDERR: {stderr}");

            exitCode.Should().Be(0);
            (stdout + stderr).Should().Contain("intact=True",
                because: "pyHanko should verify PAdES with CJK signer name as intact");
        }
        finally
        {
            Directory.Delete(tmpDir, recursive: true);
        }
    }

    [SkippableFact(DisplayName = "Unicode PAdES with Arabic reason validates under iText")]
    public async Task PadesArabicReason_ValidatesWithIText()
    {
        SkipIfITextUnavailable();

        var pdf = MinimalPdf();
        using var cert = TestCertificateFactory.CreateSelfSignedCert("CN=Unicode Arabic Interop");

        var signed = await SimpleSigner.Document(pdf)
            .WithCertificate(cert)
            .WithMetadata(reason: "سبب التوقيع")
            .SignAsync();

        var tmpDir = CreateTempDir();
        await File.WriteAllBytesAsync(Path.Combine(tmpDir, "signed.pdf"), signed);
        try
        {
            var (stdout, stderr, exitCode) = await DockerRun(
                $"-v {tmpDir}:/in simplesign-itext validate-pdf /in/signed.pdf");
            output.WriteLine($"[arabic-reason] exit={exitCode}");
            output.WriteLine(stdout);
            if (!string.IsNullOrEmpty(stderr))
                output.WriteLine($"STDERR: {stderr}");

            exitCode.Should().Be(0, because: "iText should validate PAdES with Arabic reason");
            stdout.Should().Contain("RESULT: VALID");
        }
        finally
        {
            Directory.Delete(tmpDir, recursive: true);
        }
    }

    [SkippableFact(DisplayName = "Unicode PAdES with emoji location parsed by pdfbox")]
    public async Task PadesEmojiLocation_ParsedByPdfbox()
    {
        SkipIfPdfboxUnavailable();

        var pdf = MinimalPdf();
        using var cert = TestCertificateFactory.CreateSelfSignedCert("CN=Unicode Emoji Interop");

        var signed = await SimpleSigner.Document(pdf)
            .WithCertificate(cert)
            .WithMetadata(location: "📍 São Paulo")
            .SignAsync();

        var tmpDir = CreateTempDir();
        await File.WriteAllBytesAsync(Path.Combine(tmpDir, "signed.pdf"), signed);
        try
        {
            var (stdout, stderr, exitCode) = await DockerRun(
                $"-v {tmpDir}:/in simplesign-pdfbox verify-signatures /in/signed.pdf");
            output.WriteLine($"[emoji-location] exit={exitCode}");
            output.WriteLine(stdout);
            if (!string.IsNullOrEmpty(stderr))
                output.WriteLine($"STDERR: {stderr}");

            exitCode.Should().Be(0, because: "pdfbox should parse PAdES with emoji location");
            stdout.Should().NotContain("ERROR");
        }
        finally
        {
            Directory.Delete(tmpDir, recursive: true);
        }
    }

    [SkippableFact(DisplayName = "Unicode PAdES with accented chars validates under EU DSS")]
    public async Task PadesAccentedChars_ValidatesWithEuDss()
    {
        SkipIfEuDssUnavailable();

        var pdf = MinimalPdf();
        using var cert = TestCertificateFactory.CreateSelfSignedCert("CN=Unicode Accented Interop");

        var signed = await SimpleSigner.Document(pdf)
            .WithCertificate(cert)
            .WithMetadata("Ñoño María", "Ação de teste", "São José")
            .SignAsync();

        var tmpDir = CreateTempDir();
        await File.WriteAllBytesAsync(Path.Combine(tmpDir, "signed.pdf"), signed);
        try
        {
            var (stdout, stderr, exitCode) = await DockerRun(
                $"-v {tmpDir}:/in simplesign-eu-dss validate-pades /in/signed.pdf");
            output.WriteLine($"[accented-chars] exit={exitCode}");
            output.WriteLine(stdout);
            if (!string.IsNullOrEmpty(stderr))
                output.WriteLine($"STDERR: {stderr}");

            exitCode.Should().Be(0, because: "EU DSS should validate PAdES with accented characters");
            (stdout.Contains("TOTAL_PASSED") || stdout.Contains("INDETERMINATE")).Should().BeTrue(
                because: "EU DSS should report TOTAL_PASSED or INDETERMINATE for self-signed certs");
        }
        finally
        {
            Directory.Delete(tmpDir, recursive: true);
        }
    }

    private static void SkipIfDssUnavailable()
    {
        Skip.IfNot(DockerProbe.IsDockerAvailable(), "Docker is not available on this host.");
        Skip.IfNot(DockerProbe.ImageExists("simplesign-dss"),
            "Validator image not built. Run: docker build -t simplesign-dss interop/dss-validator");
    }

    private static void SkipIfITextUnavailable()
    {
        Skip.IfNot(DockerProbe.IsDockerAvailable(), "Docker is not available on this host.");
        Skip.IfNot(DockerProbe.ImageExists("simplesign-itext"),
            "iText image not built. Run: docker build -t simplesign-itext interop/itext");
    }

    private static void SkipIfPdfboxUnavailable()
    {
        Skip.IfNot(DockerProbe.IsDockerAvailable(), "Docker is not available on this host.");
        Skip.IfNot(DockerProbe.ImageExists("simplesign-pdfbox"),
            "pdfbox image not built. Run: docker build -t simplesign-pdfbox interop/pdfbox");
    }

    private static void SkipIfEuDssUnavailable()
    {
        Skip.IfNot(DockerProbe.IsDockerAvailable(), "Docker is not available on this host.");
        Skip.IfNot(DockerProbe.ImageExists("simplesign-eu-dss"),
            "EU DSS image not built. Run: docker build -t simplesign-eu-dss interop/eu-dss");
    }

    private static string CreateTempDir()
    {
        var dir = Path.Combine(Path.GetTempPath(), $"simplesign-interop-{Guid.NewGuid():N}");
        Directory.CreateDirectory(dir);
        return dir;
    }

    private static async Task<(string stdout, string stderr, int exitCode)> DockerRun(string args)
    {
        var psi = new ProcessStartInfo("docker", $"run --rm {args}")
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
        };
        using var proc = Process.Start(psi)!;
        string stdout = await proc.StandardOutput.ReadToEndAsync();
        string stderr = await proc.StandardError.ReadToEndAsync();
        await proc.WaitForExitAsync();
        return (stdout, stderr, proc.ExitCode);
    }

    private static byte[] MinimalPdf() =>
        "%PDF-1.7\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>\nendobj\nxref\n0 4\n0000000000 65535 f\r\n0000000009 00000 n\r\n0000000058 00000 n\r\n0000000115 00000 n\r\ntrailer\n<< /Size 4 /Root 1 0 R >>\nstartxref\n186\n%%EOF\n"u8.ToArray();
}
