using System.Diagnostics;
using System.Security.Cryptography;
using Shouldly;
using SimpleSign.PAdES;
using SimpleSign.TestHelpers;
using Xunit;
using Xunit.Abstractions;

namespace SimpleSign.Interop.Tests;

/// <summary>
/// Cross-validator tests: PAdES signatures produced with different algorithms (SHA-384, SHA-512,
/// ECDSA P-256, ECDSA P-384) are validated by multiple external tools (iText, EU DSS, pyHanko).
/// Tests are skipped when Docker or the required images are unavailable.
/// </summary>
[Trait("Category", "Interop")]
public sealed class PadesCrossValidatorTests(ITestOutputHelper output)
{
    // ──────────────────────────────────────────────────────────────────────
    // iText validations
    // ──────────────────────────────────────────────────────────────────────

    [SkippableFact(DisplayName = "Cross: PAdES SHA-384 → iText validates")]
    public async Task PadesSha384_ValidatesWithIText()
    {
        SkipIfDockerUnavailable("simplesign-itext");
        var pdf = MinimalPdf();
        using var cert = TestCertificateFactory.CreateSelfSignedCert("CN=PAdES SHA384 iText Cross");
        var signed = await SimpleSigner.Document(pdf)
            .WithCertificate(cert)
            .WithHashAlgorithm(HashAlgorithmName.SHA384)
            .SignAsync();
        await ValidateWithIText(signed, "sha384");
    }

    [SkippableFact(DisplayName = "Cross: PAdES SHA-512 → iText validates")]
    public async Task PadesSha512_ValidatesWithIText()
    {
        SkipIfDockerUnavailable("simplesign-itext");
        var pdf = MinimalPdf();
        using var cert = TestCertificateFactory.CreateSelfSignedCert("CN=PAdES SHA512 iText Cross");
        var signed = await SimpleSigner.Document(pdf)
            .WithCertificate(cert)
            .WithHashAlgorithm(HashAlgorithmName.SHA512)
            .SignAsync();
        await ValidateWithIText(signed, "sha512");
    }

    [SkippableFact(DisplayName = "Cross: PAdES ECDSA P-256 → iText validates")]
    public async Task PadesEcdsaP256_ValidatesWithIText()
    {
        SkipIfDockerUnavailable("simplesign-itext");
        var pdf = MinimalPdf();
        using var cert = TestCertificateFactory.CreateEcdsaCert(ECCurve.NamedCurves.nistP256, "CN=PAdES ECDSA P256 iText Cross");
        var signed = await SimpleSigner.Document(pdf)
            .WithCertificate(cert)
            .SignAsync();
        await ValidateWithIText(signed, "ecdsa-p256");
    }

    [SkippableFact(DisplayName = "Cross: PAdES ECDSA P-384 → iText validates")]
    public async Task PadesEcdsaP384_ValidatesWithIText()
    {
        SkipIfDockerUnavailable("simplesign-itext");
        var pdf = MinimalPdf();
        using var cert = TestCertificateFactory.CreateEcdsaCert(ECCurve.NamedCurves.nistP384, "CN=PAdES ECDSA P384 iText Cross");
        var signed = await SimpleSigner.Document(pdf)
            .WithCertificate(cert)
            .SignAsync();
        await ValidateWithIText(signed, "ecdsa-p384");
    }

    // ──────────────────────────────────────────────────────────────────────
    // EU DSS validations
    // ──────────────────────────────────────────────────────────────────────

    [SkippableFact(DisplayName = "Cross: PAdES SHA-384 → EU DSS validates")]
    public async Task PadesSha384_ValidatesWithEuDss()
    {
        SkipIfDockerUnavailable("simplesign-eu-dss");
        var pdf = MinimalPdf();
        using var cert = TestCertificateFactory.CreateSelfSignedCert("CN=PAdES SHA384 EU DSS Cross");
        var signed = await SimpleSigner.Document(pdf)
            .WithCertificate(cert)
            .WithHashAlgorithm(HashAlgorithmName.SHA384)
            .SignAsync();
        await ValidateWithEuDss(signed, "sha384");
    }

    [SkippableFact(DisplayName = "Cross: PAdES SHA-512 → EU DSS validates")]
    public async Task PadesSha512_ValidatesWithEuDss()
    {
        SkipIfDockerUnavailable("simplesign-eu-dss");
        var pdf = MinimalPdf();
        using var cert = TestCertificateFactory.CreateSelfSignedCert("CN=PAdES SHA512 EU DSS Cross");
        var signed = await SimpleSigner.Document(pdf)
            .WithCertificate(cert)
            .WithHashAlgorithm(HashAlgorithmName.SHA512)
            .SignAsync();
        await ValidateWithEuDss(signed, "sha512");
    }

    [SkippableFact(DisplayName = "Cross: PAdES ECDSA P-256 → EU DSS validates")]
    public async Task PadesEcdsaP256_ValidatesWithEuDss()
    {
        SkipIfDockerUnavailable("simplesign-eu-dss");
        var pdf = MinimalPdf();
        using var cert = TestCertificateFactory.CreateEcdsaCert(ECCurve.NamedCurves.nistP256, "CN=PAdES ECDSA P256 EU DSS Cross");
        var signed = await SimpleSigner.Document(pdf)
            .WithCertificate(cert)
            .SignAsync();
        await ValidateWithEuDss(signed, "ecdsa-p256");
    }

    [SkippableFact(DisplayName = "Cross: PAdES ECDSA P-384 → EU DSS validates")]
    public async Task PadesEcdsaP384_ValidatesWithEuDss()
    {
        SkipIfDockerUnavailable("simplesign-eu-dss");
        var pdf = MinimalPdf();
        using var cert = TestCertificateFactory.CreateEcdsaCert(ECCurve.NamedCurves.nistP384, "CN=PAdES ECDSA P384 EU DSS Cross");
        var signed = await SimpleSigner.Document(pdf)
            .WithCertificate(cert)
            .SignAsync();
        await ValidateWithEuDss(signed, "ecdsa-p384");
    }

    // ──────────────────────────────────────────────────────────────────────
    // pyHanko (DSS validator) validations
    // ──────────────────────────────────────────────────────────────────────

    [SkippableFact(DisplayName = "Cross: PAdES SHA-384 → pyHanko validates")]
    public async Task PadesSha384_ValidatesWithPyHanko()
    {
        SkipIfDockerUnavailable("simplesign-dss");
        var pdf = MinimalPdf();
        using var cert = TestCertificateFactory.CreateSelfSignedCert("CN=PAdES SHA384 pyHanko Cross");
        var signed = await SimpleSigner.Document(pdf)
            .WithCertificate(cert)
            .WithHashAlgorithm(HashAlgorithmName.SHA384)
            .SignAsync();
        await ValidateWithPyHanko(signed, "sha384");
    }

    [SkippableFact(DisplayName = "Cross: PAdES SHA-512 → pyHanko validates")]
    public async Task PadesSha512_ValidatesWithPyHanko()
    {
        SkipIfDockerUnavailable("simplesign-dss");
        var pdf = MinimalPdf();
        using var cert = TestCertificateFactory.CreateSelfSignedCert("CN=PAdES SHA512 pyHanko Cross");
        var signed = await SimpleSigner.Document(pdf)
            .WithCertificate(cert)
            .WithHashAlgorithm(HashAlgorithmName.SHA512)
            .SignAsync();
        await ValidateWithPyHanko(signed, "sha512");
    }

    [SkippableFact(DisplayName = "Cross: PAdES ECDSA P-256 → pyHanko validates")]
    public async Task PadesEcdsaP256_ValidatesWithPyHanko()
    {
        SkipIfDockerUnavailable("simplesign-dss");
        var pdf = MinimalPdf();
        using var cert = TestCertificateFactory.CreateEcdsaCert(ECCurve.NamedCurves.nistP256, "CN=PAdES ECDSA P256 pyHanko Cross");
        var signed = await SimpleSigner.Document(pdf)
            .WithCertificate(cert)
            .SignAsync();
        await ValidateWithPyHanko(signed, "ecdsa-p256");
    }

    [SkippableFact(DisplayName = "Cross: PAdES ECDSA P-384 → pyHanko validates")]
    public async Task PadesEcdsaP384_ValidatesWithPyHanko()
    {
        SkipIfDockerUnavailable("simplesign-dss");
        var pdf = MinimalPdf();
        using var cert = TestCertificateFactory.CreateEcdsaCert(ECCurve.NamedCurves.nistP384, "CN=PAdES ECDSA P384 pyHanko Cross");
        var signed = await SimpleSigner.Document(pdf)
            .WithCertificate(cert)
            .SignAsync();
        await ValidateWithPyHanko(signed, "ecdsa-p384");
    }

    // ──────────────────────────────────────────────────────────────────────
    // Helpers
    // ──────────────────────────────────────────────────────────────────────

    private static byte[] MinimalPdf() =>
        "%PDF-1.7\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>\nendobj\nxref\n0 4\n0000000000 65535 f\r\n0000000009 00000 n\r\n0000000058 00000 n\r\n0000000115 00000 n\r\ntrailer\n<< /Size 4 /Root 1 0 R >>\nstartxref\n186\n%%EOF\n"u8.ToArray();

    private static void SkipIfDockerUnavailable(string image)
    {
        Skip.IfNot(DockerProbe.IsDockerAvailable(), "Docker is not available on this host.");
        Skip.IfNot(DockerProbe.ImageExists(image),
            $"Docker image '{image}' not built. Build it before running cross-validator tests.");
    }

    private static string CreateTempDir()
    {
        var dir = Path.Combine(Path.GetTempPath(), $"simplesign-interop-{Guid.NewGuid():N}");
        Directory.CreateDirectory(dir);
        return dir;
    }

    private async Task ValidateWithIText(byte[] pdfBytes, string label)
    {
        var tmpDir = CreateTempDir();
        await File.WriteAllBytesAsync(Path.Combine(tmpDir, "signed.pdf"), pdfBytes);
        try
        {
            var (stdout, stderr, exitCode) = await DockerRun(
                $"-v {tmpDir}:/in simplesign-itext validate-pdf /in/signed.pdf");
            output.WriteLine($"[iText/{label}] exit={exitCode}");
            output.WriteLine(stdout);
            if (!string.IsNullOrEmpty(stderr))
            {
                output.WriteLine($"STDERR: {stderr}");
            }
            exitCode.ShouldBe(0, $"iText should validate PAdES ({label})");
            stdout.ShouldContain("VALID");
        }
        finally
        {
            Directory.Delete(tmpDir, recursive: true);
        }
    }

    private async Task ValidateWithEuDss(byte[] pdfBytes, string label)
    {
        var tmpDir = CreateTempDir();
        await File.WriteAllBytesAsync(Path.Combine(tmpDir, "signed.pdf"), pdfBytes);
        try
        {
            var (stdout, stderr, exitCode) = await DockerRun(
                $"-v {tmpDir}:/in simplesign-eu-dss validate-pades /in/signed.pdf");
            output.WriteLine($"[EU DSS/{label}] exit={exitCode}");
            output.WriteLine(stdout);
            if (!string.IsNullOrEmpty(stderr))
            {
                output.WriteLine($"STDERR: {stderr}");
            }
            exitCode.ShouldBe(0, $"EU DSS should validate PAdES ({label})");
            (stdout.Contains("TOTAL_PASSED") || stdout.Contains("INDETERMINATE")).ShouldBeTrue(
                $"EU DSS should report TOTAL_PASSED or INDETERMINATE for self-signed certs ({label})");
        }
        finally
        {
            Directory.Delete(tmpDir, recursive: true);
        }
    }

    private async Task ValidateWithPyHanko(byte[] pdfBytes, string label)
    {
        var tmpDir = CreateTempDir();
        await File.WriteAllBytesAsync(Path.Combine(tmpDir, "signed.pdf"), pdfBytes);
        try
        {
            var (stdout, stderr, exitCode) = await DockerRun(
                $"-v {tmpDir}:/in simplesign-dss validate-pades /in/signed.pdf");
            output.WriteLine($"[pyHanko/{label}] exit={exitCode}");
            output.WriteLine(stdout);
            if (!string.IsNullOrEmpty(stderr))
            {
                output.WriteLine($"STDERR: {stderr}");
            }
            exitCode.ShouldBe(0, $"pyHanko should validate PAdES ({label})");
            stdout.ShouldContain("VALID");
        }
        finally
        {
            Directory.Delete(tmpDir, recursive: true);
        }
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
}
