using System.Diagnostics;
using Shouldly;
using SimpleSign.PAdES;
using SimpleSign.PAdES.Signing;
using SimpleSign.TestHelpers;
using Xunit;
using Xunit.Abstractions;

namespace SimpleSign.Interop.Tests;

/// <summary>
/// iText 9 interop: PAdES signatures produced by SimpleSign must be verifiable by iText 9.
/// Tests are skipped when Docker or the itext image is unavailable.
/// </summary>
[Trait("Category", "Interop")]
public sealed class ITextInteropTests(ITestOutputHelper output)
{
    [SkippableFact(DisplayName = "PAdES-B-B validates under iText 9")]
    public async Task PadesBB_ValidatesWithIText()
    {
        SkipIfDockerUnavailable();
        var pdf = MinimalPdf();
        using var cert = TestCertificateFactory.CreateSelfSignedCert("CN=PAdES iText Interop");
        var signed = await SimpleSigner.Document(pdf).WithCertificate(cert).SignAsync();
        await ValidatePdfWithIText(signed, "pades-bb");
    }

    [SkippableFact(DisplayName = "PAdES double-signed validates under iText 9")]
    public async Task PadesDoubleSigned_ValidatesWithIText()
    {
        SkipIfDockerUnavailable();
        var pdf = MinimalPdf();
        using var cert1 = TestCertificateFactory.CreateSelfSignedCert("CN=iText Signer 1");
        using var cert2 = TestCertificateFactory.CreateSelfSignedCert("CN=iText Signer 2");
        var signed1 = await SimpleSigner.Document(pdf).WithCertificate(cert1).SignAsync();
        var signed2 = await SimpleSigner.Document(signed1).WithCertificate(cert2).SignAsync();
        await ValidatePdfWithIText(signed2, "pades-double-signed");
    }

    [SkippableFact(DisplayName = "PAdES with visual appearance validates under iText 9")]
    public async Task PadesVisual_ValidatesWithIText()
    {
        SkipIfDockerUnavailable();
        var pdf = MinimalPdf();
        using var cert = TestCertificateFactory.CreateSelfSignedCert("CN=PAdES Visual iText");
        var signed = await SimpleSigner.Document(pdf)
            .WithCertificate(cert)
            .WithAppearance(SignatureAppearance.Auto())
            .WithMetadata("Test Signer", "iText interop", "Brazil")
            .SignAsync();
        await ValidatePdfWithIText(signed, "pades-visual");
    }

    [SkippableFact(DisplayName = "PAdES with metadata inspectable by iText 9")]
    public async Task PadesMetadata_InspectableByIText()
    {
        SkipIfDockerUnavailable();
        var pdf = MinimalPdf();
        using var cert = TestCertificateFactory.CreateSelfSignedCert("CN=PAdES Metadata iText");
        var signed = await SimpleSigner.Document(pdf)
            .WithCertificate(cert)
            .WithMetadata("André Almeida", "Contract review", "Vitória")
            .SignAsync();

        var tmpDir = CreateTempDir();
        await File.WriteAllBytesAsync(Path.Combine(tmpDir, "signed.pdf"), signed);
        try
        {
            var (stdout, stderr, exitCode) = await DockerRun(
                $"-v {tmpDir}:/in simplesign-itext inspect-pdf /in/signed.pdf");
            output.WriteLine(stdout);
            exitCode.ShouldBe(0);
            stdout.ShouldContain("RESULT: INSPECTED");
            stdout.ShouldContain("Reason: Contract review");
            stdout.ShouldContain("Location: Vit");
        }
        finally
        {
            Directory.Delete(tmpDir, recursive: true);
        }
    }

    [SkippableFact(DisplayName = "PAdES structure check passes under iText 9")]
    public async Task PadesBB_StructureCheckWithIText()
    {
        SkipIfDockerUnavailable();
        var pdf = MinimalPdf();
        using var cert = TestCertificateFactory.CreateSelfSignedCert("CN=PAdES Structure iText");
        var signed = await SimpleSigner.Document(pdf).WithCertificate(cert).SignAsync();

        var tmpDir = CreateTempDir();
        await File.WriteAllBytesAsync(Path.Combine(tmpDir, "signed.pdf"), signed);
        try
        {
            var (stdout, stderr, exitCode) = await DockerRun(
                $"-v {tmpDir}:/in simplesign-itext check-structure /in/signed.pdf");
            output.WriteLine(stdout);
            exitCode.ShouldBe(0);
            stdout.ShouldContain("RESULT: VALID");
            stdout.ShouldContain("Signature fields: 1");
        }
        finally
        {
            Directory.Delete(tmpDir, recursive: true);
        }
    }

    [SkippableFact(DisplayName = "PAdES with LTV validates under iText 9")]
    public async Task PadesLtv_ValidatesWithIText()
    {
        SkipIfDockerUnavailable();
        var pdf = MinimalPdf();
        using var cert = TestCertificateFactory.CreateSelfSignedCert("CN=PAdES LTV iText");
        var signed = await SimpleSigner.Document(pdf).WithCertificate(cert).WithTimestamp("http://timestamp.digicert.com").WithLtv().SignAsync();
        await ValidatePdfWithIText(signed, "pades-ltv");
    }

    private static void SkipIfDockerUnavailable()
    {
        Skip.IfNot(DockerProbe.IsDockerAvailable(), "Docker is not available on this host.");
        Skip.IfNot(DockerProbe.ImageExists("simplesign-itext"),
            "iText image not built. Run: docker build -t simplesign-itext interop/itext");
    }

    private static string CreateTempDir()
    {
        var dir = Path.Combine(Path.GetTempPath(), $"simplesign-interop-{Guid.NewGuid():N}");
        Directory.CreateDirectory(dir);
        return dir;
    }

    private async Task ValidatePdfWithIText(byte[] pdfBytes, string label)
    {
        var tmpDir = CreateTempDir();
        await File.WriteAllBytesAsync(Path.Combine(tmpDir, "signed.pdf"), pdfBytes);
        try
        {
            var (stdout, stderr, exitCode) = await DockerRun(
                $"-v {tmpDir}:/in simplesign-itext validate-pdf /in/signed.pdf");
            output.WriteLine($"[{label}] exit={exitCode}");
            output.WriteLine(stdout);
            if (!string.IsNullOrEmpty(stderr))
            {
                output.WriteLine($"STDERR: {stderr}");
            }
            exitCode.ShouldBe(0, $"iText 9 should validate our PAdES output ({label})");
            stdout.ShouldContain("RESULT: VALID");
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

    private static byte[] MinimalPdf() =>
        "%PDF-1.7\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n2 0 obj\n<< /Type /Pages /Kids [] /Count 0 >>\nendobj\nxref\n0 3\n0000000000 65535 f \n0000000009 00000 n \n0000000058 00000 n \ntrailer\n<< /Size 3 /Root 1 0 R >>\nstartxref\n110\n%%EOF"u8.ToArray();
}
