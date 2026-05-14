using System.Diagnostics;
using FluentAssertions;
using SimpleSign.PAdES;
using SimpleSign.TestHelpers;
using Xunit;
using Xunit.Abstractions;

namespace SimpleSign.Interop.Tests;

/// <summary>
/// EU DSS interop: signatures produced by SimpleSign must be recognized by the official
/// EU Digital Signature Service (ETSI EN 319 102 conformance). Tests are skipped when
/// Docker or the eu-dss image is unavailable.
/// </summary>
[Trait("Category", "Interop")]
public sealed class EuDssInteropTests(ITestOutputHelper output)
{

    [SkippableFact(DisplayName = "PAdES-B-B validates under EU DSS")]
    public async Task PadesBB_ValidatesWithEuDss()
    {
        SkipIfDockerUnavailable();
        var pdf = MinimalPdf();
        using var cert = TestCertificateFactory.CreateSelfSignedCert("CN=PAdES EU DSS Interop");
        var signed = await SimpleSigner.Document(pdf).WithCertificate(cert).SignAsync();
        await ValidatePdfWithEuDss(signed, "pades-bb");
    }

    [SkippableFact(DisplayName = "PAdES-B-B with LTV validates under EU DSS")]
    public async Task PadesBBLtv_ValidatesWithEuDss()
    {
        SkipIfDockerUnavailable();
        var pdf = MinimalPdf();
        using var cert = TestCertificateFactory.CreateSelfSignedCert("CN=PAdES LTV EU DSS Interop");
        var signed = await SimpleSigner.Document(pdf).WithCertificate(cert).WithTimestamp("http://timestamp.digicert.com").WithLtv().SignAsync();
        await ValidatePdfWithEuDss(signed, "pades-bb-ltv");
    }

    [SkippableFact(DisplayName = "PAdES double-signed validates under EU DSS")]
    public async Task PadesDoubleSigned_ValidatesWithEuDss()
    {
        SkipIfDockerUnavailable();
        var pdf = MinimalPdf();
        using var cert1 = TestCertificateFactory.CreateSelfSignedCert("CN=EU DSS Signer 1");
        using var cert2 = TestCertificateFactory.CreateSelfSignedCert("CN=EU DSS Signer 2");
        var signed1 = await SimpleSigner.Document(pdf).WithCertificate(cert1).SignAsync();
        var signed2 = await SimpleSigner.Document(signed1).WithCertificate(cert2).SignAsync();
        await ValidatePdfWithEuDss(signed2, "pades-double-signed");
    }

    private static void SkipIfDockerUnavailable()
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

    private async Task ValidatePdfWithEuDss(byte[] pdfBytes, string label)
    {
        var tmpDir = CreateTempDir();
        await File.WriteAllBytesAsync(Path.Combine(tmpDir, "signed.pdf"), pdfBytes);
        try
        {
            var (stdout, stderr, exitCode) = await DockerRun(
                $"-v {tmpDir}:/in simplesign-eu-dss validate-pades /in/signed.pdf");
            output.WriteLine($"[{label}] exit={exitCode}");
            output.WriteLine(stdout);
            if (!string.IsNullOrEmpty(stderr))
            {
                output.WriteLine($"STDERR: {stderr}");
            }
            exitCode.Should().Be(0, because: $"EU DSS should validate our PAdES output ({label})");
            (stdout.Contains("TOTAL_PASSED") || stdout.Contains("INDETERMINATE")).Should().BeTrue(
                because: "EU DSS should report TOTAL_PASSED or INDETERMINATE for self-signed certs");
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
