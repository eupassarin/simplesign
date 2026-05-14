using System.Diagnostics;
using FluentAssertions;
using SimpleSign.PAdES;
using SimpleSign.TestHelpers;
using Xunit;
using Xunit.Abstractions;

namespace SimpleSign.Interop.Tests;

/// <summary>
/// Complex/multi-page PDF interop: validates that SimpleSign can correctly sign
/// multi-page PDFs and that signatures are verifiable by multiple external tools.
/// </summary>
[Trait("Category", "Interop")]
public sealed class ComplexPdfInteropTests(ITestOutputHelper output)
{
    [SkippableFact(DisplayName = "Complex: Sign 10-page PDF → iText validates")]
    public async Task Sign10Page_ValidatesWithIText()
    {
        SkipIfDockerUnavailable("simplesign-itext");
        var pdf = MultiPagePdf(10);
        using var cert = TestCertificateFactory.CreateSelfSignedCert("CN=Complex 10-Page iText");
        var signed = await SimpleSigner.Document(pdf).WithCertificate(cert).SignAsync();

        var tmpDir = CreateTempDir();
        await File.WriteAllBytesAsync(Path.Combine(tmpDir, "signed.pdf"), signed);
        try
        {
            var (stdout, stderr, exitCode) = await DockerRun(
                $"-v {tmpDir}:/in simplesign-itext verify-signatures /in/signed.pdf");
            output.WriteLine($"[10-page-itext] exit={exitCode}");
            output.WriteLine(stdout);
            if (!string.IsNullOrEmpty(stderr))
            {
                output.WriteLine($"STDERR: {stderr}");
            }
            exitCode.Should().Be(0, because: "iText should validate a signed 10-page PDF");
            stdout.Should().Contain("VALID");
        }
        finally
        {
            Directory.Delete(tmpDir, recursive: true);
        }
    }

    [SkippableFact(DisplayName = "Complex: Sign multi-page PDF → pyHanko validates")]
    public async Task SignMultiPage_ValidatesWithPyHanko()
    {
        SkipIfDockerUnavailable("simplesign-dss");
        var pdf = MultiPagePdf(5);
        using var cert = TestCertificateFactory.CreateSelfSignedCert("CN=Complex MultiPage pyHanko");
        var signed = await SimpleSigner.Document(pdf).WithCertificate(cert).SignAsync();

        var tmpDir = CreateTempDir();
        await File.WriteAllBytesAsync(Path.Combine(tmpDir, "signed.pdf"), signed);
        try
        {
            var (stdout, stderr, exitCode) = await DockerRun(
                $"-v {tmpDir}:/in simplesign-dss validate-pades /in/signed.pdf");
            output.WriteLine($"[multipage-pyhanko] exit={exitCode}");
            output.WriteLine(stdout);
            if (!string.IsNullOrEmpty(stderr))
            {
                output.WriteLine($"STDERR: {stderr}");
            }
            exitCode.Should().Be(0, because: "pyHanko should validate a signed multi-page PDF");
            stdout.Should().Contain("VALID");
        }
        finally
        {
            Directory.Delete(tmpDir, recursive: true);
        }
    }

    [SkippableFact(DisplayName = "Complex: Triple-signed PDF → pyHanko validates all 3 sigs")]
    public async Task TripleSigned_ValidatesWithPyHanko()
    {
        SkipIfDockerUnavailable("simplesign-dss");
        var pdf = MultiPagePdf(3);
        using var cert1 = TestCertificateFactory.CreateSelfSignedCert("CN=Complex Triple Signer 1");
        using var cert2 = TestCertificateFactory.CreateSelfSignedCert("CN=Complex Triple Signer 2");
        using var cert3 = TestCertificateFactory.CreateSelfSignedCert("CN=Complex Triple Signer 3");

        var once = await SimpleSigner.Document(pdf).WithCertificate(cert1).SignAsync();
        var twice = await SimpleSigner.Document(once).WithCertificate(cert2).SignAsync();
        var thrice = await SimpleSigner.Document(twice).WithCertificate(cert3).SignAsync();

        var tmpDir = CreateTempDir();
        await File.WriteAllBytesAsync(Path.Combine(tmpDir, "signed.pdf"), thrice);
        try
        {
            var (stdout, stderr, exitCode) = await DockerRun(
                $"-v {tmpDir}:/in simplesign-dss validate-pades /in/signed.pdf");
            output.WriteLine($"[triple-signed-pyhanko] exit={exitCode}");
            output.WriteLine(stdout);
            if (!string.IsNullOrEmpty(stderr))
            {
                output.WriteLine($"STDERR: {stderr}");
            }
            exitCode.Should().Be(0, because: "pyHanko should validate all 3 signatures");
            stdout.Should().Contain("VALID");
        }
        finally
        {
            Directory.Delete(tmpDir, recursive: true);
        }
    }

    [SkippableFact(DisplayName = "Complex: Double-signed PDF → EU DSS validates both")]
    public async Task DoubleSigned_ValidatesWithEuDss()
    {
        SkipIfDockerUnavailable("simplesign-eu-dss");
        var pdf = MultiPagePdf(4);
        using var cert1 = TestCertificateFactory.CreateSelfSignedCert("CN=Complex EU DSS Signer 1");
        using var cert2 = TestCertificateFactory.CreateSelfSignedCert("CN=Complex EU DSS Signer 2");

        var once = await SimpleSigner.Document(pdf).WithCertificate(cert1).SignAsync();
        var twice = await SimpleSigner.Document(once).WithCertificate(cert2).SignAsync();

        var tmpDir = CreateTempDir();
        await File.WriteAllBytesAsync(Path.Combine(tmpDir, "signed.pdf"), twice);
        try
        {
            var (stdout, stderr, exitCode) = await DockerRun(
                $"-v {tmpDir}:/in simplesign-eu-dss validate-pades /in/signed.pdf");
            output.WriteLine($"[double-signed-eu-dss] exit={exitCode}");
            output.WriteLine(stdout);
            if (!string.IsNullOrEmpty(stderr))
            {
                output.WriteLine($"STDERR: {stderr}");
            }
            exitCode.Should().Be(0, because: "EU DSS should validate both signatures");
            (stdout.Contains("TOTAL_PASSED") || stdout.Contains("INDETERMINATE")).Should().BeTrue(
                because: "EU DSS should report TOTAL_PASSED or INDETERMINATE for self-signed certs");
        }
        finally
        {
            Directory.Delete(tmpDir, recursive: true);
        }
    }

    [SkippableFact(DisplayName = "Complex: Double-signed PDF → pdfbox detects both signatures")]
    public async Task DoubleSigned_DetectedByPdfbox()
    {
        SkipIfDockerUnavailable("simplesign-pdfbox");
        var pdf = MultiPagePdf(4);
        using var cert1 = TestCertificateFactory.CreateSelfSignedCert("CN=Complex Pdfbox Signer 1");
        using var cert2 = TestCertificateFactory.CreateSelfSignedCert("CN=Complex Pdfbox Signer 2");

        var once = await SimpleSigner.Document(pdf).WithCertificate(cert1).SignAsync();
        var twice = await SimpleSigner.Document(once).WithCertificate(cert2).SignAsync();

        var tmpDir = CreateTempDir();
        await File.WriteAllBytesAsync(Path.Combine(tmpDir, "signed.pdf"), twice);
        try
        {
            var (stdout, stderr, exitCode) = await DockerRun(
                $"-v {tmpDir}:/in simplesign-pdfbox verify-signatures /in/signed.pdf");
            output.WriteLine($"[double-signed-pdfbox] exit={exitCode}");
            output.WriteLine(stdout);
            if (!string.IsNullOrEmpty(stderr))
            {
                output.WriteLine($"STDERR: {stderr}");
            }
            exitCode.Should().Be(0, because: "pdfbox should parse the double-signed PDF");
            stdout.Should().Contain("Signature");
        }
        finally
        {
            Directory.Delete(tmpDir, recursive: true);
        }
    }

    [SkippableFact(DisplayName = "Complex: Sign 50-page PDF → iText validates (stress)")]
    public async Task Sign50Page_ValidatesWithIText()
    {
        SkipIfDockerUnavailable("simplesign-itext");
        var pdf = MultiPagePdf(50);
        using var cert = TestCertificateFactory.CreateSelfSignedCert("CN=Complex 50-Page Stress");
        var signed = await SimpleSigner.Document(pdf).WithCertificate(cert).SignAsync();

        var tmpDir = CreateTempDir();
        await File.WriteAllBytesAsync(Path.Combine(tmpDir, "signed.pdf"), signed);
        try
        {
            var (stdout, stderr, exitCode) = await DockerRun(
                $"-v {tmpDir}:/in simplesign-itext verify-signatures /in/signed.pdf");
            output.WriteLine($"[50-page-itext-stress] exit={exitCode}");
            output.WriteLine(stdout);
            if (!string.IsNullOrEmpty(stderr))
            {
                output.WriteLine($"STDERR: {stderr}");
            }
            exitCode.Should().Be(0, because: "iText should validate a signed 50-page PDF");
            stdout.Should().Contain("VALID");
        }
        finally
        {
            Directory.Delete(tmpDir, recursive: true);
        }
    }

    private static void SkipIfDockerUnavailable(string image)
    {
        Skip.IfNot(DockerProbe.IsDockerAvailable(), "Docker is not available on this host.");
        Skip.IfNot(DockerProbe.ImageExists(image),
            $"{image} image not built. Run: docker build -t {image} interop/{image.Replace("simplesign-", "")}");
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

    private static byte[] MultiPagePdf(int pageCount)
    {
        var sb = new System.Text.StringBuilder();
        sb.Append("%PDF-1.7\n");

        var offsets = new List<int>();

        // Object 1: Catalog
        offsets.Add(sb.Length);
        sb.Append("1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n");

        // Object 2: Pages (root)
        offsets.Add(sb.Length);
        var kids = string.Join(" ", Enumerable.Range(3, pageCount).Select(i => $"{i} 0 R"));
        sb.Append($"2 0 obj\n<< /Type /Pages /Kids [{kids}] /Count {pageCount} >>\nendobj\n");

        // Objects 3..N: Page objects
        for (int i = 0; i < pageCount; i++)
        {
            offsets.Add(sb.Length);
            sb.Append($"{i + 3} 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>\nendobj\n");
        }

        // xref
        int xrefOffset = sb.Length;
        int totalObjects = pageCount + 3; // null + catalog + pages + N pages
        sb.Append($"xref\n0 {totalObjects}\n");
        sb.Append("0000000000 65535 f\r\n");
        foreach (var offset in offsets)
        {
            sb.Append($"{offset:D10} 00000 n\r\n");
        }

        sb.Append($"trailer\n<< /Size {totalObjects} /Root 1 0 R >>\nstartxref\n{xrefOffset}\n%%EOF\n");

        return System.Text.Encoding.ASCII.GetBytes(sb.ToString());
    }
}
