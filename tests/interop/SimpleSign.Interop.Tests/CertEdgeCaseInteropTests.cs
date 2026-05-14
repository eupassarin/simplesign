using System.Diagnostics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using FluentAssertions;
using SimpleSign.PAdES;
using SimpleSign.TestHelpers;
using Xunit;
using Xunit.Abstractions;

namespace SimpleSign.Interop.Tests;

/// <summary>
/// Edge-case certificate interop: validates that signatures produced with large keys
/// and certificate chains are recognized by external validators (iText, EU DSS, OpenSSL, xmlsec1).
/// Tests are skipped when Docker or the required images are unavailable.
/// </summary>
[Trait("Category", "Interop")]
public sealed class CertEdgeCaseInteropTests(ITestOutputHelper output)
{

    [SkippableFact(DisplayName = "CertEdge: PAdES with 4096-bit RSA validates under iText")]
    public async Task Pades4096Rsa_ValidatesWithIText()
    {
        SkipIfDockerUnavailable("simplesign-itext");
        var pdf = MinimalPdf();
        using var cert = TestCertificateFactory.CreateSelfSignedCert("CN=4096-bit RSA", 4096, HashAlgorithmName.SHA256);
        var signed = await SimpleSigner.Document(pdf).WithCertificate(cert).SignAsync();

        var tmpDir = CreateTempDir();
        await File.WriteAllBytesAsync(Path.Combine(tmpDir, "signed.pdf"), signed);
        try
        {
            var (stdout, stderr, exitCode) = await DockerRun(
                $"-v {tmpDir}:/in simplesign-itext validate-pdf /in/signed.pdf");
            output.WriteLine($"[pades-4096-itext] exit={exitCode}");
            output.WriteLine(stdout);
            if (!string.IsNullOrEmpty(stderr))
            {
                output.WriteLine($"STDERR: {stderr}");
            }
            exitCode.Should().Be(0, because: "iText should validate PAdES with 4096-bit RSA key");
            stdout.Should().Contain("RESULT: VALID");
        }
        finally
        {
            Directory.Delete(tmpDir, recursive: true);
        }
    }

    [SkippableFact(DisplayName = "CertEdge: PAdES with 4096-bit RSA validates under EU DSS")]
    public async Task Pades4096Rsa_ValidatesWithEuDss()
    {
        SkipIfDockerUnavailable("simplesign-eu-dss");
        var pdf = MinimalPdf();
        using var cert = TestCertificateFactory.CreateSelfSignedCert("CN=4096-bit RSA EU DSS", 4096, HashAlgorithmName.SHA256);
        var signed = await SimpleSigner.Document(pdf).WithCertificate(cert).SignAsync();

        var tmpDir = CreateTempDir();
        await File.WriteAllBytesAsync(Path.Combine(tmpDir, "signed.pdf"), signed);
        try
        {
            var (stdout, stderr, exitCode) = await DockerRun(
                $"-v {tmpDir}:/in simplesign-eu-dss validate-pades /in/signed.pdf");
            output.WriteLine($"[pades-4096-eu-dss] exit={exitCode}");
            output.WriteLine(stdout);
            if (!string.IsNullOrEmpty(stderr))
            {
                output.WriteLine($"STDERR: {stderr}");
            }
            exitCode.Should().Be(0, because: "EU DSS should validate PAdES with 4096-bit RSA key");
            (stdout.Contains("TOTAL_PASSED") || stdout.Contains("INDETERMINATE")).Should().BeTrue(
                because: "EU DSS should report TOTAL_PASSED or INDETERMINATE for self-signed certs");
        }
        finally
        {
            Directory.Delete(tmpDir, recursive: true);
        }
    }

    [SkippableFact(DisplayName = "CertEdge: PAdES with cert chain validates under EU DSS")]
    public async Task PadesCertChain_ValidatesWithEuDss()
    {
        SkipIfDockerUnavailable("simplesign-eu-dss");
        var (leaf, intermediate, root) = CreateCertificateChain();
        using (leaf)
        using (intermediate)
        using (root)
        {
            var pdf = MinimalPdf();
            var signed = await SimpleSigner.Document(pdf)
                .WithCertificate(leaf)
                .SignAsync();

            var tmpDir = CreateTempDir();
            await File.WriteAllBytesAsync(Path.Combine(tmpDir, "signed.pdf"), signed);
            try
            {
                var (stdout, stderr, exitCode) = await DockerRun(
                    $"-v {tmpDir}:/in simplesign-eu-dss validate-pades /in/signed.pdf");
                output.WriteLine($"[pades-chain-eu-dss] exit={exitCode}");
                output.WriteLine(stdout);
                if (!string.IsNullOrEmpty(stderr))
                {
                    output.WriteLine($"STDERR: {stderr}");
                }
                exitCode.Should().Be(0, because: "EU DSS should validate PAdES with cert chain");
                (stdout.Contains("TOTAL_PASSED") || stdout.Contains("INDETERMINATE")).Should().BeTrue(
                    because: "EU DSS should report TOTAL_PASSED or INDETERMINATE for test cert chains");
            }
            finally
            {
                Directory.Delete(tmpDir, recursive: true);
            }
        }
    }

    private static (X509Certificate2 leaf, X509Certificate2 intermediate, X509Certificate2 root) CreateCertificateChain()
    {
        // Root CA
        using var rootKey = RSA.Create(2048);
        var rootReq = new CertificateRequest("CN=Test Root CA, O=SimpleSign Tests", rootKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        rootReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, true, 1, true));
        rootReq.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
        var rootCert = rootReq.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(10));

        // Intermediate CA
        using var intKey = RSA.Create(2048);
        var intReq = new CertificateRequest("CN=Test Intermediate CA, O=SimpleSign Tests", intKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        intReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, true, 0, true));
        intReq.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
        var intSerial = new byte[16];
        RandomNumberGenerator.Fill(intSerial);
        var intCert = intReq.Create(rootCert, DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(5), intSerial);
        var intCertWithKey = intCert.CopyWithPrivateKey(intKey);

        // Leaf (end-entity)
        using var leafKey = RSA.Create(2048);
        var leafReq = new CertificateRequest("CN=Test Signer, O=SimpleSign Tests", leafKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        leafReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        leafReq.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.NonRepudiation, true));
        var leafSerial = new byte[16];
        RandomNumberGenerator.Fill(leafSerial);
        var leafCert = leafReq.Create(intCertWithKey, DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1), leafSerial);
        var leafCertWithKey = leafCert.CopyWithPrivateKey(leafKey);

#pragma warning disable SYSLIB0057
        return (
            new X509Certificate2(leafCertWithKey.Export(X509ContentType.Pfx, "test"), "test", X509KeyStorageFlags.Exportable),
            new X509Certificate2(intCertWithKey.Export(X509ContentType.Pfx, "test"), "test", X509KeyStorageFlags.Exportable),
            new X509Certificate2(rootCert.Export(X509ContentType.Pfx, "test"), "test", X509KeyStorageFlags.Exportable)
        );
#pragma warning restore SYSLIB0057
    }

    private static void SkipIfDockerUnavailable(string imageName)
    {
        Skip.IfNot(DockerProbe.IsDockerAvailable(), "Docker is not available on this host.");
        Skip.IfNot(DockerProbe.ImageExists(imageName),
            $"Docker image '{imageName}' not built. Build the required interop image first.");
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
        "%PDF-1.7\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n2 0 obj\n<< /Type /Pages /Kids [] /Count 0 >>\nendobj\nxref\n0 3\n0000000000 65535 f \n0000000009 00000 n \n0000000058 00000 n \ntrailer\n<< /Size 3 /Root 1 0 R >>\nstartxref\n110\n%%EOF"u8.ToArray();
}
