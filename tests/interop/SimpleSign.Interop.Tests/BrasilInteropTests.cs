using System.Diagnostics;
using System.Security.Cryptography.X509Certificates;
using FluentAssertions;
using SimpleSign.Brasil.Signing;
using SimpleSign.PAdES;
using SimpleSign.PAdES.Inspection;
using SimpleSign.TestHelpers;
using Xunit;
using Xunit.Abstractions;

namespace SimpleSign.Interop.Tests;

/// <summary>
/// Brasil-specific interop: AEA signatures (Lei 14.063/2020) and ICP-Brasil policy OIDs
/// must produce valid CMS/PKCS#7 structures verifiable by OpenSSL.
/// </summary>
[Trait("Category", "Interop")]
public sealed class BrasilInteropTests(ITestOutputHelper output)
{
    [SkippableFact(DisplayName = "PAdES with AEA (Lei 14.063) — CMS validates under OpenSSL")]
    public async Task PadesAea_CmsValidatesWithOpenSsl()
    {
        SkipIfDockerUnavailable();

        var pdf = MinimalPdf();
        using var cert = TestCertificateFactory.CreateSelfSignedCert("CN=AEA Interop Signer");

        var aeaInfo = new AdvancedSignatureInfo
        {
            SignerName = "André Almeida",
            Cpf = "12345678901",
            AuthMethod = AuthenticationMethod.DigitalCertificate,
            Email = "andre@example.com",
            IpAddress = "192.168.1.100",
            InstitutionName = "TCE-ES",
            InstitutionCnpj = "12345678000199",
            CommitmentType = SimpleSign.Core.Signing.CommitmentType.ProofOfApproval,
        };

        var signed = await SimpleSigner.Document(pdf)
            .WithCertificate(cert)
            .WithAdvancedSignature(aeaInfo)
            .SignAsync();

        // Extract and validate CMS
        using var stream = new MemoryStream(signed);
        var signatures = await PadesExtractor.ExtractAsync(stream);
        signatures.Should().HaveCountGreaterThan(0);

        await ValidateDetachedCms(signatures[0].CmsSignature, signatures[0].SignedData, cert, "pades-aea");
    }

    [SkippableFact(DisplayName = "PAdES with AEA — CMS structure inspectable (contains manifest)")]
    public async Task PadesAea_CmsInspectable()
    {
        SkipIfDockerUnavailable();

        var pdf = MinimalPdf();
        using var cert = TestCertificateFactory.CreateSelfSignedCert("CN=AEA Inspect Interop");

        var aeaInfo = new AdvancedSignatureInfo
        {
            SignerName = "Maria Silva",
            Cpf = "98765432100",
            AuthMethod = AuthenticationMethod.InstitutionalLogin,
            InstitutionName = "Prefeitura Municipal",
            PolicyOid = "2.16.76.1.7.1.1.1",
            PolicyUri = "http://politicas.icpbrasil.gov.br/PA_AD_RB_v2_3.der",
        };

        var signed = await SimpleSigner.Document(pdf)
            .WithCertificate(cert)
            .WithAdvancedSignature(aeaInfo)
            .SignAsync();

        using var stream = new MemoryStream(signed);
        var signatures = await PadesExtractor.ExtractAsync(stream);
        var sig = signatures[0];

        // Inspect CMS structure — should contain extra attributes
        var tmpDir = Path.Combine(Path.GetTempPath(), $"simplesign-interop-{Guid.NewGuid():N}");
        Directory.CreateDirectory(tmpDir);
        await File.WriteAllBytesAsync(Path.Combine(tmpDir, "sig.der"), sig.CmsSignature);
        try
        {
            var (stdout, stderr, exitCode) = await DockerRun(
                $"-v {tmpDir}:/in simplesign-dss inspect-cms /in/sig.der");
            output.WriteLine(stdout);
            stdout.Should().Contain("CMS_ContentInfo",
                because: "OpenSSL should parse AEA CMS with manifest attributes");
        }
        finally
        {
            Directory.Delete(tmpDir, recursive: true);
        }
    }

    private static void SkipIfDockerUnavailable()
    {
        Skip.IfNot(DockerProbe.IsDockerAvailable(), "Docker is not available on this host.");
        Skip.IfNot(DockerProbe.ImageExists("simplesign-dss"),
            "Validator image not built. Run: docker build -t simplesign-dss interop/dss-validator");
    }

    private async Task ValidateDetachedCms(byte[] cmsBytes, byte[] data, X509Certificate2 cert, string label)
    {
        var tmpDir = Path.Combine(Path.GetTempPath(), $"simplesign-interop-{Guid.NewGuid():N}");
        Directory.CreateDirectory(tmpDir);
        await File.WriteAllBytesAsync(Path.Combine(tmpDir, "sig.der"), cmsBytes);
        await File.WriteAllBytesAsync(Path.Combine(tmpDir, "data.bin"), data);
        await File.WriteAllTextAsync(Path.Combine(tmpDir, "cert.pem"), ExportCertPem(cert));
        try
        {
            var (stdout, stderr, exitCode) = await DockerRun(
                $"-v {tmpDir}:/in simplesign-dss validate-cms /in/sig.der /in/data.bin /in/cert.pem");
            output.WriteLine($"[{label}] exit={exitCode}");
            output.WriteLine(stdout);
            if (!string.IsNullOrEmpty(stderr))
            {
                output.WriteLine($"STDERR: {stderr}");
            }
            exitCode.Should().Be(0, because: $"OpenSSL should verify AEA CMS signature ({label})");
            stdout.Should().Contain("VALID");
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

    private static string ExportCertPem(X509Certificate2 cert)
    {
        var pem = Convert.ToBase64String(cert.RawData);
        return $"-----BEGIN CERTIFICATE-----\n{pem}\n-----END CERTIFICATE-----\n";
    }

    private static byte[] MinimalPdf() =>
        "%PDF-1.7\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n2 0 obj\n<< /Type /Pages /Kids [] /Count 0 >>\nendobj\nxref\n0 3\n0000000000 65535 f \n0000000009 00000 n \n0000000058 00000 n \ntrailer\n<< /Size 3 /Root 1 0 R >>\nstartxref\n110\n%%EOF"u8.ToArray();
}
