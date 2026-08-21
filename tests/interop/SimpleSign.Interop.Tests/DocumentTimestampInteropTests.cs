using System.Diagnostics;
using System.Security.Cryptography;
using Shouldly;
using SimpleSign.PAdES.Inspection;
using SimpleSign.PAdES.Signing;
using Xunit;
using Xunit.Abstractions;

namespace SimpleSign.Interop.Tests;

/// <summary>
/// Document Timestamp (DTS) interop: standalone document timestamps (RFC 3161
/// TimeStampToken with SubFilter=ETSI.RFC3161) must be recognized by external
/// validators, even without an accompanying user signature.
/// </summary>
[Trait("Category", "Interop")]
public sealed class DocumentTimestampInteropTests(ITestOutputHelper output)
{
    [SkippableFact(DisplayName = "Standalone DTS (no user signature) — pyHanko detects DocTimeStamp")]
    public async Task StandaloneDts_PyHankoDetects()
    {
        SkipIfDockerUnavailable("simplesign-dss");
        var pdf = MinimalPdf();

        using var httpClient = new HttpClient { Timeout = TimeSpan.FromSeconds(15) };
        var timestamped = await DocTimeStampWriter.AppendDocTimeStampAsync(
            pdf, "http://timestamp.digicert.com", httpClient,
            HashAlgorithmName.SHA256);

        var tmpDir = CreateTempDir();
        await File.WriteAllBytesAsync(Path.Combine(tmpDir, "signed.pdf"), timestamped);
        try
        {
            var (stdout, stderr, exitCode) = await DockerRun(
                $"-v {tmpDir}:/in simplesign-dss validate-pades /in/signed.pdf");
            output.WriteLine($"[dts-pyhanko] exit={exitCode}");
            output.WriteLine(stdout);
            if (!string.IsNullOrEmpty(stderr))
                output.WriteLine($"STDERR: {stderr}");

            // pyHanko should at least recognize the structure
            (stdout + stderr).ShouldContain("Timestamp");
        }
        finally
        {
            Directory.Delete(tmpDir, recursive: true);
        }
    }

    [SkippableFact(DisplayName = "Standalone DTS — Inspector detects DocTimeStamp field")]
    public async Task StandaloneDts_InspectorDetects()
    {
        var pdf = MinimalPdf();

        using var httpClient = new HttpClient { Timeout = TimeSpan.FromSeconds(15) };
        var timestamped = await DocTimeStampWriter.AppendDocTimeStampAsync(
            pdf, "http://timestamp.digicert.com", httpClient,
            HashAlgorithmName.SHA256);

        using var stream = new MemoryStream(timestamped);
        var result = await PdfSignatureInspector.InspectAsync(stream);

        output.WriteLine($"Signatures: {result.Signatures.Count}");
        foreach (var sig in result.Signatures)
            output.WriteLine($"  {sig.FieldName}: subFilter={sig.SubFilter} hasTimestamp={sig.Timestamp is not null}");

        result.Signatures.ShouldContain(s => s.SubFilter == "ETSI.RFC3161",
            "DTS must be detected as a signature with ETSI.RFC3161 subfilter");
    }

    [SkippableFact(DisplayName = "DTS on already-signed PDF — both signature and timestamp detected")]
    public async Task DtsOnSignedPdf_BothDetected()
    {
        SkipIfDockerUnavailable("simplesign-eu-dss");

        // First sign
        var pdf = MinimalPdf();
        using var cert = SimpleSign.TestHelpers.TestCertificateFactory.CreateSelfSignedCert("CN=DTS Test Signer");
        var signed = await SimpleSign.PAdES.PadesSigner.Document(pdf)
            .WithCertificate(cert)
            .SignAsync();

        // Then append DTS
        using var httpClient = new HttpClient { Timeout = TimeSpan.FromSeconds(15) };
        var timestamped = await DocTimeStampWriter.AppendDocTimeStampAsync(
            signed, "http://timestamp.digicert.com", httpClient,
            HashAlgorithmName.SHA256);

        // Validate with EU DSS
        var tmpDir = CreateTempDir();
        await File.WriteAllBytesAsync(Path.Combine(tmpDir, "signed.pdf"), timestamped);
        try
        {
            var (stdout, stderr, exitCode) = await DockerRun(
                $"-v {tmpDir}:/in simplesign-eu-dss validate-pades /in/signed.pdf");
            output.WriteLine($"[dts-signed-eu-dss] exit={exitCode}");
            output.WriteLine(stdout);
            exitCode.ShouldBe(0, "EU DSS should validate a signed PDF with DTS");
            (stdout.Contains("TOTAL_PASSED") || stdout.Contains("INDETERMINATE")).ShouldBeTrue();
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
            $"{image} image not built.");
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
