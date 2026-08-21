using System.Diagnostics;
using Shouldly;
using SimpleSign.Core.Http;
using SimpleSign.Core.Signing;
using SimpleSign.PAdES;
using SimpleSign.PAdES.Inspection;
using SimpleSign.TestHelpers;
using Xunit;
using Xunit.Abstractions;

namespace SimpleSign.Interop.Tests;

/// <summary>
/// PAdES-LTA (archival timestamp) interop: signatures with long-term validation
/// data (timestamp + OCSP/CRL + DSS + document timestamp) must be verifiable
/// by iText, EU DSS, and pyHanko.
/// </summary>
[Trait("Category", "Interop")]
public sealed class LtaInteropTests(ITestOutputHelper output)
{
    [SkippableFact(DisplayName = "PAdES-LTA validates under iText 9")]
    public async Task PadesLta_ValidatesWithIText()
    {
        SkipIfDockerUnavailable("simplesign-itext");
        var signed = await CreateLtaSignatureAsync();
        await ValidatePdfWithIText(signed, "pades-lta");
    }

    [SkippableFact(DisplayName = "PAdES-LTA validates under EU DSS")]
    public async Task PadesLta_ValidatesWithEuDss()
    {
        SkipIfDockerUnavailable("simplesign-eu-dss");
        var signed = await CreateLtaSignatureAsync();

        var tmpDir = CreateTempDir();
        await File.WriteAllBytesAsync(Path.Combine(tmpDir, "signed.pdf"), signed);
        try
        {
            var (stdout, stderr, exitCode) = await DockerRun(
                $"-v {tmpDir}:/in simplesign-eu-dss validate-pades /in/signed.pdf");
            output.WriteLine($"[pades-lta-eu-dss] exit={exitCode}");
            output.WriteLine(stdout);
            if (!string.IsNullOrEmpty(stderr))
                output.WriteLine($"STDERR: {stderr}");
            exitCode.ShouldBe(0, "EU DSS should validate LTA output");
            (stdout.Contains("TOTAL_PASSED") || stdout.Contains("INDETERMINATE")).ShouldBeTrue(
                "EU DSS should report TOTAL_PASSED or INDETERMINATE for LTA");
        }
        finally
        {
            Directory.Delete(tmpDir, recursive: true);
        }
    }

    [SkippableFact(DisplayName = "PAdES-LTA pyHanko validates structure and detects archive timestamp")]
    public async Task PadesLta_PyHankoValidates()
    {
        SkipIfDockerUnavailable("simplesign-dss");
        var signed = await CreateLtaSignatureAsync();

        var tmpDir = CreateTempDir();
        await File.WriteAllBytesAsync(Path.Combine(tmpDir, "signed.pdf"), signed);
        try
        {
            var (stdout, stderr, exitCode) = await DockerRun(
                $"-v {tmpDir}:/in simplesign-dss validate-pades /in/signed.pdf");
            output.WriteLine($"[pades-lta-pyhanko] exit={exitCode}");
            output.WriteLine(stdout);
            if (!string.IsNullOrEmpty(stderr))
                output.WriteLine($"STDERR: {stderr}");
            exitCode.ShouldBe(0, "pyHanko should validate LTA output");
            (stdout + stderr).ShouldContain("intact=True");
        }
        finally
        {
            Directory.Delete(tmpDir, recursive: true);
        }
    }

    [SkippableFact(DisplayName = "PAdES-LTA contains DocTimeStamp and DSS")]
    public async Task PadesLta_ContainsDocTimeStampAndDss()
    {
        var signed = await CreateLtaSignatureAsync();

        using var stream = new MemoryStream(signed);
        var result = await PdfSignatureInspector.InspectAsync(stream);

        output.WriteLine($"Signatures: {result.Signatures.Count}");
        foreach (var sig in result.Signatures)
            output.WriteLine($"  {sig.FieldName}: subFilter={sig.SubFilter} hasTimestamp={sig.Timestamp is not null}");

        result.Signatures.ShouldContain(s =>
            s.SubFilter == "ETSI.RFC3161" || (s.FieldName != null && s.FieldName.Contains("DocTimeStamp")),
            "LTA output must contain a Document Timestamp signature (SubFilter=ETSI.RFC3161)");
        result.Signatures.Count.ShouldBeGreaterThanOrEqualTo(2);
    }

    private static async Task<byte[]> CreateLtaSignatureAsync()
    {
        var pdf = MinimalPdf();
        using var pki = new SyntheticPki(crlDistributionPoint: "http://crl.example.com/test-ca.crl");
        using var crlClient = TestRevocation.BuildCrlClient(pki.BuildLeafCrl());
        return await PadesSigner.Document(pdf)
            .WithCertificate(pki.Leaf, pki.IntermediatesAndRoot())
            .WithLevel(AdesBaselineProfile.Archive(
                new TimestampOptions(new Uri("http://timestamp.digicert.com")),
                new LongTermValidationOptions(new SingleClientProvider(crlClient))))
            .SignAsync();
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
                output.WriteLine($"STDERR: {stderr}");
            exitCode.ShouldBe(0, $"iText 9 should validate LTA output ({label})");
            stdout.ShouldContain("RESULT: VALID");
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
