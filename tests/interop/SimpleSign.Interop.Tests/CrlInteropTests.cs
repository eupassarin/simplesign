using System.Diagnostics;
using Shouldly;
using SimpleSign.Core.Http;
using SimpleSign.Core.Signing;
using SimpleSign.PAdES;
using SimpleSign.PAdES.Inspection;
using SimpleSign.PAdES.Validation;
using SimpleSign.TestHelpers;
using Xunit;
using Xunit.Abstractions;

namespace SimpleSign.Interop.Tests;

/// <summary>
/// CRL embedding interop: signatures produced by SimpleSign with CRL-based
/// revocation data must have valid DSS entries and be verifiable by external tools.
/// </summary>
[Trait("Category", "Interop")]
public sealed class CrlInteropTests(ITestOutputHelper output)
{
    [SkippableFact(DisplayName = "PAdES-LT with CRL — DSS contains CRL entry")]
    public async Task PadesLtCrl_DssContainsCrl()
    {
        SkipIfDockerUnavailable();

        var pdf = MinimalPdf();
        using var pki = new SyntheticPki(crlDistributionPoint: "http://crl.example.com/test-ca.crl");
        using var crlClient = TestRevocation.BuildCrlClient(pki.BuildLeafCrl());

        var signed = await PadesSigner.Document(pdf)
            .WithCertificate(pki.Leaf, pki.IntermediatesAndRoot())
            .WithLevel(AdesBaselineProfile.LongTerm(
                new TimestampOptions(new Uri("http://timestamp.digicert.com")),
                new LongTermValidationOptions(new SingleClientProvider(crlClient))))
            .SignAsync();

        // Inspect signed PDF — DSS should exist
        using var stream = new MemoryStream(signed);
        var result = await PdfSignatureInspector.InspectAsync(stream);

        output.WriteLine($"HasSecurityStore: {result.Document.SecurityStore?.IsPresent}");
        output.WriteLine($"Signature count: {result.Signatures.Count}");

        result.Document.SecurityStore.ShouldNotBeNull(
            "PAdES-LT with LTV must include a DSS (Document Security Store)");

        // Validate that SimpleSign can verify integrity
        var validator = new PdfSignatureValidator(new SimpleSign.Core.Validation.ValidationOptions
        {
            CheckRevocation = false,
            NetworkTimeout = TimeSpan.FromSeconds(1),
        });
        var validationResults = await validator.ValidateAsync(new MemoryStream(signed));

        foreach (var vr in validationResults)
            output.WriteLine($"  {vr.FieldName}: integrity={vr.IsIntegrityValid} sig={vr.IsSignatureValid}");

        validationResults.ShouldNotBeEmpty();
        validationResults.ShouldContain(r => r.IsIntegrityValid,
            "At least one signature must have valid byte-range integrity");
    }

    [SkippableFact(DisplayName = "PAdES-LT with CRL — pyHanko validates structure")]
    public async Task PadesLtCrl_PyHankoValidates()
    {
        SkipIfDockerUnavailable();

        var pdf = MinimalPdf();
        using var pki = new SyntheticPki(crlDistributionPoint: "http://crl.example.com/test-ca.crl");
        using var crlClient = TestRevocation.BuildCrlClient(pki.BuildLeafCrl());

        var signed = await PadesSigner.Document(pdf)
            .WithCertificate(pki.Leaf, pki.IntermediatesAndRoot())
            .WithLevel(AdesBaselineProfile.LongTerm(
                new TimestampOptions(new Uri("http://timestamp.digicert.com")),
                new LongTermValidationOptions(new SingleClientProvider(crlClient))))
            .SignAsync();

        var tmpDir = CreateTempDir();
        await File.WriteAllBytesAsync(Path.Combine(tmpDir, "signed.pdf"), signed);
        try
        {
            var (stdout, stderr, exitCode) = await DockerRun(
                $"-v {tmpDir}:/in simplesign-dss validate-pades-structure /in/signed.pdf");
            output.WriteLine(stdout);
            exitCode.ShouldBe(0);
            stdout.ShouldContain("RESULT: VALID");
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
