using System.Diagnostics;
using Shouldly;
using SimpleSign.PAdES;
using SimpleSign.TestHelpers;
using Xunit;

namespace SimpleSign.Interop.Tests;

/// <summary>
/// pdfbox interop checks: signed PDFs produced by SimpleSign must be parseable
/// by Apache pdfbox without structural errors. Tests are skipped when Docker or
/// the prebuilt pdfbox image is unavailable.
/// </summary>
[Trait("Category", "Interop")]
public sealed class PdfboxInteropTests
{
    [SkippableFact(DisplayName = "PAdES-B-B signed PDF is parseable by Apache pdfbox")]
    public async Task PadesBB_ParsedByPdfbox()
    {
        SkipIfDockerUnavailable();

        var pdf = MinimalPdf();
        using var cert = TestCertificateFactory.CreateSelfSignedCert("CN=pdfbox Interop Signer");
        var signed = await SimpleSigner.Document(pdf).WithCertificate(cert).SignAsync();

        await ValidateWithPdfbox(signed, "pades-bb");
    }

    [SkippableFact(DisplayName = "Double-signed PDF is parseable by Apache pdfbox")]
    public async Task DoubleSigned_ParsedByPdfbox()
    {
        SkipIfDockerUnavailable();

        var pdf = MinimalPdf();
        using var cert1 = TestCertificateFactory.CreateSelfSignedCert("CN=pdfbox Signer 1");
        using var cert2 = TestCertificateFactory.CreateSelfSignedCert("CN=pdfbox Signer 2");

        var signed1 = await SimpleSigner.Document(pdf).WithCertificate(cert1).SignAsync();
        var signed2 = await SimpleSigner.Document(signed1).WithCertificate(cert2).SignAsync();

        await ValidateWithPdfbox(signed2, "pades-double-signed");
    }

    private static void SkipIfDockerUnavailable()
    {
        Skip.IfNot(DockerProbe.IsDockerAvailable(), "Docker is not available on this host.");
        Skip.IfNot(DockerProbe.ImageExists("simplesign-pdfbox"),
            "pdfbox image is not built. Run: docker build -t simplesign-pdfbox interop/pdfbox");
    }

    private static async Task ValidateWithPdfbox(byte[] pdfBytes, string label)
    {
        var tmp = Path.Combine(Path.GetTempPath(), $"simplesign-interop-{Guid.NewGuid():N}.pdf");
        await File.WriteAllBytesAsync(tmp, pdfBytes);
        try
        {
            var psi = new ProcessStartInfo("docker",
                $"run --rm -v {tmp}:/in/signed.pdf simplesign-pdfbox /in/signed.pdf")
            {
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
            };
            using var proc = Process.Start(psi)!;
            string stdout = await proc.StandardOutput.ReadToEndAsync();
            string stderr = await proc.StandardError.ReadToEndAsync();
            proc.WaitForExit();

            // pdfbox debug should not report fatal parse errors.
            stderr.ShouldNotContain("Error");
            (stderr + stdout).ShouldNotContain("java.io.IOException");
        }
        finally
        {
            File.Delete(tmp);
        }
    }

    private static byte[] MinimalPdf() =>
        "%PDF-1.7\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n2 0 obj\n<< /Type /Pages /Kids [] /Count 0 >>\nendobj\nxref\n0 3\n0000000000 65535 f \n0000000009 00000 n \n0000000058 00000 n \ntrailer\n<< /Size 3 /Root 1 0 R >>\nstartxref\n110\n%%EOF"u8.ToArray();
}
