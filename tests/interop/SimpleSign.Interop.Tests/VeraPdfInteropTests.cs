using System.Diagnostics;
using System.Security.Cryptography.X509Certificates;
using Shouldly;
using SimpleSign.PAdES;
using SimpleSign.PAdES.Signing;
using SimpleSign.TestHelpers;
using Xunit;
using Xunit.Abstractions;

namespace SimpleSign.Interop.Tests;

/// <summary>
/// veraPDF interop tests: validates that documents incrementally signed by SimpleSign
/// preserve PDF/A conformance across diverse corpus files.
///
/// Sources are known-good PASS documents from the veraPDF test suite spanning
/// PDF/A-2b and PDF/A-3b. Every file is signed once, twice, and also validated
/// with auto-detected flavour to ensure robust conformance preservation.
/// </summary>
[Trait("Category", "Interop")]
[Trait("Category", "VeraPdf")]
public sealed class VeraPdfInteropTests(ITestOutputHelper output)
{
    private const string ResourcePrefix = "SimpleSign.Interop.Tests.corpus.verapdf.";
    private const string VeraPdfImage = "verapdf/cli";

    private sealed record VeraPdfCorpusFile(string ResourceName, string Flavour);

    /// <summary>All known-good PASS corpus files by flavour.</summary>
    private static readonly VeraPdfCorpusFile[] AllFiles =
    [
        new("PDF_A-1b-6-4-t01-pass-a.pdf", "1b"),
        new("PDF_A-1b-6-5-3-t01-pass-a.pdf", "1b"),
        new("PDF_A-2b-6-1-2-t02-pass-a.pdf", "2b"),
        new("PDF_A-2b-6-1-3-t01-pass-a.pdf", "2b"),
        new("PDF_A-2b-6-1-5-t01-pass-a.pdf", "2b"),
        new("PDF_A-2b-6-2-3-t01-pass-a.pdf", "2b"),
        new("PDF_A-2b-6-2-10-t01-pass-a.pdf", "2b"),
        new("PDF_A-2b-6-3-2-t01-pass-a.pdf", "2b"),
        new("PDF_A-2b-6-3-3-t01-pass-a.pdf", "2b"),
        new("PDF_A-3b-6-8-t02-pass-a.pdf", "3b"),
        new("PDF_A-3b-6-8-t02-pass-b.pdf", "3b"),
    ];

    public static IEnumerable<object[]> AllFilesData =>
        AllFiles.Select(f => new object[] { f.ResourceName, f.Flavour });

    private static byte[] LoadEmbedded(string filename)
    {
        var assembly = typeof(VeraPdfInteropTests).Assembly;
        var stream = assembly.GetManifestResourceStream(ResourcePrefix + filename)
            ?? assembly.GetManifestResourceStream(ResourcePrefix + filename.Replace('-', '_'));
        if (stream is null)
        {
            var available = string.Join(", ", assembly.GetManifestResourceNames()
                .Where(n => n.Contains("verapdf")));
            throw new FileNotFoundException(
                $"Embedded corpus resource '{filename}' not found. Available: {available}");
        }
        using (stream)
        {
            var bytes = new byte[stream.Length];
            stream.ReadExactly(bytes);
            return bytes;
        }
    }

    private static async Task<(string stdout, string stderr, int exitCode)> RunVeraPdf(
        byte[] pdf, string flavour)
    {
        var tmpDir = Path.Combine(Path.GetTempPath(), $"verapdf-{Guid.NewGuid():N}");
        Directory.CreateDirectory(tmpDir);
        try
        {
            var inputPath = Path.Combine(tmpDir, "input.pdf");
            await File.WriteAllBytesAsync(inputPath, pdf);

            var psi = new ProcessStartInfo("docker",
                $"run --rm -v {tmpDir}:/data {VeraPdfImage} verapdf --format text --flavour {flavour} -- /data/input.pdf")
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
        finally
        {
            Directory.Delete(tmpDir, recursive: true);
        }
    }

    private static void SkipIfVeraPdfUnavailable()
    {
        Skip.IfNot(DockerProbe.IsDockerAvailable(), "Docker is not available on this host.");
        Skip.IfNot(DockerProbe.ImageExists(VeraPdfImage),
            $"veraPDF CLI image not pulled. Run: docker pull {VeraPdfImage}");
    }

    /// <summary>
    /// Configures a signer for the given flavour.
    /// PDF/A-1b requires <see cref="PdfSignatureSubFilter.AdbePkcs7Detached"/>
    /// (ETSI.CAdES.detached is forbidden by the PDF/A-1 spec) and a visible
    /// appearance to satisfy the /AP dictionary requirement (ISO 19005-1 §6.9).
    /// PDF/A-2b/3b use the default ETSI.CAdES.detached with invisible signatures.
    /// </summary>
    private static PadesSignerBuilder BuildSigner(byte[] pdf, X509Certificate2 cert, string flavour)
    {
        var builder = PadesSigner
            .Document(pdf)
            .WithCertificate(cert)
            .WithPdfAPreservation();

        if (flavour == "1b")
        {
            builder = builder
                .WithSubFilter(PdfSignatureSubFilter.AdbePkcs7Detached)
                .WithAppearance(SignatureAppearance.Auto());
        }

        return builder;
    }

    // ──────────────────────────────────────────────────────────────────────
    // Single-sign tests: every corpus file signed once must still PASS
    // ──────────────────────────────────────────────────────────────────────

    [SkippableTheory]
    [MemberData(nameof(AllFilesData))]
    public async Task SignOnce_PreservesConformance(string resourceName, string flavour)
    {
        SkipIfVeraPdfUnavailable();

        byte[] pdf = LoadEmbedded(resourceName);
        using var cert = TestCertificateFactory.CreateSelfSignedCert($"CN=veraPDF {flavour} Single");

        byte[] signed = await BuildSigner(pdf, cert, flavour)
            .SignAsync();

        var (stdout, stderr, _) = await RunVeraPdf(signed, flavour);
        output.WriteLine(stdout);
        if (!string.IsNullOrEmpty(stderr))
            output.WriteLine($"STDERR: {stderr}");

        stdout.Trim().ShouldStartWith($"PASS /data/input.pdf {flavour}");
    }

    // ──────────────────────────────────────────────────────────────────────
    // Double-sign tests: every corpus file signed twice must still PASS
    // ──────────────────────────────────────────────────────────────────────

    [SkippableTheory]
    [MemberData(nameof(AllFilesData))]
    public async Task SignTwice_PreservesConformance(string resourceName, string flavour)
    {
        SkipIfVeraPdfUnavailable();

        byte[] pdf = LoadEmbedded(resourceName);
        using var cert1 = TestCertificateFactory.CreateSelfSignedCert($"CN=veraPDF {flavour} First");
        using var cert2 = TestCertificateFactory.CreateSelfSignedCert($"CN=veraPDF {flavour} Second");

        byte[] afterFirst = await BuildSigner(pdf, cert1, flavour)
            .SignAsync();

        byte[] afterSecond = await BuildSigner(afterFirst, cert2, flavour)
            .SignAsync();

        var (stdout, stderr, _) = await RunVeraPdf(afterSecond, flavour);
        output.WriteLine(stdout);
        if (!string.IsNullOrEmpty(stderr))
            output.WriteLine($"STDERR: {stderr}");

        stdout.Trim().ShouldStartWith($"PASS /data/input.pdf {flavour}");
    }

    // ──────────────────────────────────────────────────────────────────────
    // Auto-detect flavour: sign once and verify with --flavour 0
    // ──────────────────────────────────────────────────────────────────────

    [SkippableTheory]
    [MemberData(nameof(AllFilesData))]
    public async Task SignOnce_AutoDetectFlavour(string resourceName, string flavour)
    {
        SkipIfVeraPdfUnavailable();

        byte[] pdf = LoadEmbedded(resourceName);
        using var cert = TestCertificateFactory.CreateSelfSignedCert($"CN=veraPDF {flavour} AutoDetect");

        byte[] signed = await BuildSigner(pdf, cert, flavour)
            .SignAsync();

        var (stdout, stderr, _) = await RunVeraPdf(signed, "0");
        output.WriteLine(stdout);
        if (!string.IsNullOrEmpty(stderr))
            output.WriteLine($"STDERR: {stderr}");

        stdout.Trim().ShouldStartWith("PASS /data/input.pdf");
    }

    // ──────────────────────────────────────────────────────────────────────
    // Sanity check: tampered document must be rejected
    // ──────────────────────────────────────────────────────────────────────

    [SkippableFact(DisplayName = "PDF/A: tampered document is rejected by veraPDF")]
    public async Task TamperedDocument_Rejected()
    {
        SkipIfVeraPdfUnavailable();

        byte[] pdf = LoadEmbedded("PDF_A-3b-6-8-t02-pass-a.pdf");
        using var cert = TestCertificateFactory.CreateSelfSignedCert("CN=veraPDF Tamper");

        byte[] signed = await PadesSigner
            .Document(pdf)
            .WithCertificate(cert)
            .WithPdfAPreservation()
            .SignAsync();

        // Corrupt the PDF header to guarantee rejection.
        signed[5] ^= 0xFF;

        var (stdout, stderr, _) = await RunVeraPdf(signed, "3b");
        output.WriteLine(stdout);
        if (!string.IsNullOrEmpty(stderr))
            output.WriteLine($"STDERR: {stderr}");

        stdout.Trim().ShouldStartWith("FAIL /data/input.pdf 3b");
    }
}
