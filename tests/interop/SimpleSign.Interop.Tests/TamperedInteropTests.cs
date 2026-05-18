using System.Diagnostics;
using Shouldly;
using SimpleSign.PAdES;
using SimpleSign.TestHelpers;
using Xunit;
using Xunit.Abstractions;

namespace SimpleSign.Interop.Tests;

/// <summary>
/// Tampered signature tests: verifies that various validators correctly REJECT
/// signatures that have been corrupted or whose underlying data has been modified.
/// Tests are skipped when Docker or the required images are unavailable.
/// </summary>
[Trait("Category", "Interop")]
public sealed class TamperedInteropTests(ITestOutputHelper output)
{

    // ─── PAdES tampered CMS → pyHanko (simplesign-dss) ───

    [SkippableFact(DisplayName = "Tampered PAdES CMS byte → pyHanko rejects")]
    public async Task PadesTamperedCms_PyHankoRejects()
    {
        SkipIfDssUnavailable();

        var pdf = MinimalPdf();
        using var cert = TestCertificateFactory.CreateSelfSignedCert("CN=Tampered PAdES DSS");
        var signed = await SimpleSigner.Document(pdf).WithCertificate(cert).SignAsync();

        var tampered = TamperPdfContents(signed);

        var tmpDir = CreateTempDir();
        await File.WriteAllBytesAsync(Path.Combine(tmpDir, "signed.pdf"), tampered);
        try
        {
            var (stdout, stderr, exitCode) = await DockerRun(
                $"-v {tmpDir}:/in simplesign-dss validate-pades /in/signed.pdf");
            output.WriteLine($"[tampered-pades-dss] exit={exitCode}");
            output.WriteLine(stdout);
            if (!string.IsNullOrEmpty(stderr))
            {
                output.WriteLine($"STDERR: {stderr}");
            }

            var combined = stdout + stderr;
            // pyHanko should either explicitly say INVALID, error out, or fail to validate
            (combined.Contains("INVALID") || combined.Contains("error")
                || combined.Contains("Error") || combined.Contains("Traceback")
                || !combined.Contains("VALID") || exitCode != 0).ShouldBeTrue(
                "pyHanko should reject a PDF with tampered CMS signature bytes");
        }
        finally
        {
            Directory.Delete(tmpDir, recursive: true);
        }
    }

    // ─── PAdES modified after signing → pyHanko (simplesign-dss) ───

    [SkippableFact(DisplayName = "Tampered PAdES post-EOF append → pyHanko rejects")]
    public async Task PadesPostEofAppend_PyHankoRejects()
    {
        SkipIfDssUnavailable();

        var pdf = MinimalPdf();
        using var cert = TestCertificateFactory.CreateSelfSignedCert("CN=Tampered PAdES EOF");
        var signed = await SimpleSigner.Document(pdf).WithCertificate(cert).SignAsync();

        // Append extra bytes after %%EOF to break byte range coverage
        var tampered = new byte[signed.Length + 100];
        Array.Copy(signed, tampered, signed.Length);
        Array.Fill(tampered, (byte)'X', signed.Length, 100);

        var tmpDir = CreateTempDir();
        await File.WriteAllBytesAsync(Path.Combine(tmpDir, "signed.pdf"), tampered);
        try
        {
            var (stdout, stderr, exitCode) = await DockerRun(
                $"-v {tmpDir}:/in simplesign-dss validate-pades /in/signed.pdf");
            output.WriteLine($"[tampered-pades-eof] exit={exitCode}");
            output.WriteLine(stdout);
            if (!string.IsNullOrEmpty(stderr))
            {
                output.WriteLine($"STDERR: {stderr}");
            }

            var combined = stdout + stderr;
            combined.ShouldNotContain("VALID\n");
            // Accept INVALID, INDETERMINATE, error, or non-zero exit as rejection
            (combined.Contains("INVALID") || combined.Contains("INDETERMINATE")
                || combined.Contains("error") || combined.Contains("fail")
                || exitCode != 0).ShouldBeTrue(
                "validator should reject or flag modified PDF content");
        }
        finally
        {
            Directory.Delete(tmpDir, recursive: true);
        }
    }

    // ─── PAdES tampered CMS → iText ───

    [SkippableFact(DisplayName = "Tampered PAdES CMS byte → iText rejects")]
    public async Task PadesTamperedCms_ITextRejects()
    {
        SkipIfITextUnavailable();

        var pdf = MinimalPdf();
        using var cert = TestCertificateFactory.CreateSelfSignedCert("CN=Tampered PAdES iText");
        var signed = await SimpleSigner.Document(pdf).WithCertificate(cert).SignAsync();

        var tampered = TamperPdfContents(signed);

        var tmpDir = CreateTempDir();
        await File.WriteAllBytesAsync(Path.Combine(tmpDir, "signed.pdf"), tampered);
        try
        {
            var (stdout, stderr, exitCode) = await DockerRun(
                $"-v {tmpDir}:/in simplesign-itext verify-signatures /in/signed.pdf");
            output.WriteLine($"[tampered-pades-itext] exit={exitCode}");
            output.WriteLine(stdout);
            if (!string.IsNullOrEmpty(stderr))
            {
                output.WriteLine($"STDERR: {stderr}");
            }

            var combined = stdout + stderr;
            // iText should not report all signatures as VALID
            combined.ShouldNotContain("RESULT: VALID");
        }
        finally
        {
            Directory.Delete(tmpDir, recursive: true);
        }
    }

    // ─── PAdES tampered CMS → EU DSS ───

    [SkippableFact(DisplayName = "Tampered PAdES CMS byte → EU DSS reports TOTAL_FAILED")]
    public async Task PadesTamperedCms_EuDssRejects()
    {
        SkipIfEuDssUnavailable();

        var pdf = MinimalPdf();
        using var cert = TestCertificateFactory.CreateSelfSignedCert("CN=Tampered PAdES EU DSS");
        var signed = await SimpleSigner.Document(pdf).WithCertificate(cert).SignAsync();

        var tampered = TamperPdfContents(signed);

        var tmpDir = CreateTempDir();
        await File.WriteAllBytesAsync(Path.Combine(tmpDir, "signed.pdf"), tampered);
        try
        {
            var (stdout, stderr, exitCode) = await DockerRun(
                $"-v {tmpDir}:/in simplesign-eu-dss validate-pades /in/signed.pdf");
            output.WriteLine($"[tampered-pades-eu-dss] exit={exitCode}");
            output.WriteLine(stdout);
            if (!string.IsNullOrEmpty(stderr))
            {
                output.WriteLine($"STDERR: {stderr}");
            }

            var combined = stdout + stderr;
            // EU DSS should report TOTAL_FAILED, fail to parse, or not report TOTAL_PASSED
            (combined.Contains("TOTAL_FAILED") || combined.Contains("NO_SIGNATURES")
                || combined.Contains("Unable to build") || !combined.Contains("TOTAL_PASSED")
                || exitCode != 0).ShouldBeTrue(
                "EU DSS should reject a PDF with tampered CMS signature");
        }
        finally
        {
            Directory.Delete(tmpDir, recursive: true);
        }
    }

    // ─── Helpers ───

    private static byte[] TamperPdfContents(byte[] signed)
    {
        var text = System.Text.Encoding.Latin1.GetString(signed);
        int contentsIdx = text.IndexOf("/Contents <", StringComparison.Ordinal);
        if (contentsIdx < 0)
            throw new InvalidOperationException("Could not find /Contents in signed PDF");
        contentsIdx += "/Contents <".Length;

        var tampered = (byte[])signed.Clone();
        // Find a hex digit deep inside the signature and swap it to another valid hex digit.
        // This preserves hex encoding validity while corrupting the CMS binary content.
        int offset = contentsIdx + 100;
        byte b = tampered[offset];
        // Swap '0'-'9' → shift by 1, 'A'-'F'/'a'-'f' → shift by 1
        if (b >= (byte)'0' && b <= (byte)'8')
            tampered[offset] = (byte)(b + 1);
        else if (b == (byte)'9')
            tampered[offset] = (byte)'0';
        else if (b >= (byte)'A' && b <= (byte)'E')
            tampered[offset] = (byte)(b + 1);
        else if (b == (byte)'F')
            tampered[offset] = (byte)'A';
        else if (b >= (byte)'a' && b <= (byte)'e')
            tampered[offset] = (byte)(b + 1);
        else if (b == (byte)'f')
            tampered[offset] = (byte)'a';
        else
            tampered[offset] = (byte)'0'; // fallback: replace with '0'

        return tampered;
    }

    private static void SkipIfDssUnavailable()
    {
        Skip.IfNot(DockerProbe.IsDockerAvailable(), "Docker is not available on this host.");
        Skip.IfNot(DockerProbe.ImageExists("simplesign-dss"),
            "Validator image not built. Run: docker build -t simplesign-dss interop/dss-validator");
    }

    private static void SkipIfITextUnavailable()
    {
        Skip.IfNot(DockerProbe.IsDockerAvailable(), "Docker is not available on this host.");
        Skip.IfNot(DockerProbe.ImageExists("simplesign-itext"),
            "iText image not built. Run: docker build -t simplesign-itext interop/itext");
    }

    private static void SkipIfEuDssUnavailable()
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
