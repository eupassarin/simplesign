using System.Diagnostics;
using Shouldly;
using SimpleSign.PAdES;
using SimpleSign.PAdES.Inspection;
using SimpleSign.TestHelpers;
using Xunit;
using Xunit.Abstractions;

namespace SimpleSign.Interop.Tests;

/// <summary>
/// Form field / named field signing interop: SimpleSign must be able to sign
/// into specific AcroForm fields and have those signatures recognized by
/// external validators.
/// </summary>
[Trait("Category", "Interop")]
public sealed class FormFieldInteropTests(ITestOutputHelper output)
{
    [SkippableFact(DisplayName = "Named field signature — pyHanko validates and detects field name")]
    public async Task NamedField_PyHankoValidates()
    {
        SkipIfDockerUnavailable("simplesign-dss");
        var pdf = MinimalPdf();
        using var cert = TestCertificateFactory.CreateSelfSignedCert("CN=Form Field Signer");

        var signed = await PadesSigner.Document(pdf)
            .WithCertificate(cert)
            .WithFieldName("Sig1")
            .SignAsync();

        // Inspector should see the field name
        using var stream = new MemoryStream(signed);
        var result = await PdfSignatureInspector.InspectAsync(stream);
        result.Signatures.ShouldContain(s => s.FieldName == "Sig1");

        // pyHanko should validate
        var tmpDir = CreateTempDir();
        await File.WriteAllBytesAsync(Path.Combine(tmpDir, "signed.pdf"), signed);
        try
        {
            var (stdout, stderr, exitCode) = await DockerRun(
                $"-v {tmpDir}:/in simplesign-dss validate-pades /in/signed.pdf");
            output.WriteLine(stdout);
            exitCode.ShouldBe(0);
            (stdout + stderr).ShouldContain("intact=True");
        }
        finally
        {
            Directory.Delete(tmpDir, recursive: true);
        }
    }

    [SkippableFact(DisplayName = "Existing empty field — iText validates and detects field")]
    public async Task ExistingField_ITextValidates()
    {
        SkipIfDockerUnavailable("simplesign-itext");
        var pdf = PdfWithEmptySignatureField("Signature1");
        using var cert = TestCertificateFactory.CreateSelfSignedCert("CN=Existing Field Signer");

        var signed = await PadesSigner.Document(pdf)
            .WithCertificate(cert)
            .WithExistingField("Signature1")
            .SignAsync();

        var tmpDir = CreateTempDir();
        await File.WriteAllBytesAsync(Path.Combine(tmpDir, "signed.pdf"), signed);
        try
        {
            var (stdout, stderr, exitCode) = await DockerRun(
                $"-v {tmpDir}:/in simplesign-itext validate-pdf /in/signed.pdf");
            output.WriteLine(stdout);
            exitCode.ShouldBe(0);
            stdout.ShouldContain("RESULT: VALID");
        }
        finally
        {
            Directory.Delete(tmpDir, recursive: true);
        }
    }

    private static byte[] MinimalPdf() =>
        "%PDF-1.7\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n2 0 obj\n<< /Type /Pages /Kids [] /Count 0 >>\nendobj\nxref\n0 3\n0000000000 65535 f \n0000000009 00000 n \n0000000058 00000 n \ntrailer\n<< /Size 3 /Root 1 0 R >>\nstartxref\n110\n%%EOF"u8.ToArray();

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

    private static byte[] PdfWithEmptySignatureField(string fieldName)
    {
        var offsets = new List<int>();
        var sb = new System.Text.StringBuilder();

        sb.Append("%PDF-1.7\n");

        offsets.Add(sb.Length);
        sb.Append($"1 0 obj\n<< /Type /Catalog /Pages 2 0 R /AcroForm 3 0 R >>\nendobj\n");

        offsets.Add(sb.Length);
        sb.Append("2 0 obj\n<< /Type /Pages /Kids [4 0 R] /Count 1 >>\nendobj\n");

        offsets.Add(sb.Length);
        sb.Append("3 0 obj\n<< /Fields [5 0 R] >>\nendobj\n");

        offsets.Add(sb.Length);
        sb.Append("4 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Annots [6 0 R] >>\nendobj\n");

        offsets.Add(sb.Length);
        sb.Append($"5 0 obj\n<< /Type /Annot /Subtype /Widget /FT /Sig /T ({fieldName}) /Rect [100 100 300 150] /P 4 0 R /F 4 >>\nendobj\n");

        offsets.Add(sb.Length);
        sb.Append("6 0 obj\n<< /Type /Annot /Subtype /Widget /Parent 5 0 R /Rect [100 100 300 150] /P 4 0 R >>\nendobj\n");

        int xrefOffset = sb.Length;
        int totalObjects = 7;
        sb.Append($"xref\n0 {totalObjects}\n");
        sb.Append("0000000000 65535 f\r\n");
        foreach (var offset in offsets)
            sb.Append($"{offset:D10} 00000 n\r\n");

        sb.Append($"trailer\n<< /Size {totalObjects} /Root 1 0 R >>\nstartxref\n{xrefOffset}\n%%EOF\n");

        return System.Text.Encoding.ASCII.GetBytes(sb.ToString());
    }
}
