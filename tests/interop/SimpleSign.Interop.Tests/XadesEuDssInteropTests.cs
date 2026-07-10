using System.Diagnostics;
using Shouldly;
using SimpleSign.TestHelpers;
using SimpleSign.XAdES;
using Xunit;
using Xunit.Abstractions;

namespace SimpleSign.Interop.Tests;

[Trait("Category", "Interop")]
public sealed class XadesEuDssInteropTests(ITestOutputHelper output)
{

    [SkippableFact(DisplayName = "XAdES-B-B validates under EU DSS")]
    public async Task XadesBB_ValidatesWithEuDss()
    {
        SkipIfDockerUnavailable();
        using var cert = TestCertificateFactory.CreateSelfSignedCert("CN=XAdES EU DSS Interop");
        string xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><doc><id>42</id></doc>";
        byte[] signed = await XadesSigner.SignAsync(
            System.Text.Encoding.UTF8.GetBytes(xml), cert);
        await ValidateXmlWithEuDss(signed, "xades-bb");
    }

    [SkippableFact(DisplayName = "XAdES-B-T validates under EU DSS")]
    public async Task XadesBT_ValidatesWithEuDss()
    {
        SkipIfDockerUnavailable();
        using var cert = TestCertificateFactory.CreateSelfSignedCert("CN=XAdES B-T EU DSS");
        string xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><doc><data>test</data></doc>";
        var result = await XadesSigner.Document(System.Text.Encoding.UTF8.GetBytes(xml))
            .WithCertificate(cert)
            .WithLevel(XadesLevel.Timestamped)
            .SignWithDetailsAsync();
        await ValidateXmlWithEuDss(result.SignedXml, "xades-b-t");
    }

    [SkippableFact(DisplayName = "XAdES-B-LT validates under EU DSS")]
    public async Task XadesBLT_ValidatesWithEuDss()
    {
        SkipIfDockerUnavailable();
        using var cert = TestCertificateFactory.CreateSelfSignedCert("CN=XAdES B-LT EU DSS");
        string xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><doc><ltv>yes</ltv></doc>";
        var result = await XadesSigner.Document(System.Text.Encoding.UTF8.GetBytes(xml))
            .WithCertificate(cert)
            .WithLevel(XadesLevel.LongTerm)
            .SignWithDetailsAsync();
        await ValidateXmlWithEuDss(result.SignedXml, "xades-b-lt");
    }

    [SkippableFact(DisplayName = "XAdES double-signed validates under EU DSS")]
    public async Task XadesDoubleSigned_ValidatesWithEuDss()
    {
        SkipIfDockerUnavailable();
        using var cert1 = TestCertificateFactory.CreateSelfSignedCert("CN=XAdES Signer 1");
        using var cert2 = TestCertificateFactory.CreateSelfSignedCert("CN=XAdES Signer 2");
        string xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><doc>multi</doc>";
        byte[] xmlBytes = System.Text.Encoding.UTF8.GetBytes(xml);
        byte[] signed1 = await XadesSigner.SignAsync(xmlBytes, cert1);
        byte[] signed2 = await XadesSigner.SignAsync(signed1, cert2);
        await ValidateXmlWithEuDss(signed2, "xades-double-signed");
    }

    [SkippableFact(DisplayName = "XAdES-B-B Detached validates under EU DSS")]
    public async Task XadesBB_Detached_ValidatesWithEuDss()
    {
        SkipIfDockerUnavailable();
        using var cert = TestCertificateFactory.CreateSelfSignedCert("CN=XAdES Detached EU DSS");
        string xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><doc><id>detached</id></doc>";
        byte[] xmlBytes = System.Text.Encoding.UTF8.GetBytes(xml);
        byte[] signed = await XadesSigner.Document(xmlBytes)
            .WithCertificate(cert)
            .WithForm(XadesForm.Detached)
            .WithDataUri("data.xml")
            .SignAsync();
        await ValidateXmlWithEuDssDetached(signed, xmlBytes, "xades-bb-detached");
    }

    [SkippableFact(DisplayName = "XAdES-B-T Detached validates under EU DSS")]
    public async Task XadesBT_Detached_ValidatesWithEuDss()
    {
        SkipIfDockerUnavailable();
        using var cert = TestCertificateFactory.CreateSelfSignedCert("CN=XAdES B-T Detached EU DSS");
        string xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><doc><data>timestamped</data></doc>";
        byte[] xmlBytes = System.Text.Encoding.UTF8.GetBytes(xml);
        var result = await XadesSigner.Document(xmlBytes)
            .WithCertificate(cert)
            .WithForm(XadesForm.Detached)
            .WithDataUri("data.xml")
            .WithLevel(XadesLevel.Timestamped)
            .SignWithDetailsAsync();
        await ValidateXmlWithEuDssDetached(result.SignedXml, xmlBytes, "xades-bt-detached");
    }

    [SkippableFact(DisplayName = "XAdES-B-LT Detached validates under EU DSS")]
    public async Task XadesBLT_Detached_ValidatesWithEuDss()
    {
        SkipIfDockerUnavailable();
        using var cert = TestCertificateFactory.CreateSelfSignedCert("CN=XAdES B-LT Detached EU DSS");
        string xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><doc><ltv>detached</ltv></doc>";
        byte[] xmlBytes = System.Text.Encoding.UTF8.GetBytes(xml);
        var result = await XadesSigner.Document(xmlBytes)
            .WithCertificate(cert)
            .WithForm(XadesForm.Detached)
            .WithDataUri("data.xml")
            .WithLevel(XadesLevel.LongTerm)
            .SignWithDetailsAsync();
        await ValidateXmlWithEuDssDetached(result.SignedXml, xmlBytes, "xades-blt-detached");
    }

    [SkippableFact(DisplayName = "XAdES-B-B Enveloping validates under EU DSS")]
    public async Task XadesBB_Enveloping_ValidatesWithEuDss()
    {
        SkipIfDockerUnavailable();
        using var cert = TestCertificateFactory.CreateSelfSignedCert("CN=XAdES Enveloping EU DSS");
        string xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><doc><id>enveloping</id></doc>";
        byte[] xmlBytes = System.Text.Encoding.UTF8.GetBytes(xml);
        byte[] signed = await XadesSigner.Document(xmlBytes)
            .WithCertificate(cert)
            .WithForm(XadesForm.Enveloping)
            .SignAsync();
        await ValidateXmlWithEuDss(signed, "xades-bb-enveloping");
    }

    [SkippableFact(DisplayName = "XAdES-B-T Enveloping validates under EU DSS")]
    public async Task XadesBT_Enveloping_ValidatesWithEuDss()
    {
        SkipIfDockerUnavailable();
        using var cert = TestCertificateFactory.CreateSelfSignedCert("CN=XAdES B-T Enveloping EU DSS");
        string xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><doc><data>ts env</data></doc>";
        byte[] xmlBytes = System.Text.Encoding.UTF8.GetBytes(xml);
        var result = await XadesSigner.Document(xmlBytes)
            .WithCertificate(cert)
            .WithForm(XadesForm.Enveloping)
            .WithLevel(XadesLevel.Timestamped)
            .SignWithDetailsAsync();
        await ValidateXmlWithEuDss(result.SignedXml, "xades-bt-enveloping");
    }

    [SkippableFact(DisplayName = "XAdES-B-LT Enveloping validates under EU DSS")]
    public async Task XadesBLT_Enveloping_ValidatesWithEuDss()
    {
        SkipIfDockerUnavailable();
        using var cert = TestCertificateFactory.CreateSelfSignedCert("CN=XAdES B-LT Enveloping EU DSS");
        string xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><doc><ltv>env</ltv></doc>";
        byte[] xmlBytes = System.Text.Encoding.UTF8.GetBytes(xml);
        var result = await XadesSigner.Document(xmlBytes)
            .WithCertificate(cert)
            .WithForm(XadesForm.Enveloping)
            .WithLevel(XadesLevel.LongTerm)
            .SignWithDetailsAsync();
        await ValidateXmlWithEuDss(result.SignedXml, "xades-blt-enveloping");
    }

    private static void SkipIfDockerUnavailable()
    {
        Skip.IfNot(DockerProbe.IsDockerAvailable(), "Docker is not available on this host.");
        Skip.IfNot(DockerProbe.ImageExists("simplesign-eu-dss"),
            "EU DSS image not built. Run: docker build -t simplesign-eu-dss interop/eu-dss");
    }

    private static string CreateTempDir()
    {
        var dir = Path.Combine(Path.GetTempPath(), $"simplesign-xades-interop-{Guid.NewGuid():N}");
        Directory.CreateDirectory(dir);
        return dir;
    }

    private async Task ValidateXmlWithEuDss(byte[] xmlBytes, string label)
    {
        var tmpDir = CreateTempDir();
        await File.WriteAllBytesAsync(Path.Combine(tmpDir, "signed.xml"), xmlBytes);
        try
        {
            var (stdout, stderr, exitCode) = await DockerRun(
                $"-v {tmpDir}:/in simplesign-eu-dss validate-xades /in/signed.xml");
            output.WriteLine($"[{label}] exit={exitCode}");
            output.WriteLine(stdout);
            if (!string.IsNullOrEmpty(stderr))
            {
                output.WriteLine($"STDERR: {stderr}");
            }
            (stdout.Contains("TOTAL_PASSED") || stdout.Contains("INDETERMINATE")).ShouldBeTrue(
                "EU DSS should report TOTAL_PASSED or INDETERMINATE for self-signed certs");
        }
        finally
        {
            Directory.Delete(tmpDir, recursive: true);
        }
    }

    private async Task ValidateXmlWithEuDssDetached(byte[] sigBytes, byte[] dataBytes, string label)
    {
        var tmpDir = CreateTempDir();
        await File.WriteAllBytesAsync(Path.Combine(tmpDir, "signed.xml"), sigBytes);
        await File.WriteAllBytesAsync(Path.Combine(tmpDir, "data.xml"), dataBytes);
        try
        {
            var (stdout, stderr, exitCode) = await DockerRun(
                $"-v {tmpDir}:/in simplesign-eu-dss validate-xades-detached /in/signed.xml /in/data.xml");
            output.WriteLine($"[{label}] exit={exitCode}");
            output.WriteLine(stdout);
            if (!string.IsNullOrEmpty(stderr))
            {
                output.WriteLine($"STDERR: {stderr}");
            }
            (stdout.Contains("TOTAL_PASSED") || stdout.Contains("INDETERMINATE")).ShouldBeTrue(
                "EU DSS should report TOTAL_PASSED or INDETERMINATE for self-signed certs");
        }
        finally
        {
            Directory.Delete(tmpDir, recursive: true);
        }
    }

    private static async Task<(string stdout, string stderr, int exitCode)> DockerRun(string args)
    {
        using var p = new Process
        {
            StartInfo = new ProcessStartInfo("docker", $"run --rm {args}")
            {
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
            },
        };
        p.Start();
        var stdoutTask = p.StandardOutput.ReadToEndAsync();
        var stderrTask = p.StandardError.ReadToEndAsync();
        await p.WaitForExitAsync();
        await Task.WhenAll(stdoutTask, stderrTask);
        return (stdoutTask.Result, stderrTask.Result, p.ExitCode);
    }
}
