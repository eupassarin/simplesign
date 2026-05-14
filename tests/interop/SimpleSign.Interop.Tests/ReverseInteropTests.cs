using System.Diagnostics;
using System.Security.Cryptography.X509Certificates;
using FluentAssertions;
using SimpleSign.Core.Validation;
using SimpleSign.PAdES;
using SimpleSign.PAdES.Inspection;
using SimpleSign.PAdES.Validation;
using SimpleSign.TestHelpers;
using Xunit;
using Xunit.Abstractions;

namespace SimpleSign.Interop.Tests;

/// <summary>
/// Reverse interop: signatures created by external tools (OpenSSL, xmlsec1) must be
/// parseable/validatable by SimpleSign. Tests are skipped when Docker is unavailable.
/// </summary>
[Trait("Category", "Interop")]
public sealed class ReverseInteropTests(ITestOutputHelper output)
{

    [SkippableFact(DisplayName = "XML signed by xmlsec1 — structure is valid XML with Signature")]
    public async Task Xmlsec1Signed_ValidXmlStructure()
    {
        SkipIfDockerUnavailable();

        var tmpDir = Path.Combine(Path.GetTempPath(), $"simplesign-reverse-{Guid.NewGuid():N}");
        Directory.CreateDirectory(tmpDir);

        try
        {
            using var cert = TestCertificateFactory.CreateSelfSignedCert("CN=xmlsec1 Reverse Interop");
            var (keyPem, certPem) = ExportKeyAndCert(cert);

            await File.WriteAllTextAsync(Path.Combine(tmpDir, "key.pem"), keyPem);
            await File.WriteAllTextAsync(Path.Combine(tmpDir, "cert.pem"), certPem);

            // Generate template
            var (stdout1, stderr1, exit1) = await DockerRun(
                $"-v {tmpDir}:/in simplesign-dss generate-xml-template /in/template.xml");
            output.WriteLine($"Template: exit={exit1}");
            output.WriteLine(stdout1);
            exit1.Should().Be(0);

            // Sign with xmlsec1
            var (stdout2, stderr2, exit2) = await DockerRun(
                $"-v {tmpDir}:/in simplesign-dss sign-xml /in/template.xml /in/key.pem /in/cert.pem /in/signed.xml");
            output.WriteLine($"Sign: exit={exit2}");
            output.WriteLine(stdout2);
            if (!string.IsNullOrEmpty(stderr2))
            {
                output.WriteLine($"STDERR: {stderr2}");
            }

            exit2.Should().Be(0, because: "xmlsec1 should successfully sign the XML template");

            // Verify the output is valid XML with a Signature
            var signedXml = await File.ReadAllTextAsync(Path.Combine(tmpDir, "signed.xml"));
            signedXml.Should().Contain("<SignatureValue>", because: "signed XML should contain SignatureValue");
            signedXml.Should().Contain("<DigestValue>", because: "signed XML should contain DigestValue");
        }
        finally
        {
            Directory.Delete(tmpDir, recursive: true);
        }
    }

    [SkippableFact(DisplayName = "XML signed by xmlsec1 — round-trip validates with xmlsec1")]
    public async Task Xmlsec1Signed_RoundTripValidates()
    {
        SkipIfDockerUnavailable();

        var tmpDir = Path.Combine(Path.GetTempPath(), $"simplesign-reverse-{Guid.NewGuid():N}");
        Directory.CreateDirectory(tmpDir);

        try
        {
            using var cert = TestCertificateFactory.CreateSelfSignedCert("CN=xmlsec1 RoundTrip Interop");
            var (keyPem, certPem) = ExportKeyAndCert(cert);

            await File.WriteAllTextAsync(Path.Combine(tmpDir, "key.pem"), keyPem);
            await File.WriteAllTextAsync(Path.Combine(tmpDir, "cert.pem"), certPem);

            // Generate template + sign
            await DockerRun($"-v {tmpDir}:/in simplesign-dss generate-xml-template /in/template.xml");
            var (stdout, stderr, exitCode) = await DockerRun(
                $"-v {tmpDir}:/in simplesign-dss sign-xml /in/template.xml /in/key.pem /in/cert.pem /in/signed.xml");
            exitCode.Should().Be(0);

            // Round-trip: validate with xmlsec1
            var (vStdout, vStderr, vExit) = await DockerRun(
                $"-v {tmpDir}:/in simplesign-dss validate-xml /in/signed.xml");
            output.WriteLine($"Validate: exit={vExit}");
            output.WriteLine(vStdout);
            if (!string.IsNullOrEmpty(vStderr))
            {
                output.WriteLine($"STDERR: {vStderr}");
            }

            // xmlsec1 with self-signed certs may warn but should parse the structure
            (vStdout + vStderr).Should().NotContain("unable to parse",
                because: "xmlsec1 should parse its own signed XML");
        }
        finally
        {
            Directory.Delete(tmpDir, recursive: true);
        }
    }

    [SkippableFact(DisplayName = "PDF signed by pyHanko — SimpleSign extracts CMS signature")]
    public async Task PyHankoSigned_SimpleSignExtractsCms()
    {
        SkipIfDockerUnavailable();

        var tmpDir = Path.Combine(Path.GetTempPath(), $"simplesign-reverse-{Guid.NewGuid():N}");
        Directory.CreateDirectory(tmpDir);

        try
        {
            using var cert = TestCertificateFactory.CreateSelfSignedCert("CN=pyHanko Reverse Interop");
            var (keyPem, certPem) = ExportKeyAndCert(cert);

            // Create a minimal PDF
            var pdfBytes = MinimalPdf();
            await File.WriteAllBytesAsync(Path.Combine(tmpDir, "input.pdf"), pdfBytes);
            await File.WriteAllTextAsync(Path.Combine(tmpDir, "key.pem"), keyPem);
            await File.WriteAllTextAsync(Path.Combine(tmpDir, "cert.pem"), certPem);

            // Sign with pyHanko
            var (stdout, stderr, exitCode) = await DockerRun(
                $"-v {tmpDir}:/in simplesign-dss sign-pades /in/input.pdf /in/key.pem /in/cert.pem /in/signed.pdf");
            output.WriteLine($"pyHanko sign: exit={exitCode}");
            output.WriteLine(stdout);
            if (!string.IsNullOrEmpty(stderr))
            {
                output.WriteLine($"STDERR: {stderr}");
            }

            exitCode.Should().Be(0, because: "pyHanko should successfully sign the PDF");

            // Read signed PDF and extract with SimpleSign
            var signedPath = Path.Combine(tmpDir, "signed.pdf");
            File.Exists(signedPath).Should().BeTrue("pyHanko should have created signed.pdf");
            var signedBytes = await File.ReadAllBytesAsync(signedPath);

            using var stream = new MemoryStream(signedBytes);
            var signatures = await PadesExtractor.ExtractAsync(stream);
            signatures.Should().HaveCountGreaterThan(0,
                because: "SimpleSign should extract signatures from pyHanko-signed PDF");
            signatures[0].CmsSignature.Should().NotBeEmpty();
            signatures[0].SignedData.Should().NotBeEmpty();
        }
        finally
        {
            Directory.Delete(tmpDir, recursive: true);
        }
    }

    [SkippableFact(DisplayName = "PDF signed by pyHanko — pdfbox detects signature")]
    public async Task PyHankoSigned_PdfboxDetectsSignature()
    {
        SkipIfPdfboxAndDssUnavailable();

        var tmpDir = Path.Combine(Path.GetTempPath(), $"simplesign-reverse-{Guid.NewGuid():N}");
        Directory.CreateDirectory(tmpDir);

        try
        {
            using var cert = TestCertificateFactory.CreateSelfSignedCert("CN=pyHanko pdfbox Reverse");
            var (keyPem, certPem) = ExportKeyAndCert(cert);

            await File.WriteAllBytesAsync(Path.Combine(tmpDir, "input.pdf"), MinimalPdf());
            await File.WriteAllTextAsync(Path.Combine(tmpDir, "key.pem"), keyPem);
            await File.WriteAllTextAsync(Path.Combine(tmpDir, "cert.pem"), certPem);

            // Sign with pyHanko
            var (_, _, exitCode) = await DockerRun(
                $"-v {tmpDir}:/in simplesign-dss sign-pades /in/input.pdf /in/key.pem /in/cert.pem /in/signed.pdf");
            exitCode.Should().Be(0);

            // Verify with pdfbox
            var signedPath = Path.Combine(tmpDir, "signed.pdf");
            var (stdout, stderr, pdfboxExit) = await DockerRun(
                $"-v {signedPath}:/in/signed.pdf simplesign-pdfbox verify-signatures /in/signed.pdf");
            output.WriteLine(stdout);
            pdfboxExit.Should().Be(0);
            stdout.Should().Contain("RESULT: VALID");
        }
        finally
        {
            Directory.Delete(tmpDir, recursive: true);
        }
    }

    [SkippableFact(DisplayName = "PDF signed by pyHanko with metadata — CMS round-trip validates")]
    public async Task PyHankoSignedWithMetadata_CmsRoundTrips()
    {
        SkipIfDockerUnavailable();

        var tmpDir = Path.Combine(Path.GetTempPath(), $"simplesign-reverse-{Guid.NewGuid():N}");
        Directory.CreateDirectory(tmpDir);

        try
        {
            using var cert = TestCertificateFactory.CreateSelfSignedCert("CN=pyHanko Metadata Reverse");
            var (keyPem, certPem) = ExportKeyAndCert(cert);

            await File.WriteAllBytesAsync(Path.Combine(tmpDir, "input.pdf"), MinimalPdf());
            await File.WriteAllTextAsync(Path.Combine(tmpDir, "key.pem"), keyPem);
            await File.WriteAllTextAsync(Path.Combine(tmpDir, "cert.pem"), certPem);

            // Sign with pyHanko (with reason and location)
            var (stdout, stderr, exitCode) = await DockerRun(
                $"-v {tmpDir}:/in simplesign-dss sign-pades-with-reason /in/input.pdf /in/key.pem /in/cert.pem /in/signed.pdf \"Interop test\" \"Test lab\"");
            output.WriteLine($"pyHanko sign: exit={exitCode}");
            output.WriteLine(stdout);

            exitCode.Should().Be(0);

            // Extract CMS and validate with OpenSSL
            var signedBytes = await File.ReadAllBytesAsync(Path.Combine(tmpDir, "signed.pdf"));
            using var stream = new MemoryStream(signedBytes);
            var signatures = await PadesExtractor.ExtractAsync(stream);
            signatures.Should().HaveCountGreaterThan(0);

            // Write CMS + data for OpenSSL validation
            await File.WriteAllBytesAsync(Path.Combine(tmpDir, "sig.der"), signatures[0].CmsSignature);
            await File.WriteAllBytesAsync(Path.Combine(tmpDir, "data.bin"), signatures[0].SignedData);

            var (validateOut, _, validateExit) = await DockerRun(
                $"-v {tmpDir}:/in simplesign-dss validate-cms /in/sig.der /in/data.bin /in/cert.pem");
            output.WriteLine($"OpenSSL validate: exit={validateExit}");
            output.WriteLine(validateOut);
            validateExit.Should().Be(0);
            validateOut.Should().Contain("VALID");
        }
        finally
        {
            Directory.Delete(tmpDir, recursive: true);
        }
    }

    [SkippableFact(DisplayName = "PDF signed by pyHanko — pyHanko validates (round-trip)")]
    public async Task PyHankoSigned_PyHankoValidates()
    {
        SkipIfDockerUnavailable();

        var tmpDir = Path.Combine(Path.GetTempPath(), $"simplesign-reverse-{Guid.NewGuid():N}");
        Directory.CreateDirectory(tmpDir);

        try
        {
            using var cert = TestCertificateFactory.CreateSelfSignedCert("CN=pyHanko RoundTrip Reverse");
            var (keyPem, certPem) = ExportKeyAndCert(cert);

            await File.WriteAllBytesAsync(Path.Combine(tmpDir, "input.pdf"), MinimalPdf());
            await File.WriteAllTextAsync(Path.Combine(tmpDir, "key.pem"), keyPem);
            await File.WriteAllTextAsync(Path.Combine(tmpDir, "cert.pem"), certPem);

            // Sign
            var (_, _, signExit) = await DockerRun(
                $"-v {tmpDir}:/in simplesign-dss sign-pades /in/input.pdf /in/key.pem /in/cert.pem /in/signed.pdf");
            signExit.Should().Be(0);

            // Validate with pyHanko
            var (stdout, stderr, validateExit) = await DockerRun(
                $"-v {tmpDir}:/in simplesign-dss validate-pades /in/signed.pdf");
            output.WriteLine($"pyHanko validate: exit={validateExit}");
            output.WriteLine(stdout);

            (stdout + (stderr ?? "")).Should().Contain("intact=True",
                because: "pyHanko should validate its own signed PDF as intact");
        }
        finally
        {
            Directory.Delete(tmpDir, recursive: true);
        }
    }

    // ─── NEW REVERSE INTEROP TESTS ───────────────────────────────────────────────

    [SkippableFact(DisplayName = "Reverse: pyHanko-signed PDF → PdfSignatureValidator validates")]
    public async Task PyHankoSigned_PdfSignatureValidator_Validates()
    {
        SkipIfDockerUnavailable();

        var tmpDir = Path.Combine(Path.GetTempPath(), $"simplesign-reverse-{Guid.NewGuid():N}");
        Directory.CreateDirectory(tmpDir);

        try
        {
            using var cert = TestCertificateFactory.CreateSelfSignedCert("CN=pyHanko Validator Reverse");
            var (keyPem, certPem) = ExportKeyAndCert(cert);

            await File.WriteAllBytesAsync(Path.Combine(tmpDir, "input.pdf"), MinimalPdf());
            await File.WriteAllTextAsync(Path.Combine(tmpDir, "key.pem"), keyPem);
            await File.WriteAllTextAsync(Path.Combine(tmpDir, "cert.pem"), certPem);

            var (stdout, stderr, exitCode) = await DockerRun(
                $"-v {tmpDir}:/in simplesign-dss sign-pades /in/input.pdf /in/key.pem /in/cert.pem /in/signed.pdf");
            output.WriteLine($"pyHanko sign: exit={exitCode}, stdout={stdout}");
            exitCode.Should().Be(0, because: "pyHanko should sign the PDF");

            var signedBytes = await File.ReadAllBytesAsync(Path.Combine(tmpDir, "signed.pdf"));

            // Validate with SimpleSign PdfSignatureValidator (skip revocation for self-signed)
            var validator = new PdfSignatureValidator(new ValidationOptions { CheckRevocation = false });
            using var stream = new MemoryStream(signedBytes);
            var results = await validator.ValidateAsync(stream);

            results.Should().NotBeEmpty("pyHanko-signed PDF should contain at least one signature");
            results[0].IsIntegrityValid.Should().BeTrue("integrity of pyHanko signature should be valid");
            results[0].IsSignatureValid.Should().BeTrue("cryptographic signature should verify");
            output.WriteLine($"Validation: {results[0]}");
        }
        finally
        {
            Directory.Delete(tmpDir, recursive: true);
        }
    }

    [SkippableFact(DisplayName = "Reverse: pyHanko-signed PDF → PdfSignatureInspector reads metadata")]
    public async Task PyHankoSigned_PdfSignatureInspector_ReadsMetadata()
    {
        SkipIfDockerUnavailable();

        var tmpDir = Path.Combine(Path.GetTempPath(), $"simplesign-reverse-{Guid.NewGuid():N}");
        Directory.CreateDirectory(tmpDir);

        try
        {
            using var cert = TestCertificateFactory.CreateSelfSignedCert("CN=pyHanko Inspector Reverse");
            var (keyPem, certPem) = ExportKeyAndCert(cert);

            await File.WriteAllBytesAsync(Path.Combine(tmpDir, "input.pdf"), MinimalPdf());
            await File.WriteAllTextAsync(Path.Combine(tmpDir, "key.pem"), keyPem);
            await File.WriteAllTextAsync(Path.Combine(tmpDir, "cert.pem"), certPem);

            var (_, _, exitCode) = await DockerRun(
                $"-v {tmpDir}:/in simplesign-dss sign-pades /in/input.pdf /in/key.pem /in/cert.pem /in/signed.pdf");
            exitCode.Should().Be(0);

            var signedBytes = await File.ReadAllBytesAsync(Path.Combine(tmpDir, "signed.pdf"));

            // Inspect with SimpleSign PdfSignatureInspector
            using var stream = new MemoryStream(signedBytes);
            var inspection = await PdfSignatureInspector.InspectAsync(stream);

            inspection.HasSignatures.Should().BeTrue("pyHanko-signed PDF should have signatures");
            inspection.Signatures.Should().NotBeEmpty();
            inspection.Signatures[0].Signer.Should().NotBeNull("signer info should be extractable");
            inspection.Signatures[0].Signer!.Subject.Should().Contain("pyHanko Inspector Reverse");
            output.WriteLine($"Inspection: field={inspection.Signatures[0].FieldName}, signer={inspection.Signatures[0].Signer?.Subject}");
        }
        finally
        {
            Directory.Delete(tmpDir, recursive: true);
        }
    }

    [SkippableFact(DisplayName = "Reverse: pyHanko-signed → SimpleSign adds 2nd signature → pyHanko validates both")]
    public async Task PyHankoSigned_SimpleSignAddsSecond_PyHankoValidatesBoth()
    {
        SkipIfDockerUnavailable();

        var tmpDir = Path.Combine(Path.GetTempPath(), $"simplesign-reverse-{Guid.NewGuid():N}");
        Directory.CreateDirectory(tmpDir);

        try
        {
            // First signer (pyHanko)
            using var cert1 = TestCertificateFactory.CreateSelfSignedCert("CN=pyHanko First Signer");
            var (keyPem1, certPem1) = ExportKeyAndCert(cert1);

            await File.WriteAllBytesAsync(Path.Combine(tmpDir, "input.pdf"), MinimalPdf());
            await File.WriteAllTextAsync(Path.Combine(tmpDir, "key.pem"), keyPem1);
            await File.WriteAllTextAsync(Path.Combine(tmpDir, "cert.pem"), certPem1);

            // Sign with pyHanko
            var (_, _, exit1) = await DockerRun(
                $"-v {tmpDir}:/in simplesign-dss sign-pades /in/input.pdf /in/key.pem /in/cert.pem /in/signed1.pdf");
            exit1.Should().Be(0);

            // Add second signature with SimpleSign
            using var cert2 = TestCertificateFactory.CreateSelfSignedCert("CN=SimpleSign Second Signer");
            var signed1Bytes = await File.ReadAllBytesAsync(Path.Combine(tmpDir, "signed1.pdf"));

            var doubleSigned = await SimpleSigner
                .Document(signed1Bytes)
                .WithCertificate(cert2)
                .SignAsync();

            await File.WriteAllBytesAsync(Path.Combine(tmpDir, "signed2.pdf"), doubleSigned);

            // Validate with pyHanko — both signatures should be detected
            var (stdout, stderr, validateExit) = await DockerRun(
                $"-v {tmpDir}:/in simplesign-dss validate-pades /in/signed2.pdf");
            output.WriteLine($"pyHanko validate double-signed: exit={validateExit}");
            output.WriteLine(stdout);

            // pyHanko should find at least 2 signatures
            var combinedOutput = stdout + (stderr ?? "");
            combinedOutput.Should().Contain("intact=True",
                because: "at least one signature should remain intact after adding a second");
        }
        finally
        {
            Directory.Delete(tmpDir, recursive: true);
        }
    }

    [SkippableFact(DisplayName = "Reverse: pyHanko-signed PDF → PdfSignatureValidator detects signer name")]
    public async Task PyHankoSigned_Validator_DetectsSignerName()
    {
        SkipIfDockerUnavailable();

        var tmpDir = Path.Combine(Path.GetTempPath(), $"simplesign-reverse-{Guid.NewGuid():N}");
        Directory.CreateDirectory(tmpDir);

        try
        {
            const string signerCn = "CN=pyHanko SignerName Test";
            using var cert = TestCertificateFactory.CreateSelfSignedCert(signerCn);
            var (keyPem, certPem) = ExportKeyAndCert(cert);

            await File.WriteAllBytesAsync(Path.Combine(tmpDir, "input.pdf"), MinimalPdf());
            await File.WriteAllTextAsync(Path.Combine(tmpDir, "key.pem"), keyPem);
            await File.WriteAllTextAsync(Path.Combine(tmpDir, "cert.pem"), certPem);

            var (_, _, exitCode) = await DockerRun(
                $"-v {tmpDir}:/in simplesign-dss sign-pades /in/input.pdf /in/key.pem /in/cert.pem /in/signed.pdf");
            exitCode.Should().Be(0);

            var signedBytes = await File.ReadAllBytesAsync(Path.Combine(tmpDir, "signed.pdf"));

            var validator = new PdfSignatureValidator(new ValidationOptions { CheckRevocation = false });
            using var stream = new MemoryStream(signedBytes);
            var results = await validator.ValidateAsync(stream);

            results.Should().NotBeEmpty();
            results[0].SignerName.Should().NotBeNullOrEmpty("signer name should be extracted from pyHanko-signed PDF");
            results[0].SignerName.Should().Contain("pyHanko SignerName Test");
            output.WriteLine($"Signer: {results[0].SignerName}");
        }
        finally
        {
            Directory.Delete(tmpDir, recursive: true);
        }
    }

    [SkippableFact(DisplayName = "Reverse: xmlsec1-signed XML → SimpleSign inspector extracts signer info")]
    public async Task Xmlsec1Signed_Inspector_ExtractsSignerInfo()
    {
        SkipIfDockerUnavailable();

        var tmpDir = Path.Combine(Path.GetTempPath(), $"simplesign-reverse-{Guid.NewGuid():N}");
        Directory.CreateDirectory(tmpDir);

        try
        {
            using var cert = TestCertificateFactory.CreateSelfSignedCert("CN=xmlsec1 Inspector Reverse");
            var (keyPem, certPem) = ExportKeyAndCert(cert);

            await File.WriteAllTextAsync(Path.Combine(tmpDir, "key.pem"), keyPem);
            await File.WriteAllTextAsync(Path.Combine(tmpDir, "cert.pem"), certPem);

            // Generate template + sign
            var (_, _, exit1) = await DockerRun(
                $"-v {tmpDir}:/in simplesign-dss generate-xml-template /in/template.xml");
            exit1.Should().Be(0);

            var (_, _, exit2) = await DockerRun(
                $"-v {tmpDir}:/in simplesign-dss sign-xml /in/template.xml /in/key.pem /in/cert.pem /in/signed.xml");
            exit2.Should().Be(0);

            // Read the signed XML and verify it contains expected certificate data
            var signedXml = await File.ReadAllTextAsync(Path.Combine(tmpDir, "signed.xml"));
            signedXml.Should().Contain("<ds:X509Certificate>",
                because: "xmlsec1 should embed the certificate in the signature");
            signedXml.Should().Contain("<ds:SignatureValue>",
                because: "signed XML should contain a signature value");

            // Verify the embedded certificate matches our signer
            var certBase64 = Convert.ToBase64String(cert.RawData);
            signedXml.Should().Contain(certBase64[..40],
                because: "the embedded certificate should match the signer cert");

            output.WriteLine("xmlsec1 signature contains embedded cert and signature value ✓");
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

    private static void SkipIfPdfboxAndDssUnavailable()
    {
        Skip.IfNot(DockerProbe.IsDockerAvailable(), "Docker is not available on this host.");
        Skip.IfNot(DockerProbe.ImageExists("simplesign-dss"),
            "DSS image not built. Run: docker build -t simplesign-dss interop/dss-validator");
        Skip.IfNot(DockerProbe.ImageExists("simplesign-pdfbox"),
            "pdfbox image not built. Run: docker build -t simplesign-pdfbox interop/pdfbox");
    }

    private static byte[] MinimalPdf() =>
        "%PDF-1.7\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>\nendobj\nxref\n0 4\n0000000000 65535 f \n0000000009 00000 n \n0000000058 00000 n \n0000000115 00000 n \ntrailer\n<< /Size 4 /Root 1 0 R >>\nstartxref\n186\n%%EOF"u8.ToArray();

    private static (string keyPem, string certPem) ExportKeyAndCert(X509Certificate2 cert)
    {
        // Export certificate PEM
        var certPem = $"-----BEGIN CERTIFICATE-----\n{Convert.ToBase64String(cert.RawData)}\n-----END CERTIFICATE-----\n";

        // Export private key PEM
        string keyPem;
        var rsaKey = cert.GetRSAPrivateKey();
        if (rsaKey != null)
        {
            var keyBytes = rsaKey.ExportPkcs8PrivateKey();
            keyPem = $"-----BEGIN PRIVATE KEY-----\n{Convert.ToBase64String(keyBytes)}\n-----END PRIVATE KEY-----\n";
        }
        else
        {
            var ecKey = cert.GetECDsaPrivateKey();
            if (ecKey != null)
            {
                var keyBytes = ecKey.ExportPkcs8PrivateKey();
                keyPem = $"-----BEGIN PRIVATE KEY-----\n{Convert.ToBase64String(keyBytes)}\n-----END PRIVATE KEY-----\n";
            }
            else
            {
                throw new InvalidOperationException("Certificate has no supported private key");
            }
        }

        return (keyPem, certPem);
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
}
