using System.Diagnostics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Shouldly;
using SimpleSign.PAdES;
using SimpleSign.PAdES.Inspection;
using SimpleSign.PAdES.Signing;
using SimpleSign.TestHelpers;
using Xunit;
using Xunit.Abstractions;

namespace SimpleSign.Interop.Tests;

/// <summary>
/// PAdES interop: PDFs signed by SimpleSign must have their embedded CMS/PKCS#7
/// signatures verifiable by OpenSSL, and their PDF structure parseable by pdfbox.
/// Tests are skipped when Docker or prebuilt images are unavailable.
/// </summary>
[Trait("Category", "Interop")]
public sealed class PadesDssInteropTests(ITestOutputHelper output)
{
    [SkippableFact(DisplayName = "PAdES-B-B CMS signature validates under OpenSSL")]
    public async Task PadesBB_CmsValidatesWithOpenSsl()
    {
        SkipIfDockerUnavailable();

        var pdf = MinimalPdf();
        using var cert = TestCertificateFactory.CreateSelfSignedCert("CN=PAdES Interop Signer");

        var signed = await SimpleSigner.Document(pdf).WithCertificate(cert).SignAsync();

        // Extract CMS from the signed PDF
        using var stream = new MemoryStream(signed);
        var signatures = await PadesExtractor.ExtractAsync(stream);

        signatures.Count().ShouldBeGreaterThan(0);
        var sig = signatures[0];

        await ValidateDetachedCms(sig.CmsSignature, sig.SignedData, cert, "pades-bb");
    }

    [SkippableFact(DisplayName = "PAdES-B-B with LTV — CMS validates under OpenSSL")]
    public async Task PadesBB_WithLtv_CmsValidatesWithOpenSsl()
    {
        SkipIfDockerUnavailable();

        var pdf = MinimalPdf();
        using var cert = TestCertificateFactory.CreateSelfSignedCert("CN=PAdES LTV Interop");

        var signed = await SimpleSigner.Document(pdf)
            .WithCertificate(cert)
            .WithTimestamp("http://timestamp.digicert.com")
            .WithLtv()
            .SignAsync();

        using var stream = new MemoryStream(signed);
        var signatures = await PadesExtractor.ExtractAsync(stream);
        var sig = signatures[0];

        await ValidateDetachedCms(sig.CmsSignature, sig.SignedData, cert, "pades-bb-ltv");
    }

    [SkippableFact(DisplayName = "Double-signed PAdES — both CMS signatures validate under OpenSSL")]
    public async Task PadesDoubleSigned_BothCmsValidate()
    {
        SkipIfDockerUnavailable();

        var pdf = MinimalPdf();
        using var cert1 = TestCertificateFactory.CreateSelfSignedCert("CN=PAdES Signer 1");
        using var cert2 = TestCertificateFactory.CreateSelfSignedCert("CN=PAdES Signer 2");

        var signed1 = await SimpleSigner.Document(pdf).WithCertificate(cert1).SignAsync();
        var signed2 = await SimpleSigner.Document(signed1).WithCertificate(cert2).SignAsync();

        using var stream = new MemoryStream(signed2);
        var signatures = await PadesExtractor.ExtractAsync(stream);

        signatures.Count().ShouldBe(2);

        // Validate first signature
        await ValidateDetachedCms(signatures[0].CmsSignature, signatures[0].SignedData, cert1, "pades-double-sig1");
        // Validate second signature
        await ValidateDetachedCms(signatures[1].CmsSignature, signatures[1].SignedData, cert2, "pades-double-sig2");
    }

    [SkippableFact(DisplayName = "PAdES CMS structure is inspectable by OpenSSL")]
    public async Task PadesBB_CmsInspectable()
    {
        SkipIfDockerUnavailable();

        var pdf = MinimalPdf();
        using var cert = TestCertificateFactory.CreateSelfSignedCert("CN=PAdES Inspect Interop");
        var signed = await SimpleSigner.Document(pdf).WithCertificate(cert).SignAsync();

        using var stream = new MemoryStream(signed);
        var signatures = await PadesExtractor.ExtractAsync(stream);
        var sig = signatures[0];

        var tmpDir = Path.Combine(Path.GetTempPath(), $"simplesign-interop-{Guid.NewGuid():N}");
        Directory.CreateDirectory(tmpDir);
        var sigPath = Path.Combine(tmpDir, "sig.der");
        await File.WriteAllBytesAsync(sigPath, sig.CmsSignature);

        try
        {
            var (stdout, stderr, exitCode) = await DockerRun(
                $"-v {tmpDir}:/in simplesign-dss inspect-cms /in/sig.der");

            output.WriteLine(stdout);

            // OpenSSL should be able to parse the CMS structure
            stdout.ShouldContain("CMS_ContentInfo");
        }
        finally
        {
            Directory.Delete(tmpDir, recursive: true);
        }
    }

    [SkippableFact(DisplayName = "PAdES with SHA-384 — CMS validates under OpenSSL")]
    public async Task PadesSha384_CmsValidatesWithOpenSsl()
    {
        SkipIfDockerUnavailable();
        var pdf = MinimalPdf();
        using var cert = TestCertificateFactory.CreateSelfSignedCert("CN=PAdES SHA384 Interop", 2048, HashAlgorithmName.SHA384);
        var signed = await SimpleSigner.Document(pdf)
            .WithCertificate(cert)
            .WithHashAlgorithm(HashAlgorithmName.SHA384)
            .SignAsync();
        using var stream = new MemoryStream(signed);
        var signatures = await PadesExtractor.ExtractAsync(stream);
        signatures.Count().ShouldBeGreaterThan(0);
        await ValidateDetachedCms(signatures[0].CmsSignature, signatures[0].SignedData, cert, "pades-sha384");
    }

    [SkippableFact(DisplayName = "PAdES with SHA-512 — CMS validates under OpenSSL")]
    public async Task PadesSha512_CmsValidatesWithOpenSsl()
    {
        SkipIfDockerUnavailable();
        var pdf = MinimalPdf();
        using var cert = TestCertificateFactory.CreateSelfSignedCert("CN=PAdES SHA512 Interop", 2048, HashAlgorithmName.SHA512);
        var signed = await SimpleSigner.Document(pdf)
            .WithCertificate(cert)
            .WithHashAlgorithm(HashAlgorithmName.SHA512)
            .SignAsync();
        using var stream = new MemoryStream(signed);
        var signatures = await PadesExtractor.ExtractAsync(stream);
        signatures.Count().ShouldBeGreaterThan(0);
        await ValidateDetachedCms(signatures[0].CmsSignature, signatures[0].SignedData, cert, "pades-sha512");
    }

    [SkippableFact(DisplayName = "PAdES with ECDSA P-256 — CMS validates under OpenSSL")]
    public async Task PadesEcdsaP256_CmsValidatesWithOpenSsl()
    {
        SkipIfDockerUnavailable();
        var pdf = MinimalPdf();
        using var cert = TestCertificateFactory.CreateEcdsaCert(ECCurve.NamedCurves.nistP256, "CN=PAdES ECDSA P256 Interop");
        var signed = await SimpleSigner.Document(pdf).WithCertificate(cert).SignAsync();
        using var stream = new MemoryStream(signed);
        var signatures = await PadesExtractor.ExtractAsync(stream);
        signatures.Count().ShouldBeGreaterThan(0);
        await ValidateDetachedCms(signatures[0].CmsSignature, signatures[0].SignedData, cert, "pades-ecdsa-p256");
    }

    [SkippableFact(DisplayName = "PAdES with ECDSA P-384 — CMS validates under OpenSSL")]
    public async Task PadesEcdsaP384_CmsValidatesWithOpenSsl()
    {
        SkipIfDockerUnavailable();
        var pdf = MinimalPdf();
        using var cert = TestCertificateFactory.CreateEcdsaCert(ECCurve.NamedCurves.nistP384, "CN=PAdES ECDSA P384 Interop");
        var signed = await SimpleSigner.Document(pdf).WithCertificate(cert).SignAsync();
        using var stream = new MemoryStream(signed);
        var signatures = await PadesExtractor.ExtractAsync(stream);
        signatures.Count().ShouldBeGreaterThan(0);
        await ValidateDetachedCms(signatures[0].CmsSignature, signatures[0].SignedData, cert, "pades-ecdsa-p384");
    }

    [SkippableFact(DisplayName = "PAdES-B-B validates under pyHanko")]
    public async Task PadesBB_ValidatesWithPyHanko()
    {
        SkipIfDockerUnavailable();
        var pdf = MinimalPdf();
        using var cert = TestCertificateFactory.CreateSelfSignedCert("CN=PAdES pyHanko Interop");
        var signed = await SimpleSigner.Document(pdf).WithCertificate(cert).SignAsync();

        var tmpDir = Path.Combine(Path.GetTempPath(), $"simplesign-interop-{Guid.NewGuid():N}");
        Directory.CreateDirectory(tmpDir);
        var pdfPath = Path.Combine(tmpDir, "signed.pdf");
        await File.WriteAllBytesAsync(pdfPath, signed);
        try
        {
            var (stdout, stderr, exitCode) = await DockerRun(
                $"-v {tmpDir}:/in simplesign-dss validate-pades /in/signed.pdf");
            output.WriteLine(stdout);
            if (!string.IsNullOrEmpty(stderr))
                output.WriteLine($"STDERR: {stderr}");
            // pyHanko should at least recognize the signature as intact
            (stdout + stderr).ShouldContain("intact=True");
        }
        finally
        {
            Directory.Delete(tmpDir, recursive: true);
        }
    }

    [SkippableFact(DisplayName = "PAdES byte-range structure validates under pyHanko")]
    public async Task PadesBB_StructureValidatesWithPyHanko()
    {
        SkipIfDockerUnavailable();
        var pdf = MinimalPdf();
        using var cert = TestCertificateFactory.CreateSelfSignedCert("CN=PAdES Structure Interop");
        var signed = await SimpleSigner.Document(pdf).WithCertificate(cert).SignAsync();

        var tmpDir = Path.Combine(Path.GetTempPath(), $"simplesign-interop-{Guid.NewGuid():N}");
        Directory.CreateDirectory(tmpDir);
        var pdfPath = Path.Combine(tmpDir, "signed.pdf");
        await File.WriteAllBytesAsync(pdfPath, signed);
        try
        {
            var (stdout, stderr, exitCode) = await DockerRun(
                $"-v {tmpDir}:/in simplesign-dss validate-pades-structure /in/signed.pdf");
            output.WriteLine(stdout);
            exitCode.ShouldBe(0);
            stdout.ShouldContain("Start offset: OK");
            stdout.ShouldContain("RESULT: VALID");
        }
        finally
        {
            Directory.Delete(tmpDir, recursive: true);
        }
    }

    [SkippableFact(DisplayName = "PAdES-B-B signature detected by pdfbox verify")]
    public async Task PadesBB_VerifiedByPdfbox()
    {
        SkipIfPdfboxUnavailable();
        var pdf = MinimalPdf();
        using var cert = TestCertificateFactory.CreateSelfSignedCert("CN=PAdES pdfbox Verify Interop");
        var signed = await SimpleSigner.Document(pdf).WithCertificate(cert).SignAsync();

        var tmp = Path.Combine(Path.GetTempPath(), $"simplesign-interop-{Guid.NewGuid():N}.pdf");
        await File.WriteAllBytesAsync(tmp, signed);
        try
        {
            var psi = new ProcessStartInfo("docker",
                $"run --rm -v {tmp}:/in/signed.pdf simplesign-pdfbox verify-signatures /in/signed.pdf")
            {
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
            };
            using var proc = Process.Start(psi)!;
            string stdout = await proc.StandardOutput.ReadToEndAsync();
            string stderr = await proc.StandardError.ReadToEndAsync();
            await proc.WaitForExitAsync();

            output.WriteLine(stdout);
            proc.ExitCode.ShouldBe(0);
            stdout.ShouldContain("RESULT: VALID");
        }
        finally
        {
            File.Delete(tmp);
        }
    }

    [SkippableFact(DisplayName = "PAdES with visual appearance — pyHanko validates byte-range")]
    public async Task PadesVisualAppearance_PyHankoValidates()
    {
        SkipIfDockerUnavailable();
        var pdf = MinimalPdf();
        using var cert = TestCertificateFactory.CreateSelfSignedCert("CN=PAdES Visual Interop");
        var signed = await SimpleSigner.Document(pdf)
            .WithCertificate(cert)
            .WithAppearance(SignatureAppearance.Auto())
            .WithMetadata("Visual Signer", "Interop test", "Brazil")
            .SignAsync();

        var tmpDir = Path.Combine(Path.GetTempPath(), $"simplesign-interop-{Guid.NewGuid():N}");
        Directory.CreateDirectory(tmpDir);
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

    [SkippableFact(DisplayName = "PAdES with visual appearance — pdfbox detects signature")]
    public async Task PadesVisualAppearance_PdfboxVerifies()
    {
        SkipIfPdfboxUnavailable();
        var pdf = MinimalPdf();
        using var cert = TestCertificateFactory.CreateSelfSignedCert("CN=PAdES Visual pdfbox Interop");
        var signed = await SimpleSigner.Document(pdf)
            .WithCertificate(cert)
            .WithAppearance(new SignatureAppearance
            {
                Page = 1,
                X = 50,
                Y = 50,
                ShowDate = true,
                ShowReason = true,
                ShowLocation = true,
            })
            .WithMetadata("Test Signer", "Visual interop", "São Paulo")
            .SignAsync();

        var tmp = Path.Combine(Path.GetTempPath(), $"simplesign-interop-{Guid.NewGuid():N}.pdf");
        await File.WriteAllBytesAsync(tmp, signed);
        try
        {
            var psi = new ProcessStartInfo("docker",
                $"run --rm -v {tmp}:/in/signed.pdf simplesign-pdfbox verify-signatures /in/signed.pdf")
            {
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
            };
            using var proc = Process.Start(psi)!;
            string stdout = await proc.StandardOutput.ReadToEndAsync();
            string stderr = await proc.StandardError.ReadToEndAsync();
            await proc.WaitForExitAsync();
            output.WriteLine(stdout);
            proc.ExitCode.ShouldBe(0);
            stdout.ShouldContain("RESULT: VALID");
        }
        finally
        {
            File.Delete(tmp);
        }
    }

    [SkippableFact(DisplayName = "PAdES certification signature — CMS validates under OpenSSL")]
    public async Task PadesCertification_CmsValidates()
    {
        SkipIfDockerUnavailable();
        var pdf = MinimalPdf();
        using var cert = TestCertificateFactory.CreateSelfSignedCert("CN=PAdES Certification Interop");
        var signed = await SimpleSigner.Document(pdf)
            .WithCertificate(cert)
            .AsCertification(CertificationLevel.NoChanges)
            .SignAsync();

        using var stream = new MemoryStream(signed);
        var signatures = await PadesExtractor.ExtractAsync(stream);
        signatures.Count().ShouldBeGreaterThan(0);
        await ValidateDetachedCms(signatures[0].CmsSignature, signatures[0].SignedData, cert, "pades-certification");
    }

    [SkippableFact(DisplayName = "PAdES with rich metadata — pyHanko validates integrity")]
    public async Task PadesMetadata_PyHankoValidates()
    {
        SkipIfDockerUnavailable();
        var pdf = MinimalPdf();
        using var cert = TestCertificateFactory.CreateSelfSignedCert("CN=PAdES Metadata Interop");
        var signed = await SimpleSigner.Document(pdf)
            .WithCertificate(cert)
            .WithMetadata("André Almeida", "Contract approval", "Vitória, ES")
            .SignAsync();

        var tmpDir = Path.Combine(Path.GetTempPath(), $"simplesign-interop-{Guid.NewGuid():N}");
        Directory.CreateDirectory(tmpDir);
        await File.WriteAllBytesAsync(Path.Combine(tmpDir, "signed.pdf"), signed);
        try
        {
            var (stdout, stderr, exitCode) = await DockerRun(
                $"-v {tmpDir}:/in simplesign-dss validate-pades /in/signed.pdf");
            output.WriteLine(stdout);
            (stdout + stderr).ShouldContain("intact=True");
        }
        finally
        {
            Directory.Delete(tmpDir, recursive: true);
        }
    }

    [SkippableFact(DisplayName = "PAdES with PDF/A preservation — pdfbox parses without errors")]
    public async Task PadesPdfA_PdfboxParses()
    {
        SkipIfPdfboxUnavailable();
        var pdf = MinimalPdf();
        using var cert = TestCertificateFactory.CreateSelfSignedCert("CN=PAdES PDF/A Interop");
        var signed = await SimpleSigner.Document(pdf)
            .WithCertificate(cert)
            .WithPdfAPreservation()
            .SignAsync();

        var tmp = Path.Combine(Path.GetTempPath(), $"simplesign-interop-{Guid.NewGuid():N}.pdf");
        await File.WriteAllBytesAsync(tmp, signed);
        try
        {
            var psi = new ProcessStartInfo("docker",
                $"run --rm -v {tmp}:/in/signed.pdf simplesign-pdfbox debug /in/signed.pdf")
            {
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
            };
            using var proc = Process.Start(psi)!;
            string stdout = await proc.StandardOutput.ReadToEndAsync();
            string stderr = await proc.StandardError.ReadToEndAsync();
            await proc.WaitForExitAsync();
            output.WriteLine(stdout);
            stderr.ShouldNotContain("Error");
            (stderr + stdout).ShouldNotContain("java.io.IOException");
        }
        finally
        {
            File.Delete(tmp);
        }
    }

    [SkippableFact(DisplayName = "PAdES deferred (2-phase) signing — CMS validates under OpenSSL")]
    public async Task PadesDeferred_CmsValidates()
    {
        SkipIfDockerUnavailable();
        var pdf = MinimalPdf();
        using var cert = TestCertificateFactory.CreateSelfSignedCert("CN=PAdES Deferred Interop");

        // Phase 1: prepare
        var prepResult = await DeferredSigner.PrepareAsync(pdf, cert);

        // Phase 2: sign the hash with the private key (simulating HSM)
        using var rsa = cert.GetRSAPrivateKey()!;
        var signedHash = rsa.SignData(prepResult.HashToSign, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        // Phase 3: complete
        var signed = await DeferredSigner.CompleteAsync(prepResult.SessionData, signedHash);

        // Validate CMS
        using var stream = new MemoryStream(signed);
        var signatures = await PadesExtractor.ExtractAsync(stream);
        signatures.Count().ShouldBeGreaterThan(0);
        await ValidateDetachedCms(signatures[0].CmsSignature, signatures[0].SignedData, cert, "pades-deferred");
    }

    [SkippableFact(DisplayName = "PAdES batch signing (3 PDFs) — all CMS validate under OpenSSL")]
    public async Task PadesBatch_AllCmsValidate()
    {
        SkipIfDockerUnavailable();
        using var cert = TestCertificateFactory.CreateSelfSignedCert("CN=PAdES Batch Interop");

        await using var batcher = BatchSigner.Create(cert).Build();
        var pdfs = Enumerable.Range(0, 3).Select(_ => MinimalPdf()).ToList();

        for (int i = 0; i < pdfs.Count; i++)
        {
            var signed = await batcher.SignAsync(pdfs[i]);
            using var stream = new MemoryStream(signed);
            var signatures = await PadesExtractor.ExtractAsync(stream);
            signatures.Count().ShouldBeGreaterThan(0);
            await ValidateDetachedCms(signatures[0].CmsSignature, signatures[0].SignedData, cert, $"pades-batch-{i}");
        }
    }

    [SkippableFact(DisplayName = "PAdES with LTV — pyHanko validates structure")]
    public async Task PadesLtv_PyHankoStructure()
    {
        SkipIfDockerUnavailable();
        var pdf = MinimalPdf();
        using var cert = TestCertificateFactory.CreateSelfSignedCert("CN=PAdES LTV Structure Interop");
        var signed = await SimpleSigner.Document(pdf)
            .WithCertificate(cert)
            .WithTimestamp("http://timestamp.digicert.com")
            .WithLtv()
            .SignAsync();

        var tmpDir = Path.Combine(Path.GetTempPath(), $"simplesign-interop-{Guid.NewGuid():N}");
        Directory.CreateDirectory(tmpDir);
        await File.WriteAllBytesAsync(Path.Combine(tmpDir, "signed.pdf"), signed);
        try
        {
            var (stdout, stderr, exitCode) = await DockerRun(
                $"-v {tmpDir}:/in simplesign-dss validate-pades-structure /in/signed.pdf");
            output.WriteLine(stdout);
            exitCode.ShouldBe(0);
            stdout.ShouldContain("Start offset: OK");
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

    private static void SkipIfPdfboxUnavailable()
    {
        Skip.IfNot(DockerProbe.IsDockerAvailable(), "Docker is not available on this host.");
        Skip.IfNot(DockerProbe.ImageExists("simplesign-pdfbox"),
            "pdfbox image is not built. Run: docker build -t simplesign-pdfbox interop/pdfbox");
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

            exitCode.ShouldBe(0, $"OpenSSL should verify the CMS from our PAdES output ({label})");
            stdout.ShouldContain("VALID");
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
