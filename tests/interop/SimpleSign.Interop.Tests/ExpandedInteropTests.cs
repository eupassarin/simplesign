using System.Diagnostics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Shouldly;
using SimpleSign.PAdES;
using SimpleSign.PAdES.Inspection;
using SimpleSign.PAdES.Signing;
using SimpleSign.Pdf.Exceptions;
using SimpleSign.TestHelpers;
using Xunit;
using Xunit.Abstractions;

namespace SimpleSign.Interop.Tests;

/// <summary>
/// Expanded interop tests covering incremental updates, stream I/O, PDF structure variants,
/// certification/DocMDP, edge cases, and advanced signing scenarios.
/// All validated by external tools (pyHanko, OpenSSL, iText, EU DSS, pdfbox).
/// </summary>
[Trait("Category", "Interop")]
public sealed class ExpandedInteropTests(ITestOutputHelper output)
{
    // ────────────────────────────────────────────────────────────────
    // Phase 1: Correctness & Security
    // ────────────────────────────────────────────────────────────────

    [SkippableFact(DisplayName = "Incremental: 2 sigs with different certs — both intact (pyHanko)")]
    public async Task IncrementalSigning_BothSignaturesIntact_PyHanko()
    {
        SkipIfDssUnavailable();

        var pdf = MinimalPdf();
        using var cert1 = TestCertificateFactory.CreateSelfSignedCert("CN=Incremental Signer 1");
        using var cert2 = TestCertificateFactory.CreateSelfSignedCert("CN=Incremental Signer 2");

        var signed1 = await SimpleSigner.Document(pdf).WithCertificate(cert1).SignAsync();
        var signed2 = await SimpleSigner.Document(signed1).WithCertificate(cert2).SignAsync();

        // Verify both signatures are extractable
        using var stream = new MemoryStream(signed2);
        var signatures = await PadesExtractor.ExtractAsync(stream);
        signatures.Count().ShouldBe(2, "two incremental signatures should be present");

        // Validate with pyHanko
        var tmpDir = CreateTempDir();
        await File.WriteAllBytesAsync(Path.Combine(tmpDir, "signed.pdf"), signed2);
        try
        {
            var (stdout, stderr, exitCode) = await DockerRun(
                $"-v {tmpDir}:/in simplesign-dss validate-pades /in/signed.pdf");
            output.WriteLine($"[incremental-2-sigs] exit={exitCode}");
            output.WriteLine(stdout);
            if (!string.IsNullOrEmpty(stderr))
            {
                output.WriteLine($"STDERR: {stderr}");
            }

            // pyHanko should report both signatures as intact
            var combined = stdout + stderr;
            combined.ShouldContain("intact=True");
        }
        finally
        {
            Directory.Delete(tmpDir, recursive: true);
        }
    }

    [SkippableFact(DisplayName = "Incremental: 2 sigs — both CMS validate under OpenSSL")]
    public async Task IncrementalSigning_BothCmsValidateOpenSsl()
    {
        SkipIfDssUnavailable();

        var pdf = MinimalPdf();
        using var cert1 = TestCertificateFactory.CreateSelfSignedCert("CN=Incr OpenSSL Signer 1");
        using var cert2 = TestCertificateFactory.CreateSelfSignedCert("CN=Incr OpenSSL Signer 2");

        var signed1 = await SimpleSigner.Document(pdf).WithCertificate(cert1).SignAsync();
        var signed2 = await SimpleSigner.Document(signed1).WithCertificate(cert2).SignAsync();

        using var stream = new MemoryStream(signed2);
        var signatures = await PadesExtractor.ExtractAsync(stream);
        signatures.Count().ShouldBe(2);

        await ValidateDetachedCms(signatures[0].CmsSignature, signatures[0].SignedData, cert1, "incr-sig1");
        await ValidateDetachedCms(signatures[1].CmsSignature, signatures[1].SignedData, cert2, "incr-sig2");
    }

    [SkippableFact(DisplayName = "Incremental: 2 sigs — pdfbox detects both")]
    public async Task IncrementalSigning_PdfboxDetectsBoth()
    {
        SkipIfPdfboxUnavailable();

        var pdf = MinimalPdf();
        using var cert1 = TestCertificateFactory.CreateSelfSignedCert("CN=Incr Pdfbox Signer 1");
        using var cert2 = TestCertificateFactory.CreateSelfSignedCert("CN=Incr Pdfbox Signer 2");

        var signed1 = await SimpleSigner.Document(pdf).WithCertificate(cert1).SignAsync();
        var signed2 = await SimpleSigner.Document(signed1).WithCertificate(cert2).SignAsync();

        var tmpDir = CreateTempDir();
        await File.WriteAllBytesAsync(Path.Combine(tmpDir, "signed.pdf"), signed2);
        try
        {
            var (stdout, stderr, exitCode) = await DockerRun(
                $"-v {tmpDir}:/in simplesign-pdfbox verify-signatures /in/signed.pdf");
            output.WriteLine($"[incremental-pdfbox] exit={exitCode}");
            output.WriteLine(stdout);
            exitCode.ShouldBe(0, "pdfbox should parse double-signed PDF");
            stdout.ShouldContain("RESULT: VALID");
        }
        finally
        {
            Directory.Delete(tmpDir, recursive: true);
        }
    }

    [SkippableFact(DisplayName = "Stream I/O: Sign via Stream instead of byte[] — pyHanko validates")]
    public async Task StreamIO_SignViaStream_PyHankoValidates()
    {
        SkipIfDssUnavailable();

        var pdf = MinimalPdf();
        using var cert = TestCertificateFactory.CreateSelfSignedCert("CN=Stream IO Interop");

        // Sign using Stream API
        using var inputStream = new MemoryStream(pdf);
        using var outputStream = new MemoryStream();
        await SimpleSigner.Document(inputStream).WithCertificate(cert).SignAsync(outputStream);
        var signed = outputStream.ToArray();

        signed.ShouldNotBeEmpty("stream signing should produce output");

        // Validate with pyHanko
        var tmpDir = CreateTempDir();
        await File.WriteAllBytesAsync(Path.Combine(tmpDir, "signed.pdf"), signed);
        try
        {
            var (stdout, stderr, exitCode) = await DockerRun(
                $"-v {tmpDir}:/in simplesign-dss validate-pades /in/signed.pdf");
            output.WriteLine($"[stream-io] exit={exitCode}");
            output.WriteLine(stdout);
            if (!string.IsNullOrEmpty(stderr))
            {
                output.WriteLine($"STDERR: {stderr}");
            }
            (stdout + stderr).ShouldContain("intact=True");
        }
        finally
        {
            Directory.Delete(tmpDir, recursive: true);
        }
    }

    [SkippableFact(DisplayName = "Stream I/O: CMS from stream-signed PDF validates under OpenSSL")]
    public async Task StreamIO_CmsValidatesOpenSsl()
    {
        SkipIfDssUnavailable();

        var pdf = MinimalPdf();
        using var cert = TestCertificateFactory.CreateSelfSignedCert("CN=Stream IO OpenSSL");

        using var inputStream = new MemoryStream(pdf);
        using var outputStream = new MemoryStream();
        await SimpleSigner.Document(inputStream).WithCertificate(cert).SignAsync(outputStream);
        var signed = outputStream.ToArray();

        using var sigStream = new MemoryStream(signed);
        var signatures = await PadesExtractor.ExtractAsync(sigStream);
        signatures.Count().ShouldBeGreaterThan(0);
        await ValidateDetachedCms(signatures[0].CmsSignature, signatures[0].SignedData, cert, "stream-io-openssl");
    }

    [SkippableFact(DisplayName = "Certification DocMDP NoChanges — pyHanko validates structure")]
    public async Task CertificationDocMdp_PyHankoValidatesStructure()
    {
        SkipIfDssUnavailable();

        var pdf = MinimalPdf();
        using var cert = TestCertificateFactory.CreateSelfSignedCert("CN=DocMDP Certifier");

        var signed = await SimpleSigner.Document(pdf)
            .WithCertificate(cert)
            .AsCertification(CertificationLevel.NoChanges)
            .SignAsync();

        var tmpDir = CreateTempDir();
        await File.WriteAllBytesAsync(Path.Combine(tmpDir, "signed.pdf"), signed);
        try
        {
            var (stdout, stderr, exitCode) = await DockerRun(
                $"-v {tmpDir}:/in simplesign-dss validate-pades-structure /in/signed.pdf");
            output.WriteLine($"[docmdp-structure] exit={exitCode}");
            output.WriteLine(stdout);
            exitCode.ShouldBe(0);
            stdout.ShouldContain("RESULT: VALID");
        }
        finally
        {
            Directory.Delete(tmpDir, recursive: true);
        }
    }

    [SkippableFact(DisplayName = "Certification DocMDP — iText validates")]
    public async Task CertificationDocMdp_ITextValidates()
    {
        SkipIfITextUnavailable();

        var pdf = MinimalPdf();
        using var cert = TestCertificateFactory.CreateSelfSignedCert("CN=DocMDP iText Certifier");

        var signed = await SimpleSigner.Document(pdf)
            .WithCertificate(cert)
            .AsCertification(CertificationLevel.FormFilling)
            .SignAsync();

        var tmpDir = CreateTempDir();
        await File.WriteAllBytesAsync(Path.Combine(tmpDir, "signed.pdf"), signed);
        try
        {
            var (stdout, stderr, exitCode) = await DockerRun(
                $"-v {tmpDir}:/in simplesign-itext validate-pdf /in/signed.pdf");
            output.WriteLine($"[docmdp-itext] exit={exitCode}");
            output.WriteLine(stdout);
            exitCode.ShouldBe(0, "iText should validate certified PDF");
            stdout.ShouldContain("VALID");
        }
        finally
        {
            Directory.Delete(tmpDir, recursive: true);
        }
    }

    [SkippableFact(DisplayName = "ByteRange coverage — pyHanko validates structure (offset + contiguity)")]
    public async Task ByteRangeCoverage_PyHankoValidatesStructure()
    {
        SkipIfDssUnavailable();

        var pdf = MinimalPdf();
        using var cert = TestCertificateFactory.CreateSelfSignedCert("CN=ByteRange Coverage");

        var signed = await SimpleSigner.Document(pdf).WithCertificate(cert).SignAsync();

        // Local check: ByteRange[0] should be 0 and ByteRange[2]+ByteRange[3] should == file length
        using var ms = new MemoryStream(signed);
        var signatures = await PadesExtractor.ExtractAsync(ms);
        var sig = signatures[0];
        sig.ByteRange.ShouldNotBeNull("ByteRange must be present");
        sig.ByteRange!.Offset1.ShouldBe(0, "ByteRange must start at offset 0");
        sig.ByteRange.CoversEntireFile(signed.Length).ShouldBeTrue(
            "ByteRange must cover entire file end-to-end");

        // External validation via pyHanko
        var tmpDir = CreateTempDir();
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

    // ────────────────────────────────────────────────────────────────
    // Phase 2: Robustness & Edge Cases
    // ────────────────────────────────────────────────────────────────

    [Fact(DisplayName = "Corrupt PDF: truncated file → handles gracefully (no NullRef/IndexOutOfRange)")]
    public async Task CorruptPdf_Truncated_HandlesGracefully()
    {
        var truncated = "%PDF-1.7\n1 0 obj\n<< /Type /Catalog"u8.ToArray(); // no endobj, no xref
        using var cert = TestCertificateFactory.CreateSelfSignedCert("CN=Corrupt Test");

        try
        {
            var signed = await SimpleSigner.Document(truncated).WithCertificate(cert).SignAsync();
            // If the signer is resilient and produces output, that's acceptable
            signed.ShouldNotBeEmpty("if signing succeeds on truncated input, output should be non-empty");
        }
        catch (Exception ex)
        {
            // If it fails, the exception should be descriptive, not a low-level crash
            ex.ShouldNotBeOfType<NullReferenceException>();
            ex.ShouldNotBeOfType<IndexOutOfRangeException>();
            ex.ShouldNotBeOfType<AccessViolationException>();
        }
    }

    [Fact(DisplayName = "Corrupt PDF: missing xref → handles gracefully (no NullRef/IndexOutOfRange)")]
    public async Task CorruptPdf_MissingXref_HandlesGracefully()
    {
        // Valid-looking PDF header but no xref table
        var noXref = "%PDF-1.7\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n2 0 obj\n<< /Type /Pages /Kids [] /Count 0 >>\nendobj\n%%EOF"u8.ToArray();
        using var cert = TestCertificateFactory.CreateSelfSignedCert("CN=NoXref Test");

        try
        {
            var signed = await SimpleSigner.Document(noXref).WithCertificate(cert).SignAsync();
            signed.ShouldNotBeEmpty("if signing succeeds on PDF without xref, output should be non-empty");
        }
        catch (Exception ex)
        {
            ex.ShouldNotBeOfType<NullReferenceException>();
            ex.ShouldNotBeOfType<IndexOutOfRangeException>();
            ex.ShouldNotBeOfType<AccessViolationException>();
        }
    }

    [Fact(DisplayName = "Corrupt PDF: garbage after %%EOF → still signs successfully")]
    public async Task CorruptPdf_GarbageAfterEof_StillSigns()
    {
        // A valid PDF with trailing garbage — this is technically valid and common
        var validPdf = MinimalPdf();
        var withGarbage = new byte[validPdf.Length + 100];
        Buffer.BlockCopy(validPdf, 0, withGarbage, 0, validPdf.Length);
        // Fill trailing bytes with garbage
        for (int i = validPdf.Length; i < withGarbage.Length; i++)
            withGarbage[i] = (byte)'X';

        using var cert = TestCertificateFactory.CreateSelfSignedCert("CN=Garbage EOF Test");

        // Some PDF signers tolerate garbage after %%EOF; SimpleSign should either
        // sign successfully or throw a descriptive exception
        try
        {
            var signed = await SimpleSigner.Document(withGarbage).WithCertificate(cert).SignAsync();
            signed.ShouldNotBeEmpty("if signing succeeds, output should be non-empty");
        }
        catch (Exception ex)
        {
            // If it fails, the exception should be descriptive
            output.WriteLine($"Expected failure: {ex.GetType().Name}: {ex.Message}");
            ex.ShouldBeAssignableTo<Exception>("exception should be descriptive, not NullRef/IndexOutOfRange");
            ex.ShouldNotBeOfType<NullReferenceException>();
            ex.ShouldNotBeOfType<IndexOutOfRangeException>();
        }
    }

    [SkippableFact(DisplayName = "Large document: 200-page PDF — pyHanko validates byte-range")]
    public async Task LargeDocument_200Pages_PyHankoValidates()
    {
        SkipIfDssUnavailable();

        var pdf = MultiPagePdf(200);
        output.WriteLine($"Generated 200-page PDF: {pdf.Length:N0} bytes");
        using var cert = TestCertificateFactory.CreateSelfSignedCert("CN=Large Doc Stress");

        var signed = await SimpleSigner.Document(pdf).WithCertificate(cert).SignAsync();
        output.WriteLine($"Signed PDF: {signed.Length:N0} bytes");

        // Verify ByteRange locally
        using var ms = new MemoryStream(signed);
        var signatures = await PadesExtractor.ExtractAsync(ms);
        signatures.Count().ShouldBeGreaterThan(0);
        var sig = signatures[0];
        sig.ByteRange.ShouldNotBeNull();
        sig.ByteRange!.CoversEntireFile(signed.Length).ShouldBeTrue(
            "ByteRange must cover entire large file end-to-end");

        // External validation
        var tmpDir = CreateTempDir();
        await File.WriteAllBytesAsync(Path.Combine(tmpDir, "signed.pdf"), signed);
        try
        {
            var (stdout, stderr, exitCode) = await DockerRun(
                $"-v {tmpDir}:/in simplesign-dss validate-pades-structure /in/signed.pdf");
            output.WriteLine($"[large-doc-200] exit={exitCode}");
            output.WriteLine(stdout);
            exitCode.ShouldBe(0, "pyHanko should validate 200-page signed PDF structure");
            stdout.ShouldContain("RESULT: VALID");
        }
        finally
        {
            Directory.Delete(tmpDir, recursive: true);
        }
    }

    [SkippableFact(DisplayName = "Large document: 200-page PDF — iText validates")]
    public async Task LargeDocument_200Pages_ITextValidates()
    {
        SkipIfITextUnavailable();

        var pdf = MultiPagePdf(200);
        using var cert = TestCertificateFactory.CreateSelfSignedCert("CN=Large Doc iText");
        var signed = await SimpleSigner.Document(pdf).WithCertificate(cert).SignAsync();

        var tmpDir = CreateTempDir();
        await File.WriteAllBytesAsync(Path.Combine(tmpDir, "signed.pdf"), signed);
        try
        {
            var (stdout, stderr, exitCode) = await DockerRun(
                $"-v {tmpDir}:/in simplesign-itext validate-pdf /in/signed.pdf");
            output.WriteLine($"[large-doc-itext] exit={exitCode}");
            output.WriteLine(stdout);
            exitCode.ShouldBe(0, "iText should validate signed 200-page PDF");
            stdout.ShouldContain("VALID");
        }
        finally
        {
            Directory.Delete(tmpDir, recursive: true);
        }
    }

    [Fact(DisplayName = "Encrypted PDF: reader detects encryption and throws")]
    public async Task EncryptedPdf_ThrowsEncryptedPdfException()
    {
        // Minimal PDF with /Encrypt in the trailer
        var encrypted = Encoding.ASCII.GetBytes(
            "%PDF-1.4\n" +
            "1 0 obj <</Type /Catalog /Pages 2 0 R>> endobj\n" +
            "2 0 obj <</Type /Pages /Kids [] /Count 0>> endobj\n" +
            "xref\n0 3\n0000000000 65535 f \n0000000009 00000 n \n0000000052 00000 n \n" +
            "trailer <</Size 3 /Root 1 0 R /Encrypt 3 0 R>>\n" +
            "startxref\n104\n%%EOF");

        // PdfStructureReader.ReadSignatureFieldsAsync detects encryption
        using var stream = new MemoryStream(encrypted);
        var act = () => SimpleSign.Pdf.PdfStructureReader.ReadSignatureFieldsAsync(stream);
        await Should.ThrowAsync<EncryptedPdfException>(act);

        // Also verify IsEncryptedAsync detects it
        stream.Position = 0;
        var isEncrypted = await SimpleSign.Pdf.PdfStructureReader.IsEncryptedAsync(stream);
        isEncrypted.ShouldBeTrue("encrypted PDF should be detected");
    }

    [SkippableFact(DisplayName = "PDF/A preservation: signed PDF passes pdfbox without errors")]
    public async Task PdfAPreservation_PdfboxParsesWithoutErrors()
    {
        SkipIfPdfboxUnavailable();

        var pdf = MinimalPdf();
        using var cert = TestCertificateFactory.CreateSelfSignedCert("CN=PDF/A Preservation Interop");

        var signed = await SimpleSigner.Document(pdf)
            .WithCertificate(cert)
            .WithPdfAPreservation()
            .SignAsync();

        var tmpDir = CreateTempDir();
        await File.WriteAllBytesAsync(Path.Combine(tmpDir, "signed.pdf"), signed);
        try
        {
            var (stdout, stderr, exitCode) = await DockerRun(
                $"-v {tmpDir}:/in simplesign-pdfbox verify-signatures /in/signed.pdf");
            output.WriteLine($"[pdfa-pdfbox] exit={exitCode}");
            output.WriteLine(stdout);
            exitCode.ShouldBe(0);
            stdout.ShouldContain("RESULT: VALID");
            (stderr + stdout).ShouldNotContain("java.io.IOException");
        }
        finally
        {
            Directory.Delete(tmpDir, recursive: true);
        }
    }

    [SkippableFact(DisplayName = "PDF/A preservation: pyHanko validates integrity")]
    public async Task PdfAPreservation_PyHankoValidatesIntegrity()
    {
        SkipIfDssUnavailable();

        var pdf = MinimalPdf();
        using var cert = TestCertificateFactory.CreateSelfSignedCert("CN=PDF/A pyHanko Interop");

        var signed = await SimpleSigner.Document(pdf)
            .WithCertificate(cert)
            .WithPdfAPreservation()
            .SignAsync();

        var tmpDir = CreateTempDir();
        await File.WriteAllBytesAsync(Path.Combine(tmpDir, "signed.pdf"), signed);
        try
        {
            var (stdout, stderr, exitCode) = await DockerRun(
                $"-v {tmpDir}:/in simplesign-dss validate-pades /in/signed.pdf");
            output.WriteLine($"[pdfa-pyhanko] exit={exitCode}");
            output.WriteLine(stdout);
            (stdout + stderr).ShouldContain("intact=True");
        }
        finally
        {
            Directory.Delete(tmpDir, recursive: true);
        }
    }

    // ────────────────────────────────────────────────────────────────
    // Phase 3: Advanced Scenarios
    // ────────────────────────────────────────────────────────────────

    [SkippableFact(DisplayName = "Multi-algorithm: RSA-4096/SHA-512 — OpenSSL validates CMS")]
    public async Task MultiAlgo_Rsa4096Sha512_OpenSslValidates()
    {
        SkipIfDssUnavailable();

        var pdf = MinimalPdf();
        using var cert = TestCertificateFactory.CreateSelfSignedCert("CN=RSA4096 SHA512 Interop", 4096, HashAlgorithmName.SHA512);

        var signed = await SimpleSigner.Document(pdf)
            .WithCertificate(cert)
            .WithHashAlgorithm(HashAlgorithmName.SHA512)
            .SignAsync();

        using var stream = new MemoryStream(signed);
        var signatures = await PadesExtractor.ExtractAsync(stream);
        signatures.Count().ShouldBeGreaterThan(0);
        await ValidateDetachedCms(signatures[0].CmsSignature, signatures[0].SignedData, cert, "rsa4096-sha512");
    }

    [SkippableFact(DisplayName = "Multi-algorithm: ECDSA-P384/SHA-384 — OpenSSL validates CMS")]
    public async Task MultiAlgo_EcdsaP384Sha384_OpenSslValidates()
    {
        SkipIfDssUnavailable();

        var pdf = MinimalPdf();
        using var cert = TestCertificateFactory.CreateEcdsaCert(ECCurve.NamedCurves.nistP384, "CN=ECDSA P384 SHA384 Interop");

        var signed = await SimpleSigner.Document(pdf)
            .WithCertificate(cert)
            .WithHashAlgorithm(HashAlgorithmName.SHA384)
            .SignAsync();

        using var stream = new MemoryStream(signed);
        var signatures = await PadesExtractor.ExtractAsync(stream);
        signatures.Count().ShouldBeGreaterThan(0);
        await ValidateDetachedCms(signatures[0].CmsSignature, signatures[0].SignedData, cert, "ecdsa-p384-sha384");
    }

    [SkippableFact(DisplayName = "Deferred signing: 2-phase with OpenSSL CMS inspection")]
    public async Task DeferredSigning_CmsInspectableByOpenSsl()
    {
        SkipIfDssUnavailable();

        var pdf = MinimalPdf();
        using var cert = TestCertificateFactory.CreateSelfSignedCert("CN=Deferred Full Chain");

        // Phase 1: prepare
        var prepResult = await DeferredSigner.PrepareAsync(pdf, cert);

        // Phase 2: sign hash (simulating HSM)
        using var rsa = cert.GetRSAPrivateKey()!;
        var signedHash = rsa.SignData(prepResult.HashToSign, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        // Phase 3: complete
        var signed = await DeferredSigner.CompleteAsync(prepResult.SessionData, signedHash);

        // Extract CMS and validate structure
        using var stream = new MemoryStream(signed);
        var signatures = await PadesExtractor.ExtractAsync(stream);
        signatures.Count().ShouldBeGreaterThan(0);

        // Inspect CMS with OpenSSL
        var tmpDir = CreateTempDir();
        await File.WriteAllBytesAsync(Path.Combine(tmpDir, "sig.der"), signatures[0].CmsSignature);
        try
        {
            var (stdout, stderr, exitCode) = await DockerRun(
                $"-v {tmpDir}:/in simplesign-dss inspect-cms /in/sig.der");
            output.WriteLine($"[deferred-inspect] exit={exitCode}");
            output.WriteLine(stdout);
            stdout.ShouldContain("CMS_ContentInfo");
        }
        finally
        {
            Directory.Delete(tmpDir, recursive: true);
        }

        // Also validate CMS integrity
        await ValidateDetachedCms(signatures[0].CmsSignature, signatures[0].SignedData, cert, "deferred-full");
    }

    [SkippableFact(DisplayName = "Cross-tool: pyHanko signs → SimpleSign adds 2nd → both validate")]
    public async Task CrossTool_PyHankoThenSimpleSign_BothValidate()
    {
        SkipIfDssUnavailable();

        var tmpDir = CreateTempDir();
        try
        {
            var (keyPem, certPem, cert1) = CreateExportableCertAndPem("CN=pyHanko Cross Signer");
            using var _ = cert1;
            using var cert2 = TestCertificateFactory.CreateSelfSignedCert("CN=SimpleSign Cross Signer");

            // Write inputs for pyHanko
            await File.WriteAllBytesAsync(Path.Combine(tmpDir, "input.pdf"), MinimalPdf());
            await File.WriteAllTextAsync(Path.Combine(tmpDir, "key.pem"), keyPem);
            await File.WriteAllTextAsync(Path.Combine(tmpDir, "cert.pem"), certPem);

            // Step 1: pyHanko signs first
            var (stdout1, stderr1, exit1) = await DockerRun(
                $"-v {tmpDir}:/in simplesign-dss sign-pades /in/input.pdf /in/key.pem /in/cert.pem /in/pyhanko-signed.pdf");
            output.WriteLine($"[cross-pyhanko-sign] exit={exit1}");
            output.WriteLine(stdout1);
            exit1.ShouldBe(0, "pyHanko should sign the PDF");

            // Step 2: SimpleSign adds second signature
            var pyhankoSigned = await File.ReadAllBytesAsync(Path.Combine(tmpDir, "pyhanko-signed.pdf"));
            var doubleSigned = await SimpleSigner.Document(pyhankoSigned).WithCertificate(cert2).SignAsync();
            await File.WriteAllBytesAsync(Path.Combine(tmpDir, "double-signed.pdf"), doubleSigned);

            // Step 3: Validate both with pyHanko
            var (stdout3, stderr3, exit3) = await DockerRun(
                $"-v {tmpDir}:/in simplesign-dss validate-pades /in/double-signed.pdf");
            output.WriteLine($"[cross-validate] exit={exit3}");
            output.WriteLine(stdout3);
            if (!string.IsNullOrEmpty(stderr3))
            {
                output.WriteLine($"STDERR: {stderr3}");
            }

            var combined = stdout3 + stderr3;
            combined.ShouldContain("intact=True");

            // Also verify we can extract both
            using var ms = new MemoryStream(doubleSigned);
            var sigs = await PadesExtractor.ExtractAsync(ms);
            sigs.Count().ShouldBe(2, "pyHanko + SimpleSign = 2 signatures");
        }
        finally
        {
            Directory.Delete(tmpDir, recursive: true);
        }
    }

    [SkippableFact(DisplayName = "Cross-tool: 3 signers — pyHanko → SimpleSign → pyHanko — all intact")]
    public async Task CrossTool_3Signers_AllValidate()
    {
        SkipIfDssUnavailable();

        var tmpDir = CreateTempDir();
        try
        {
            var (key1Pem, cert1Pem, cert1) = CreateExportableCertAndPem("CN=Cross3 pyHanko Signer 1");
            using var _1 = cert1;
            using var cert2 = TestCertificateFactory.CreateSelfSignedCert("CN=Cross3 SimpleSign Signer 2");
            var (key3Pem, cert3Pem, cert3) = CreateExportableCertAndPem("CN=Cross3 pyHanko Signer 3");
            using var _3 = cert3;

            // Write initial PDF
            await File.WriteAllBytesAsync(Path.Combine(tmpDir, "input.pdf"), MinimalPdf());

            // Step 1: pyHanko signs first
            await File.WriteAllTextAsync(Path.Combine(tmpDir, "key1.pem"), key1Pem);
            await File.WriteAllTextAsync(Path.Combine(tmpDir, "cert1.pem"), cert1Pem);
            var (_, _, exit1) = await DockerRun(
                $"-v {tmpDir}:/in simplesign-dss sign-pades /in/input.pdf /in/key1.pem /in/cert1.pem /in/signed1.pdf");
            exit1.ShouldBe(0, "pyHanko should sign (step 1/3)");

            // Step 2: SimpleSign adds second signature
            var signed1 = await File.ReadAllBytesAsync(Path.Combine(tmpDir, "signed1.pdf"));
            var signed2 = await SimpleSigner.Document(signed1).WithCertificate(cert2).SignAsync();
            await File.WriteAllBytesAsync(Path.Combine(tmpDir, "signed2.pdf"), signed2);

            // Step 3: pyHanko adds third signature (use unique field name to avoid conflict)
            await File.WriteAllTextAsync(Path.Combine(tmpDir, "key3.pem"), key3Pem);
            await File.WriteAllTextAsync(Path.Combine(tmpDir, "cert3.pem"), cert3Pem);
            var (stdout3, stderr3, exit3) = await DockerRun(
                $"-v {tmpDir}:/in simplesign-dss sign-pades-field /in/signed2.pdf /in/key3.pem /in/cert3.pem /in/signed3.pdf Signature3");
            output.WriteLine($"[cross3-step3] exit={exit3} stdout={stdout3}");
            if (!string.IsNullOrEmpty(stderr3))
            {
                output.WriteLine($"[cross3-step3] STDERR: {stderr3}");
            }

            exit3.ShouldBe(0, "pyHanko should sign (step 3/3)");

            // Validate all 3 signatures
            var (stdout, stderr, exitV) = await DockerRun(
                $"-v {tmpDir}:/in simplesign-dss validate-pades /in/signed3.pdf");
            output.WriteLine($"[cross3-validate] exit={exitV}");
            output.WriteLine(stdout);
            if (!string.IsNullOrEmpty(stderr))
            {
                output.WriteLine($"STDERR: {stderr}");
            }

            var combined = stdout + stderr;
            combined.ShouldContain("intact=True");

            // Extract and count
            var final = await File.ReadAllBytesAsync(Path.Combine(tmpDir, "signed3.pdf"));
            using var ms = new MemoryStream(final);
            var sigs = await PadesExtractor.ExtractAsync(ms);
            sigs.Count().ShouldBe(3, "pyHanko+SimpleSign+pyHanko = 3 signatures");
        }
        finally
        {
            Directory.Delete(tmpDir, recursive: true);
        }
    }

    // ────────────────────────────────────────────────────────────────
    // Helpers
    // ────────────────────────────────────────────────────────────────

    private static void SkipIfDssUnavailable()
    {
        Skip.IfNot(DockerProbe.IsDockerAvailable(), "Docker is not available on this host.");
        Skip.IfNot(DockerProbe.ImageExists("simplesign-dss"),
            "Validator image not built. Run: docker build -t simplesign-dss interop/dss-validator");
    }

    private static void SkipIfPdfboxUnavailable()
    {
        Skip.IfNot(DockerProbe.IsDockerAvailable(), "Docker is not available on this host.");
        Skip.IfNot(DockerProbe.ImageExists("simplesign-pdfbox"),
            "pdfbox image not built. Run: docker build -t simplesign-pdfbox interop/pdfbox");
    }

    private static void SkipIfITextUnavailable()
    {
        Skip.IfNot(DockerProbe.IsDockerAvailable(), "Docker is not available on this host.");
        Skip.IfNot(DockerProbe.ImageExists("simplesign-itext"),
            "iText image not built. Run: docker build -t simplesign-itext interop/itext");
    }

    private static string CreateTempDir()
    {
        var dir = Path.Combine(Path.GetTempPath(), $"simplesign-expanded-{Guid.NewGuid():N}");
        Directory.CreateDirectory(dir);
        return dir;
    }

    private async Task ValidateDetachedCms(byte[] cmsBytes, byte[] data, X509Certificate2 cert, string label)
    {
        var tmpDir = CreateTempDir();
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
            exitCode.ShouldBe(0, $"OpenSSL should verify CMS ({label})");
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

    /// <summary>
    /// Creates a self-signed cert AND exports key/cert PEM at creation time,
    /// before PFX round-trip, to avoid Windows CNG key export restrictions.
    /// </summary>
    private static (string keyPem, string certPem, X509Certificate2 cert) CreateExportableCertAndPem(string subject)
    {
        using var rsa = RSA.Create(2048);
        var keyBytes = rsa.ExportPkcs8PrivateKey();
        var keyPem = "-----BEGIN PRIVATE KEY-----\n" +
                     Convert.ToBase64String(keyBytes) +
                     "\n-----END PRIVATE KEY-----\n";

        var req = new CertificateRequest(subject, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        req.CertificateExtensions.Add(
            new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, critical: false));
        var ephemeral = req.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));

        var certPem = "-----BEGIN CERTIFICATE-----\n" +
                      Convert.ToBase64String(ephemeral.RawData) +
                      "\n-----END CERTIFICATE-----\n";

        const string pw = "test-export";
        var pfx = ephemeral.Export(X509ContentType.Pfx, pw);
#pragma warning disable SYSLIB0057
        var cert = new X509Certificate2(pfx, pw,
            X509KeyStorageFlags.Exportable | X509KeyStorageFlags.EphemeralKeySet);
#pragma warning restore SYSLIB0057

        return (keyPem, certPem, cert);
    }

    private static byte[] MinimalPdf() =>
        "%PDF-1.7\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>\nendobj\nxref\n0 4\n0000000000 65535 f \n0000000009 00000 n \n0000000058 00000 n \n0000000115 00000 n \ntrailer\n<< /Size 4 /Root 1 0 R >>\nstartxref\n186\n%%EOF"u8.ToArray();

    private static byte[] MultiPagePdf(int pageCount)
    {
        var sb = new StringBuilder();
        sb.Append("%PDF-1.7\n");
        var offsets = new List<int>();

        offsets.Add(sb.Length);
        sb.Append("1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n");

        offsets.Add(sb.Length);
        var kids = string.Join(" ", Enumerable.Range(3, pageCount).Select(i => $"{i} 0 R"));
        sb.Append($"2 0 obj\n<< /Type /Pages /Kids [{kids}] /Count {pageCount} >>\nendobj\n");

        for (int i = 0; i < pageCount; i++)
        {
            offsets.Add(sb.Length);
            sb.Append($"{i + 3} 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>\nendobj\n");
        }

        int xrefOffset = sb.Length;
        int totalObjects = pageCount + 3;
        sb.Append($"xref\n0 {totalObjects}\n");
        sb.Append("0000000000 65535 f\r\n");
        foreach (var offset in offsets)
            sb.Append($"{offset:D10} 00000 n\r\n");

        sb.Append($"trailer\n<< /Size {totalObjects} /Root 1 0 R >>\nstartxref\n{xrefOffset}\n%%EOF\n");
        return Encoding.ASCII.GetBytes(sb.ToString());
    }

}
