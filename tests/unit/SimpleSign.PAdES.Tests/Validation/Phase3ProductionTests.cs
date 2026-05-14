using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using FluentAssertions;
using SimpleSign.Core.Constants;
using SimpleSign.Core.Crypto;
using SimpleSign.Core.Http;
using SimpleSign.Core.Revocation;
using SimpleSign.Core.Validation;
using SimpleSign.PAdES.Validation;
using SimpleSign.Pdf;
using SimpleSign.Pdf.Enums;
using SimpleSign.Pdf.Exceptions;
using Xunit;
namespace SimpleSign.PAdES.Tests.Validation;

/// <summary>
/// Phase 3 tests: Validator refactoring, HttpClient injection, encrypted PDF, batch validation, PDF/A detection.
/// </summary>
public sealed class Phase3ProductionTests
{
    // ── Fixtures ──────────────────────────────────────────────────────────────

    private static X509Certificate2 CreateCert(string subject = "CN=Phase3 Test")
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest(subject, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        req.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, false));
        var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        return CertificateLoader.LoadPkcs12(cert.Export(X509ContentType.Pkcs12, "test-export"), "test-export");
    }

    private static byte[] CreateMinimalPdf()
    {
        var sb = new StringBuilder();
        sb.AppendLine("%PDF-1.4");
        sb.AppendLine("1 0 obj <</Type /Catalog /Pages 2 0 R>> endobj");
        sb.AppendLine("2 0 obj <</Type /Pages /Kids [3 0 R] /Count 1>> endobj");
        sb.AppendLine("3 0 obj <</Type /Page /Parent 2 0 R /MediaBox [0 0 612 792]>> endobj");
        sb.AppendLine("xref");
        sb.AppendLine("0 4");
        sb.AppendLine("0000000000 65535 f ");
        sb.AppendLine("0000000009 00000 n ");
        sb.AppendLine("0000000058 00000 n ");
        sb.AppendLine("0000000115 00000 n ");
        sb.AppendLine("trailer <</Size 4 /Root 1 0 R>>");
        sb.AppendLine("startxref");
        sb.AppendLine("183");
        sb.AppendLine("%%EOF");
        return Encoding.ASCII.GetBytes(sb.ToString());
    }

    // ══════════════════════════════════════════════════════════════════════════
    // A1. IntegrityVerifier tests
    // ══════════════════════════════════════════════════════════════════════════

    [Fact(DisplayName = "Null digest returns false in hash verification")]
    public void IntegrityVerifier_VerifyDocumentHash_NullDigest_ReturnsFalse()
    {
        var cmsData = new CmsSignedData
        {
            DigestAlgorithmOid = Oids.Sha256,
            MessageDigest = null
        };
        var warnings = new List<string>();

        IntegrityVerifier.VerifyDocumentHash([], cmsData, warnings).Should().BeFalse();
    }

    [Fact(DisplayName = "Empty digest returns false in hash verification")]
    public void IntegrityVerifier_VerifyDocumentHash_EmptyDigest_ReturnsFalse()
    {
        var cmsData = new CmsSignedData
        {
            DigestAlgorithmOid = Oids.Sha256,
            MessageDigest = []
        };
        var warnings = new List<string>();

        IntegrityVerifier.VerifyDocumentHash([], cmsData, warnings).Should().BeFalse();
    }

    [Fact(DisplayName = "Matching SHA-256 hash returns true")]
    public void IntegrityVerifier_VerifyDocumentHash_Sha256Match_ReturnsTrue()
    {
        byte[] data = "Hello SimpleSign"u8.ToArray();
        byte[] hash = SHA256.HashData(data);
        var cmsData = new CmsSignedData
        {
            DigestAlgorithmOid = Oids.Sha256,
            MessageDigest = hash
        };
        var warnings = new List<string>();

        IntegrityVerifier.VerifyDocumentHash(data, cmsData, warnings).Should().BeTrue();
        warnings.Should().BeEmpty();
    }

    [Fact(DisplayName = "Mismatched SHA-256 hash returns false")]
    public void IntegrityVerifier_VerifyDocumentHash_Sha256Mismatch_ReturnsFalse()
    {
        byte[] data = "Hello"u8.ToArray();
        var cmsData = new CmsSignedData
        {
            DigestAlgorithmOid = Oids.Sha256,
            MessageDigest = new byte[32]
        };
        var warnings = new List<string>();

        IntegrityVerifier.VerifyDocumentHash(data, cmsData, warnings).Should().BeFalse();
    }

    [Fact(DisplayName = "SHA-1 computation adds legacy algorithm warning")]
    public void IntegrityVerifier_ComputeSha1_AddsWarning()
    {
        var warnings = new List<string>();
        byte[] result = IntegrityVerifier.ComputeSha1("test"u8.ToArray(), warnings);

        result.Should().HaveCount(20);
        warnings.Should().ContainSingle().Which.Should().Contain("SHA-1");
    }

    [Fact(DisplayName = "Unsupported OID throws NotSupportedException")]
    public void IntegrityVerifier_VerifyDocumentHash_UnsupportedOid_Throws()
    {
        var cmsData = new CmsSignedData
        {
            DigestAlgorithmOid = "1.2.3.4.999",
            MessageDigest = new byte[32]
        };
        var act = () => IntegrityVerifier.VerifyDocumentHash([], cmsData, []);

        act.Should().Throw<NotSupportedException>();
    }

    // ══════════════════════════════════════════════════════════════════════════
    // A1. CryptoVerifier tests
    // ══════════════════════════════════════════════════════════════════════════

    [Fact(DisplayName = "Null certificate returns false in signature verification")]
    public void CryptoVerifier_VerifySignature_NullCert_ReturnsFalse()
    {
        var cmsData = new CmsSignedData
        {
            SignerCertificate = null,
            SignedAttrs = new byte[] { 0xA0, 0x01 },
            Signature = new byte[] { 0x01 }
        };

        CryptoVerifier.VerifySignature(cmsData).Should().BeFalse();
    }

    [Fact(DisplayName = "Null signed attributes return false")]
    public void CryptoVerifier_VerifySignature_NullAttrs_ReturnsFalse()
    {
        using var cert = CreateCert();
        var cmsData = new CmsSignedData
        {
            SignerCertificate = cert,
            SignedAttrs = null,
            Signature = new byte[] { 0x01 }
        };

        CryptoVerifier.VerifySignature(cmsData).Should().BeFalse();
    }

    [Fact(DisplayName = "EdDSA (Ed25519) returns explicit unsupported runtime error")]
    public void CryptoVerifier_VerifySignature_Ed25519_ThrowsNotSupportedException()
    {
        using var cert = CreateCert();
        var cmsData = new CmsSignedData
        {
            SignerCertificate = cert,
            SignedAttrs = new byte[] { 0xA0, 0x00 },
            Signature = new byte[] { 0x00 },
            DigestAlgorithmOid = Oids.Sha256,
            SignatureAlgorithmOid = Oids.Ed25519
        };

        var act = () => CryptoVerifier.VerifySignature(cmsData);
        act.Should().Throw<NotSupportedException>()
            .WithMessage("*EdDSA*");
    }

    [Fact(DisplayName = "SigningCertV2 with matching hash generates no errors")]
    public void CryptoVerifier_ValidateSigningCertV2_Match_NoErrors()
    {
        using var cert = CreateCert();
        byte[] hash = SHA256.HashData(cert.RawData);
        var cmsData = new CmsSignedData
        {
            SignerCertificate = cert,
            SigningCertificateV2Hash = hash
        };
        var errors = new List<string>();

        CryptoVerifier.ValidateSigningCertV2(cmsData, errors);

        errors.Should().BeEmpty();
    }

    [Fact(DisplayName = "SigningCertV2 with mismatched hash adds error")]
    public void CryptoVerifier_ValidateSigningCertV2_Mismatch_AddsError()
    {
        using var cert = CreateCert();
        var cmsData = new CmsSignedData
        {
            SignerCertificate = cert,
            SigningCertificateV2Hash = new byte[32]
        };
        var errors = new List<string>();

        CryptoVerifier.ValidateSigningCertV2(cmsData, errors);

        errors.Should().ContainSingle().Which.Should().Contain("mismatch");
    }

    [Fact(DisplayName = "SigningCertV2 with null hash generates no error")]
    public void CryptoVerifier_ValidateSigningCertV2_NullHash_NoOp()
    {
        using var cert = CreateCert();
        var cmsData = new CmsSignedData
        {
            SignerCertificate = cert,
            SigningCertificateV2Hash = null
        };
        var errors = new List<string>();

        CryptoVerifier.ValidateSigningCertV2(cmsData, errors);

        errors.Should().BeEmpty();
    }

    // ══════════════════════════════════════════════════════════════════════════
    // A1. DssExtractor tests
    // ══════════════════════════════════════════════════════════════════════════

    [Fact(DisplayName = "PDF without DSS returns null dictionary")]
    public void DssExtractor_FindDssDictionary_NoDss_ReturnsNull()
    {
        var data = Encoding.ASCII.GetBytes("%PDF-1.4\ntrailer <</Size 1>>\n%%EOF");

        DssExtractor.FindDssDictionary(data).Should().BeNull();
    }

    [Fact(DisplayName = "IndexOfBytes finds pattern in haystack")]
    public void DssExtractor_IndexOfBytes_FindsPattern()
    {
        ReadOnlySpan<byte> haystack = "Hello World"u8;
        ReadOnlySpan<byte> needle = "World"u8;

        DssExtractor.IndexOfBytes(haystack, needle).Should().Be(6);
    }

    [Fact(DisplayName = "IndexOfBytes returns -1 when pattern not found")]
    public void DssExtractor_IndexOfBytes_NotFound_ReturnsNegative()
    {
        ReadOnlySpan<byte> haystack = "Hello"u8;
        ReadOnlySpan<byte> needle = "World"u8;

        DssExtractor.IndexOfBytes(haystack, needle).Should().Be(-1);
    }

    [Fact(DisplayName = "ParseObjRefs extracts object references correctly")]
    public void DssExtractor_ParseObjRefs_ExtractsReferences()
    {
        ReadOnlySpan<byte> content = "10 0 R 20 0 R 30 0 R"u8;

        var refs = DssExtractor.ParseObjRefs(content).ToList();

        refs.Should().BeEquivalentTo([10, 20, 30]);
    }

    // ══════════════════════════════════════════════════════════════════════════
    // A1. RevocationChecker tests
    // ══════════════════════════════════════════════════════════════════════════

    [Fact(DisplayName = "Certificate without OCSP/CRL throws ValidationException")]
    public async Task RevocationChecker_NoUrlAvailable_ThrowsInvalidOperation()
    {
        // Self-signed cert has no OCSP/CRL URLs
        using var cert = CreateCert();
        var checker = new RevocationChecker(
            new OcspClient(new HttpClient()),
            new CrlClient(new HttpClient()));

        var act = () => checker.CheckRevocationAsync(cert, [cert], [], CancellationToken.None);

        await act.Should().ThrowAsync<ValidationException>()
            .WithMessage("*no OCSP or CRL URL*");
    }

    // ══════════════════════════════════════════════════════════════════════════
    // A2. HttpClient injection tests
    // ══════════════════════════════════════════════════════════════════════════

    [Fact(DisplayName = "HttpClientProvider returns same client instance")]
    public void DefaultHttpClientProvider_GetClient_ReturnsSameInstance()
    {
        var provider = DefaultHttpClientProvider.Instance;

        var client1 = provider.GetClient();
        var client2 = provider.GetClient();

        client1.Should().BeSameAs(client2);
    }

    [Fact(DisplayName = "Default HttpClient has 30 second timeout")]
    public void DefaultHttpClientProvider_GetClient_Has30sTimeout()
    {
        var client = DefaultHttpClientProvider.Instance.GetClient();

        client.Timeout.Should().Be(TimeSpan.FromSeconds(30));
    }

    [Fact(DisplayName = "Validator accepts IHttpClientProvider in constructor")]
    public void PdfSignatureValidator_AcceptsIHttpClientProvider()
    {
        var provider = DefaultHttpClientProvider.Instance;

        var validator = new PdfSignatureValidator(provider);

        validator.Should().NotBeNull();
    }

    [Fact(DisplayName = "Null provider throws ArgumentNullException")]
    public void PdfSignatureValidator_ProviderNull_Throws()
    {
        var act = () => new PdfSignatureValidator(httpClientProvider: null!);

        act.Should().Throw<ArgumentNullException>();
    }

    [Fact(DisplayName = "WithHttpClientProvider returns new builder instance")]
    public void SignerBuilder_WithHttpClientProvider_ReturnsNewInstance()
    {
        using var cert = CreateCert();
        var pdf = CreateMinimalPdf();
        var builder = SimpleSigner.Document(pdf).WithCertificate(cert);
        var provider = DefaultHttpClientProvider.Instance;

        var newBuilder = builder.WithHttpClientProvider(provider);

        newBuilder.Should().NotBeSameAs(builder);
    }

    // ══════════════════════════════════════════════════════════════════════════
    // A3. Encrypted PDF detection tests
    // ══════════════════════════════════════════════════════════════════════════

    [Fact(DisplayName = "Encrypted PDF throws EncryptedPdfException")]
    public async Task EncryptedPdf_ReadSignatureFields_ThrowsEncryptedPdfException()
    {
        // Create a fake encrypted PDF with /Encrypt in the trailer
        var pdf = Encoding.ASCII.GetBytes(
            "%PDF-1.4\n" +
            "1 0 obj <</Type /Catalog /Pages 2 0 R>> endobj\n" +
            "xref\n0 2\n0000000000 65535 f \n0000000009 00000 n \n" +
            "trailer <</Size 2 /Root 1 0 R /Encrypt 3 0 R>>\n" +
            "startxref\n57\n%%EOF");

        using var stream = new MemoryStream(pdf);
        var act = () => PdfStructureReader.ReadSignatureFieldsAsync(stream);

        await act.Should().ThrowAsync<EncryptedPdfException>();
    }

    [Fact(DisplayName = "Normal PDF is not detected as encrypted")]
    public async Task IsEncryptedAsync_NormalPdf_ReturnsFalse()
    {
        var pdf = CreateMinimalPdf();
        using var stream = new MemoryStream(pdf);

        var result = await PdfStructureReader.IsEncryptedAsync(stream);

        result.Should().BeFalse();
    }

    [Fact(DisplayName = "Encrypted PDF is detected correctly")]
    public async Task IsEncryptedAsync_EncryptedPdf_ReturnsTrue()
    {
        var pdf = Encoding.ASCII.GetBytes(
            "%PDF-1.4\n" +
            "trailer <</Size 1 /Encrypt 2 0 R>>\n" +
            "startxref\n10\n%%EOF");
        using var stream = new MemoryStream(pdf);

        var result = await PdfStructureReader.IsEncryptedAsync(stream);

        result.Should().BeTrue();
    }

    // ══════════════════════════════════════════════════════════════════════════
    // B1. Batch validation tests
    // ══════════════════════════════════════════════════════════════════════════

    [Fact(DisplayName = "Batch validation with empty list returns empty")]
    public async Task ValidateBatchAsync_EmptyList_ReturnsEmpty()
    {
        var validator = new PdfSignatureValidator(new ValidationOptions { CheckRevocation = false });
        var items = new List<(Stream, string?)>();

        var results = await validator.ValidateBatchAsync(items);

        results.Should().BeEmpty();
    }

    [Fact(DisplayName = "Batch validation returns result for each PDF")]
    public async Task ValidateBatchAsync_MultiplePdfs_ReturnsResultForEach()
    {
        using var cert = CreateCert();
        byte[] signedPdf = await SimpleSigner.Document(CreateMinimalPdf())
            .WithCertificate(cert)
            .SignAsync();

        var items = new List<(Stream Stream, string? Identifier)>
        {
            (new MemoryStream(signedPdf), "doc1.pdf"),
            (new MemoryStream(signedPdf), "doc2.pdf"),
            (new MemoryStream(signedPdf), "doc3.pdf")
        };

        var validator = new PdfSignatureValidator(new ValidationOptions { CheckRevocation = false });
        var results = await validator.ValidateBatchAsync(items, maxConcurrency: 2);

        results.Should().HaveCount(3);
        results.Should().AllSatisfy(r => r.IsProcessed.Should().BeTrue());
        results.Select(r => r.Identifier).Should().BeEquivalentTo(["doc1.pdf", "doc2.pdf", "doc3.pdf"]);
    }

    [Fact(DisplayName = "Invalid PDF in batch returns error without throwing")]
    public async Task ValidateBatchAsync_InvalidPdf_ReturnsErrorNotException()
    {
        var items = new List<(Stream Stream, string? Identifier)>
        {
            (new MemoryStream("not a pdf"u8.ToArray()), "bad.pdf")
        };

        var validator = new PdfSignatureValidator(new ValidationOptions { CheckRevocation = false });
        var results = await validator.ValidateBatchAsync(items);

        results.Should().ContainSingle();
        results[0].IsProcessed.Should().BeFalse();
        results[0].Error.Should().NotBeNullOrEmpty();
        results[0].Identifier.Should().Be("bad.pdf");
    }

    [Fact(DisplayName = "Invalid concurrency throws ArgumentOutOfRangeException")]
    public async Task ValidateBatchAsync_InvalidConcurrency_Throws()
    {
        var validator = new PdfSignatureValidator();

        var act = () => validator.ValidateBatchAsync([], maxConcurrency: 0);

        await act.Should().ThrowAsync<ArgumentOutOfRangeException>();
    }

    [Fact(DisplayName = "Batch validation preserves document index")]
    public async Task ValidateBatchAsync_PreservesIndex()
    {
        using var cert = CreateCert();
        byte[] signedPdf = await SimpleSigner.Document(CreateMinimalPdf())
            .WithCertificate(cert)
            .SignAsync();

        var items = new List<(Stream Stream, string? Identifier)>
        {
            (new MemoryStream(signedPdf), "first"),
            (new MemoryStream(signedPdf), "second")
        };

        var validator = new PdfSignatureValidator(new ValidationOptions { CheckRevocation = false });
        var results = await validator.ValidateBatchAsync(items);

        results[0].Index.Should().Be(0);
        results[0].Identifier.Should().Be("first");
        results[1].Index.Should().Be(1);
        results[1].Identifier.Should().Be("second");
    }

    // ══════════════════════════════════════════════════════════════════════════
    // B2. PDF/A detection tests
    // ══════════════════════════════════════════════════════════════════════════

    [Fact(DisplayName = "PDF without PDF/A returns level None")]
    public void DetectPdfALevel_NoPdfA_ReturnsNone()
    {
        var data = Encoding.ASCII.GetBytes("%PDF-1.4 some content");

        PdfStructureReader.DetectPdfALevel(data).Should().Be(PdfALevel.None);
    }

    [Fact(DisplayName = "PDF/A-1b is detected correctly")]
    public void DetectPdfALevel_PdfA1b_DetectsCorrectly()
    {
        var xmp = "%PDF-1.4\n<pdfaid:part>1</pdfaid:part><pdfaid:conformance>B</pdfaid:conformance>";
        var data = Encoding.ASCII.GetBytes(xmp);

        PdfStructureReader.DetectPdfALevel(data).Should().Be(PdfALevel.A1b);
    }

    [Fact(DisplayName = "PDF/A-2a is detected correctly")]
    public void DetectPdfALevel_PdfA2a_DetectsCorrectly()
    {
        var xmp = "%PDF-1.4\n<pdfaid:part>2</pdfaid:part><pdfaid:conformance>A</pdfaid:conformance>";
        var data = Encoding.ASCII.GetBytes(xmp);

        PdfStructureReader.DetectPdfALevel(data).Should().Be(PdfALevel.A2a);
    }

    [Fact(DisplayName = "PDF/A-3u is detected correctly")]
    public void DetectPdfALevel_PdfA3u_DetectsCorrectly()
    {
        var xmp = "%PDF-1.4\n<pdfaid:part>3</pdfaid:part><pdfaid:conformance>U</pdfaid:conformance>";
        var data = Encoding.ASCII.GetBytes(xmp);

        PdfStructureReader.DetectPdfALevel(data).Should().Be(PdfALevel.A3u);
    }

    [Fact(DisplayName = "Normal PDF returns PDF/A level None via async")]
    public async Task DetectPdfALevelAsync_NormalPdf_ReturnsNone()
    {
        var pdf = CreateMinimalPdf();
        using var stream = new MemoryStream(pdf);

        var level = await PdfStructureReader.DetectPdfALevelAsync(stream);

        level.Should().Be(PdfALevel.None);
    }

    // ══════════════════════════════════════════════════════════════════════════
    // RSA-PSS support tests
    // ══════════════════════════════════════════════════════════════════════════

    private static X509Certificate2 CreatePssCert(string subject = "CN=PSS Test")
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest(subject, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
        req.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, false));
        var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        return CertificateLoader.LoadPkcs12(cert.Export(X509ContentType.Pkcs12, "test-export"), "test-export");
    }

    [Fact(DisplayName = "PSS certificate detects RSA-PSS padding")]
    public void DetectRsaPadding_PssCert_ReturnsPss()
    {
        using var cert = CreatePssCert();
        var padding = CmsSignatureBuilder.DetectRsaPadding(cert);
        padding.Should().Be(RSASignaturePadding.Pss);
    }

    [Fact(DisplayName = "PKCS#1 certificate detects PKCS1 padding")]
    public void DetectRsaPadding_Pkcs1Cert_ReturnsPkcs1()
    {
        using var cert = CreateCert();
        var padding = CmsSignatureBuilder.DetectRsaPadding(cert);
        padding.Should().Be(RSASignaturePadding.Pkcs1);
    }

    [Fact(DisplayName = "RSA-PSS signature completes full round-trip")]
    public async Task SignAndValidate_RsaPss_RoundTrips()
    {
        using var cert = CreatePssCert();
        byte[] signedPdf = await SimpleSigner.Document(CreateMinimalPdf())
            .WithCertificate(cert)
            .SignAsync();

        signedPdf.Should().NotBeEmpty();

        var validator = new PdfSignatureValidator(new ValidationOptions { CheckRevocation = false });
        var results = await validator.ValidateAsync(new MemoryStream(signedPdf));

        results.Should().ContainSingle();
        // Self-signed cert fails chain validation — only check crypto integrity
        results[0].IsIntegrityValid.Should().BeTrue();
        results[0].IsSignatureValid.Should().BeTrue();
    }

    [Fact(DisplayName = "CmsParser extracts signature algorithm OID")]
    public void CmsParser_ExtractsSignatureAlgorithmOid()
    {
        // Build a CMS with a known OID and verify the parser extracts it
        using var cert = CreateCert();
        byte[] cms = CmsSignatureBuilder.Build(
            "hello"u8, cert, HashAlgorithmName.SHA256);

        var parsed = CmsParser.Parse(cms);
        parsed.SignatureAlgorithmOid.Should().Be(Oids.RsaSha256);
    }

    [Fact(DisplayName = "CmsParser with PSS certificate extracts RSA-PSS OID")]
    public void CmsParser_PssCert_ExtractsPssOid()
    {
        using var cert = CreatePssCert();
        byte[] cms = CmsSignatureBuilder.Build(
            "hello"u8, cert, HashAlgorithmName.SHA256);

        var parsed = CmsParser.Parse(cms);
        parsed.SignatureAlgorithmOid.Should().Be(Oids.RsaPss);
    }

    [Fact(DisplayName = "RSA-PSS OID constant has correct value")]
    public void Oids_RsaPss_HasCorrectValue()
    {
        Oids.RsaPss.Should().Be("1.2.840.113549.1.1.10");
    }

    [Fact(DisplayName = "Ed25519 OID constant has correct value")]
    public void Oids_Ed25519_HasCorrectValue()
    {
        Oids.Ed25519.Should().Be("1.3.101.112");
    }

    [Fact(DisplayName = "Ed448 OID constant has correct value")]
    public void Oids_Ed448_HasCorrectValue()
    {
        Oids.Ed448.Should().Be("1.3.101.113");
    }
}
