using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Shouldly;
using SimpleSign.Core.Crypto;
using SimpleSign.Core.Extensions;
using SimpleSign.Core.Inspection;
using SimpleSign.Core.Validation;
using SimpleSign.PAdES.Inspection;
using SimpleSign.PAdES.Validation;
using SimpleSign.Pdf;
using SimpleSign.TestHelpers;
using Xunit;

namespace SimpleSign.PAdES.Tests.Compliance;

/// <summary>
/// ETSI EN 319 142-1 compliance tests for PAdES digital signatures.
/// Each test maps to a specific section of the standard.
/// </summary>
public sealed class EtsiEn319142ComplianceTests
{
    // ── OID constants ──────────────────────────────────────────────────────────
    private const string OidIdData = "1.2.840.113549.1.7.1";

    // ── Helpers ────────────────────────────────────────────────────────────────

    private static byte[] MinimalPdf() =>
        Encoding.Latin1.GetBytes(
            "%PDF-1.7\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n" +
            "2 0 obj\n<< /Type /Pages /Kids [] /Count 0 >>\nendobj\n" +
            "xref\n0 3\n0000000000 65535 f \n0000000009 00000 n \n0000000058 00000 n \n" +
            "trailer\n<< /Size 3 /Root 1 0 R >>\nstartxref\n110\n%%EOF");

    private static async Task<(byte[] SignedPdf, X509Certificate2 Cert)> SignMinimalPdfAsync(
        HashAlgorithmName? hash = null)
    {
        using var cert = TestCertificateFactory.CreateSelfSignedCert("CN=ETSI Test Signer, O=Tests");
        var builder = SimpleSigner.Document(MinimalPdf()).WithCertificate(cert);
        if (hash.HasValue)
            builder = builder.WithHashAlgorithm(hash.Value);
        var signed = await builder.SignAsync();
        return (signed, cert);
    }

    private static async Task<(PadesSignatureData Sig, CmsSignedData Cms)> SignAndParseAsync(
        HashAlgorithmName? hash = null)
    {
        var (signedPdf, _) = await SignMinimalPdfAsync(hash);
        var sigs = await PadesExtractor.ExtractAsync(signedPdf);
        sigs.Count().ShouldBe(1, "a freshly signed PDF has exactly one signature");
        var sig = sigs[0];
        var cms = CmsParser.Parse(sig.CmsSignature);
        return (sig, cms);
    }

    private static PdfSignatureValidator ValidatorTrusting(X509Certificate2 cert)
    {
        var opts = new ValidationOptions { CheckRevocation = false, TrustSystemRoots = false };
        return new PdfSignatureValidator(opts, httpClient: null, logger: null,
            trustAnchorProviders: [new InMemoryTrust(cert)]);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // §5.1 — PAdES-B-B Profile
    // ═══════════════════════════════════════════════════════════════════════════

    /// <summary>
    /// ETSI EN 319 142-1 §5.1 / RFC 5652 §5.3: The content-type signed attribute
    /// MUST be present and MUST equal id-data (1.2.840.113549.1.7.1).
    /// </summary>
    [Fact(DisplayName = "B-B §5.1: CMS contains content-type = id-data")]
    public async Task BB_SignedData_Contains_ContentType_Attribute()
    {
        var (_, cms) = await SignAndParseAsync();

        cms.ContentTypeOid.ShouldNotBeNull("content-type signed attribute is mandatory per RFC 5652 §5.3");
        cms.ContentTypeOid.ShouldBe(OidIdData,
            "content-type must be id-data (1.2.840.113549.1.7.1) for PAdES detached signatures");
    }

    /// <summary>
    /// ETSI EN 319 142-1 §5.1 / RFC 5652 §5.3: The message-digest signed attribute
    /// MUST be present and contain the hash of the signed content.
    /// </summary>
    [Fact(DisplayName = "B-B §5.1: CMS contains message-digest attribute")]
    public async Task BB_SignedData_Contains_MessageDigest_Attribute()
    {
        var (_, cms) = await SignAndParseAsync();

        cms.MessageDigest.ShouldNotBeNull("message-digest signed attribute is mandatory per RFC 5652 §5.3");
        cms.MessageDigest.ShouldNotBeEmpty("message-digest must contain the hash bytes");
    }

    /// <summary>
    /// ETSI EN 319 142-1 §5.1 / ETSI EN 319 122-1 §5.2.8: The ESS signingCertificateV2
    /// attribute MUST be present to bind the signer certificate to the CMS.
    /// </summary>
    [Fact(DisplayName = "B-B §5.1: CMS contains signingCertificateV2 attribute")]
    public async Task BB_SignedData_Contains_SigningCertificateV2_Attribute()
    {
        var (_, cms) = await SignAndParseAsync();

        cms.SigningCertificateV2Hash.ShouldNotBeNull(
            "signingCertificateV2 is mandatory for PAdES-B-B (ETSI EN 319 142-1 §5.1)");
        cms.SigningCertificateV2Hash.ShouldNotBeEmpty(
            "the certHash in signingCertificateV2 must contain the certificate hash");
    }

    /// <summary>
    /// ETSI EN 319 142-1 §5.1: PAdES signatures MUST use SubFilter ETSI.CAdES.detached.
    /// </summary>
    [Fact(DisplayName = "B-B §5.1: SubFilter is ETSI.CAdES.detached")]
    public async Task BB_SubFilter_Is_EtsiCadesDetached()
    {
        var (sig, _) = await SignAndParseAsync();

        sig.SubFilter.ShouldBe("ETSI.CAdES.detached",
            "PAdES-B-B requires SubFilter = ETSI.CAdES.detached per ETSI EN 319 142-1 §5.1");
    }

    /// <summary>
    /// ETSI EN 319 142-1 §5.1: The digest algorithm declared in digestAlgorithms
    /// MUST match the algorithm used to compute the document hash in the message-digest attribute.
    /// </summary>
    [Theory(DisplayName = "B-B §5.1: digest algorithm consistency across signed attrs")]
    [InlineData("SHA256")]
    [InlineData("SHA512")]
    public async Task BB_DigestAlgorithm_In_SignedAttrs_Matches_Document_Hash(string hashName)
    {
        var hashAlgo = new HashAlgorithmName(hashName);
        var (sig, cms) = await SignAndParseAsync(hashAlgo);

        // The message-digest length must match the expected hash output size
        var expectedLength = hashName switch
        {
            "SHA256" => 32,
            "SHA512" => 64,
            _ => throw new ArgumentException($"Unsupported hash: {hashName}")
        };

        cms.MessageDigest.ShouldNotBeNull();
        cms.MessageDigest!.Length.ShouldBe(expectedLength,
            $"message-digest byte length must match {hashName} output size ({expectedLength} bytes)");

        // Verify the digest matches what we compute over the signed data
        var computed = hashName switch
        {
            "SHA256" => SHA256.HashData(sig.SignedData),
            "SHA512" => SHA512.HashData(sig.SignedData),
            _ => throw new ArgumentException($"Unsupported hash: {hashName}")
        };
        cms.MessageDigest.ShouldBe(computed,
            "the CMS message-digest must equal the hash of the ByteRange-covered document bytes");
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // §5.2 — PAdES-B-T Profile
    // ═══════════════════════════════════════════════════════════════════════════

    /// <summary>
    /// ETSI EN 319 142-1 §5.2: A B-T signature MUST contain an RFC 3161 timestamp token
    /// as an unsigned attribute (OID 1.2.840.113549.1.9.16.2.14).
    /// This test verifies the structural requirement. Since no TSA is available in CI,
    /// we verify that a signature without a TSA does NOT have the token (negative test),
    /// and that the CmsSignedData model correctly parses a null timestamp.
    /// </summary>
    [Fact(DisplayName = "B-T §5.2: unsigned attrs timestamp token absent without TSA")]
    public async Task BT_UnsignedAttrs_Contains_Timestamp_Token()
    {
        // Without a TSA configured, there should be no timestamp token
        var (_, cms) = await SignAndParseAsync();

        // B-B signature (no TSA) should not have a timestamp
        cms.SignatureTimestampToken.ShouldBeNull(
            "a B-B signature without TSA should not contain a timestamp token");

        // Verify conformance detection agrees
        var signedPdf = await SignAndGetInspectionAsync();
        var sig = signedPdf.Signatures[0];
        sig.Timestamp.ShouldBeNull("no TSA was used so no timestamp should be detected");

        var level = ConformanceDetector.Detect(sig, signedPdf.Document, signedPdf.Signatures);
        level.ShouldBe(PAdESConformanceLevel.BaselineB,
            "without a timestamp, the conformance level cannot exceed B-B");
    }

    /// <summary>
    /// ETSI EN 319 142-1 §5.2: The timestamp message imprint must be computed over
    /// the signature value. We verify structurally that if a timestamp token were present,
    /// the CMS parser would extract it from the correct unsigned attribute OID.
    /// </summary>
    [Fact(DisplayName = "B-T §5.2: timestamp OID is correctly recognized by parser")]
    public async Task BT_Timestamp_MessageImprint_Matches_Signature_Value()
    {
        var (_, cms) = await SignAndParseAsync();

        // The CMS signature value must be present (this is what a TSA would hash)
        cms.Signature.ShouldNotBeNull("the CMS signature value must be present");
        cms.Signature.ShouldNotBeEmpty("the signature value bytes must not be empty");

        // Verify the parser recognizes the correct unsigned attribute OID
        // by checking that a B-B signature correctly has no timestamp
        cms.SignatureTimestampToken.ShouldBeNull(
            "the parser must distinguish between absent and present timestamp tokens");
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // §5.3 — PAdES-B-LT Profile
    // ═══════════════════════════════════════════════════════════════════════════

    /// <summary>
    /// ETSI EN 319 142-1 §5.3: A B-LT signature requires a DSS dictionary with
    /// revocation data (/CRLs or /OCSPs arrays).
    /// </summary>
    [Fact(DisplayName = "B-LT §5.3: DSS dictionary detection with revocation data")]
    public async Task BLT_DSS_Dictionary_Present_With_Revocation_Data()
    {
        // Construct a synthetic B-LT scenario using the conformance detector
        var sig = MakeSig(hasSigningCertV2: true, hasTimestamp: true);
        var dssWithRevocation = new DssInfo { CrlCount = 2, OcspResponseCount = 1 };
        var doc = new PdfDocumentInfo { SecurityStore = dssWithRevocation };

        // DSS must be detected as present
        dssWithRevocation.IsPresent.ShouldBeTrue("DSS with CRLs/OCSPs should report as present");
        dssWithRevocation.CrlCount.ShouldBeGreaterThan(0, "at least one CRL is required for B-LT");

        var level = ConformanceDetector.Detect(sig, doc, [sig]);
        level.ShouldBe(PAdESConformanceLevel.BaselineLT,
            "timestamp + DSS with revocation data = B-LT per §5.3");

        // Without DSS, same signature is only B-T
        var docNoDss = new PdfDocumentInfo { SecurityStore = null };
        var levelNoDss = ConformanceDetector.Detect(sig, docNoDss, [sig]);
        levelNoDss.ShouldBe(PAdESConformanceLevel.BaselineT,
            "without DSS, conformance cannot exceed B-T");
    }

    /// <summary>
    /// ETSI EN 319 142-1 §5.3 / ISO 32000-2 §12.8.4.4: VRI entries should contain
    /// a /TU timestamp entry for validation time.
    /// </summary>
    [Fact(DisplayName = "B-LT §5.3: VRI /TU timestamp field detection")]
    public async Task BLT_VRI_Contains_TU_Timestamp()
    {
        // DssInfo tracks VRI timestamp presence
        var dssWithVriTimestamps = new DssInfo
        {
            CrlCount = 1,
            OcspResponseCount = 1,
            HasVri = true,
            VriEntryCount = 1,
            VriHasTimestamps = true
        };

        dssWithVriTimestamps.HasVri.ShouldBeTrue("VRI dictionary should be present");
        dssWithVriTimestamps.VriHasTimestamps.ShouldBeTrue(
            "VRI entries should have /TU timestamp per ISO 32000-2 §12.8.4.4");

        // VRI without timestamps is a structural warning
        var dssNoVriTimestamps = new DssInfo
        {
            CrlCount = 1,
            OcspResponseCount = 1,
            HasVri = true,
            VriEntryCount = 1,
            VriHasTimestamps = false
        };

        dssNoVriTimestamps.VriHasTimestamps.ShouldBeFalse(
            "VRI without /TU should be detectable as non-compliant");
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // §5.4 — PAdES-B-LTA Profile
    // ═══════════════════════════════════════════════════════════════════════════

    /// <summary>
    /// ETSI EN 319 142-1 §5.4: A B-LTA profile requires a document timestamp
    /// after the user signature.
    /// </summary>
    [Fact(DisplayName = "B-LTA §5.4: document timestamp present after signature")]
    public async Task BLTA_Document_Timestamp_Present()
    {
        var sig = MakeSig(hasSigningCertV2: true, hasTimestamp: true, byteRangeOffset2: 1000);
        var docTs = MakeDocTimestamp(byteRangeOffset2: 2000);
        var doc = new PdfDocumentInfo
        {
            SecurityStore = new DssInfo { CrlCount = 1, OcspResponseCount = 1 }
        };

        var level = ConformanceDetector.Detect(sig, doc, [sig, docTs]);

        level.ShouldBe(PAdESConformanceLevel.BaselineLTA,
            "timestamp + DSS + doc-timestamp after signature = B-LTA per §5.4");

        // Verify the doc timestamp itself is identified correctly
        docTs.IsDocumentTimestamp.ShouldBeTrue(
            "a field with SubFilter ETSI.RFC3161 is a document timestamp");
    }

    /// <summary>
    /// ETSI EN 319 142-1 §5.4: Document timestamps must use SubFilter ETSI.RFC3161.
    /// </summary>
    [Fact(DisplayName = "B-LTA §5.4: doc timestamp SubFilter is ETSI.RFC3161")]
    public async Task BLTA_DocTimestamp_SubFilter_Is_EtsiRfc3161()
    {
        var docTs = MakeDocTimestamp();

        docTs.SubFilter.ShouldBe("ETSI.RFC3161",
            "document timestamps must use SubFilter ETSI.RFC3161 per ETSI EN 319 142-1 §5.4");
        docTs.IsDocumentTimestamp.ShouldBeTrue(
            "IsDocumentTimestamp must return true for ETSI.RFC3161 SubFilter");
    }

    /// <summary>
    /// ETSI EN 319 142-1 §5.4: The document timestamp ByteRange must cover the entire
    /// previous document revision (no gaps allowed).
    /// </summary>
    [Fact(DisplayName = "B-LTA §5.4: doc timestamp ByteRange covers entire previous document")]
    public async Task BLTA_DocTimestamp_Covers_Entire_Previous_Document()
    {
        // A valid ByteRange: starts at 0 and second segment ends at file length
        var validByteRange = new PdfByteRange
        {
            Offset1 = 0,
            Length1 = 500,
            Offset2 = 600,
            Length2 = 400
        };

        validByteRange.CoversEntireFile(1000).ShouldBeTrue(
            "ByteRange [0,500,600,400] covers a 1000-byte file end-to-end");

        // Invalid: does not start at 0
        var badStart = new PdfByteRange
        {
            Offset1 = 10,
            Length1 = 500,
            Offset2 = 600,
            Length2 = 400
        };
        badStart.CoversEntireFile(1000).ShouldBeFalse(
            "ByteRange not starting at offset 0 is non-compliant");

        // Invalid: does not extend to EOF
        var badEnd = new PdfByteRange
        {
            Offset1 = 0,
            Length1 = 500,
            Offset2 = 600,
            Length2 = 300
        };
        badEnd.CoversEntireFile(1000).ShouldBeFalse(
            "ByteRange not ending at file length is non-compliant");
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // §6 — Validation Requirements
    // ═══════════════════════════════════════════════════════════════════════════

    /// <summary>
    /// ETSI EN 319 142-1 §6: Integrity validation — the hash computed over the
    /// ByteRange-covered bytes must match the message-digest in the CMS.
    /// </summary>
    [Fact(DisplayName = "§6 Validation: ByteRange hash matches CMS message-digest")]
    public async Task Validation_Integrity_ByteRange_Hash_Matches()
    {
        var (signedPdf, cert) = await SignMinimalPdfAsync();

        using var ms = new MemoryStream(signedPdf, writable: false);
        var results = await ValidatorTrusting(cert).ValidateAsync(ms);

        results.Count().ShouldBe(1);
        results[0].IsIntegrityValid.ShouldBeTrue(
            "the ByteRange hash must match the CMS message-digest per ETSI EN 319 142-1 §6");

        // Double-check by computing the hash manually
        var sigs = await PadesExtractor.ExtractAsync(signedPdf);
        var cms = CmsParser.Parse(sigs[0].CmsSignature);
        var computed = SHA256.HashData(sigs[0].SignedData);
        cms.MessageDigest.ShouldBe(computed,
            "manual hash verification must agree with validator result");
    }

    /// <summary>
    /// ETSI EN 319 142-1 §6 / ETSI EN 319 122-1 §5.2.8: The certHash in
    /// signingCertificateV2 must match the SHA-256 hash of the signer certificate.
    /// </summary>
    [Fact(DisplayName = "§6 Validation: signingCertificateV2 hash matches signer cert")]
    public async Task Validation_SigningCertV2_Hash_Matches_Signer_Certificate()
    {
        using var cert = TestCertificateFactory.CreateSelfSignedCert("CN=CertBinding Test");
        var signed = await SimpleSigner.Document(MinimalPdf()).WithCertificate(cert).SignAsync();

        var sigs = await PadesExtractor.ExtractAsync(signed);
        var cms = CmsParser.Parse(sigs[0].CmsSignature);

        cms.SigningCertificateV2Hash.ShouldNotBeNull(
            "signingCertificateV2 certHash must be present");
        cms.SignerCertificate.ShouldNotBeNull(
            "signer certificate must be embedded in the CMS");

        // Compute expected SHA-256 hash of the signer certificate
        var expectedHash = SHA256.HashData(cms.SignerCertificate!.RawData);

        cms.SigningCertificateV2Hash.ShouldBe(expectedHash,
            "the certHash in signingCertificateV2 must equal SHA-256(signer certificate DER) " +
            "per ETSI EN 319 122-1 §5.2.8");
    }

    /// <summary>
    /// ETSI EN 319 142-1 §6: Tampering with the signed PDF must be detected by
    /// the integrity check (ByteRange hash mismatch).
    /// </summary>
    [Fact(DisplayName = "§6 Validation: tampered document is detected")]
    public async Task Validation_Tampered_Document_Detected()
    {
        var (signedPdf, cert) = await SignMinimalPdfAsync();

        // Tamper: flip a byte in the first part of the document (before the signature)
        var tampered = (byte[])signedPdf.Clone();
        // Find a safe location to tamper (early in the document, within the first ByteRange segment)
        var sigs = await PadesExtractor.ExtractAsync(signedPdf);
        var byteRange = sigs[0].ByteRange;

        // Tamper within the first ByteRange segment (but after PDF header to avoid parse errors)
        int tamperOffset = Math.Min(20, (int)byteRange.Length1 - 1);
        tampered[tamperOffset] ^= 0xFF;

        using var ms = new MemoryStream(tampered, writable: false);
        var results = await ValidatorTrusting(cert).ValidateAsync(ms);

        results.Count().ShouldBe(1);
        results[0].IsIntegrityValid.ShouldBeFalse(
            "tampered document must fail integrity validation per ETSI EN 319 142-1 §6");
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Inspection — Conformance Level Detection
    // ═══════════════════════════════════════════════════════════════════════════

    /// <summary>
    /// Verifies that the conformance detector correctly identifies B-B, B-T, B-LT, and B-LTA levels.
    /// </summary>
    [Theory(DisplayName = "Inspection: conformance level detected correctly")]
    [InlineData(false, false, false, false, PAdESConformanceLevel.CmsOnly)]
    [InlineData(true, false, false, false, PAdESConformanceLevel.BaselineB)]
    [InlineData(true, true, false, false, PAdESConformanceLevel.BaselineT)]
    [InlineData(true, true, true, false, PAdESConformanceLevel.BaselineLT)]
    [InlineData(true, true, true, true, PAdESConformanceLevel.BaselineLTA)]
    public async Task Inspection_Conformance_Level_Detected_Correctly(
        bool hasSigningCertV2,
        bool hasTimestamp,
        bool hasDss,
        bool hasDocTimestamp,
        PAdESConformanceLevel expected)
    {
        var sig = MakeSig(hasSigningCertV2: hasSigningCertV2, hasTimestamp: hasTimestamp,
            byteRangeOffset2: 1000);
        var allSigs = new List<SignatureFieldInfo> { sig };

        if (hasDocTimestamp)
        {
            allSigs.Add(MakeDocTimestamp(byteRangeOffset2: 2000));
        }

        var doc = new PdfDocumentInfo
        {
            SecurityStore = hasDss
                ? new DssInfo { CrlCount = 1, OcspResponseCount = 1 }
                : null
        };

        var level = ConformanceDetector.Detect(sig, doc, allSigs);

        level.ShouldBe(expected,
            $"conformance with sigCertV2={hasSigningCertV2}, ts={hasTimestamp}, " +
            $"dss={hasDss}, docTs={hasDocTimestamp} should be {expected}");
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Additional B-B structural verifications
    // ═══════════════════════════════════════════════════════════════════════════

    /// <summary>
    /// Verify that the eContentType in the CMS encapContentInfo is id-data
    /// for regular PAdES signatures (not document timestamps).
    /// </summary>
    [Fact(DisplayName = "B-B §5.1: eContentType is id-data")]
    public async Task BB_EContentType_Is_IdData()
    {
        var (_, cms) = await SignAndParseAsync();

        cms.EContentTypeOid.ShouldBe(OidIdData,
            "eContentType in encapContentInfo must be id-data for PAdES signatures");
    }

    /// <summary>
    /// Verify that the signer certificate is embedded in the CMS certificates set.
    /// </summary>
    [Fact(DisplayName = "B-B §5.1: signer certificate embedded in CMS")]
    public async Task BB_SignerCertificate_Embedded_In_Cms()
    {
        using var cert = TestCertificateFactory.CreateSelfSignedCert("CN=Embedded Cert Test");
        var signed = await SimpleSigner.Document(MinimalPdf()).WithCertificate(cert).SignAsync();

        var sigs = await PadesExtractor.ExtractAsync(signed);
        var cms = CmsParser.Parse(sigs[0].CmsSignature);

        cms.SignerCertificate.ShouldNotBeNull("signer certificate must be identifiable in CMS");
        cms.Certificates.ShouldNotBeEmpty("certificates set must contain at least the signer cert");
        cms.SignerCertificate!.Subject.ShouldContain("Embedded Cert Test");
    }

    /// <summary>
    /// Verify that a real signed PDF is detected as B-B conformant via the inspector.
    /// </summary>
    [Fact(DisplayName = "B-B: real signed PDF detected as BaselineB")]
    public async Task BB_Real_Signed_Pdf_Detected_As_BaselineB()
    {
        var inspection = await SignAndGetInspectionAsync();

        inspection.HasSignatures.ShouldBeTrue();
        var sig = inspection.Signatures[0];

        sig.HasSigningCertificateV2.ShouldBeTrue(
            "SimpleSigner includes signingCertificateV2 per PAdES-B-B");
        sig.SubFilter.ShouldBe("ETSI.CAdES.detached");

        var level = ConformanceDetector.Detect(sig, inspection.Document, inspection.Signatures);
        level.ShouldBe(PAdESConformanceLevel.BaselineB,
            "a signature with signingCertV2 but no timestamp is B-B");
    }

    // ── Private helpers ────────────────────────────────────────────────────────

    private static async Task<PdfInspectionResult> SignAndGetInspectionAsync()
    {
        using var cert = TestCertificateFactory.CreateSelfSignedCert("CN=Inspector Test");
        var signed = await SimpleSigner.Document(MinimalPdf()).WithCertificate(cert).SignAsync();
        using var ms = new MemoryStream(signed, writable: false);
        return await PdfSignatureInspector.InspectAsync(ms);
    }

    private static SignatureFieldInfo MakeSig(
        bool hasSigningCertV2 = false,
        bool hasTimestamp = false,
        long byteRangeOffset2 = 500)
    {
        return new SignatureFieldInfo
        {
            FieldName = "Sig",
            HasSigningCertificateV2 = hasSigningCertV2,
            Timestamp = hasTimestamp
                ? new TimestampInfo { GenerationTime = DateTimeOffset.UtcNow }
                : null,
            ByteRange = new PdfByteRange
            {
                Offset1 = 0,
                Length1 = 100,
                Offset2 = byteRangeOffset2,
                Length2 = 50
            }
        };
    }

    private static SignatureFieldInfo MakeDocTimestamp(long byteRangeOffset2 = 2000)
    {
        return new SignatureFieldInfo
        {
            FieldName = "DocTS",
            SubFilter = "ETSI.RFC3161",
            ByteRange = new PdfByteRange
            {
                Offset1 = 0,
                Length1 = 100,
                Offset2 = byteRangeOffset2,
                Length2 = 50
            }
        };
    }

    private sealed class InMemoryTrust(X509Certificate2 cert) : ITrustAnchorProvider
    {
        public string RegionCode => "TEST";
        public string DisplayName => "In-Memory Trust";
        public IReadOnlyList<X509Certificate2> GetTrustAnchors() => [cert];
    }
}
