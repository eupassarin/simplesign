using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Shouldly;
using SimpleSign.Core.Constants;
using SimpleSign.Core.Crypto;
using SimpleSign.Core.Validation;
using SimpleSign.PAdES.Validation;
using SimpleSign.Pdf;
using SimpleSign.Pdf.Enums;
using Xunit;

namespace SimpleSign.PAdES.Tests.Validation;

/// <summary>
/// Tests for PDF/A level detection and RSA-PSS signing round-trips.
/// </summary>
[Trait("Category", "Unit")]
public sealed class PdfADetectionAndRsaPssTests
{
    private static X509Certificate2 CreateCert(string subject = "CN=PDF/A Test")
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

    private static X509Certificate2 CreatePssCert(string subject = "CN=PSS Test")
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest(subject, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
        req.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, false));
        var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        return CertificateLoader.LoadPkcs12(cert.Export(X509ContentType.Pkcs12, "test-export"), "test-export");
    }

    private static X509Certificate2 CreatePssCert(HashAlgorithmName hash, string subject = "CN=PSS Test")
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest(subject, rsa, hash, RSASignaturePadding.Pss);
        req.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, false));
        var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        return CertificateLoader.LoadPkcs12(cert.Export(X509ContentType.Pkcs12, "test-export"), "test-export");
    }

    public static IEnumerable<object[]> PssHashVariants() =>
    [
        [HashAlgorithmName.SHA256, Oids.Sha256, 32],
        [HashAlgorithmName.SHA384, Oids.Sha384, 48],
        [HashAlgorithmName.SHA512, Oids.Sha512, 64]
    ];

    private static int IndexOf(byte[] haystack, byte[] needle)
    {
        for (int i = 0; i <= haystack.Length - needle.Length; i++)
        {
            bool match = true;
            for (int j = 0; j < needle.Length; j++)
            {
                if (haystack[i + j] != needle[j])
                {
                    match = false;
                    break;
                }
            }
            if (match)
            {
                return i;
            }
        }
        return -1;
    }

    // ── PDF/A detection ───────────────────────────────────────────────────

    [Fact(DisplayName = "PDF without PDF/A returns level None")]
    public void DetectPdfALevel_NoPdfA_ReturnsNone()
    {
        var data = Encoding.ASCII.GetBytes("%PDF-1.4 some content");

        PdfStructureReader.DetectPdfALevel(data).ShouldBe(PdfALevel.None);
    }

    [Fact(DisplayName = "PDF/A-1b is detected correctly")]
    public void DetectPdfALevel_PdfA1b_DetectsCorrectly()
    {
        var xmp = "%PDF-1.4\n<pdfaid:part>1</pdfaid:part><pdfaid:conformance>B</pdfaid:conformance>";
        var data = Encoding.ASCII.GetBytes(xmp);

        PdfStructureReader.DetectPdfALevel(data).ShouldBe(PdfALevel.A1b);
    }

    [Fact(DisplayName = "PDF/A-2a is detected correctly")]
    public void DetectPdfALevel_PdfA2a_DetectsCorrectly()
    {
        var xmp = "%PDF-1.4\n<pdfaid:part>2</pdfaid:part><pdfaid:conformance>A</pdfaid:conformance>";
        var data = Encoding.ASCII.GetBytes(xmp);

        PdfStructureReader.DetectPdfALevel(data).ShouldBe(PdfALevel.A2a);
    }

    [Fact(DisplayName = "PDF/A-3u is detected correctly")]
    public void DetectPdfALevel_PdfA3u_DetectsCorrectly()
    {
        var xmp = "%PDF-1.4\n<pdfaid:part>3</pdfaid:part><pdfaid:conformance>U</pdfaid:conformance>";
        var data = Encoding.ASCII.GetBytes(xmp);

        PdfStructureReader.DetectPdfALevel(data).ShouldBe(PdfALevel.A3u);
    }

    [Fact(DisplayName = "Normal PDF returns PDF/A level None via async")]
    public async Task DetectPdfALevelAsync_NormalPdf_ReturnsNone()
    {
        var pdf = CreateMinimalPdf();
        using var stream = new MemoryStream(pdf);

        var level = await PdfStructureReader.DetectPdfALevelAsync(stream);

        level.ShouldBe(PdfALevel.None);
    }

    // ── RSA-PSS support ───────────────────────────────────────────────────

    [Fact(DisplayName = "PSS certificate detects RSA-PSS padding")]
    public void DetectRsaPadding_PssCert_ReturnsPss()
    {
        using var cert = CreatePssCert();
        var padding = CmsSignatureBuilder.DetectRsaPadding(cert);
        padding.ShouldBe(RSASignaturePadding.Pss);
    }

    [Fact(DisplayName = "PKCS#1 certificate detects PKCS1 padding")]
    public void DetectRsaPadding_Pkcs1Cert_ReturnsPkcs1()
    {
        using var cert = CreateCert();
        var padding = CmsSignatureBuilder.DetectRsaPadding(cert);
        padding.ShouldBe(RSASignaturePadding.Pkcs1);
    }

    [Fact(DisplayName = "RSA-PSS signature completes full round-trip")]
    public async Task SignAndValidate_RsaPss_RoundTrips()
    {
        using var cert = CreatePssCert();
        byte[] signedPdf = await PadesSigner.Document(CreateMinimalPdf())
            .WithCertificate(cert)
            .SignAsync();

        signedPdf.ShouldNotBeEmpty();

        var validator = new PdfSignatureValidator(new ValidationOptions { CheckRevocation = false });
        var results = await validator.ValidateAsync(new MemoryStream(signedPdf));

        results.Count().ShouldBe(1);
        // Self-signed cert fails chain validation — only check crypto integrity
        results[0].IsIntegrityValid.ShouldBeTrue();
        results[0].IsSignatureValid.ShouldBeTrue();
    }

    [Fact(DisplayName = "CmsParser extracts signature algorithm OID")]
    public void CmsParser_ExtractsSignatureAlgorithmOid()
    {
        // Build a CMS with a known OID and verify the parser extracts it
        using var cert = CreateCert();
        byte[] cms = CmsSignatureBuilder.Build(
            "hello"u8, cert, HashAlgorithmName.SHA256);

        var parsed = CmsParser.Parse(cms);
        parsed.SignatureAlgorithmOid.ShouldBe(Oids.RsaSha256);
    }

    [Fact(DisplayName = "CmsParser with PSS certificate extracts RSA-PSS OID")]
    public void CmsParser_PssCert_ExtractsPssOid()
    {
        using var cert = CreatePssCert();
        byte[] cms = CmsSignatureBuilder.Build(
            "hello"u8, cert, HashAlgorithmName.SHA256);

        var parsed = CmsParser.Parse(cms);
        parsed.SignatureAlgorithmOid.ShouldBe(Oids.RsaPss);
    }

    [Fact(DisplayName = "RSA-PSS OID constant has correct value")]
    public void Oids_RsaPss_HasCorrectValue() => Oids.RsaPss.ShouldBe("1.2.840.113549.1.1.10");

    [Fact(DisplayName = "Ed25519 OID constant has correct value")]
    public void Oids_Ed25519_HasCorrectValue() => Oids.Ed25519.ShouldBe("1.3.101.112");

    [Fact(DisplayName = "Ed448 OID constant has correct value")]
    public void Oids_Ed448_HasCorrectValue() => Oids.Ed448.ShouldBe("1.3.101.113");

    // ── RSASSA-PSS variants (PS256 / PS384 / PS512) — RFC 4055 §3.1 ───────

    [Theory(DisplayName = "RSA-PSS round-trip signs and validates for each hash variant")]
    [MemberData(nameof(PssHashVariants))]
    public async Task SignAndValidate_RsaPss_Variants_RoundTrip(HashAlgorithmName hash, string expectedHashOid, int expectedSaltLength)
    {
        _ = expectedHashOid; // documented in test name + CmsBuilder_PssCert_WritesPssParams
        _ = expectedSaltLength; // documented in test name + CmsBuilder_PssCert_WritesPssParams

        using var cert = CreatePssCert(hash);
        byte[] signedPdf = await PadesSigner.Document(CreateMinimalPdf())
            .WithCertificate(cert)
            .SignAsync();

        signedPdf.ShouldNotBeEmpty();

        var validator = new PdfSignatureValidator(new ValidationOptions { CheckRevocation = false });
        var results = await validator.ValidateAsync(new MemoryStream(signedPdf));

        results.Count().ShouldBe(1);
        // Self-signed cert fails chain validation — only check crypto integrity
        results[0].IsIntegrityValid.ShouldBeTrue();
        results[0].IsSignatureValid.ShouldBeTrue();
    }

    [Theory(DisplayName = "CmsBuilder writes RSASSA-PSS-params with correct hash OID, mgf1, and saltLength")]
    [MemberData(nameof(PssHashVariants))]
    public void CmsBuilder_PssCert_WritesPssParams(HashAlgorithmName hash, string expectedHashOid, int expectedSaltLength)
    {
        using var cert = CreatePssCert(hash);
        byte[] cms = CmsSignatureBuilder.Build(
            "hello"u8, cert, hash);

        // The CMS bytes contain the AlgorithmIdentifier for the signer. Locate the
        // 1.2.840.113549.1.1.10 (id-RSASSA-PSS) OID and verify what follows.
        byte[] oidBytes = [0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0A];
        int oidIdx = IndexOf(cms, oidBytes);
        oidIdx.ShouldBeGreaterThan(-1, "id-RSASSA-PSS OID must be present in the CMS");

        // After the OID, the AlgorithmIdentifier SEQUENCE contains RSASSA-PSS-params.
        // Walk forward to the params SEQUENCE; it begins with 0x30.
        int afterOid = oidIdx + oidBytes.Length;
        int paramsStart = -1;
        for (int i = afterOid; i < cms.Length - 2; i++)
        {
            if (cms[i] == 0x30)
            {
                paramsStart = i;
                break;
            }
        }
        paramsStart.ShouldBeGreaterThan(-1, "RSASSA-PSS-params SEQUENCE must follow the OID");

        // Decode the params SEQUENCE and check the three fields.
        var paramsReader = new AsnReader(cms.AsSpan(paramsStart).ToArray(), AsnEncodingRules.BER);
        var paramsSeq = paramsReader.ReadSequence();

        // [0] EXPLICIT hashAlgorithm = SEQUENCE { OID, NULL? }
        var hashAlgReader = paramsSeq.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0, true));
        var hashAlgSeq = hashAlgReader.ReadSequence();
        string actualHashOid = hashAlgSeq.ReadObjectIdentifier();
        actualHashOid.ShouldBe(expectedHashOid);

        // [1] EXPLICIT maskGenAlgorithm = SEQUENCE { OID id-mgf1, SEQUENCE { OID hash, NULL? } }
        var mgfReader = paramsSeq.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 1, true));
        var mgfSeq = mgfReader.ReadSequence();
        mgfSeq.ReadObjectIdentifier().ShouldBe(Oids.Mgf1);
        var mgfHashSeq = mgfSeq.ReadSequence();
        mgfHashSeq.ReadObjectIdentifier().ShouldBe(expectedHashOid);

        // [2] EXPLICIT saltLength INTEGER
        var saltReader = paramsSeq.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 2, true));
        saltReader.ReadInteger().ShouldBe(expectedSaltLength);
    }

    [Theory(DisplayName = "CryptoUtility.ParsePssHashAlgorithm returns correct hash from PSS params")]
    [MemberData(nameof(PssHashVariants))]
    public void ParsePssHashAlgorithm_ValidPssParams_ReturnsExpectedHash(HashAlgorithmName expectedHash, string expectedHashOid, int expectedSaltLength)
    {
        // Build the params bytes the same way CmsSignatureBuilder does
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSequence())
        {
            using (writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0, true)))
            using (writer.PushSequence())
            {
                writer.WriteObjectIdentifier(expectedHashOid);
                writer.WriteNull();
            }
            using (writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 1, true)))
            using (writer.PushSequence())
            {
                writer.WriteObjectIdentifier(Oids.Mgf1);
                using (writer.PushSequence())
                {
                    writer.WriteObjectIdentifier(expectedHashOid);
                    writer.WriteNull();
                }
            }
            using (writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 2, true)))
            {
                writer.WriteInteger(expectedSaltLength);
            }
        }
        byte[] paramsBytes = writer.Encode();

        CryptoUtility.ParsePssHashAlgorithm(paramsBytes).ShouldBe(expectedHash);
    }

    [Fact(DisplayName = "ParsePssHashAlgorithm with empty params returns SHA-256 (RFC default)")]
    public void ParsePssHashAlgorithm_EmptyParams_ReturnsSha256()
    {
        var result = CryptoUtility.ParsePssHashAlgorithm(default(ReadOnlySpan<byte>));
        result.ShouldBe(HashAlgorithmName.SHA256);
    }

    [Fact(DisplayName = "ParsePssHashAlgorithm with empty SEQUENCE (no hashAlgorithm field) returns SHA-256")]
    public void ParsePssHashAlgorithm_EmptySequence_ReturnsSha256()
    {
        // RSASSA-PSS-params with no [0] element — all fields are RFC default (SHA-256)
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSequence())
        {
            // empty
        }
        byte[] paramsBytes = writer.Encode();
        CryptoUtility.ParsePssHashAlgorithm(paramsBytes).ShouldBe(HashAlgorithmName.SHA256);
    }

    [Fact(DisplayName = "CmsParser round-trips PSS signatures across all hash variants")]
    public void CmsParser_PssVariants_AllExtractPssOid()
    {
        foreach (var hash in new HashAlgorithmName[] { HashAlgorithmName.SHA256, HashAlgorithmName.SHA384, HashAlgorithmName.SHA512 })
        {
            using var cert = CreatePssCert(hash);
            byte[] cms = CmsSignatureBuilder.Build("hello"u8, cert, hash);

            var parsed = CmsParser.Parse(cms);
            parsed.SignatureAlgorithmOid.ShouldBe(Oids.RsaPss);
        }
    }
}
