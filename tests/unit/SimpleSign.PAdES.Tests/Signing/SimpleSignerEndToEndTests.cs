using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using FluentAssertions;
using SimpleSign.Core.Crypto;
using SimpleSign.Core.Validation;
using SimpleSign.PAdES.Validation;
using SimpleSign.Pdf;
using Xunit;
namespace SimpleSign.PAdES.Tests.Core;

/// <summary>
/// End-to-end tests: sign → validate → detect tampering.
/// No network or external certificates required — uses RSA/ECDSA certs generated in memory.
/// </summary>
public sealed class SimpleSignerEndToEndTests
{
    private static byte[] BuildMinimalPdf()
    {
        return Encoding.Latin1.GetBytes("%PDF-1.7\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n2 0 obj\n<< /Type /Pages /Kids [] /Count 0 >>\nendobj\nxref\n0 3\n0000000000 65535 f \n0000000009 00000 n \n0000000058 00000 n \ntrailer\n<< /Size 3 /Root 1 0 R >>\nstartxref\n110\n%%EOF");
    }

    private static X509Certificate2 CreateRsaCert(string subject = "CN=Test Signer, O=Tests, C=BR")
    {
        using RSA key = RSA.Create(2048);
        CertificateRequest certificateRequest = new CertificateRequest(subject, key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        certificateRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, critical: false));
        X509Certificate2 x509Certificate = certificateRequest.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1.0), DateTimeOffset.UtcNow.AddYears(1));
        return CertificateLoader.LoadPkcs12(x509Certificate.Export(X509ContentType.Pfx, "test-export"), "test-export");
    }

    private static X509Certificate2 CreateEcdsaCert(string subject = "CN=ECDSA Signer, O=Tests, C=BR")
    {
        using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        CertificateRequest certificateRequest = new CertificateRequest(subject, key, HashAlgorithmName.SHA256);
        certificateRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, critical: false));
        X509Certificate2 x509Certificate = certificateRequest.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1.0), DateTimeOffset.UtcNow.AddYears(1));
        return CertificateLoader.LoadPkcs12(x509Certificate.Export(X509ContentType.Pfx, "test-export"), "test-export");
    }

    private static PdfSignatureValidator ValidatorTrusting(params X509Certificate2[] certs)
    {
        return new PdfSignatureValidator(new ValidationOptions
        {
            CheckRevocation = false,
            TrustedRoots = certs.ToList()
        });
    }

    [Fact(DisplayName = "RSA signature produces valid integrity and signature")]
    public async Task SignAsync_RsaCert_ProducesValidIntegrityAndSignature()
    {
        using X509Certificate2 cert = CreateRsaCert();
        byte[] pdfBytes = BuildMinimalPdf();
        using MemoryStream stream = new MemoryStream(await SimpleSigner.Document(pdfBytes).WithCertificate(cert).SignAsync());
        IReadOnlyList<SignatureValidationResult> readOnlyList = await ValidatorTrusting(cert).ValidateAsync(stream);
        readOnlyList.Should().ContainSingle("");
        readOnlyList[0].IsIntegrityValid.Should().BeTrue("");
        readOnlyList[0].IsSignatureValid.Should().BeTrue("");
    }

    [Fact(DisplayName = "ECDSA signature produces valid signature")]
    public async Task SignAsync_EcdsaCert_ProducesValidSignature()
    {
        using X509Certificate2 cert = CreateEcdsaCert();
        byte[] pdfBytes = BuildMinimalPdf();
        using MemoryStream stream = new MemoryStream(await SimpleSigner.Document(pdfBytes).WithCertificate(cert).SignAsync());
        IReadOnlyList<SignatureValidationResult> readOnlyList = await ValidatorTrusting(cert).ValidateAsync(stream);
        readOnlyList.Should().ContainSingle("");
        readOnlyList[0].IsIntegrityValid.Should().BeTrue("");
        readOnlyList[0].IsSignatureValid.Should().BeTrue("");
    }

    [Fact(DisplayName = "Signature with SHA-512 validates correctly")]
    public async Task SignAsync_Sha512_ValidatesCorrectly()
    {
        using X509Certificate2 cert = CreateRsaCert();
        byte[] pdfBytes = BuildMinimalPdf();
        using MemoryStream stream = new MemoryStream(await SimpleSigner.Document(pdfBytes).WithCertificate(cert).WithHashAlgorithm(HashAlgorithmName.SHA512)
            .SignAsync());
        IReadOnlyList<SignatureValidationResult> readOnlyList = await ValidatorTrusting(cert).ValidateAsync(stream);
        readOnlyList.Should().ContainSingle("");
        readOnlyList[0].IsIntegrityValid.Should().BeTrue("");
        readOnlyList[0].DigestAlgorithmOid.Should().Be("2.16.840.1.101.3.4.2.3", "");
    }

    [Fact(DisplayName = "Byte tampering in document detects integrity failure")]
    public async Task SignAsync_TamperByte_IntegrityFails()
    {
        using X509Certificate2 cert = CreateRsaCert();
        byte[] array = (byte[])(await SimpleSigner.Document(BuildMinimalPdf()).WithCertificate(cert).SignAsync()).Clone();
        array[50] ^= byte.MaxValue;
        using MemoryStream stream = new MemoryStream(array);
        IReadOnlyList<SignatureValidationResult> readOnlyList = await ValidatorTrusting(cert).ValidateAsync(stream);
        readOnlyList.Should().ContainSingle("");
        readOnlyList[0].IsIntegrityValid.Should().BeFalse("tampering should be detected");
    }

    [Fact(DisplayName = "Tampering at end of document detects integrity failure")]
    public async Task SignAsync_TamperAfterEnd_IntegrityFails()
    {
        using X509Certificate2 cert = CreateRsaCert();
        byte[] array = (byte[])(await SimpleSigner.Document(BuildMinimalPdf()).WithCertificate(cert).SignAsync()).Clone();
        array[^50] ^= 1;
        using MemoryStream stream = new MemoryStream(array);
        IReadOnlyList<SignatureValidationResult> readOnlyList = await ValidatorTrusting(cert).ValidateAsync(stream);
        readOnlyList.Should().ContainSingle("");
        readOnlyList[0].IsIntegrityValid.Should().BeFalse("");
    }

    [Fact(DisplayName = "Multiple signers validate correctly")]
    public async Task SignAsync_MultipleSigners_BothValidate()
    {
        using X509Certificate2 cert1 = CreateRsaCert("CN=Signer One, C=BR");
        using X509Certificate2 cert2 = CreateRsaCert("CN=Signer Two, C=BR");
        byte[] pdfBytes = BuildMinimalPdf();
        using MemoryStream stream = new MemoryStream(await SimpleSigner.Document(await SimpleSigner.Document(pdfBytes).WithCertificate(cert1).WithFieldName("Sig1")
            .SignAsync()).WithCertificate(cert2).WithFieldName("Sig2")
            .SignAsync());
        IReadOnlyList<SignatureValidationResult> actualValue = await ValidatorTrusting(cert1, cert2).ValidateAsync(stream);
        actualValue.Should().HaveCount(2, "");
        actualValue.Should().AllSatisfy(delegate (SignatureValidationResult r)
        {
            r.IsIntegrityValid.Should().BeTrue("");
        }, "");
        actualValue.Should().AllSatisfy(delegate (SignatureValidationResult r)
        {
            r.IsSignatureValid.Should().BeTrue("");
        }, "");
    }

    [Fact(DisplayName = "Multiple signers have distinct field names")]
    public async Task SignAsync_MultipleSigners_HaveDistinctFieldNames()
    {
        using X509Certificate2 cert1 = CreateRsaCert("CN=Signer One, C=BR");
        using X509Certificate2 cert2 = CreateRsaCert("CN=Signer Two, C=BR");
        using MemoryStream stream = new MemoryStream(await SimpleSigner.Document(await SimpleSigner.Document(BuildMinimalPdf()).WithCertificate(cert1).WithFieldName("SigA")
            .SignAsync()).WithCertificate(cert2).WithFieldName("SigB")
            .SignAsync());
        _ = new PdfStructureReader();
        IReadOnlyList<PdfSignatureField> readOnlyList = await PdfStructureReader.ReadSignatureFieldsAsync(stream);
        readOnlyList.Should().HaveCount(2, "");
        readOnlyList.Select((PdfSignatureField f) => f.SigDictObjectNumber).Should().OnlyHaveUniqueItems("each signature should have a different object number");
    }

    [Fact(DisplayName = "Tampering between signatures keeps first one intact")]
    public async Task SignAsync_TamperBetweenSignatures_FirstIntactSecondFails()
    {
        using X509Certificate2 cert1 = CreateRsaCert("CN=First, C=BR");
        using X509Certificate2 cert2 = CreateRsaCert("CN=Second, C=BR");
        byte[] pdfBytes = (await SimpleSigner.Document(BuildMinimalPdf()).WithCertificate(cert1).SignAsync()).Concat(new byte[10]).ToArray();
        using MemoryStream stream = new MemoryStream(await SimpleSigner.Document(pdfBytes).WithCertificate(cert2).SignAsync());
        IReadOnlyList<SignatureValidationResult> actualValue = await ValidatorTrusting(cert1, cert2).ValidateAsync(stream);
        actualValue.Should().HaveCount(2, "");
        actualValue.Should().AllSatisfy(delegate (SignatureValidationResult r)
        {
            r.IsSignatureValid.Should().BeTrue("");
        }, "");
    }

    [Theory(DisplayName = "Known OIDs return expected algorithm name")]
    [InlineData(new object[] { "2.16.840.1.101.3.4.2.1", "SHA-256" })]
    [InlineData(new object[] { "2.16.840.1.101.3.4.2.3", "SHA-512" })]
    [InlineData(new object[] { "2.16.840.1.101.3.4.2.2", "SHA-384" })]
    [InlineData(new object[] { "1.3.14.3.2.26", "SHA-1 (legacy)" })]
    [InlineData(new object[] { "1.2.3.4.5", "1.2.3.4.5" })]
    public void DigestAlgorithmName_KnownOids_ReturnsExpectedName(string oid, string expected)
    {
        SignatureValidationResult signatureValidationResult = new SignatureValidationResult
        {
            DigestAlgorithmOid = oid
        };
        signatureValidationResult.DigestAlgorithmName.Should().Be(expected, "");
    }

    [Fact(DisplayName = "Null OID returns null algorithm name")]
    public void DigestAlgorithmName_NullOid_ReturnsNull()
    {
        SignatureValidationResult signatureValidationResult = new SignatureValidationResult
        {
            DigestAlgorithmOid = null
        };
        signatureValidationResult.DigestAlgorithmName.Should().BeNull("");
    }
}
