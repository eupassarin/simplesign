using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Shouldly;
using SimpleSign.Core.Constants;
using SimpleSign.Core.Crypto;
using SimpleSign.Core.Validation;
using Xunit;

namespace SimpleSign.PAdES.Tests.Validation;

/// <summary>
/// Tests for CryptoVerifier: signature verification, SigningCertV2 validation, and EdDSA fallback.
/// </summary>
[Trait("Category", "Unit")]
public sealed class CryptoVerifierTests
{
    private static X509Certificate2 CreateCert(string subject = "CN=CryptoVerifier Test")
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest(subject, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        req.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, false));
        var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        return CertificateLoader.LoadPkcs12(cert.Export(X509ContentType.Pkcs12, "test-export"), "test-export");
    }

    [Fact(DisplayName = "Null certificate returns false in signature verification")]
    public void VerifySignature_NullCert_ReturnsFalse()
    {
        var cmsData = new CmsSignedData
        {
            SignerCertificate = null,
            SignedAttrs = [0xA0, 0x01],
            Signature = [0x01]
        };

        CryptoVerifier.VerifySignature(cmsData).ShouldBeFalse();
    }

    [Fact(DisplayName = "Null signed attributes return false")]
    public void VerifySignature_NullAttrs_ReturnsFalse()
    {
        using var cert = CreateCert();
        var cmsData = new CmsSignedData
        {
            SignerCertificate = cert,
            SignedAttrs = null,
            Signature = [0x01]
        };

        CryptoVerifier.VerifySignature(cmsData).ShouldBeFalse();
    }

    [Fact(DisplayName = "EdDSA (Ed25519) falls through to ECDSA path without throwing")]
    public void VerifySignature_Ed25519_DoesNotThrow()
    {
        using var cert = CreateCert();
        var cmsData = new CmsSignedData
        {
            SignerCertificate = cert,
            SignedAttrs = [0xA0, 0x00],
            Signature = [0x00],
            DigestAlgorithmOid = Oids.Sha256,
            SignatureAlgorithmOid = Oids.Ed25519
        };

        // EdDSA verification now falls through to the ECDSA path.
        // On runtimes that expose EdDSA via GetECDsaPublicKey (NET 9+),
        // verification runs and returns false (garbage signature).
        // On platforms without EdDSA, the fallback NotSupportedException
        // provides a clear error message.
        bool result = CryptoVerifier.VerifySignature(cmsData);
        result.ShouldBeFalse();
    }

    [Fact(DisplayName = "SigningCertV2 with matching hash generates no errors")]
    public void ValidateSigningCertV2_Match_NoErrors()
    {
        using var cert = CreateCert();
        byte[] hash = SHA256.HashData(cert.RawData);
        var cmsData = new CmsSignedData
        {
            SignerCertificate = cert,
            SigningCertificateHash = hash,
            SigningCertificateHashAlgorithmOid = "2.16.840.1.101.3.4.2.1" // SHA-256
        };
        var errors = new List<string>();

        CryptoVerifier.ValidateSigningCertV2(cmsData, errors);

        errors.ShouldBeEmpty();
    }

    [Fact(DisplayName = "SigningCertV2 with mismatched hash adds error")]
    public void ValidateSigningCertV2_Mismatch_AddsError()
    {
        using var cert = CreateCert();
        var cmsData = new CmsSignedData
        {
            SignerCertificate = cert,
            SigningCertificateHash = new byte[32],
            SigningCertificateHashAlgorithmOid = "2.16.840.1.101.3.4.2.1" // SHA-256
        };
        var errors = new List<string>();

        CryptoVerifier.ValidateSigningCertV2(cmsData, errors);

        errors.Count().ShouldBe(1);
        errors[0].ShouldContain("mismatch");
    }

    [Fact(DisplayName = "SigningCertV2 with null hash generates no error")]
    public void ValidateSigningCertV2_NullHash_NoOp()
    {
        using var cert = CreateCert();
        var cmsData = new CmsSignedData
        {
            SignerCertificate = cert,
            SigningCertificateHash = null
        };
        var errors = new List<string>();

        CryptoVerifier.ValidateSigningCertV2(cmsData, errors);

        errors.ShouldBeEmpty();
    }
}
