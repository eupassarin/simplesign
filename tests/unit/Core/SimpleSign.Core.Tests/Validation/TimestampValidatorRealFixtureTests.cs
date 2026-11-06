using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Shouldly;
using SimpleSign.Core.Crypto;
using SimpleSign.Core.Validation;
using SimpleSign.TestFixtures;
using Xunit;

namespace SimpleSign.Core.Tests.Validation;

/// <summary>
/// Real-fixture tests for <c>TimestampValidator.Validate</c> using a captured
/// freetsa.org RFC 3161 token. Exercises full token parsing, TSA signature
/// verification, hash-match check, and genTime extraction.
/// </summary>
/// <remarks>
/// The fixture was created via <c>openssl ts -query -data /tmp/digest.bin</c> where
/// <c>digest.bin = sha256("SimpleSign fixture record")</c>. Therefore:
/// <para>token.messageImprint.hashedMessage = sha256(sha256("SimpleSign fixture record"))</para>
/// <para>To pass <c>ValidateHashMatch</c> we set <c>Signature = sha256("SimpleSign fixture record")</c>.</para>
/// </remarks>
[Trait("Category", "Unit")]
public sealed class TimestampValidatorRealFixtureTests
{
    private static byte[] TimestampedSignaturePreImage =>
        SHA256.HashData(Encoding.ASCII.GetBytes("SimpleSign fixture record"));

    [Fact(DisplayName = "Validate returns true for matching real freetsa token")]
    public void Validate_RealToken_ReturnsTrue()
    {
        var cms = new CmsSignedData
        {
            Signature = TimestampedSignaturePreImage,
            SignatureTimestampToken = RecordedFixtures.FreeTsaToken,
        };
        var warnings = new List<string>();

        var result = TimestampValidator.Validate(cms, warnings);

        result!.Value.ShouldBeTrue();
    }

    [Fact(DisplayName = "Validate returns false when Signature does not match messageImprint")]
    public void Validate_HashMismatch_ReturnsFalse()
    {
        var cms = new CmsSignedData
        {
            Signature = "some-other-bytes-that-do-not-match"u8.ToArray(),
            SignatureTimestampToken = RecordedFixtures.FreeTsaToken,
        };
        var warnings = new List<string>();

        var result = TimestampValidator.Validate(cms, warnings);

        result!.Value.ShouldBeFalse();
        warnings.ShouldContain(w => w.Contains("hash mismatch", StringComparison.OrdinalIgnoreCase));
    }

    [Fact(DisplayName = "Validate returns null when no timestamp token is present")]
    public void Validate_NoTimestamp_ReturnsNull()
    {
        var cms = new CmsSignedData
        {
            Signature = [1, 2, 3],
            SignatureTimestampToken = null,
        };
        var warnings = new List<string>();

        var result = TimestampValidator.Validate(cms, warnings);

        result.ShouldBeNull();
        warnings.ShouldBeEmpty();
    }

    [Fact(DisplayName = "Validate returns null when Signature is null")]
    public void Validate_NoSignature_ReturnsNull()
    {
        var cms = new CmsSignedData
        {
            Signature = null,
            SignatureTimestampToken = RecordedFixtures.FreeTsaToken,
        };
        var warnings = new List<string>();

        var result = TimestampValidator.Validate(cms, warnings);

        result.ShouldBeNull();
    }

    [Fact(DisplayName = "Validate invokes chain validator with TSA certificates from real token")]
    public void Validate_WithChainValidator_PassesTsaCerts()
    {
        var cms = new CmsSignedData
        {
            Signature = TimestampedSignaturePreImage,
            SignatureTimestampToken = RecordedFixtures.FreeTsaToken,
        };
        var warnings = new List<string>();
        bool chainCalled = false;
        int certCount = 0;

        bool ChainValidator(
            System.Security.Cryptography.X509Certificates.X509Certificate2? signer,
            IReadOnlyList<System.Security.Cryptography.X509Certificates.X509Certificate2> embedded,
            List<string> errors,
            List<string> warns)
        {
            chainCalled = true;
            certCount = embedded.Count;
            return true;
        }

        var result = TimestampValidator.Validate(cms, warnings, ChainValidator);

        result!.Value.ShouldBeTrue();
        chainCalled.ShouldBeTrue();
        certCount.ShouldBeGreaterThan(0);
    }

    [Fact(DisplayName = "Validate gracefully handles malformed timestamp token")]
    public void Validate_MalformedToken_ReturnsNullWithWarning()
    {
        var cms = new CmsSignedData
        {
            Signature = TimestampedSignaturePreImage,
            SignatureTimestampToken = [0x30, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00],
        };
        var warnings = new List<string>();

        var result = TimestampValidator.Validate(cms, warnings);

        result.ShouldBeNull();
        warnings.ShouldNotBeEmpty();
    }

    [Fact(DisplayName = "Validate with SigningTime far after genTime emits warning")]
    public void Validate_SigningTimeAfterGenTime_EmitsWarning()
    {
        // genTime in fixture is 2026-04-29; SigningTime in 2099 is well past genTime + 5min,
        // so the validator should emit "before signingTime".
        var cms = new CmsSignedData
        {
            Signature = TimestampedSignaturePreImage,
            SignatureTimestampToken = RecordedFixtures.FreeTsaToken,
            SigningTime = new DateTimeOffset(2099, 1, 1, 0, 0, 0, TimeSpan.Zero),
        };
        var warnings = new List<string>();

        var result = TimestampValidator.Validate(cms, warnings);

        result!.Value.ShouldBeTrue();
        warnings.ShouldContain(w => w.Contains("before signingTime", StringComparison.OrdinalIgnoreCase));
    }

    [Fact(DisplayName = "Validate identifies signer cert by issuerAndSerialNumber when multiple certs are present")]
    public void Validate_MultiCertToken_SignerIdentifiedByIssuerAndSerial()
    {
        // Build a synthetic CMS TSA token where the SIGNER cert is embedded at position [1]
        // and a DECOY cert is at position [0]. The upstream fix (eedf8a3) ensures the signer
        // is correctly identified via issuerAndSerialNumber and moved to Certificates[0] before
        // the chain validator is invoked.

        using RSA signerKey = RSA.Create(2048);
        using var signerCert = BuildSelfSignedCert(signerKey, "CN=TSA Signer, O=Test");

        using RSA decoyKey = RSA.Create(2048);
        using var decoyCert = BuildSelfSignedCert(decoyKey, "CN=Decoy Cert, O=Test");

        // cmsData.Signature is the "pre-image" — ValidateHashMatch hashes it and compares
        // to the hashedMessage inside TSTInfo. So tokenBytes is built with SHA256(sigValue).
        byte[] sigValue = "unit-test-preimage"u8.ToArray();
        byte[] hashedSig = SHA256.HashData(sigValue);
        byte[] tokenBytes = BuildSyntheticTsaToken(signerKey, signerCert, decoyCert, hashedSig);

        var cms = new CmsSignedData
        {
            Signature = sigValue,
            SignatureTimestampToken = tokenBytes,
        };

        var warnings = new List<string>();
        X509Certificate2? receivedSigner = null;

        bool ChainValidator(
            X509Certificate2? signer,
            IReadOnlyList<X509Certificate2> embedded,
            List<string> errors,
            List<string> warns)
        {
            receivedSigner = signer;
            return true;
        }

        var result = TimestampValidator.Validate(cms, warnings, ChainValidator);

        result!.Value.ShouldBeTrue("synthetic token should validate successfully");
        receivedSigner.ShouldNotBeNull("chain validator must receive a signer cert");
        receivedSigner!.Thumbprint.ShouldBe(signerCert.Thumbprint,
            "signer cert must be the ACTUAL signer (identified by issuerAndSerialNumber), not the decoy at position [0]");
    }

    /// <summary>
    /// Builds a minimal but cryptographically valid RFC 3161 CMS timestamp token with two
    /// embedded certificates: a decoy at position [0] and the real signer at position [1].
    /// </summary>
    private static byte[] BuildSyntheticTsaToken(
        RSA signerKey,
        System.Security.Cryptography.X509Certificates.X509Certificate2 signerCert,
        System.Security.Cryptography.X509Certificates.X509Certificate2 decoyCert,
        byte[] preImageHash)
    {
        byte[] tstInfoBytes;
        {
            var w = new AsnWriter(AsnEncodingRules.DER);
            using (w.PushSequence())
            {
                w.WriteInteger(1);
                w.WriteObjectIdentifier("1.2.3.4");
                using (w.PushSequence())
                {
                    using (w.PushSequence())
                    { w.WriteObjectIdentifier("2.16.840.1.101.3.4.2.1"); }
                    w.WriteOctetString(preImageHash);
                }
                w.WriteInteger(1234567890);
                w.WriteGeneralizedTime(DateTimeOffset.UtcNow);
            }
            tstInfoBytes = w.Encode();
        }

        byte[] signedAttrsBytes;
        {
            var w = new AsnWriter(AsnEncodingRules.DER);
            using (w.PushSetOf())
            {
                using (w.PushSequence())
                {
                    w.WriteObjectIdentifier("1.2.840.113549.1.9.3");
                    using (w.PushSetOf())
                    { w.WriteObjectIdentifier("1.2.840.113549.1.9.16.1.4"); }
                }
                using (w.PushSequence())
                {
                    w.WriteObjectIdentifier("1.2.840.113549.1.9.4");
                    using (w.PushSetOf())
                    { w.WriteOctetString(SHA256.HashData(tstInfoBytes)); }
                }
                using (w.PushSequence())
                {
                    w.WriteObjectIdentifier("1.2.840.113549.1.9.16.2.47");
                    using (w.PushSetOf())
                    using (w.PushSequence())
                    using (w.PushSequence())
                    using (w.PushSequence())
                    {
                        w.WriteOctetString(SHA256.HashData(signerCert.RawData));
                    }
                }
            }
            signedAttrsBytes = w.Encode();
        }

        byte[] attrsForSigning = (byte[])signedAttrsBytes.Clone();
        attrsForSigning[0] = 0x31; // SET OF tag for signing
        byte[] signature = signerKey.SignData(attrsForSigning, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        var cmsWriter = new AsnWriter(AsnEncodingRules.DER);
        using (cmsWriter.PushSequence())
        {
            cmsWriter.WriteObjectIdentifier("1.2.840.113549.1.7.2");
            using (cmsWriter.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0, true)))
            {
                using (cmsWriter.PushSequence())
                {
                    cmsWriter.WriteInteger(3);
                    using (cmsWriter.PushSetOf())
                    {
                        using (cmsWriter.PushSequence())
                        { cmsWriter.WriteObjectIdentifier("2.16.840.1.101.3.4.2.1"); }
                    }
                    using (cmsWriter.PushSequence())
                    {
                        cmsWriter.WriteObjectIdentifier("1.2.840.113549.1.9.16.1.4");
                        using (cmsWriter.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0, true)))
                        {
                            cmsWriter.WriteOctetString(tstInfoBytes);
                        }
                    }
                    // Certs: decoy first, real signer second (tests the reordering fix)
                    using (cmsWriter.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0, true)))
                    {
                        cmsWriter.WriteEncodedValue(decoyCert.RawData);
                        cmsWriter.WriteEncodedValue(signerCert.RawData);
                    }
                    using (cmsWriter.PushSetOf())
                    {
                        using (cmsWriter.PushSequence())
                        {
                            cmsWriter.WriteInteger(1);
                            using (cmsWriter.PushSequence())
                            {
                                cmsWriter.WriteEncodedValue(signerCert.IssuerName.RawData);
                                cmsWriter.WriteIntegerUnsigned(signerCert.SerialNumberBytes.Span);
                            }
                            using (cmsWriter.PushSequence())
                            { cmsWriter.WriteObjectIdentifier("2.16.840.1.101.3.4.2.1"); }
                            byte[] signedAttrsCopy = (byte[])signedAttrsBytes.Clone();
                            signedAttrsCopy[0] = 0xA0; // IMPLICIT [0] constructed
                            cmsWriter.WriteEncodedValue(signedAttrsCopy);
                            using (cmsWriter.PushSequence())
                            {
                                cmsWriter.WriteObjectIdentifier("1.2.840.113549.1.1.11");
                                cmsWriter.WriteNull();
                            }
                            cmsWriter.WriteOctetString(signature);
                        }
                    }
                }
            }
        }
        return cmsWriter.Encode();
    }

    private static X509Certificate2 BuildSelfSignedCert(RSA key, string subject)
    {
        var req = new CertificateRequest(subject, key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var usages = new OidCollection { new Oid("1.3.6.1.5.5.7.3.8") };
        req.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(usages, critical: true));
        var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        return X509CertificateLoader.LoadCertificate(cert.RawData);
    }
}
