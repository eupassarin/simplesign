using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using Shouldly;
using SimpleSign.Core.Constants;
using SimpleSign.Core.Crypto;
using Xunit;

namespace SimpleSign.Core.Tests.Compliance;

/// <summary>
/// Validates that CMS signatures produced by <see cref="CmsSignatureBuilder"/>
/// with SHA-3 digest and signature algorithms conform to RFC 9688 at the ASN.1 wire level.
/// Each test maps to a specific section of the RFC.
/// </summary>
[Trait("Category", "Unit")]
public sealed class Rfc9688Sha3CmsComplianceTests : IDisposable
{
    private const string IdSignedData = "1.2.840.113549.1.7.2";
    private const string OidSigningCertificateV2 = "1.2.840.113549.1.9.16.2.47";

    private readonly X509Certificate2 _rsaCert;
    private readonly byte[] _cmsSha3_256;
    private readonly byte[] _cmsSha3_384;
    private readonly byte[] _cmsSha3_512;

    private static bool IsSha3Available()
    {
        try
        {
            SHA3_256.HashData("test"u8);
            return true;
        }
        catch (PlatformNotSupportedException)
        {
            return false;
        }
    }

    public Rfc9688Sha3CmsComplianceTests()
    {
        Skip.If(!IsSha3Available(), "SHA-3 not supported on this platform/runtime");

        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=RFC9688 Test", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var temp = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        _rsaCert = CertificateLoader.LoadPkcs12(temp.Export(X509ContentType.Pkcs12, "t"), "t");

        _cmsSha3_256 = CmsSignatureBuilder.Build("hello rfc9688"u8.ToArray(), _rsaCert, HashAlgorithmName.SHA3_256,
            padesAttributes: true);
        _cmsSha3_384 = CmsSignatureBuilder.Build("hello rfc9688"u8.ToArray(), _rsaCert, HashAlgorithmName.SHA3_384,
            padesAttributes: true);
        _cmsSha3_512 = CmsSignatureBuilder.Build("hello rfc9688"u8.ToArray(), _rsaCert, HashAlgorithmName.SHA3_512,
            padesAttributes: true);
    }

    public void Dispose() => _rsaCert.Dispose();

    private static AsnReader OpenSignedData(byte[] cms)
    {
        var reader = new AsnReader(cms, AsnEncodingRules.DER);
        var contentInfo = reader.ReadSequence();
        var oid = contentInfo.ReadObjectIdentifier();
        oid.ShouldBe(IdSignedData);
        var wrapper = contentInfo.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0, true));
        return wrapper.ReadSequence();
    }

    private static AsnReader OpenSignerInfo(byte[] cms)
    {
        var sd = OpenSignedData(cms);
        sd.ReadInteger();
        sd.ReadEncodedValue();
        sd.ReadEncodedValue();
        if (sd.HasData && sd.PeekTag() == new Asn1Tag(TagClass.ContextSpecific, 0, true))
            sd.ReadEncodedValue();
        if (sd.HasData && sd.PeekTag() == new Asn1Tag(TagClass.ContextSpecific, 1, true))
            sd.ReadEncodedValue();
        var signerInfosSet = sd.ReadSetOf();
        return signerInfosSet.ReadSequence();
    }

    private static void AssertOidInDigestAlgorithms(byte[] cms, string expectedOid)
    {
        var sd = OpenSignedData(cms);
        sd.ReadInteger();
        var digestAlgs = sd.ReadSetOf();
        var algIds = new List<string>();
        while (digestAlgs.HasData)
        {
            var seq = digestAlgs.ReadSequence();
            algIds.Add(seq.ReadObjectIdentifier());
        }
        algIds.ShouldContain(expectedOid, $"digestAlgorithms must include {expectedOid}");
    }

    private static void AssertAlgorithmIdentifier(AsnReader algorithm, string expectedOid, bool hasNull)
    {
        algorithm.ReadObjectIdentifier().ShouldBe(expectedOid);
        if (hasNull)
        {
            algorithm.ReadNull();
        }

        algorithm.ThrowIfNotEmpty();
    }

    [SkippableFact(DisplayName = "RFC 9688 SHA-3 digest parameters are absent in SignedData and SignerInfo")]
    public void Sha3_DigestAlgorithmIdentifiers_OmitParameters()
    {
        foreach ((byte[] cms, string oid) in new[]
        {
            (_cmsSha3_256, Oids.Sha3_256),
            (_cmsSha3_384, Oids.Sha3_384),
            (_cmsSha3_512, Oids.Sha3_512)
        })
        {
            var signedData = OpenSignedData(cms);
            _ = signedData.ReadInteger();
            var algorithms = signedData.ReadSetOf();
            AssertAlgorithmIdentifier(algorithms.ReadSequence(), oid, hasNull: false);
            algorithms.ThrowIfNotEmpty();

            var signerInfo = OpenSignerInfo(cms);
            _ = signerInfo.ReadInteger();
            _ = signerInfo.ReadEncodedValue();
            AssertAlgorithmIdentifier(signerInfo.ReadSequence(), oid, hasNull: false);
        }
    }

    [SkippableFact(DisplayName = "RFC 9688 RSA with SHA-3 signature parameters contain NULL")]
    public void RsaSha3_SignatureAlgorithmIdentifiers_ContainNull()
    {
        foreach ((byte[] cms, string oid) in new[]
        {
            (_cmsSha3_256, Oids.RsaSha3_256),
            (_cmsSha3_384, Oids.RsaSha3_384),
            (_cmsSha3_512, Oids.RsaSha3_512)
        })
        {
            var signerInfo = OpenSignerInfo(cms);
            _ = signerInfo.ReadInteger();
            _ = signerInfo.ReadEncodedValue();
            _ = signerInfo.ReadEncodedValue();
            _ = signerInfo.ReadEncodedValue();
            AssertAlgorithmIdentifier(signerInfo.ReadSequence(), oid, hasNull: true);
        }
    }

    [SkippableFact(DisplayName = "RFC 9688 ECDSA with SHA-3 signature parameters are absent")]
    public void EcdsaSha3_SignatureAlgorithmIdentifiers_OmitParameters()
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest("CN=RFC9688 ECDSA Test", ecdsa, HashAlgorithmName.SHA256);
        using var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));

        foreach ((HashAlgorithmName hash, string oid) in new[]
        {
            (HashAlgorithmName.SHA3_256, Oids.EcdsaSha3_256),
            (HashAlgorithmName.SHA3_384, Oids.EcdsaSha3_384),
            (HashAlgorithmName.SHA3_512, Oids.EcdsaSha3_512)
        })
        {
            byte[] cms = CmsSignatureBuilder.Build("hello rfc9688"u8, certificate, hash);
            var signerInfo = OpenSignerInfo(cms);
            _ = signerInfo.ReadInteger();
            _ = signerInfo.ReadEncodedValue();
            _ = signerInfo.ReadEncodedValue();
            _ = signerInfo.ReadEncodedValue();
            AssertAlgorithmIdentifier(signerInfo.ReadSequence(), oid, hasNull: false);
        }
    }

    [SkippableFact(DisplayName = "RFC 9688 SHA-3 CMS can be decoded by SignedCms")]
    public void Sha3_Cms_DecodesWithIndependentParser()
    {
        foreach ((byte[] cms, string digestOid) in new[]
        {
            (_cmsSha3_256, Oids.Sha3_256),
            (_cmsSha3_384, Oids.Sha3_384),
            (_cmsSha3_512, Oids.Sha3_512)
        })
        {
            var parsed = new SignedCms(new ContentInfo("hello rfc9688"u8.ToArray()), detached: true);
            parsed.Decode(cms);
            parsed.SignerInfos.Count.ShouldBe(1);
            parsed.SignerInfos[0].DigestAlgorithm.Value.ShouldBe(digestOid);
        }
    }

    // ── RFC 9688 §2.1: SHA-3 Digest OIDs ─────────────────────────────────────

    [SkippableFact(DisplayName = "RFC 9688 §2.1 SignedData digestAlgorithms contains id-sha3-256")]
    public void SignedData_DigestAlgorithms_Contains_Sha3_256() =>
        AssertOidInDigestAlgorithms(_cmsSha3_256, Oids.Sha3_256);

    [SkippableFact(DisplayName = "RFC 9688 §2.1 SignedData digestAlgorithms contains id-sha3-384")]
    public void SignedData_DigestAlgorithms_Contains_Sha3_384() =>
        AssertOidInDigestAlgorithms(_cmsSha3_384, Oids.Sha3_384);

    [SkippableFact(DisplayName = "RFC 9688 §2.1 SignedData digestAlgorithms contains id-sha3-512")]
    public void SignedData_DigestAlgorithms_Contains_Sha3_512() =>
        AssertOidInDigestAlgorithms(_cmsSha3_512, Oids.Sha3_512);

    // ── RFC 9688 §2.1: SHA-3 digest OID in SignerInfo ────────────────────────

    [SkippableFact(DisplayName = "RFC 9688 §2.1 SignerInfo digestAlgorithm = id-sha3-256")]
    public void SignerInfo_DigestAlgorithm_Is_Sha3_256()
    {
        var si = OpenSignerInfo(_cmsSha3_256);
        si.ReadInteger();
        si.ReadEncodedValue();
        var digestAlg = si.ReadSequence();
        var oid = digestAlg.ReadObjectIdentifier();
        oid.ShouldBe(Oids.Sha3_256, "SignerInfo digestAlgorithm must be id-sha3-256");
    }

    [SkippableFact(DisplayName = "RFC 9688 §2.1 SignerInfo digestAlgorithm = id-sha3-384")]
    public void SignerInfo_DigestAlgorithm_Is_Sha3_384()
    {
        var si = OpenSignerInfo(_cmsSha3_384);
        si.ReadInteger();
        si.ReadEncodedValue();
        var digestAlg = si.ReadSequence();
        var oid = digestAlg.ReadObjectIdentifier();
        oid.ShouldBe(Oids.Sha3_384, "SignerInfo digestAlgorithm must be id-sha3-384");
    }

    [SkippableFact(DisplayName = "RFC 9688 §2.1 SignerInfo digestAlgorithm = id-sha3-512")]
    public void SignerInfo_DigestAlgorithm_Is_Sha3_512()
    {
        var si = OpenSignerInfo(_cmsSha3_512);
        si.ReadInteger();
        si.ReadEncodedValue();
        var digestAlg = si.ReadSequence();
        var oid = digestAlg.ReadObjectIdentifier();
        oid.ShouldBe(Oids.Sha3_512, "SignerInfo digestAlgorithm must be id-sha3-512");
    }

    // ── RFC 9688 §3: SHA-3 Signature Algorithm OIDs ──────────────────────────

    [SkippableFact(DisplayName = "RFC 9688 §3 SignerInfo signatureAlgorithm = id-rsassa-pkcs1-v1_5-with-sha3-256")]
    public void SignerInfo_SignatureAlgorithm_Is_RsaSha3_256()
    {
        var si = OpenSignerInfo(_cmsSha3_256);
        si.ReadInteger();
        si.ReadEncodedValue();
        si.ReadEncodedValue();
        si.ReadEncodedValue();
        var sigAlg = si.ReadSequence();
        var oid = sigAlg.ReadObjectIdentifier();
        oid.ShouldBe(Oids.RsaSha3_256, "signatureAlgorithm must be id-rsassa-pkcs1-v1_5-with-sha3-256");
    }

    [SkippableFact(DisplayName = "RFC 9688 §3 SignerInfo signatureAlgorithm = id-rsassa-pkcs1-v1_5-with-sha3-384")]
    public void SignerInfo_SignatureAlgorithm_Is_RsaSha3_384()
    {
        var si = OpenSignerInfo(_cmsSha3_384);
        si.ReadInteger();
        si.ReadEncodedValue();
        si.ReadEncodedValue();
        si.ReadEncodedValue();
        var sigAlg = si.ReadSequence();
        var oid = sigAlg.ReadObjectIdentifier();
        oid.ShouldBe(Oids.RsaSha3_384, "signatureAlgorithm must be id-rsassa-pkcs1-v1_5-with-sha3-384");
    }

    [SkippableFact(DisplayName = "RFC 9688 §3 SignerInfo signatureAlgorithm = id-rsassa-pkcs1-v1_5-with-sha3-512")]
    public void SignerInfo_SignatureAlgorithm_Is_RsaSha3_512()
    {
        var si = OpenSignerInfo(_cmsSha3_512);
        si.ReadInteger();
        si.ReadEncodedValue();
        si.ReadEncodedValue();
        si.ReadEncodedValue();
        var sigAlg = si.ReadSequence();
        var oid = sigAlg.ReadObjectIdentifier();
        oid.ShouldBe(Oids.RsaSha3_512, "signatureAlgorithm must be id-rsassa-pkcs1-v1_5-with-sha3-512");
    }

    // ── SHA-3 messageDigest size ─────────────────────────────────────────────

    [SkippableFact(DisplayName = "RFC 9688 §2.1 signedAttrs messageDigest = 32 bytes for SHA3-256")]
    public void SignedAttrs_MessageDigest_Sha3_256_Is_32_Bytes()
    {
        var si = OpenSignerInfo(_cmsSha3_256);
        si.ReadInteger();
        si.ReadEncodedValue();
        si.ReadEncodedValue();
        var raw = si.ReadEncodedValue().ToArray();
        raw[0] = 0x31;
        var reader = new AsnReader(raw, AsnEncodingRules.DER);
        var set = reader.ReadSetOf();
        ReadOnlyMemory<byte> digest = default;
        while (set.HasData)
        {
            var attr = set.ReadSequence();
            var oid = attr.ReadObjectIdentifier();
            var valSetBytes = attr.ReadEncodedValue().ToArray();
            var valReader = new AsnReader(valSetBytes, AsnEncodingRules.DER);
            var valSet = valReader.ReadSetOf();
            if (oid == "1.2.840.113549.1.9.4")
            {
                digest = valSet.ReadOctetString();
            }
        }
        digest.Length.ShouldBeGreaterThan(0);
        digest.Length.ShouldBe(32);
    }

    [SkippableFact(DisplayName = "RFC 9688 §2.1 signedAttrs messageDigest = 48 bytes for SHA3-384")]
    public void SignedAttrs_MessageDigest_Sha3_384_Is_48_Bytes()
    {
        var si = OpenSignerInfo(_cmsSha3_384);
        si.ReadInteger();
        si.ReadEncodedValue();
        si.ReadEncodedValue();
        var raw = si.ReadEncodedValue().ToArray();
        raw[0] = 0x31;
        var reader = new AsnReader(raw, AsnEncodingRules.DER);
        var set = reader.ReadSetOf();
        ReadOnlyMemory<byte> digest = default;
        while (set.HasData)
        {
            var attr = set.ReadSequence();
            var oid = attr.ReadObjectIdentifier();
            var valSetBytes = attr.ReadEncodedValue().ToArray();
            var valReader = new AsnReader(valSetBytes, AsnEncodingRules.DER);
            var valSet = valReader.ReadSetOf();
            if (oid == "1.2.840.113549.1.9.4")
            {
                digest = valSet.ReadOctetString();
            }
        }
        digest.Length.ShouldBeGreaterThan(0);
        digest.Length.ShouldBe(48);
    }

    [SkippableFact(DisplayName = "RFC 9688 §2.1 signedAttrs messageDigest = 64 bytes for SHA3-512")]
    public void SignedAttrs_MessageDigest_Sha3_512_Is_64_Bytes()
    {
        var si = OpenSignerInfo(_cmsSha3_512);
        si.ReadInteger();
        si.ReadEncodedValue();
        si.ReadEncodedValue();
        var raw = si.ReadEncodedValue().ToArray();
        raw[0] = 0x31;
        var reader = new AsnReader(raw, AsnEncodingRules.DER);
        var set = reader.ReadSetOf();
        ReadOnlyMemory<byte> digest = default;
        while (set.HasData)
        {
            var attr = set.ReadSequence();
            var oid = attr.ReadObjectIdentifier();
            var valSetBytes = attr.ReadEncodedValue().ToArray();
            var valReader = new AsnReader(valSetBytes, AsnEncodingRules.DER);
            var valSet = valReader.ReadSetOf();
            if (oid == "1.2.840.113549.1.9.4")
            {
                digest = valSet.ReadOctetString();
            }
        }
        digest.Length.ShouldBeGreaterThan(0);
        digest.Length.ShouldBe(64);
    }

    // ── PAdES attribute: signingCertificateV2 ─────────────────────────────────

    [SkippableFact(DisplayName = "RFC 5035 signedAttrs contains signingCertificateV2 with SHA3-256")]
    public void SignedAttrs_Contains_SigningCertificateV2_With_Sha3_256()
    {
        var si = OpenSignerInfo(_cmsSha3_256);
        si.ReadInteger();
        si.ReadEncodedValue();
        si.ReadEncodedValue();
        var raw = si.ReadEncodedValue().ToArray();
        raw[0] = 0x31;
        var reader = new AsnReader(raw, AsnEncodingRules.DER);
        var set = reader.ReadSetOf();
        var oids = new List<string>();
        while (set.HasData)
        {
            var attr = set.ReadSequence();
            oids.Add(attr.ReadObjectIdentifier());
            attr.ReadEncodedValue();
        }
        oids.ShouldContain(OidSigningCertificateV2,
            "signingCertificateV2 is required by PAdES-B-B (RFC 5035)");
    }

    // ── Signature verification ───────────────────────────────────────────────

    [SkippableFact(DisplayName = "RFC 9688 signature verifies with SHA3-256")]
    public void Signature_Verifies_With_Sha3_256()
    {
        var parsed = CmsParser.Parse(_cmsSha3_256);
        using var rsaPub = _rsaCert.GetRSAPublicKey()!;
        var valid = rsaPub.VerifyData(parsed.SignedAttrs!, parsed.Signature!,
            HashAlgorithmName.SHA3_256, RSASignaturePadding.Pkcs1);
        valid.ShouldBeTrue("CMS signature must verify with SHA3-256 at the cryptographic level");
    }
}
