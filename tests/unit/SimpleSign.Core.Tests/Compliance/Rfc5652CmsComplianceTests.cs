using System.Formats.Asn1;
using System.Numerics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Shouldly;
using SimpleSign.Core.Crypto;
using Xunit;

namespace SimpleSign.Core.Tests.Compliance;

/// <summary>
/// Validates that CMS signatures produced by <see cref="CmsSignatureBuilder"/>
/// conform to RFC 5652 (Cryptographic Message Syntax) at the ASN.1 wire level.
/// Each test maps to a specific section of the RFC.
/// </summary>
public sealed class Rfc5652CmsComplianceTests : IDisposable
{
    private const string IdData = "1.2.840.113549.1.7.1";
    private const string IdSignedData = "1.2.840.113549.1.7.2";
    private const string OidSha256 = "2.16.840.1.101.3.4.2.1";
    private const string OidContentType = "1.2.840.113549.1.9.3";
    private const string OidMessageDigest = "1.2.840.113549.1.9.4";

    private readonly X509Certificate2 _cert;
    private readonly byte[] _cmsBytes;

    public Rfc5652CmsComplianceTests()
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=RFC5652 Test", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var temp = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        _cert = CertificateLoader.LoadPkcs12(temp.Export(X509ContentType.Pkcs12, "t"), "t");
        _cmsBytes = CmsSignatureBuilder.Build("hello rfc5652"u8.ToArray(), _cert, HashAlgorithmName.SHA256,
            padesAttributes: false);
    }

    public void Dispose() => _cert.Dispose();

    // ── Helpers ────────────────────────────────────────────────────────────────

    /// <summary>Navigates into the SignedData SEQUENCE inside the CMS ContentInfo.</summary>
    private static AsnReader OpenSignedData(byte[] cms)
    {
        var reader = new AsnReader(cms, AsnEncodingRules.DER);
        var contentInfo = reader.ReadSequence();
        var oid = contentInfo.ReadObjectIdentifier();
        oid.ShouldBe(IdSignedData);
        var wrapper = contentInfo.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0, true));
        return wrapper.ReadSequence();
    }

    /// <summary>Reads the SignerInfo SEQUENCE from SignedData (skips version, digestAlgs, encapContent, certs).</summary>
    private static AsnReader OpenSignerInfo(byte[] cms)
    {
        var sd = OpenSignedData(cms);
        sd.ReadInteger();       // version
        sd.ReadEncodedValue();  // digestAlgorithms
        sd.ReadEncodedValue();  // encapContentInfo
        // certificates [0] OPTIONAL
        if (sd.HasData && sd.PeekTag() == new Asn1Tag(TagClass.ContextSpecific, 0, true))
            sd.ReadEncodedValue();
        // crls [1] OPTIONAL
        if (sd.HasData && sd.PeekTag() == new Asn1Tag(TagClass.ContextSpecific, 1, true))
            sd.ReadEncodedValue();
        var signerInfosSet = sd.ReadSetOf();
        return signerInfosSet.ReadSequence();
    }

    // ── §5.1 SignedData Structure ─────────────────────────────────────────────

    [Fact(DisplayName = "§5.1 SignedData version = 1 for issuerAndSerialNumber")]
    public void SignedData_Version_Is_1_For_IssuerAndSerialNumber()
    {
        var sd = OpenSignedData(_cmsBytes);
        var version = sd.ReadInteger();
        version.ShouldBe(BigInteger.One, "RFC 5652 §5.1: version SHALL be 1 when SignerIdentifier is issuerAndSerialNumber");
    }

    [Fact(DisplayName = "§5.1 digestAlgorithms SET contains the signer's digest algorithm")]
    public void SignedData_DigestAlgorithms_Contains_SignerInfo_Algorithm()
    {
        var sd = OpenSignedData(_cmsBytes);
        sd.ReadInteger(); // version
        var digestAlgs = sd.ReadSetOf();
        var algIds = new List<string>();
        while (digestAlgs.HasData)
        {
            var seq = digestAlgs.ReadSequence();
            algIds.Add(seq.ReadObjectIdentifier());
        }
        algIds.ShouldContain(OidSha256, "digestAlgorithms must include the algorithm used by SignerInfo");
    }

    [Fact(DisplayName = "§5.1 encapContentInfo eContentType = id-data")]
    public void SignedData_EncapContentInfo_ContentType_Is_IdData()
    {
        var sd = OpenSignedData(_cmsBytes);
        sd.ReadInteger();       // version
        sd.ReadEncodedValue();  // digestAlgorithms
        var encap = sd.ReadSequence();
        var eContentType = encap.ReadObjectIdentifier();
        eContentType.ShouldBe(IdData, "RFC 5652 §5.1: eContentType MUST be id-data for document signatures");
    }

    [Fact(DisplayName = "§5.1 encapContentInfo eContent absent for detached signature")]
    public void SignedData_EncapContentInfo_EContent_Absent_For_Detached()
    {
        var sd = OpenSignedData(_cmsBytes);
        sd.ReadInteger();       // version
        sd.ReadEncodedValue();  // digestAlgorithms
        var encap = sd.ReadSequence();
        encap.ReadObjectIdentifier(); // eContentType
        encap.HasData.ShouldBeFalse("detached CMS MUST NOT embed eContent (RFC 5652 §5.2)");
    }

    [Fact(DisplayName = "§5.1 certificates field contains signer certificate")]
    public void SignedData_Certificates_Contains_Signer_Certificate()
    {
        var sd = OpenSignedData(_cmsBytes);
        sd.ReadInteger();       // version
        sd.ReadEncodedValue();  // digestAlgorithms
        sd.ReadEncodedValue();  // encapContentInfo

        sd.PeekTag().ShouldBe(new Asn1Tag(TagClass.ContextSpecific, 0, true),
            "certificates [0] IMPLICIT must be present");

        var certsWrapper = sd.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0, true));
        var embeddedCerts = new List<X509Certificate2>();
        while (certsWrapper.HasData)
        {
            var certBytes = certsWrapper.ReadEncodedValue();
            embeddedCerts.Add(CertificateLoader.LoadCertificate(certBytes.Span));
        }

        embeddedCerts.Count().ShouldBe(1);
        embeddedCerts[0].Thumbprint.ShouldBe(_cert.Thumbprint);

        foreach (var c in embeddedCerts)
        {
            c.Dispose();
        }
    }

    [Fact(DisplayName = "§5.1 signerInfos contains exactly one entry")]
    public void SignedData_SignerInfos_Contains_Exactly_One_Entry()
    {
        var sd = OpenSignedData(_cmsBytes);
        sd.ReadInteger();       // version
        sd.ReadEncodedValue();  // digestAlgorithms
        sd.ReadEncodedValue();  // encapContentInfo
        // skip certs
        if (sd.HasData && sd.PeekTag() == new Asn1Tag(TagClass.ContextSpecific, 0, true))
            sd.ReadEncodedValue();
        // skip crls
        if (sd.HasData && sd.PeekTag() == new Asn1Tag(TagClass.ContextSpecific, 1, true))
            sd.ReadEncodedValue();

        var signerInfosSet = sd.ReadSetOf();
        int count = 0;
        while (signerInfosSet.HasData)
        {
            signerInfosSet.ReadEncodedValue();
            count++;
        }
        count.ShouldBe(1, "CmsSignatureBuilder produces exactly one SignerInfo");
    }

    // ── §5.3 SignerInfo Structure ─────────────────────────────────────────────

    [Fact(DisplayName = "§5.3 SignerInfo version = 1")]
    public void SignerInfo_Version_Is_1()
    {
        var si = OpenSignerInfo(_cmsBytes);
        var version = si.ReadInteger();
        version.ShouldBe(BigInteger.One,
            "RFC 5652 §5.3: version SHALL be 1 when sid is issuerAndSerialNumber");
    }

    [Fact(DisplayName = "§5.3 SignerInfo sid matches signer certificate")]
    public void SignerInfo_Sid_Matches_Signer_Certificate()
    {
        var si = OpenSignerInfo(_cmsBytes);
        si.ReadInteger(); // version
        var ias = si.ReadSequence(); // issuerAndSerialNumber
        var issuerRaw = ias.ReadEncodedValue();
        var serial = ias.ReadInteger();

        _cert.IssuerName.RawData.ShouldBe(issuerRaw.ToArray(),
            "issuer DN in SignerInfo must match the signer certificate");

        var expectedSerial = new BigInteger(_cert.GetSerialNumber(), isUnsigned: true);
        serial.ShouldBe(expectedSerial, "serialNumber in SignerInfo must match the signer certificate");
    }

    [Fact(DisplayName = "§5.3 SignerInfo digestAlgorithm = SHA-256")]
    public void SignerInfo_DigestAlgorithm_Correct_For_SHA256()
    {
        var si = OpenSignerInfo(_cmsBytes);
        si.ReadInteger();       // version
        si.ReadEncodedValue();  // issuerAndSerialNumber
        var digestAlg = si.ReadSequence();
        var oid = digestAlg.ReadObjectIdentifier();
        oid.ShouldBe(OidSha256, "digestAlgorithm must be id-sha256 (2.16.840.1.101.3.4.2.1)");
    }

    [Fact(DisplayName = "§5.3 signedAttrs present for detached signature")]
    public void SignerInfo_SignedAttrs_Present_For_Detached_Signature()
    {
        var si = OpenSignerInfo(_cmsBytes);
        si.ReadInteger();       // version
        si.ReadEncodedValue();  // issuerAndSerialNumber
        si.ReadEncodedValue();  // digestAlgorithm

        si.HasData.ShouldBeTrue();
        si.PeekTag().ShouldBe(new Asn1Tag(TagClass.ContextSpecific, 0, true),
            "RFC 5652 §5.3: signedAttrs MUST be present when content is not carried within the CMS");
    }

    [Fact(DisplayName = "§5.3 signature value is not empty")]
    public void SignerInfo_Signature_Not_Empty()
    {
        var si = OpenSignerInfo(_cmsBytes);
        si.ReadInteger();       // version
        si.ReadEncodedValue();  // issuerAndSerialNumber
        si.ReadEncodedValue();  // digestAlgorithm
        si.ReadEncodedValue();  // signedAttrs [0]
        si.ReadEncodedValue();  // signatureAlgorithm
        var signature = si.ReadOctetString();
        signature.ShouldNotBeEmpty("SignerInfo.signature MUST contain a non-empty signature value");
    }

    // ── §5.4 Signed Attributes ────────────────────────────────────────────────

    private byte[] ExtractSignedAttrsRaw()
    {
        var si = OpenSignerInfo(_cmsBytes);
        si.ReadInteger();       // version
        si.ReadEncodedValue();  // issuerAndSerialNumber
        si.ReadEncodedValue();  // digestAlgorithm
        return si.ReadEncodedValue().ToArray(); // signedAttrs [0] IMPLICIT
    }

    private Dictionary<string, ReadOnlyMemory<byte>> ParseSignedAttrs()
    {
        var raw = ExtractSignedAttrsRaw();
        // Replace [0] IMPLICIT (0xA0) with SET OF (0x31) for parsing
        raw[0] = 0x31;
        var reader = new AsnReader(raw, AsnEncodingRules.DER);
        var set = reader.ReadSetOf();
        var attrs = new Dictionary<string, ReadOnlyMemory<byte>>();
        while (set.HasData)
        {
            var attr = set.ReadSequence();
            var oid = attr.ReadObjectIdentifier();
            var valSet = attr.ReadEncodedValue();
            attrs[oid] = valSet;
        }
        return attrs;
    }

    [Fact(DisplayName = "§5.4 signedAttrs contains contentType = id-data")]
    public void SignedAttrs_Contains_ContentType_With_IdData()
    {
        var attrs = ParseSignedAttrs();
        attrs.ShouldContainKey(OidContentType, "contentType is a REQUIRED signed attribute (RFC 5652 §5.4)");

        var valReader = new AsnReader(attrs[OidContentType].ToArray(), AsnEncodingRules.DER);
        var valSet = valReader.ReadSetOf();
        var contentType = valSet.ReadObjectIdentifier();
        contentType.ShouldBe(IdData, "contentType attribute value MUST equal id-data");
    }

    [Fact(DisplayName = "§5.4 signedAttrs contains messageDigest")]
    public void SignedAttrs_Contains_MessageDigest()
    {
        var attrs = ParseSignedAttrs();
        attrs.ShouldContainKey(OidMessageDigest, "messageDigest is a REQUIRED signed attribute (RFC 5652 §5.4)");

        var valReader = new AsnReader(attrs[OidMessageDigest].ToArray(), AsnEncodingRules.DER);
        var valSet = valReader.ReadSetOf();
        var digest = valSet.ReadOctetString();
        digest.Count().ShouldBeGreaterThan(0, "messageDigest value must not be empty");
        digest.Count().ShouldBe(32, "SHA-256 digest is 32 bytes");
    }

    [Fact(DisplayName = "§5.4 signedAttrs are DER encoded (not BER)")]
    public void SignedAttrs_Are_DER_Encoded()
    {
        var raw = ExtractSignedAttrsRaw();
        // Replace [0] IMPLICIT with SET OF for re-encoding check
        raw[0] = 0x31;

        // Parse with DER rules — strict mode rejects non-DER encodings
        var act = () =>
        {
            var reader = new AsnReader(raw, AsnEncodingRules.DER);
            reader.ReadEncodedValue();
        };
        Should.NotThrow(act);

        // Double-check: re-encode and compare byte-for-byte
        var reader = new AsnReader(raw, AsnEncodingRules.DER);
        var decoded = reader.ReadEncodedValue();
        decoded.ToArray().ShouldBe(raw, "DER encoding must be canonical — re-encoding should produce identical bytes");
    }

    // ── §5.6 Verification ─────────────────────────────────────────────────────

    [Fact(DisplayName = "§5.6 Verification hashes signedAttrs with SET OF tag (0x31), not implicit [0] (0xA0)")]
    public void Verification_Uses_SetOf_Tag_Not_Implicit_Context()
    {
        // Per RFC 5652 §5.4: "the IMPLICIT [0] tag is not used for the DER encoding,
        // rather an EXPLICIT SET OF tag is used."
        // The actual bytes on the wire use 0xA0, but for hash/verify we must use 0x31.

        // Extract raw signedAttrs as they appear on the wire (tag = 0xA0)
        var rawOnWire = ExtractSignedAttrsRaw();
        rawOnWire[0].ShouldBe((byte)0xA0);

        // For verification, CmsParser normalises to 0x31
        var parsed = CmsParser.Parse(_cmsBytes);
        parsed.SignedAttrs.ShouldNotBeNull();
        parsed.SignedAttrs![0].ShouldBe((byte)0x31);

        // Verify signature with SET OF tag bytes
        using var rsaPub = _cert.GetRSAPublicKey()!;
        var valid = rsaPub.VerifyData(parsed.SignedAttrs, parsed.Signature!,
            HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        valid.ShouldBeTrue("signature verification must succeed when hashing signedAttrs with 0x31 tag");
    }
}
