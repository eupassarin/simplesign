using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Shouldly;
using SimpleSign.Brasil.IcpBrasil;

namespace SimpleSign.Brasil.Tests;

/// <summary>
/// Tests for the static detection helpers in <see cref="IcpBrasilChainValidator"/>:
/// <c>IsIcpBrasilCertificate</c>, <c>DetectPolicy</c>, <c>DetectCertificateLevel</c>,
/// and <c>ExtractCpfCnpj</c>. We build synthetic certificates carrying the specific
/// extensions the validator looks for, without ever talking to a real ICP-Brasil CA.
/// </summary>
public sealed class IcpBrasilDetectionTests
{
    private const string CertPoliciesOid = "2.5.29.32";
    private const string SubjectAltNameOid = "2.5.29.17";

    // ── IsIcpBrasilCertificate via Issuer name ───────────────────────────────

    [Fact(DisplayName = "IsIcpBrasilCertificate detects via Issuer name")]
    public void IsIcpBrasilCertificate_IssuerContainsIcpBrasil_ReturnsTrue()
    {
        // Issuer == Subject (self-signed) and contains the literal "ICP-Brasil"
        using var cert = CreatePlainCert("CN=AC Test, O=ICP-Brasil, C=BR");
        IcpBrasilChainValidator.IsIcpBrasilCertificate(cert).ShouldBeTrue();
    }

    [Fact(DisplayName = "IsIcpBrasilCertificate returns false for unrelated certificate")]
    public void IsIcpBrasilCertificate_Unrelated_ReturnsFalse()
    {
        using var cert = CreatePlainCert("CN=Random Self-signed, O=Generic, C=US");
        IcpBrasilChainValidator.IsIcpBrasilCertificate(cert).ShouldBeFalse();
    }

    [Fact(DisplayName = "IsIcpBrasilCertificate detects bundled root certs (Issuer contains ICP-Brasil)")]
    public void IsIcpBrasilCertificate_BundledRoot_ReturnsTrue()
    {
        var roots = IcpBrasilChainValidator.LoadBundledAcRaizCerts();
        roots.ShouldNotBeEmpty();
        // Every bundled AC Raiz cert has "ICP-Brasil" in its issuer (self-signed root)
        foreach (var c in roots)
            IcpBrasilChainValidator.IsIcpBrasilCertificate(c).ShouldBeTrue();
    }

    [Fact(DisplayName = "IsIcpBrasilCertificate detects via 2.16.76.1 policy OID (no Issuer match)")]
    public void IsIcpBrasilCertificate_PolicyOidInArc_ReturnsTrue()
    {
        // Subject/Issuer don't contain "ICP-Brasil"; detection must succeed via the OID arc.
        using var cert = CreateCertWithCertificatePolicy("2.16.76.1.7.1.1.2.3");
        IcpBrasilChainValidator.IsIcpBrasilCertificate(cert).ShouldBeTrue();
    }

    [Fact(DisplayName = "IsIcpBrasilCertificate returns false for non-Brasil policy OID")]
    public void IsIcpBrasilCertificate_NonBrasilPolicy_ReturnsFalse()
    {
        using var cert = CreateCertWithCertificatePolicy("1.3.6.1.4.1.99999.1");
        IcpBrasilChainValidator.IsIcpBrasilCertificate(cert).ShouldBeFalse();
    }

    // ── DetectPolicy ─────────────────────────────────────────────────────────

    [Theory(DisplayName = "DetectPolicy maps known OIDs to policy enum")]
    [InlineData("2.16.76.1.7.1.1.2.3", IcpBrasilPolicy.AdRb)]
    [InlineData("2.16.76.1.7.1.1.1.3", IcpBrasilPolicy.AdRb)]
    [InlineData("2.16.76.1.7.1.2.2.3", IcpBrasilPolicy.AdRt)]
    [InlineData("2.16.76.1.7.1.3.2.3", IcpBrasilPolicy.AdRv)]
    [InlineData("2.16.76.1.7.1.4.2.3", IcpBrasilPolicy.AdRc)]
    [InlineData("2.16.76.1.7.1.5.2.3", IcpBrasilPolicy.AdRa)]
    public void DetectPolicy_KnownOid_ReturnsPolicy(string oid, IcpBrasilPolicy expected)
    {
        using var cert = CreateCertWithCertificatePolicy(oid);
        IcpBrasilChainValidator.DetectPolicy(cert).ShouldBe(expected);
    }

    [Fact(DisplayName = "DetectPolicy returns null for cert without certificate policies extension")]
    public void DetectPolicy_NoExtension_ReturnsNull()
    {
        using var cert = CreatePlainCert();
        IcpBrasilChainValidator.DetectPolicy(cert).ShouldBeNull();
    }

    [Fact(DisplayName = "DetectPolicy returns null for cert with unknown policy OID")]
    public void DetectPolicy_UnknownOid_ReturnsNull()
    {
        using var cert = CreateCertWithCertificatePolicy("2.16.76.1.7.1.99.99.99");
        IcpBrasilChainValidator.DetectPolicy(cert).ShouldBeNull();
    }

    // ── DetectCertificateLevel ───────────────────────────────────────────────

    // The OID arc is 2.16.76.1.2.{level}.{type}; the byte after `60 4C 01 02` is the level:
    // A1=01, A2=02, A3=03, A4=04, S1=0B, S2=0C, S3=0D, S4=0E.
    [Theory(DisplayName = "DetectCertificateLevel maps level byte to enum")]
    [InlineData("2.16.76.1.2.1.1.1", IcpBrasilCertificateLevel.A1)]
    [InlineData("2.16.76.1.2.2.1.1", IcpBrasilCertificateLevel.A2)]
    [InlineData("2.16.76.1.2.3.1.1", IcpBrasilCertificateLevel.A3)]
    [InlineData("2.16.76.1.2.4.1.1", IcpBrasilCertificateLevel.A4)]
    [InlineData("2.16.76.1.2.11.1.1", IcpBrasilCertificateLevel.S1)]
    [InlineData("2.16.76.1.2.12.1.1", IcpBrasilCertificateLevel.S2)]
    [InlineData("2.16.76.1.2.13.1.1", IcpBrasilCertificateLevel.S3)]
    [InlineData("2.16.76.1.2.14.1.1", IcpBrasilCertificateLevel.S4)]
    public void DetectCertificateLevel_KnownArc_ReturnsLevel(string oid, IcpBrasilCertificateLevel expected)
    {
        using var cert = CreateCertWithCertificatePolicy(oid);
        IcpBrasilChainValidator.DetectCertificateLevel(cert).ShouldBe(expected);
    }

    [Fact(DisplayName = "DetectCertificateLevel returns null for cert without policy extension")]
    public void DetectCertificateLevel_NoExtension_ReturnsNull()
    {
        using var cert = CreatePlainCert();
        IcpBrasilChainValidator.DetectCertificateLevel(cert).ShouldBeNull();
    }

    [Fact(DisplayName = "DetectCertificateLevel returns null for non-ICP arc")]
    public void DetectCertificateLevel_NonIcpArc_ReturnsNull()
    {
        using var cert = CreateCertWithCertificatePolicy("1.3.6.1.4.1.99999.1");
        IcpBrasilChainValidator.DetectCertificateLevel(cert).ShouldBeNull();
    }

    [Fact(DisplayName = "DetectCertificateLevel returns null for unknown level byte (e.g. 0x05)")]
    public void DetectCertificateLevel_UnknownLevelByte_ReturnsNull()
    {
        // 2.16.76.1.2.5 → level byte 0x05 (not mapped to A1..A4 / S1..S4)
        using var cert = CreateCertWithCertificatePolicy("2.16.76.1.2.5.1.1");
        IcpBrasilChainValidator.DetectCertificateLevel(cert).ShouldBeNull();
    }

    // ── ExtractCpfCnpj via SAN otherName ─────────────────────────────────────

    [Fact(DisplayName = "ExtractCpfCnpj extracts valid CPF from SAN otherName 2.16.76.1.3.1")]
    public void ExtractCpfCnpj_WithCpfSan_ReturnsCpf()
    {
        // CPF is at positions 8..18 of the holder-data string. Pad with 8 leading chars.
        // Use a known-valid CPF (11144477735).
        const string cpf = "11144477735";
        const string holderData = "AAAAAAAA" + cpf + "more"; // 8 prefix + 11 CPF + suffix

        using var cert = CreateCertWithSan([("2.16.76.1.3.1", holderData)]);
        var (extractedCpf, cnpj) = IcpBrasilChainValidator.ExtractCpfCnpj(cert);

        extractedCpf.ShouldBe(cpf);
        cnpj.ShouldBeNull();
    }

    [Fact(DisplayName = "ExtractCpfCnpj extracts valid CNPJ from SAN otherName 2.16.76.1.3.3")]
    public void ExtractCpfCnpj_WithCnpjSan_ReturnsCnpj()
    {
        const string cnpj = "11444777000161"; // valid 14-digit CNPJ
        const string cnpjData = cnpj + "extra";

        using var cert = CreateCertWithSan([("2.16.76.1.3.3", cnpjData)]);
        var (cpf, extractedCnpj) = IcpBrasilChainValidator.ExtractCpfCnpj(cert);

        cpf.ShouldBeNull();
        extractedCnpj.ShouldBe(cnpj);
    }

    [Fact(DisplayName = "ExtractCpfCnpj returns null when SAN contains invalid CPF")]
    public void ExtractCpfCnpj_InvalidCpf_ReturnsNull()
    {
        // 8-char prefix + 11 digits but bad check digit
        const string holderData = "AAAAAAAA" + "11111111111";
        using var cert = CreateCertWithSan([("2.16.76.1.3.1", holderData)]);
        var (cpf, _) = IcpBrasilChainValidator.ExtractCpfCnpj(cert);
        cpf.ShouldBeNull();
    }

    [Fact(DisplayName = "ExtractCpfCnpj returns nulls when no SAN extension is present")]
    public void ExtractCpfCnpj_NoSan_ReturnsNulls()
    {
        using var cert = CreatePlainCert();
        var (cpf, cnpj) = IcpBrasilChainValidator.ExtractCpfCnpj(cert);
        cpf.ShouldBeNull();
        cnpj.ShouldBeNull();
    }

    [Fact(DisplayName = "ExtractCpfCnpj skips non-otherName SAN entries gracefully")]
    public void ExtractCpfCnpj_OnlyDnsSan_ReturnsNulls()
    {
        // Build SAN with just a dNSName (tag [2]) — should be skipped, no CPF/CNPJ found
        var w = new AsnWriter(AsnEncodingRules.DER);
        using (w.PushSequence())
        {
            w.WriteCharacterString(
                UniversalTagNumber.IA5String,
                "example.com",
                new Asn1Tag(TagClass.ContextSpecific, 2));
        }

        using var cert = CreateCertWithExtension(SubjectAltNameOid, w.Encode());
        var (cpf, cnpj) = IcpBrasilChainValidator.ExtractCpfCnpj(cert);
        cpf.ShouldBeNull();
        cnpj.ShouldBeNull();
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    private static X509Certificate2 CreatePlainCert(string subject = "CN=Plain Test")
    {
        using RSA key = RSA.Create(2048);
        var req = new CertificateRequest(subject, key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        return req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
    }

    private static X509Certificate2 CreateCertWithExtension(string oid, byte[] rawData)
    {
        using RSA key = RSA.Create(2048);
        var req = new CertificateRequest("CN=Ext Test", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        req.CertificateExtensions.Add(new X509Extension(oid, rawData, critical: false));
        return req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
    }

    /// <summary>
    /// Builds a CertificatePolicies extension carrying a single PolicyInformation entry
    /// with the given policy OID (no qualifiers), then attaches it to a self-signed cert.
    /// </summary>
    private static X509Certificate2 CreateCertWithCertificatePolicy(string policyOid)
    {
        // CertificatePolicies ::= SEQUENCE OF PolicyInformation
        // PolicyInformation   ::= SEQUENCE { policyIdentifier OID }
        var w = new AsnWriter(AsnEncodingRules.DER);
        using (w.PushSequence())
        {
            using (w.PushSequence())
            {
                w.WriteObjectIdentifier(policyOid);
            }
        }
        return CreateCertWithExtension(CertPoliciesOid, w.Encode());
    }

    /// <summary>
    /// Builds a SubjectAlternativeName extension carrying one or more otherName entries
    /// of the form: [0] IMPLICIT SEQUENCE { typeId OID, value [0] EXPLICIT SEQUENCE { UTF8String } }.
    /// (Wrapping the value in an inner SEQUENCE matches what the parser reads.)
    /// </summary>
    private static X509Certificate2 CreateCertWithSan((string oid, string utf8Value)[] otherNames)
    {
        var w = new AsnWriter(AsnEncodingRules.DER);
        using (w.PushSequence())
        {
            foreach (var (oid, utf8Value) in otherNames)
            {
                using (w.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0, isConstructed: true)))
                {
                    w.WriteObjectIdentifier(oid);
                    using (w.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0, isConstructed: true)))
                    {
                        w.WriteCharacterString(UniversalTagNumber.UTF8String, utf8Value);
                    }
                }
            }
        }
        return CreateCertWithExtension(SubjectAltNameOid, w.Encode());
    }
}
