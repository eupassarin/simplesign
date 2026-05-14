using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using FluentAssertions;
using SimpleSign.Brasil.GovBr;

namespace SimpleSign.Brasil.Tests;

/// <summary>
/// Tests for the static detection helpers in <see cref="GovBrChainValidator"/>:
/// <c>IsGovBrCertificate</c>, <c>DetectAssuranceLevel</c>, <c>ExtractCpfFromSan</c>,
/// and bundled-cert loaders.
/// </summary>
public sealed class GovBrDetectionTests
{
    private const string SubjectAltNameOid = "2.5.29.17";
    private const string CertPoliciesOid = "2.5.29.32";

    // ── IsGovBrCertificate via Issuer name ───────────────────────────────────

    [Fact(DisplayName = "IsGovBrCertificate detects via Issuer containing Gov-Br")]
    public void IsGovBrCertificate_IssuerContainsGovBr_ReturnsTrue()
    {
        using var cert = CreatePlainCert("CN=Gov-Br Test Issuer, O=Gov-Br, C=BR");
        GovBrChainValidator.IsGovBrCertificate(cert).Should().BeTrue();
    }

    [Fact(DisplayName = "IsGovBrCertificate returns false for unrelated certificate")]
    public void IsGovBrCertificate_Unrelated_ReturnsFalse()
    {
        using var cert = CreatePlainCert("CN=Random, O=Other, C=US");
        GovBrChainValidator.IsGovBrCertificate(cert).Should().BeFalse();
    }

    // ── IsGovBrCertificate via 2.16.76.3 policy OID ──────────────────────────

    [Fact(DisplayName = "IsGovBrCertificate detects via 2.16.76.3 policy OID (no Issuer match)")]
    public void IsGovBrCertificate_PolicyOidInArc_ReturnsTrue()
    {
        // Subject/Issuer don't contain "Gov-Br"; detection must succeed via the OID arc.
        using var cert = CreateCertWithCertificatePolicy("2.16.76.3.2.1.1");
        GovBrChainValidator.IsGovBrCertificate(cert).Should().BeTrue();
    }

    [Fact(DisplayName = "IsGovBrCertificate returns false for non-Gov.br policy OID")]
    public void IsGovBrCertificate_NonGovBrPolicy_ReturnsFalse()
    {
        using var cert = CreateCertWithCertificatePolicy("1.3.6.1.4.1.99999.1");
        GovBrChainValidator.IsGovBrCertificate(cert).Should().BeFalse();
    }

    // ── DetectAssuranceLevel ─────────────────────────────────────────────────

    // Pattern: 2.16.76.3.2.{level} → byte after `60 4C 03 02` is the level (1..4).
    [Theory(DisplayName = "DetectAssuranceLevel maps level byte to enum")]
    [InlineData("2.16.76.3.2.1.1", GovBrAssuranceLevel.Level1)]
    [InlineData("2.16.76.3.2.2.1", GovBrAssuranceLevel.Level2)]
    [InlineData("2.16.76.3.2.3.1", GovBrAssuranceLevel.Level3)]
    [InlineData("2.16.76.3.2.4.1", GovBrAssuranceLevel.Level4)]
    public void DetectAssuranceLevel_KnownArc_ReturnsLevel(string oid, GovBrAssuranceLevel expected)
    {
        using var cert = CreateCertWithCertificatePolicy(oid);
        GovBrChainValidator.DetectAssuranceLevel(cert).Should().Be(expected);
    }

    [Fact(DisplayName = "DetectAssuranceLevel returns null for cert without policy extension")]
    public void DetectAssuranceLevel_NoExtension_ReturnsNull()
    {
        using var cert = CreatePlainCert();
        GovBrChainValidator.DetectAssuranceLevel(cert).Should().BeNull();
    }

    [Fact(DisplayName = "DetectAssuranceLevel returns null for non-Gov.br arc")]
    public void DetectAssuranceLevel_NonGovBrArc_ReturnsNull()
    {
        using var cert = CreateCertWithCertificatePolicy("1.3.6.1.4.1.99999.1");
        GovBrChainValidator.DetectAssuranceLevel(cert).Should().BeNull();
    }

    [Fact(DisplayName = "DetectAssuranceLevel returns null for unknown level byte (0x05)")]
    public void DetectAssuranceLevel_UnknownLevelByte_ReturnsNull()
    {
        using var cert = CreateCertWithCertificatePolicy("2.16.76.3.2.5.1");
        GovBrChainValidator.DetectAssuranceLevel(cert).Should().BeNull();
    }

    // ── LoadBundledGovBrCerts ────────────────────────────────────────────────

    [Fact(DisplayName = "LoadBundledGovBrCerts returns at least one certificate")]
    public void LoadBundledGovBrCerts_ReturnsCerts()
    {
        var certs = GovBrChainValidator.LoadBundledGovBrCerts();
        certs.Should().NotBeEmpty();
        certs.Should().AllSatisfy(c => c.Should().NotBeNull());
    }

    // ── ExtractCpfFromSan ────────────────────────────────────────────────────

    [Fact(DisplayName = "ExtractCpfFromSan extracts 11-digit CPF from UTF8String value")]
    public void ExtractCpfFromSan_Utf8StringValue_ReturnsCpf()
    {
        const string cpf = "11144477735"; // canonical valid CPF
        using var cert = CreateCertWithSan([("2.16.76.1.3.1", cpf, UniversalTagNumber.UTF8String)]);
        GovBrChainValidator.ExtractCpfFromSan(cert).Should().Be(cpf);
    }

    [Fact(DisplayName = "ExtractCpfFromSan extracts 11-digit CPF from IA5String value")]
    public void ExtractCpfFromSan_Ia5StringValue_ReturnsCpf()
    {
        const string cpf = "12345678909"; // canonical valid CPF
        using var cert = CreateCertWithSan([("2.16.76.1.3.1", cpf, UniversalTagNumber.IA5String)]);
        GovBrChainValidator.ExtractCpfFromSan(cert).Should().Be(cpf);
    }

    [Fact(DisplayName = "ExtractCpfFromSan strips non-digit characters and returns 11 digits")]
    public void ExtractCpfFromSan_FormattedValue_StripsAndReturns11Digits()
    {
        // Validator extracts digits only; "111.444.777-35" → 11 digits
        const string formatted = "111.444.777-35";
        using var cert = CreateCertWithSan([("2.16.76.1.3.1", formatted, UniversalTagNumber.UTF8String)]);
        GovBrChainValidator.ExtractCpfFromSan(cert).Should().Be("11144477735");
    }

    [Fact(DisplayName = "ExtractCpfFromSan returns null when value has fewer than 11 digits")]
    public void ExtractCpfFromSan_NotEnoughDigits_ReturnsNull()
    {
        using var cert = CreateCertWithSan([("2.16.76.1.3.1", "abc12345", UniversalTagNumber.UTF8String)]);
        GovBrChainValidator.ExtractCpfFromSan(cert).Should().BeNull();
    }

    [Fact(DisplayName = "ExtractCpfFromSan returns null when no SAN extension")]
    public void ExtractCpfFromSan_NoSan_ReturnsNull()
    {
        using var cert = CreatePlainCert();
        GovBrChainValidator.ExtractCpfFromSan(cert).Should().BeNull();
    }

    [Fact(DisplayName = "ExtractCpfFromSan returns null when SAN has only dNSName entries")]
    public void ExtractCpfFromSan_OnlyDnsName_ReturnsNull()
    {
        var w = new AsnWriter(AsnEncodingRules.DER);
        using (w.PushSequence())
        {
            w.WriteCharacterString(
                UniversalTagNumber.IA5String,
                "example.com",
                new Asn1Tag(TagClass.ContextSpecific, 2));
        }

        using var cert = CreateCertWithExtension(SubjectAltNameOid, w.Encode());
        GovBrChainValidator.ExtractCpfFromSan(cert).Should().BeNull();
    }

    [Fact(DisplayName = "ExtractCpfFromSan ignores otherName entries with non-CPF OID")]
    public void ExtractCpfFromSan_OtherNameWithDifferentOid_ReturnsNull()
    {
        // OID 2.16.76.1.3.3 (CNPJ) carrying a 14-digit number — should NOT be matched as CPF
        using var cert = CreateCertWithSan([("2.16.76.1.3.3", "11444777000161", UniversalTagNumber.UTF8String)]);
        GovBrChainValidator.ExtractCpfFromSan(cert).Should().BeNull();
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
    /// with the given policy OID, attached to a self-signed cert.
    /// </summary>
    private static X509Certificate2 CreateCertWithCertificatePolicy(string policyOid)
    {
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
    /// Builds a SubjectAlternativeName extension with one or more otherName entries.
    /// Each entry: [0] IMPLICIT SEQUENCE { OID, [0] EXPLICIT ANY (UTF8String or IA5String) }.
    /// </summary>
    private static X509Certificate2 CreateCertWithSan((string oid, string value, UniversalTagNumber stringTag)[] otherNames)
    {
        var w = new AsnWriter(AsnEncodingRules.DER);
        using (w.PushSequence())
        {
            foreach (var (oid, value, stringTag) in otherNames)
            {
                using (w.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0, isConstructed: true)))
                {
                    w.WriteObjectIdentifier(oid);
                    using (w.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0, isConstructed: true)))
                    {
                        w.WriteCharacterString(stringTag, value);
                    }
                }
            }
        }
        return CreateCertWithExtension(SubjectAltNameOid, w.Encode());
    }
}
