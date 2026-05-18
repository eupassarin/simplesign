using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Shouldly;
using SimpleSign.Core.Inspection;
using Xunit;

namespace SimpleSign.Core.Tests.Inspection;

/// <summary>
/// Tests for the CRL Distribution Points (CDP), Authority Information Access (AIA),
/// and Key Usage extension parsing in <see cref="CertificateInfo"/>.
/// Builds certificates with synthetic extensions to exercise the parsers.
/// </summary>
public sealed class CertificateInfoExtensionTests
{
    private const string CdpOid = "2.5.29.31";
    private const string AiaOid = "1.3.6.1.5.5.7.1.1";
    private const string OcspOid = "1.3.6.1.5.5.7.48.1";
    private const string CaIssuersOid = "1.3.6.1.5.5.7.48.2";

    // ── CRL Distribution Point parsing ───────────────────────────────────────

    [Fact(DisplayName = "From extracts CRL URL from certificate with CDP extension")]
    public void From_CertWithCdp_ExtractsCrlUrl()
    {
        using var cert = CreateCertWithExtension(CdpOid, BuildCdpExtension("http://example.com/ca.crl"));
        var info = CertificateInfo.From(cert);
        info.CrlUrl.ShouldBe("http://example.com/ca.crl");
    }

    [Fact(DisplayName = "From with no CDP extension returns null CrlUrl")]
    public void From_CertWithoutCdp_ReturnsNullCrlUrl()
    {
        using var cert = CreateCertWithoutExtensions();
        var info = CertificateInfo.From(cert);
        info.CrlUrl.ShouldBeNull();
    }

    [Fact(DisplayName = "From with malformed CDP extension returns null CrlUrl (best-effort parse)")]
    public void From_CertWithGarbageCdp_ReturnsNullCrlUrl()
    {
        // Single byte → cannot parse → catch returns null
        using var cert = CreateCertWithExtension(CdpOid, [0xFF]);
        var info = CertificateInfo.From(cert);
        info.CrlUrl.ShouldBeNull();
    }

    // ── AIA parsing (OCSP + CA Issuers) ──────────────────────────────────────

    [Fact(DisplayName = "From extracts OCSP URL from AIA extension")]
    public void From_CertWithOcspInAia_ExtractsOcspUrl()
    {
        using var cert = CreateCertWithExtension(
            AiaOid,
            BuildAiaExtension([(OcspOid, "http://ocsp.example.com")]));
        var info = CertificateInfo.From(cert);
        info.OcspUrl.ShouldBe("http://ocsp.example.com");
        info.AiaUrls.ShouldContain("http://ocsp.example.com");
    }

    [Fact(DisplayName = "From extracts both OCSP and CA Issuers URLs from AIA")]
    public void From_CertWithMultipleAia_ExtractsAllUrls()
    {
        using var cert = CreateCertWithExtension(
            AiaOid,
            BuildAiaExtension([
                (OcspOid, "http://ocsp.example.com"),
                (CaIssuersOid, "http://example.com/ca.crt")
            ]));
        var info = CertificateInfo.From(cert);
        info.OcspUrl.ShouldBe("http://ocsp.example.com");
        info.AiaUrls.ShouldContain("http://ocsp.example.com");
        info.AiaUrls.ShouldContain("http://example.com/ca.crt");
    }

    [Fact(DisplayName = "From with no AIA extension returns null OcspUrl and empty AiaUrls")]
    public void From_CertWithoutAia_ReturnsEmpty()
    {
        using var cert = CreateCertWithoutExtensions();
        var info = CertificateInfo.From(cert);
        info.OcspUrl.ShouldBeNull();
        info.AiaUrls.ShouldBeEmpty();
    }

    [Fact(DisplayName = "From with malformed AIA extension returns null/empty (best-effort parse)")]
    public void From_CertWithGarbageAia_ReturnsEmpty()
    {
        using var cert = CreateCertWithExtension(AiaOid, [0xFF]);
        var info = CertificateInfo.From(cert);
        info.OcspUrl.ShouldBeNull();
        info.AiaUrls.ShouldBeEmpty();
    }

    // ── Key Usage flags ──────────────────────────────────────────────────────

    [Fact(DisplayName = "From extracts NonRepudiation key usage")]
    public void From_CertWithNonRepudiation_ExtractsFlag()
    {
        using var cert = CreateCertWithKeyUsage(X509KeyUsageFlags.NonRepudiation);
        var info = CertificateInfo.From(cert);
        info.HasNonRepudiation.ShouldBeTrue();
        info.KeyUsages.ShouldContain("NonRepudiation");
    }

    [Fact(DisplayName = "From extracts all common key usage flags")]
    public void From_CertWithMultipleKeyUsages_ExtractsAllFlags()
    {
        using var cert = CreateCertWithKeyUsage(
            X509KeyUsageFlags.DigitalSignature |
            X509KeyUsageFlags.KeyEncipherment |
            X509KeyUsageFlags.DataEncipherment |
            X509KeyUsageFlags.KeyAgreement);

        var info = CertificateInfo.From(cert);
        info.KeyUsages.ShouldContain("DigitalSignature");
        info.KeyUsages.ShouldContain("KeyEncipherment");
        info.KeyUsages.ShouldContain("DataEncipherment");
        info.KeyUsages.ShouldContain("KeyAgreement");
    }

    [Fact(DisplayName = "From extracts CA-style key usage flags (KeyCertSign, CrlSign)")]
    public void From_CertWithCaKeyUsages_ExtractsCaFlags()
    {
        using var cert = CreateCertWithKeyUsage(
            X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign);

        var info = CertificateInfo.From(cert);
        info.KeyUsages.ShouldContain("KeyCertSign");
        info.KeyUsages.ShouldContain("CrlSign");
    }

    [Fact(DisplayName = "From with no key usage extension returns empty list")]
    public void From_CertWithoutKeyUsage_ReturnsEmpty()
    {
        using var cert = CreateCertWithoutExtensions();
        var info = CertificateInfo.From(cert);
        info.HasNonRepudiation.ShouldBeFalse();
        info.KeyUsages.ShouldBeEmpty();
    }

    // ── Extended Key Usage ───────────────────────────────────────────────────

    [Fact(DisplayName = "From extracts Extended Key Usage OIDs")]
    public void From_CertWithEku_ExtractsEkuOids()
    {
        using RSA key = RSA.Create(2048);
        var req = new CertificateRequest("CN=EKU Test", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        var ekuExt = new X509EnhancedKeyUsageExtension(
            new OidCollection { new("1.3.6.1.5.5.7.3.4") }, // emailProtection
            critical: false);
        req.CertificateExtensions.Add(ekuExt);

        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        var info = CertificateInfo.From(cert);
        info.ExtendedKeyUsages.ShouldContain("1.3.6.1.5.5.7.3.4");
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    private static X509Certificate2 CreateCertWithExtension(string oid, byte[] rawData)
    {
        using RSA key = RSA.Create(2048);
        var req = new CertificateRequest("CN=Ext Test", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        req.CertificateExtensions.Add(new X509Extension(oid, rawData, critical: false));
        return req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
    }

    private static X509Certificate2 CreateCertWithKeyUsage(X509KeyUsageFlags flags)
    {
        using RSA key = RSA.Create(2048);
        var req = new CertificateRequest("CN=KU Test", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        req.CertificateExtensions.Add(new X509KeyUsageExtension(flags, critical: false));
        return req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
    }

    private static X509Certificate2 CreateCertWithoutExtensions()
    {
        using RSA key = RSA.Create(2048);
        var req = new CertificateRequest("CN=Plain Test", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        return req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
    }

    /// <summary>
    /// Builds an AIA extension byte payload:
    /// AuthorityInfoAccessSyntax ::= SEQUENCE OF AccessDescription
    /// AccessDescription ::= SEQUENCE { accessMethod OID, accessLocation [6] IA5String }
    /// </summary>
    private static byte[] BuildAiaExtension((string oid, string url)[] entries)
    {
        var w = new AsnWriter(AsnEncodingRules.DER);
        using (w.PushSequence())
        {
            foreach (var (oid, url) in entries)
            {
                using (w.PushSequence())
                {
                    w.WriteObjectIdentifier(oid);
                    w.WriteCharacterString(
                        UniversalTagNumber.IA5String,
                        url,
                        new Asn1Tag(TagClass.ContextSpecific, 6));
                }
            }
        }
        return w.Encode();
    }

    /// <summary>
    /// Builds a CRL Distribution Points extension payload with one DistributionPoint
    /// containing one URI in distributionPointName.
    /// </summary>
    private static byte[] BuildCdpExtension(string url)
    {
        var w = new AsnWriter(AsnEncodingRules.DER);
        using (w.PushSequence())
        {
            // DistributionPoint ::= SEQUENCE
            using (w.PushSequence())
            {
                // distributionPointName [0] CHOICE
                using (w.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0, true)))
                {
                    // fullName [0] GeneralNames
                    using (w.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0, true)))
                    {
                        // GeneralName: uniformResourceIdentifier [6] IA5String
                        w.WriteCharacterString(
                            UniversalTagNumber.IA5String,
                            url,
                            new Asn1Tag(TagClass.ContextSpecific, 6));
                    }
                }
            }
        }
        return w.Encode();
    }
}
