using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using FluentAssertions;
using SimpleSign.Core.Revocation;
using Xunit;

namespace SimpleSign.Core.Tests.Revocation;

/// <summary>
/// Tests for the URL-extraction helpers in <see cref="OcspClient"/> and <see cref="CrlClient"/>.
/// These exercise pure ASN.1 parsing of synthetic AIA / CDP extensions — no network calls.
/// </summary>
public sealed class RevocationUrlExtractionTests
{
    private const string AiaOid = "1.3.6.1.5.5.7.1.1";
    private const string CdpOid = "2.5.29.31";
    private const string OcspMethodOid = "1.3.6.1.5.5.7.48.1";
    private const string CaIssuersMethodOid = "1.3.6.1.5.5.7.48.2";

    // ── OcspClient.GetOcspUrl + ParseAiaUri ──────────────────────────────────

    [Fact(DisplayName = "GetOcspUrl returns OCSP URL when AIA contains id-ad-ocsp entry")]
    public void GetOcspUrl_AiaWithOcsp_ReturnsUrl()
    {
        using var cert = CreateCertWithExtension(
            AiaOid, BuildAia([(OcspMethodOid, "http://ocsp.example.com")]));
        OcspClient.GetOcspUrl(cert).Should().Be("http://ocsp.example.com");
    }

    [Fact(DisplayName = "GetOcspUrl returns null when AIA has only caIssuers")]
    public void GetOcspUrl_AiaWithoutOcsp_ReturnsNull()
    {
        using var cert = CreateCertWithExtension(
            AiaOid, BuildAia([(CaIssuersMethodOid, "http://ca.example.com/ca.crt")]));
        OcspClient.GetOcspUrl(cert).Should().BeNull();
    }

    [Fact(DisplayName = "GetOcspUrl returns null when AIA extension is absent")]
    public void GetOcspUrl_NoAiaExtension_ReturnsNull()
    {
        using var cert = CreatePlainCert();
        OcspClient.GetOcspUrl(cert).Should().BeNull();
    }

    [Fact(DisplayName = "GetCaIssuersUrl returns CA Issuers URL when AIA contains it")]
    public void GetCaIssuersUrl_AiaWithCaIssuers_ReturnsUrl()
    {
        using var cert = CreateCertWithExtension(
            AiaOid, BuildAia([(CaIssuersMethodOid, "http://ca.example.com/ca.crt")]));
        OcspClient.GetCaIssuersUrl(cert).Should().Be("http://ca.example.com/ca.crt");
    }

    [Fact(DisplayName = "GetCaIssuersUrl returns null when AIA extension is absent")]
    public void GetCaIssuersUrl_NoAia_ReturnsNull()
    {
        using var cert = CreatePlainCert();
        OcspClient.GetCaIssuersUrl(cert).Should().BeNull();
    }

    [Fact(DisplayName = "ParseAiaUri returns first matching URI when multiple AIA entries exist")]
    public void ParseAiaUri_MultipleEntries_ReturnsFirstMatch()
    {
        var rawAia = BuildAia([
            (CaIssuersMethodOid, "http://ca.example.com/ca.crt"),
            (OcspMethodOid, "http://ocsp.example.com"),
            (OcspMethodOid, "http://ocsp2.example.com"),
        ]);

        OcspClient.ParseAiaUri(rawAia, OcspMethodOid).Should().Be("http://ocsp.example.com");
    }

    [Fact(DisplayName = "ParseAiaUri skips non-URI GeneralName types")]
    public void ParseAiaUri_NonUriEntry_SkipsAndContinues()
    {
        // Build AIA where first AccessDescription has a dirName [4] instead of URI [6],
        // followed by a real OCSP entry. Parser must skip the dirName and find the URI.
        var w = new AsnWriter(AsnEncodingRules.DER);
        using (w.PushSequence())
        {
            // Entry 1: OCSP method + dirName GeneralName ([4] tag) — should be skipped
            using (w.PushSequence())
            {
                w.WriteObjectIdentifier(OcspMethodOid);
                using (w.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 4, isConstructed: true)))
                {
                    // empty placeholder
                }
            }
            // Entry 2: OCSP method + URI [6] tag — should be returned
            using (w.PushSequence())
            {
                w.WriteObjectIdentifier(OcspMethodOid);
                w.WriteCharacterString(
                    UniversalTagNumber.IA5String,
                    "http://ocsp-found.example",
                    new Asn1Tag(TagClass.ContextSpecific, 6));
            }
        }

        OcspClient.ParseAiaUri(w.Encode(), OcspMethodOid).Should().Be("http://ocsp-found.example");
    }

    [Fact(DisplayName = "ParseAiaUri returns null on malformed bytes")]
    public void ParseAiaUri_GarbageBytes_ReturnsNull()
    {
        OcspClient.ParseAiaUri([0xFF, 0x01, 0x02], OcspMethodOid).Should().BeNull();
    }

    // ── CrlClient.GetCrlUrl ──────────────────────────────────────────────────

    [Fact(DisplayName = "GetCrlUrl returns http URL from CRL Distribution Points extension")]
    public void GetCrlUrl_ValidCdpWithHttp_ReturnsUrl()
    {
        using var cert = CreateCertWithExtension(CdpOid, BuildCdp("http://example.com/ca.crl"));
        CrlClient.GetCrlUrl(cert).Should().Be("http://example.com/ca.crl");
    }

    [Fact(DisplayName = "GetCrlUrl returns null when only ldap:// URLs are present")]
    public void GetCrlUrl_LdapOnly_ReturnsNull()
    {
        using var cert = CreateCertWithExtension(CdpOid, BuildCdp("ldap://example.com/cn=ca"));
        CrlClient.GetCrlUrl(cert).Should().BeNull();
    }

    [Fact(DisplayName = "GetCrlUrl returns https URL")]
    public void GetCrlUrl_HttpsUrl_Returned()
    {
        using var cert = CreateCertWithExtension(CdpOid, BuildCdp("https://example.com/ca.crl"));
        CrlClient.GetCrlUrl(cert).Should().Be("https://example.com/ca.crl");
    }

    [Fact(DisplayName = "GetCrlUrl returns null when CDP extension is absent")]
    public void GetCrlUrl_NoCdp_ReturnsNull()
    {
        using var cert = CreatePlainCert();
        CrlClient.GetCrlUrl(cert).Should().BeNull();
    }

    [Fact(DisplayName = "GetCrlUrl returns null on malformed CDP bytes")]
    public void GetCrlUrl_MalformedCdp_ReturnsNull()
    {
        using var cert = CreateCertWithExtension(CdpOid, [0xFF, 0xFE]);
        CrlClient.GetCrlUrl(cert).Should().BeNull();
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    private static X509Certificate2 CreatePlainCert()
    {
        using RSA key = RSA.Create(2048);
        var req = new CertificateRequest("CN=Plain", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        return req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
    }

    private static X509Certificate2 CreateCertWithExtension(string oid, byte[] rawData)
    {
        using RSA key = RSA.Create(2048);
        var req = new CertificateRequest("CN=Ext Test", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        req.CertificateExtensions.Add(new X509Extension(oid, rawData, critical: false));
        return req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
    }

    /// <summary>Builds an AIA extension payload from the given (method-OID, URL) pairs.</summary>
    private static byte[] BuildAia((string oid, string url)[] entries)
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

    /// <summary>Builds a CDP extension payload with one fullName URI.</summary>
    private static byte[] BuildCdp(string url)
    {
        var w = new AsnWriter(AsnEncodingRules.DER);
        using (w.PushSequence())
        {
            using (w.PushSequence())
            {
                using (w.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0, isConstructed: true)))
                {
                    using (w.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0, isConstructed: true)))
                    {
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
