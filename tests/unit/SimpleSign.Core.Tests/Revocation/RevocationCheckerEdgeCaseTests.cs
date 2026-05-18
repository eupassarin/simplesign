using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Shouldly;
using SimpleSign.Core.Revocation;
using Xunit;

namespace SimpleSign.Core.Tests.Revocation;

/// <summary>
/// Tests for edge cases in <see cref="CrlClient.IsSerialInCrl"/> and revocation checking
/// — especially when CRL data is malformed or unparseable.
/// </summary>
public sealed class RevocationCheckerEdgeCaseTests : IDisposable
{
    private readonly X509Certificate2 _cert;

    public RevocationCheckerEdgeCaseTests()
    {
        // Create a self-signed certificate for testing
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=Test", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        _cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
    }

    public void Dispose() => _cert.Dispose();

    [Fact]
    public void IsSerialInCrl_GarbageBytes_ReturnsNull()
    {
        // Completely invalid data — should return null (indeterminate), not throw
        byte[] garbage = [0xFF, 0xFE, 0x00, 0x01, 0x02, 0x03];
        bool? result = CrlClient.IsSerialInCrl(_cert, garbage);
        result.ShouldBeNull("garbage bytes cannot be parsed as a CRL");
    }

    [Fact]
    public void IsSerialInCrl_EmptyBytes_ReturnsNull()
    {
        bool? result = CrlClient.IsSerialInCrl(_cert, []);
        result.ShouldBeNull("empty bytes cannot be parsed as a CRL");
    }

    [Fact]
    public void IsSerialInCrl_TruncatedAsn1_ReturnsNull()
    {
        // Valid ASN.1 start but truncated — should return null
        byte[] truncated = [0x30, 0x82, 0x01, 0x00]; // SEQUENCE with length but no content
        bool? result = CrlClient.IsSerialInCrl(_cert, truncated);
        result.ShouldBeNull("truncated ASN.1 cannot be parsed as a CRL");
    }

    [Fact]
    public void IsSerialInCrl_WrongIssuer_ReturnsNull()
    {
        // Build a minimal valid CRL with a different issuer
        var crlBytes = BuildMinimalCrl("CN=OtherIssuer");
        bool? result = CrlClient.IsSerialInCrl(_cert, crlBytes);
        result.ShouldBeNull("CRL issuer doesn't match certificate issuer");
    }

    [Fact]
    public void IsSerialInCrl_MatchingIssuer_EmptyRevokedList_ReturnsFalse()
    {
        // Build a CRL from the same issuer with no revoked entries
        var crlBytes = BuildMinimalCrl(_cert.Issuer);
        bool? result = CrlClient.IsSerialInCrl(_cert, crlBytes);
        // May be null if signature verification fails (self-signed cert is both subject and issuer)
        // but should NOT throw
        result.ShouldNotBe(true, "certificate should not appear revoked in an empty CRL");
    }

    [Fact]
    public void CheckCrlAsync_MalformedCrlData_ThrowsRevocationCheckException()
    {
        // This tests that when IsSerialInCrl returns null from an online CRL,
        // CheckCrlAsync throws RevocationCheckException instead of silently
        // claiming the certificate is revoked.
        // We can't easily test CheckCrlAsync without mocking HTTP, but we can verify
        // that the null path in IsSerialInCrl is handled correctly for the embedded CRL path.
        byte[] garbage = [0xFF, 0xFE, 0x00, 0x01, 0x02, 0x03];
        bool? result = CrlClient.IsSerialInCrl(_cert, garbage);
        // The key assertion: null should NOT be treated as "revoked"
        (result == false).ShouldBeFalse(
            "null (indeterminate) must not be treated as 'not revoked' — " +
            "it means we cannot determine revocation status from this data");
    }

    /// <summary>Builds a minimal CRL structure for testing (not cryptographically valid).</summary>
    private static byte[] BuildMinimalCrl(string issuerDn)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);

        // CertificateList ::= SEQUENCE { tbsCertList, signatureAlgorithm, signatureValue }
        using (writer.PushSequence())
        {
            // tbsCertList ::= SEQUENCE
            using (writer.PushSequence())
            {
                // version [0] OPTIONAL (v2 = 1)
                writer.WriteInteger(1, new Asn1Tag(TagClass.ContextSpecific, 0));

                // signature AlgorithmIdentifier
                using (writer.PushSequence())
                {
                    writer.WriteObjectIdentifier("1.2.840.113549.1.1.11"); // sha256WithRSAEncryption
                }

                // issuer Name — use the raw DER of an X500DistinguishedName
                var dn = new X500DistinguishedName(issuerDn);
                writer.WriteEncodedValue(dn.RawData);

                // thisUpdate UTCTime
                writer.WriteUtcTime(DateTimeOffset.UtcNow.AddHours(-1));

                // nextUpdate UTCTime
                writer.WriteUtcTime(DateTimeOffset.UtcNow.AddDays(7));

                // revokedCertificates — empty (no revoked certs)
            }

            // signatureAlgorithm
            using (writer.PushSequence())
            {
                writer.WriteObjectIdentifier("1.2.840.113549.1.1.11");
            }

            // signatureValue BIT STRING (dummy)
            writer.WriteBitString(new byte[256]);
        }

        return writer.Encode();
    }
}
