using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using FluentAssertions;
using SimpleSign.Core.Revocation;
using SimpleSign.TestHelpers;
using Xunit;

namespace SimpleSign.Core.Tests.Revocation;

public sealed class CrlClientTests
{
    // ── CRL builder helpers ──────────────────────────────────────────────────

    private static byte[] BuildCrl(
        byte[] issuerNameRawData,
        byte[]? revokedSerial = null,
        DateTimeOffset? nextUpdate = null)
    {
        var tbsWriter = new AsnWriter(AsnEncodingRules.DER);
        using (tbsWriter.PushSequence()) // TBSCertList
        {
            // signature AlgorithmIdentifier (sha256WithRSAEncryption)
            using (tbsWriter.PushSequence())
            {
                tbsWriter.WriteObjectIdentifier("1.2.840.113549.1.1.11");
                tbsWriter.WriteNull();
            }

            // issuer Name
            tbsWriter.WriteEncodedValue(issuerNameRawData);

            // thisUpdate UTCTime
            tbsWriter.WriteUtcTime(DateTimeOffset.UtcNow.AddDays(-1));

            // nextUpdate UTCTime (optional)
            if (nextUpdate.HasValue)
                tbsWriter.WriteUtcTime(nextUpdate.Value);

            // revokedCertificates (optional)
            if (revokedSerial is not null)
            {
                using (tbsWriter.PushSequence()) // SEQUENCE OF
                {
                    using (tbsWriter.PushSequence()) // single entry
                    {
                        tbsWriter.WriteInteger(revokedSerial);
                        tbsWriter.WriteUtcTime(DateTimeOffset.UtcNow.AddDays(-1));
                    }
                }
            }
        }

        byte[] tbsBytes = tbsWriter.Encode();

        var crlWriter = new AsnWriter(AsnEncodingRules.DER);
        using (crlWriter.PushSequence()) // CertificateList
        {
            crlWriter.WriteEncodedValue(tbsBytes);

            // signatureAlgorithm
            using (crlWriter.PushSequence())
            {
                crlWriter.WriteObjectIdentifier("1.2.840.113549.1.1.11");
                crlWriter.WriteNull();
            }

            // signatureValue BIT STRING (dummy)
            crlWriter.WriteBitString(new byte[256]);
        }

        return crlWriter.Encode();
    }

    private static byte[] BuildSignedCrl(X509Certificate2 caCertWithKey, byte[]? revokedSerial = null)
    {
        var tbsWriter = new AsnWriter(AsnEncodingRules.DER);
        using (tbsWriter.PushSequence())
        {
            using (tbsWriter.PushSequence())
            {
                tbsWriter.WriteObjectIdentifier("1.2.840.113549.1.1.11");
                tbsWriter.WriteNull();
            }

            tbsWriter.WriteEncodedValue(caCertWithKey.SubjectName.RawData);
            tbsWriter.WriteUtcTime(DateTimeOffset.UtcNow.AddDays(-1));
            tbsWriter.WriteUtcTime(DateTimeOffset.UtcNow.AddYears(1));

            if (revokedSerial is not null)
            {
                using (tbsWriter.PushSequence())
                {
                    using (tbsWriter.PushSequence())
                    {
                        tbsWriter.WriteInteger(revokedSerial);
                        tbsWriter.WriteUtcTime(DateTimeOffset.UtcNow.AddDays(-1));
                    }
                }
            }
        }

        byte[] tbsBytes = tbsWriter.Encode();

        using var rsa = caCertWithKey.GetRSAPrivateKey()!;
        byte[] signature = rsa.SignData(tbsBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        var crlWriter = new AsnWriter(AsnEncodingRules.DER);
        using (crlWriter.PushSequence())
        {
            crlWriter.WriteEncodedValue(tbsBytes);

            using (crlWriter.PushSequence())
            {
                crlWriter.WriteObjectIdentifier("1.2.840.113549.1.1.11");
                crlWriter.WriteNull();
            }

            crlWriter.WriteBitString(signature);
        }

        return crlWriter.Encode();
    }

    // ── Static method tests ──────────────────────────────────────────────────

    [Fact(DisplayName = "Certificate without CDP returns null CRL URL")]
    public void GetCrlUrl_CertWithoutCdp_ReturnsNull()
    {
        using var cert = TestCertificateFactory.CreateSelfSignedCert();
        CrlClient.GetCrlUrl(cert).Should().BeNull();
    }

    [Fact(DisplayName = "Empty CRL returns false for non-revoked serial")]
    public void IsSerialInCrl_EmptyCrl_ReturnsFalse()
    {
        using var issuer = TestCertificateFactory.CreateCaCert();
        using var leaf = TestCertificateFactory.CreateLeafCert(issuer);

        byte[] crl = BuildCrl(issuer.SubjectName.RawData, nextUpdate: DateTimeOffset.UtcNow.AddYears(1));

        CrlClient.IsSerialInCrl(leaf, crl).Should().BeFalse();
    }

    [Fact(DisplayName = "Serial present in CRL returns true")]
    public void IsSerialInCrl_CertInCrl_ReturnsTrue()
    {
        using var issuer = TestCertificateFactory.CreateCaCert();
        byte[] serial = [0x01, 0x02, 0x03];
        using var leaf = TestCertificateFactory.CreateLeafCert(issuer, serialNumber: serial);

        byte[] crl = BuildCrl(issuer.SubjectName.RawData, revokedSerial: serial,
            nextUpdate: DateTimeOffset.UtcNow.AddYears(1));

        CrlClient.IsSerialInCrl(leaf, crl).Should().BeTrue();
    }

    [Fact(DisplayName = "CRL issuer mismatch returns null")]
    public void IsSerialInCrl_CrlIssuerMismatch_ReturnsNull()
    {
        using var issuer = TestCertificateFactory.CreateCaCert();
        using var leaf = TestCertificateFactory.CreateLeafCert(issuer);

        using var otherIssuer = TestCertificateFactory.CreateCaCert("CN=Other CA, O=Other");
        byte[] crl = BuildCrl(otherIssuer.SubjectName.RawData, nextUpdate: DateTimeOffset.UtcNow.AddYears(1));

        CrlClient.IsSerialInCrl(leaf, crl).Should().BeNull();
    }

    [Fact(DisplayName = "Expired CRL returns null")]
    public void IsSerialInCrl_ExpiredCrl_ReturnsNull()
    {
        using var issuer = TestCertificateFactory.CreateCaCert();
        using var leaf = TestCertificateFactory.CreateLeafCert(issuer);

        byte[] crl = BuildCrl(issuer.SubjectName.RawData, nextUpdate: DateTimeOffset.UtcNow.AddDays(-1));

        CrlClient.IsSerialInCrl(leaf, crl).Should().BeNull();
    }

    [Fact(DisplayName = "Valid CRL signature returns true")]
    public void VerifyCrlSignature_ValidSignature_ReturnsTrue()
    {
        using var ca = TestCertificateFactory.CreateCaCert();
        byte[] crl = BuildSignedCrl(ca);

        // Extract tbsCertList, signature from the CRL
        var reader = new AsnReader(crl, AsnEncodingRules.DER);
        var seq = reader.ReadSequence();
        byte[] tbsData = seq.PeekEncodedValue().ToArray();
        seq.ReadSequence(); // skip tbs
        var sigAlgSeq = seq.ReadSequence();
        string sigAlgOid = sigAlgSeq.ReadObjectIdentifier();
        byte[] signature = seq.ReadBitString(out _);

        CrlClient.VerifyCrlSignature(ca, tbsData, signature, sigAlgOid).Should().BeTrue();
    }

    [Fact(DisplayName = "Invalid CRL signature returns false")]
    public void VerifyCrlSignature_InvalidSignature_ReturnsFalse()
    {
        using var ca = TestCertificateFactory.CreateCaCert();

        byte[] tbsData = [0x30, 0x03, 0x01, 0x01, 0xFF];
        byte[] badSignature = new byte[256];

        CrlClient.VerifyCrlSignature(ca, tbsData, badSignature, "1.2.840.113549.1.1.11")
            .Should().BeFalse();
    }

    // ── Instance method tests (mocked HTTP) ──────────────────────────────────

    [Fact(DisplayName = "CRL check via HTTP with empty CRL returns true")]
    public async Task CheckCrlAsync_EmptyCrl_ReturnsTrue()
    {
        using var issuer = TestCertificateFactory.CreateCaCert();
        using var leaf = TestCertificateFactory.CreateLeafCert(issuer);

        byte[] crl = BuildCrl(issuer.SubjectName.RawData, nextUpdate: DateTimeOffset.UtcNow.AddYears(1));
        using var httpClient = MockHttpHandler.ForGetBytes(crl);

        var client = new CrlClient(httpClient);
        bool result = await client.CheckCrlAsync(leaf, "http://example.com/test.crl", CancellationToken.None);

        result.Should().BeTrue();
    }

    [Fact(DisplayName = "CRL network failure throws HttpRequestException")]
    public async Task CheckCrlAsync_NetworkFailure_ThrowsHttpRequestException()
    {
        using var cert = TestCertificateFactory.CreateSelfSignedCert();
        using var httpClient = MockHttpHandler.Failing();

        var client = new CrlClient(httpClient);

        await FluentActions.Awaiting(() =>
                client.CheckCrlAsync(cert, "http://example.com/test.crl", CancellationToken.None))
            .Should().ThrowAsync<HttpRequestException>();
    }
}
