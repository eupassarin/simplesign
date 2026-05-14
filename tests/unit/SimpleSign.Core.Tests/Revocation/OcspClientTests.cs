using System.Formats.Asn1;
using System.Security.Cryptography.X509Certificates;
using FluentAssertions;
using SimpleSign.Core.Revocation;
using SimpleSign.TestHelpers;
using Xunit;

namespace SimpleSign.Core.Tests.Revocation;

public sealed class OcspClientTests
{
    #region Fixtures

    private static readonly X509Certificate2 CaCert = TestCertificateFactory.CreateCaCert();
    private static readonly X509Certificate2 LeafCert = TestCertificateFactory.CreateLeafCert(CaCert);
    private static readonly X509Certificate2 SelfSignedCert = TestCertificateFactory.CreateSelfSignedCert();

    private enum OcspResponseStatus { Successful = 0, MalformedRequest = 1 }

    private static byte[] BuildMinimalOcspResponse(int responseStatus, int? certStatusTag = null)
    {
        var outer = new AsnWriter(AsnEncodingRules.DER);
        using (outer.PushSequence()) // OCSPResponse
        {
            outer.WriteEnumeratedValue((OcspResponseStatus)responseStatus);

            if (responseStatus == 0 && certStatusTag.HasValue)
            {
                // responseBytes [0] EXPLICIT ResponseBytes
                // ResponseBytes ::= SEQUENCE { responseType OID, response OCTET STRING }
                using (outer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0, true)))
                {
                    using (outer.PushSequence())
                    {
                        outer.WriteObjectIdentifier("1.3.6.1.5.5.7.48.1.1"); // id-pkix-ocsp-basic
                        byte[] basicOcsp = BuildBasicOcspResponse(certStatusTag.Value);
                        outer.WriteOctetString(basicOcsp);
                    }
                }
            }
        }
        return outer.Encode();
    }

    private static byte[] BuildBasicOcspResponse(int certStatusTag)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSequence()) // BasicOCSPResponse
        {
            // tbsResponseData
            using (writer.PushSequence())
            {
                // responderID [2] EXPLICIT KeyHash
                using (writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 2, true)))
                {
                    writer.WriteOctetString(new byte[20]); // dummy key hash
                }

                // producedAt GeneralizedTime
                writer.WriteGeneralizedTime(DateTimeOffset.UtcNow, omitFractionalSeconds: true);

                // responses SEQUENCE OF SingleResponse
                using (writer.PushSequence())
                {
                    using (writer.PushSequence()) // SingleResponse
                    {
                        // CertID SEQUENCE
                        using (writer.PushSequence())
                        {
                            using (writer.PushSequence()) // hashAlgorithm
                            {
                                writer.WriteObjectIdentifier("1.3.14.3.2.26"); // SHA-1
                                writer.WriteNull();
                            }
                            writer.WriteOctetString(new byte[20]); // issuerNameHash
                            writer.WriteOctetString(new byte[20]); // issuerKeyHash
                            writer.WriteInteger(1);                // serialNumber
                        }

                        // certStatus — context-specific tag with empty content
                        writer.WriteNull(new Asn1Tag(TagClass.ContextSpecific, certStatusTag));

                        // thisUpdate GeneralizedTime
                        writer.WriteGeneralizedTime(DateTimeOffset.UtcNow, omitFractionalSeconds: true);
                    }
                }
            }

            // signatureAlgorithm
            using (writer.PushSequence())
            {
                writer.WriteObjectIdentifier("1.2.840.113549.1.1.11"); // sha256WithRSAEncryption
                writer.WriteNull();
            }

            // signature BIT STRING (dummy — no responder cert embedded so verification is skipped)
            writer.WriteBitString(new byte[64]);
        }
        return writer.Encode();
    }

    #endregion

    #region Static method tests

    [Fact(DisplayName = "OCSP request with valid certificate returns ASN.1 bytes")]
    public void BuildOcspRequest_ValidCert_ReturnsAsn1EncodedBytes()
    {
        byte[] result = OcspClient.BuildOcspRequest(SelfSignedCert, issuerCert: null);

        result.Should().NotBeEmpty();
        result[0].Should().Be(0x30, "OCSP request must start with ASN.1 SEQUENCE tag");
        result.Length.Should().BeGreaterThan(20);
    }

    [Fact(DisplayName = "OCSP request with issuer returns ASN.1 bytes")]
    public void BuildOcspRequest_WithIssuer_ReturnsAsn1EncodedBytes()
    {
        byte[] result = OcspClient.BuildOcspRequest(LeafCert, issuerCert: CaCert);

        result.Should().NotBeEmpty();
        result[0].Should().Be(0x30);
        result.Length.Should().BeGreaterThan(20);
    }

    [Fact(DisplayName = "Public key extraction returns non-empty bytes")]
    public void ExtractPublicKeyBytes_ValidCert_ReturnsNonEmpty()
    {
        byte[] result = OcspClient.ExtractPublicKeyBytes(SelfSignedCert);

        result.Should().NotBeEmpty();
    }

    [Fact(DisplayName = "Certificate without AIA returns null OCSP URL")]
    public void GetOcspUrl_CertWithoutAia_ReturnsNull()
    {
        string? result = OcspClient.GetOcspUrl(SelfSignedCert);

        result.Should().BeNull();
    }

    [Fact(DisplayName = "Certificate without AIA returns null CA Issuers URL")]
    public void GetCaIssuersUrl_CertWithoutAia_ReturnsNull()
    {
        string? result = OcspClient.GetCaIssuersUrl(SelfSignedCert);

        result.Should().BeNull();
    }

    [Fact(DisplayName = "Invalid AIA data returns null URI")]
    public void ParseAiaUri_InvalidData_ReturnsNull()
    {
        byte[] garbage = [0xFF, 0xFE, 0x00, 0x01, 0x02];

        string? result = OcspClient.ParseAiaUri(garbage, "1.3.6.1.5.5.7.48.1");

        result.Should().BeNull();
    }

    [Fact(DisplayName = "OCSP response with 'good' status returns true")]
    public void ParseOcspResponse_GoodStatus_ReturnsTrue()
    {
        byte[] response = BuildMinimalOcspResponse(responseStatus: 0, certStatusTag: 0);

        bool result = OcspClient.ParseOcspResponse(response, SelfSignedCert);

        result.Should().BeTrue();
    }

    [Fact(DisplayName = "OCSP response with 'revoked' status returns false")]
    public void ParseOcspResponse_RevokedStatus_ReturnsFalse()
    {
        byte[] response = BuildMinimalOcspResponse(responseStatus: 0, certStatusTag: 1);

        bool result = OcspClient.ParseOcspResponse(response, SelfSignedCert);

        result.Should().BeFalse();
    }

    [Fact(DisplayName = "Non-successful OCSP response throws InvalidOperationException")]
    public void ParseOcspResponse_NonSuccessfulStatus_ThrowsInvalidOperationException()
    {
        byte[] response = BuildMinimalOcspResponse(responseStatus: 1);

        Action act = () => OcspClient.ParseOcspResponse(response, SelfSignedCert);

        act.Should().Throw<InvalidOperationException>()
            .WithMessage("*not 'successful'*");
    }

    [Fact(DisplayName = "Invalid OCSP signature returns false")]
    public void VerifyOcspSignature_InvalidSignature_ReturnsFalse()
    {
        byte[] data = [0x01, 0x02, 0x03];
        byte[] badSignature = new byte[256];

        bool result = OcspClient.VerifyOcspSignature(
            SelfSignedCert, data, badSignature, "1.2.840.113549.1.1.11");

        result.Should().BeFalse();
    }

    #endregion

    #region Instance method tests

    [Fact(DisplayName = "OCSP server returns 'good' via HTTP returns true")]
    public async Task CheckOcspAsync_ServerReturnsGood_ReturnsTrue()
    {
        byte[] goodResponse = BuildMinimalOcspResponse(responseStatus: 0, certStatusTag: 0);
        using var httpClient = MockHttpHandler.ForPostBytes(goodResponse);
        var client = new OcspClient(httpClient);

        bool result = await client.CheckOcspAsync(SelfSignedCert, "http://ocsp.test/", CancellationToken.None);

        result.Should().BeTrue();
    }

    [Fact(DisplayName = "OCSP server returns 500 throws HttpRequestException")]
    public async Task CheckOcspAsync_ServerReturns500_ThrowsHttpRequestException()
    {
        byte[] empty = [];
        using var httpClient = MockHttpHandler.ForPostBytes(empty, System.Net.HttpStatusCode.InternalServerError);
        var client = new OcspClient(httpClient);

        Func<Task> act = () => client.CheckOcspAsync(SelfSignedCert, "http://ocsp.test/", CancellationToken.None);

        await act.Should().ThrowAsync<HttpRequestException>();
    }

    #endregion
}
