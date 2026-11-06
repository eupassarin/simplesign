using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Shouldly;
using SimpleSign.Core.Constants;
using SimpleSign.Core.Revocation;
using SimpleSign.TestHelpers;
using Xunit;

namespace SimpleSign.Core.Tests.Revocation;

[Trait("Category", "Unit")]
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

        result.ShouldNotBeEmpty();
        result[0].ShouldBe((byte)0x30);
        result.Length.ShouldBeGreaterThan(20);
    }

    [Fact(DisplayName = "OCSP request with issuer returns ASN.1 bytes")]
    public void BuildOcspRequest_WithIssuer_ReturnsAsn1EncodedBytes()
    {
        byte[] result = OcspClient.BuildOcspRequest(LeafCert, issuerCert: CaCert);

        result.ShouldNotBeEmpty();
        result[0].ShouldBe((byte)0x30);
        result.Length.ShouldBeGreaterThan(20);
    }

    [Fact(DisplayName = "Public key extraction returns non-empty bytes")]
    public void ExtractPublicKeyBytes_ValidCert_ReturnsNonEmpty()
    {
        byte[] result = OcspClient.ExtractPublicKeyBytes(SelfSignedCert);

        result.ShouldNotBeEmpty();
    }

    [Fact(DisplayName = "Certificate without AIA returns null OCSP URL")]
    public void GetOcspUrl_CertWithoutAia_ReturnsNull()
    {
        string? result = OcspClient.GetOcspUrl(SelfSignedCert);

        result.ShouldBeNull();
    }

    [Fact(DisplayName = "Certificate without AIA returns null CA Issuers URL")]
    public void GetCaIssuersUrl_CertWithoutAia_ReturnsNull()
    {
        string? result = OcspClient.GetCaIssuersUrl(SelfSignedCert);

        result.ShouldBeNull();
    }

    [Fact(DisplayName = "Invalid AIA data returns null URI")]
    public void ParseAiaUri_InvalidData_ReturnsNull()
    {
        byte[] garbage = [0xFF, 0xFE, 0x00, 0x01, 0x02];

        string? result = OcspClient.ParseAiaUri(garbage, "1.3.6.1.5.5.7.48.1");

        result.ShouldBeNull();
    }

    [Fact(DisplayName = "OCSP response with 'good' status returns true")]
    public void ParseOcspResponse_GoodStatus_ReturnsTrue()
    {
        byte[] response = BuildMinimalOcspResponse(responseStatus: 0, certStatusTag: 0);

        bool result = OcspClient.ParseOcspResponse(response, SelfSignedCert);

        result.ShouldBeTrue();
    }

    [Fact(DisplayName = "OCSP response with 'revoked' status returns false")]
    public void ParseOcspResponse_RevokedStatus_ReturnsFalse()
    {
        byte[] response = BuildMinimalOcspResponse(responseStatus: 0, certStatusTag: 1);

        bool result = OcspClient.ParseOcspResponse(response, SelfSignedCert);

        result.ShouldBeFalse();
    }

    [Fact(DisplayName = "Non-successful OCSP response throws InvalidOperationException")]
    public void ParseOcspResponse_NonSuccessfulStatus_ThrowsInvalidOperationException()
    {
        byte[] response = BuildMinimalOcspResponse(responseStatus: 1);

        Action act = () => OcspClient.ParseOcspResponse(response, SelfSignedCert);

        Should.Throw<InvalidOperationException>(act)
            .Message.ShouldContain("not 'successful'");
    }

    [Fact(DisplayName = "Invalid OCSP signature returns false")]
    public void VerifyOcspSignature_InvalidSignature_ReturnsFalse()
    {
        byte[] data = [0x01, 0x02, 0x03];
        byte[] badSignature = new byte[256];

        bool result = OcspClient.VerifyOcspSignature(
            SelfSignedCert, data, badSignature, "1.2.840.113549.1.1.11");

        result.ShouldBeFalse();
    }

    // ── PS256/PS384/PS512 OCSP signature verification ───────────────────────

    private static byte[] BuildPssParams(HashAlgorithmName hash, string hashOid, int saltLength)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSequence())
        {
            using (writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0, true)))
            using (writer.PushSequence())
            {
                writer.WriteObjectIdentifier(hashOid);
                writer.WriteNull();
            }
            using (writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 1, true)))
            using (writer.PushSequence())
            {
                writer.WriteObjectIdentifier(Oids.Mgf1);
                using (writer.PushSequence())
                {
                    writer.WriteObjectIdentifier(hashOid);
                    writer.WriteNull();
                }
            }
            using (writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 2, true)))
            {
                writer.WriteInteger(saltLength);
            }
        }
        return writer.Encode();
    }

    private static X509Certificate2 CreatePssCert(HashAlgorithmName hash, string subject = "CN=PSS Responder, O=Tests")
    {
        using RSA key = RSA.Create(2048);
        var req = new CertificateRequest(subject, key, hash, RSASignaturePadding.Pss);
        req.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, false));
        var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));

        const string password = "test-export";
        var pfx = cert.Export(X509ContentType.Pfx, password);
#pragma warning disable SYSLIB0057
        var flags = X509KeyStorageFlags.Exportable;
        if (!OperatingSystem.IsMacOS())
            flags |= X509KeyStorageFlags.EphemeralKeySet;
        return new X509Certificate2(pfx, password, flags);
#pragma warning restore SYSLIB0057
    }

    [Fact(DisplayName = "PS384 OCSP signature with proper RSASSA-PSS-params is verified successfully")]
    public void VerifyOcspSignature_Ps384_ReturnsTrue()
    {
        using var responder = CreatePssCert(HashAlgorithmName.SHA384);
        byte[] tbsData = [0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01];
        byte[] pssParams = BuildPssParams(HashAlgorithmName.SHA384, Oids.Sha384, 48);

        using var rsa = responder.GetRSAPrivateKey()!;
        byte[] signature = rsa.SignData(tbsData, HashAlgorithmName.SHA384, RSASignaturePadding.Pss);

        OcspClient.VerifyOcspSignature(responder, tbsData, signature, Oids.RsaPss, pssParams)
            .ShouldBeTrue("PS384 OCSP signature with proper params must verify when responder uses the same hash");
    }

    [Fact(DisplayName = "PS256 OCSP signature with proper RSASSA-PSS-params is verified successfully")]
    public void VerifyOcspSignature_Ps256_ReturnsTrue()
    {
        using var responder = CreatePssCert(HashAlgorithmName.SHA256);
        byte[] tbsData = [0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01];
        byte[] pssParams = BuildPssParams(HashAlgorithmName.SHA256, Oids.Sha256, 32);

        using var rsa = responder.GetRSAPrivateKey()!;
        byte[] signature = rsa.SignData(tbsData, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);

        OcspClient.VerifyOcspSignature(responder, tbsData, signature, Oids.RsaPss, pssParams)
            .ShouldBeTrue();
    }

    [Fact(DisplayName = "PS512 OCSP signature with proper RSASSA-PSS-params is verified successfully")]
    public void VerifyOcspSignature_Ps512_ReturnsTrue()
    {
        using var responder = CreatePssCert(HashAlgorithmName.SHA512);
        byte[] tbsData = [0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01];
        byte[] pssParams = BuildPssParams(HashAlgorithmName.SHA512, Oids.Sha512, 64);

        using var rsa = responder.GetRSAPrivateKey()!;
        byte[] signature = rsa.SignData(tbsData, HashAlgorithmName.SHA512, RSASignaturePadding.Pss);

        OcspClient.VerifyOcspSignature(responder, tbsData, signature, Oids.RsaPss, pssParams)
            .ShouldBeTrue();
    }

    [Fact(DisplayName = "PS384 OCSP verification returns false when params claim the wrong hash")]
    public void VerifyOcspSignature_Ps384WithSha256Params_ReturnsFalse()
    {
        using var responder = CreatePssCert(HashAlgorithmName.SHA384);
        byte[] tbsData = [0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01];
        // Sign with SHA-384, but the params claim SHA-256 — verification must fail
        // (it would otherwise silently accept the wrong hash).
        byte[] pssParams = BuildPssParams(HashAlgorithmName.SHA256, Oids.Sha256, 32);

        using var rsa = responder.GetRSAPrivateKey()!;
        byte[] signature = rsa.SignData(tbsData, HashAlgorithmName.SHA384, RSASignaturePadding.Pss);

        OcspClient.VerifyOcspSignature(responder, tbsData, signature, Oids.RsaPss, pssParams)
            .ShouldBeFalse("PSS verification must honour the hash declared in the params");
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

        result.ShouldBeTrue();
    }

    [Fact(DisplayName = "OCSP server returns 500 throws HttpRequestException")]
    public async Task CheckOcspAsync_ServerReturns500_ThrowsHttpRequestException()
    {
        byte[] empty = [];
        using var httpClient = MockHttpHandler.ForPostBytes(empty, System.Net.HttpStatusCode.InternalServerError);
        var client = new OcspClient(httpClient);

        Func<Task> act = () => client.CheckOcspAsync(SelfSignedCert, "http://ocsp.test/", CancellationToken.None);

        await Should.ThrowAsync<HttpRequestException>(act);
    }

    #endregion
}
