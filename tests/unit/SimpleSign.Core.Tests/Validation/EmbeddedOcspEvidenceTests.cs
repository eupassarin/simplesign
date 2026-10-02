using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SimpleSign.Core.Revocation;
using SimpleSign.TestHelpers;
using Xunit;

namespace SimpleSign.Core.Tests.Validation;

public sealed class EmbeddedOcspEvidenceTests
{
    private static readonly DateTimeOffset s_validationTime =
        new(2026, 1, 15, 12, 0, 0, TimeSpan.Zero);

    [Fact]
    public void CheckEmbeddedOcspResponse_IssuerSignedMatchingResponse_ReturnsGood()
    {
        using var pki = new SyntheticPki();
        using var httpClient = new HttpClient();
        byte[] response = BuildResponse(pki.Leaf, pki.IntermediateCa, pki.IntermediateCa,
            s_validationTime.AddHours(-1), s_validationTime.AddHours(1));

        Assert.True(new OcspClient(httpClient).CheckEmbeddedOcspResponse(
            pki.Leaf, pki.IntermediateCa, response, s_validationTime));
    }

    [Fact]
    public void CheckEmbeddedOcspResponse_AuthorizedDelegatedResponder_ReturnsGood()
    {
        using var pki = new SyntheticPki();
        using var httpClient = new HttpClient();
        using RSA key = RSA.Create(2048);
        var request = new CertificateRequest("CN=Delegated OCSP Responder", key,
            HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
            new OidCollection { new Oid("1.3.6.1.5.5.7.3.9") }, false));
        DateTimeOffset now = DateTimeOffset.UtcNow;
        using var issued = request.Create(pki.IntermediateCa, now.AddHours(-1), now.AddHours(2), [1, 2, 3]);
        using var responder = issued.CopyWithPrivateKey(key);
        byte[] response = BuildResponse(pki.Leaf, pki.IntermediateCa, responder,
            now.AddMinutes(-1), now.AddHours(1), embedResponder: true);

        Assert.True(new OcspClient(httpClient).CheckEmbeddedOcspResponse(
            pki.Leaf, pki.IntermediateCa, response, now));
    }

    [Fact]
    public void CheckEmbeddedOcspResponse_WrongCertIdOrSignature_ReturnsUnknown()
    {
        using var pki = new SyntheticPki();
        using var httpClient = new HttpClient();
        var client = new OcspClient(httpClient);
        byte[] wrongId = BuildResponse(pki.Leaf, pki.IntermediateCa, pki.IntermediateCa,
            s_validationTime.AddHours(-1), s_validationTime.AddHours(1), wrongCertId: true);
        byte[] damaged = BuildResponse(pki.Leaf, pki.IntermediateCa, pki.IntermediateCa,
            s_validationTime.AddHours(-1), s_validationTime.AddHours(1));
        damaged[^1] ^= 0x01;

        Assert.Null(client.CheckEmbeddedOcspResponse(pki.Leaf, pki.IntermediateCa, wrongId, s_validationTime));
        Assert.Null(client.CheckEmbeddedOcspResponse(pki.Leaf, pki.IntermediateCa, damaged, s_validationTime));
    }

    [Fact]
    public void CheckEmbeddedOcspResponse_UnauthorizedResponderOrInvalidInterval_ReturnsUnknown()
    {
        using var pki = new SyntheticPki();
        using var httpClient = new HttpClient();
        var client = new OcspClient(httpClient);
        byte[] unauthorized = BuildResponse(pki.Leaf, pki.IntermediateCa, pki.Leaf,
            s_validationTime.AddHours(-1), s_validationTime.AddHours(1), embedResponder: true);
        byte[] early = BuildResponse(pki.Leaf, pki.IntermediateCa, pki.IntermediateCa,
            s_validationTime.AddHours(1), s_validationTime.AddHours(2));
        byte[] expired = BuildResponse(pki.Leaf, pki.IntermediateCa, pki.IntermediateCa,
            s_validationTime.AddHours(-2), s_validationTime.AddHours(-1));

        Assert.Null(client.CheckEmbeddedOcspResponse(pki.Leaf, pki.IntermediateCa, unauthorized, s_validationTime));
        Assert.Null(client.CheckEmbeddedOcspResponse(pki.Leaf, pki.IntermediateCa, early, s_validationTime));
        Assert.Null(client.CheckEmbeddedOcspResponse(pki.Leaf, pki.IntermediateCa, expired, s_validationTime));
    }

    private static byte[] BuildResponse(
        X509Certificate2 subject,
        X509Certificate2 issuer,
        X509Certificate2 responder,
        DateTimeOffset thisUpdate,
        DateTimeOffset nextUpdate,
        bool wrongCertId = false,
        bool embedResponder = false)
    {
        var tbsWriter = new AsnWriter(AsnEncodingRules.DER);
        using (tbsWriter.PushSequence())
        {
            using (tbsWriter.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 1, true)))
            {
                tbsWriter.WriteEncodedValue(responder.SubjectName.RawData);
            }
            tbsWriter.WriteGeneralizedTime(thisUpdate);
            using (tbsWriter.PushSequence())
            {
                using (tbsWriter.PushSequence())
                {
                    using (tbsWriter.PushSequence())
                    {
                        using (tbsWriter.PushSequence())
                        {
                            tbsWriter.WriteObjectIdentifier("1.3.14.3.2.26");
                            tbsWriter.WriteNull();
                        }
#pragma warning disable CA5350
                        tbsWriter.WriteOctetString(SHA1.HashData(subject.IssuerName.RawData));
                        byte[] keyHash = SHA1.HashData(OcspClient.ExtractPublicKeyBytes(issuer));
#pragma warning restore CA5350
                        if (wrongCertId)
                        {
                            keyHash[0] ^= 0x01;
                        }
                        tbsWriter.WriteOctetString(keyHash);
                        tbsWriter.WriteInteger(new System.Numerics.BigInteger(
                            subject.SerialNumberBytes.Span, isUnsigned: true, isBigEndian: true));
                    }
                    tbsWriter.WriteNull(new Asn1Tag(TagClass.ContextSpecific, 0));
                    tbsWriter.WriteGeneralizedTime(thisUpdate);
                    using (tbsWriter.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0, true)))
                    {
                        tbsWriter.WriteGeneralizedTime(nextUpdate);
                    }
                }
            }
        }

        byte[] tbs = tbsWriter.Encode();
        using RSA key = responder.GetRSAPrivateKey()!;
        byte[] signature = key.SignData(tbs, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var basicWriter = new AsnWriter(AsnEncodingRules.DER);
        using (basicWriter.PushSequence())
        {
            basicWriter.WriteEncodedValue(tbs);
            using (basicWriter.PushSequence())
            {
                basicWriter.WriteObjectIdentifier("1.2.840.113549.1.1.11");
                basicWriter.WriteNull();
            }
            basicWriter.WriteBitString(signature);
            if (embedResponder)
            {
                using (basicWriter.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0, true)))
                {
                    using (basicWriter.PushSequence())
                    {
                        basicWriter.WriteEncodedValue(responder.RawData);
                    }
                }
            }
        }

        var responseWriter = new AsnWriter(AsnEncodingRules.DER);
        using (responseWriter.PushSequence())
        {
            responseWriter.WriteEnumeratedValue(OcspResponseStatus.Successful);
            using (responseWriter.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0, true)))
            {
                using (responseWriter.PushSequence())
                {
                    responseWriter.WriteObjectIdentifier("1.3.6.1.5.5.7.48.1.1");
                    responseWriter.WriteOctetString(basicWriter.Encode());
                }
            }
        }
        return responseWriter.Encode();
    }

    private enum OcspResponseStatus
    {
        Successful = 0,
    }
}
