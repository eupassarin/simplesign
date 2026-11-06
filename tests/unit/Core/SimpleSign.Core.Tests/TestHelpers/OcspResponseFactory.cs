using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SimpleSign.Core.Revocation;

namespace SimpleSign.Core.Tests.TestHelpers;

/// <summary>Builds signed OCSP responses with chosen <c>thisUpdate</c> and <c>nextUpdate</c>.</summary>
internal static class OcspResponseFactory
{
    internal static byte[] Build(
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
