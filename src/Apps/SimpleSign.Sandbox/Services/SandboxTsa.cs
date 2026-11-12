using System.Formats.Asn1;
using System.Numerics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace SimpleSign.Sandbox.Services;

/// <summary>
/// An RFC 3161 time-stamping authority: reads the request (hash algorithm, imprint, nonce, certReq)
/// and returns a granted response with the current time, signed by the given TSA certificate. The
/// TSTInfo names the TSA (the tsa field) with <paramref name="tsaName"/>, its own subject by default, and its genTime is
/// the current time moved by <paramref name="clockShift"/> (a TSA whose clock is wrong). The TSTInfo gives its accuracy
/// (one second, as EN 319 422 asks) unless <paramref name="accuracy"/> is false.
/// </summary>
internal sealed class SandboxTsa(X509Certificate2 tsa, RSA key, IReadOnlyList<X509Certificate2> chain, X500DistinguishedName? tsaName = null,
    TimeSpan clockShift = default, bool accuracy = true)
{
    private const string TstInfoOid = "1.2.840.113549.1.9.16.1.4";
    private const string SignedDataOid = "1.2.840.113549.1.7.2";
    private static long s_serial = DateTimeOffset.UtcNow.ToUnixTimeSeconds() * 1000;


    public byte[] Respond(byte[] requestBytes)
    {
        var reader = new AsnReader(requestBytes, AsnEncodingRules.DER).ReadSequence();
        _ = reader.ReadInteger();
        var imprint = reader.ReadSequence();
        var algorithm = imprint.ReadSequence();
        string hashOid = algorithm.ReadObjectIdentifier();
        byte[] hash = imprint.ReadOctetString();
        BigInteger? nonce = null;
        bool certReq = false;
        while (reader.HasData)
        {
            var tag = reader.PeekTag();
            if (tag.HasSameClassAndValue(Asn1Tag.Integer))
            {
                nonce = reader.ReadInteger();
            }
            else if (tag.HasSameClassAndValue(Asn1Tag.Boolean))
            {
                certReq = reader.ReadBoolean();
            }
            else
            {
                reader.ReadEncodedValue();
            }
        }

        byte[] token = BuildToken(hashOid, hash, nonce, certReq);
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSequence())
        {
            using (writer.PushSequence())
            {
                writer.WriteInteger(0);
            }

            writer.WriteEncodedValue(token);
        }

        return writer.Encode();
    }

    private byte[] BuildToken(string hashOid, byte[] hash, BigInteger? nonce, bool includeCertificates)
    {
        var tstInfo = new AsnWriter(AsnEncodingRules.DER);
        using (tstInfo.PushSequence())
        {
            tstInfo.WriteInteger(1);
            tstInfo.WriteObjectIdentifier("1.3.6.1.4.1.99999.3161.1"); // sandbox TSA policy (private arc)
            using (tstInfo.PushSequence())
            {
                using (tstInfo.PushSequence())
                {
                    tstInfo.WriteObjectIdentifier(hashOid);
                    tstInfo.WriteNull();
                }

                tstInfo.WriteOctetString(hash);
            }

            tstInfo.WriteInteger(Interlocked.Increment(ref s_serial));
            tstInfo.WriteGeneralizedTime(DateTimeOffset.UtcNow + clockShift, omitFractionalSeconds: true);
            if (accuracy)
            {
                using (tstInfo.PushSequence()) // accuracy { seconds 1 }
                {
                    tstInfo.WriteInteger(1);
                }
            }

            if (nonce is { } n)
            {
                tstInfo.WriteInteger(n);
            }

            // tsa [0] GeneralName: directoryName [4] (a CHOICE, so both tags are explicit).
            using (tstInfo.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0, true)))
            using (tstInfo.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 4, true)))
            {
                tstInfo.WriteEncodedValue((tsaName ?? tsa.SubjectName).RawData);
            }
        }

        byte[] content = tstInfo.Encode();
        byte[] contentDigest = SHA256.HashData(content);

        var attributes = new AsnWriter(AsnEncodingRules.DER);
        using (attributes.PushSetOf())
        {
            Attribute(attributes, "1.2.840.113549.1.9.3", w => w.WriteObjectIdentifier(TstInfoOid));
            Attribute(attributes, "1.2.840.113549.1.9.5", w => w.WriteUtcTime(DateTimeOffset.UtcNow + clockShift));
            Attribute(attributes, "1.2.840.113549.1.9.4", w => w.WriteOctetString(contentDigest));
            // ESS signing-certificate-v2 (RFC 5816): SHA-256 of the TSA certificate.
            Attribute(attributes, "1.2.840.113549.1.9.16.2.47", w =>
            {
                using (w.PushSequence())
                using (w.PushSequence())
                using (w.PushSequence())
                {
                    w.WriteOctetString(SHA256.HashData(tsa.RawData));
                }
            });
        }

        byte[] signedAttributes = attributes.Encode();
        byte[] signature = key.SignData(signedAttributes, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        signedAttributes[0] = 0xA0; // [0] IMPLICIT in SignerInfo

        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSequence())
        {
            writer.WriteObjectIdentifier(SignedDataOid);
            using (writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0, true)))
            using (writer.PushSequence())
            {
                writer.WriteInteger(3);
                using (writer.PushSetOf())
                {
                    Algorithm(writer, "2.16.840.1.101.3.4.2.1");
                }

                using (writer.PushSequence())
                {
                    writer.WriteObjectIdentifier(TstInfoOid);
                    using (writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0, true)))
                    {
                        writer.WriteOctetString(content);
                    }
                }

                // The TSA certificate is always included (and its chain when certReq is set).
                using (writer.PushSetOf(new Asn1Tag(TagClass.ContextSpecific, 0, true)))
                {
                    writer.WriteEncodedValue(tsa.RawData);
                    if (includeCertificates)
                    {
                        foreach (var certificate in chain)
                        {
                            writer.WriteEncodedValue(certificate.RawData);
                        }
                    }
                }

                using (writer.PushSetOf())
                using (writer.PushSequence())
                {
                    writer.WriteInteger(1);
                    using (writer.PushSequence())
                    {
                        writer.WriteEncodedValue(tsa.IssuerName.RawData);
                        writer.WriteInteger(new BigInteger(tsa.SerialNumberBytes.Span, isUnsigned: true, isBigEndian: true));
                    }

                    Algorithm(writer, "2.16.840.1.101.3.4.2.1");
                    writer.WriteEncodedValue(signedAttributes);
                    Algorithm(writer, "1.2.840.113549.1.1.11");
                    writer.WriteOctetString(signature);
                }
            }
        }

        return writer.Encode();
    }

    private static void Attribute(AsnWriter writer, string oid, Action<AsnWriter> value)
    {
        using (writer.PushSequence())
        {
            writer.WriteObjectIdentifier(oid);
            using (writer.PushSetOf())
            {
                value(writer);
            }
        }
    }

    private static void Algorithm(AsnWriter writer, string oid)
    {
        using (writer.PushSequence())
        {
            writer.WriteObjectIdentifier(oid);
            writer.WriteNull();
        }
    }
}
