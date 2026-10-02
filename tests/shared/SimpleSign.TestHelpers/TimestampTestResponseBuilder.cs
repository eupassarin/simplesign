using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Numerics;

namespace SimpleSign.TestHelpers;

/// <summary>Builds signed RFC 3161 responses for deterministic test requests.</summary>
public static class TimestampTestResponseBuilder
{
    /// <summary>Builds a granted response bound to the hash algorithm, imprint, and nonce in a timestamp request.</summary>
    /// <param name="requestBytes">DER-encoded RFC 3161 timestamp request.</param>
    /// <param name="alterImprint">Whether to return a different message imprint for negative tests.</param>
    /// <param name="alterNonce">Whether to return a different nonce for negative tests.</param>
    /// <returns>A DER-encoded granted timestamp response.</returns>
    public static byte[] CreateForRequest(byte[] requestBytes, bool alterImprint = false, bool alterNonce = false)
    {
        ArgumentNullException.ThrowIfNull(requestBytes);

        var requestReader = new AsnReader(requestBytes, AsnEncodingRules.DER);
        var request = requestReader.ReadSequence();
        _ = request.ReadInteger();
        var imprint = request.ReadSequence();
        var algorithm = imprint.ReadSequence();
        string hashOid = algorithm.ReadObjectIdentifier();
        if (algorithm.HasData)
        {
            _ = algorithm.ReadEncodedValue();
        }

        byte[] hash = imprint.ReadOctetString();
        var nonce = request.ReadInteger();
        if (alterImprint)
        {
            hash[0] ^= 0xFF;
        }
        if (alterNonce)
        {
            nonce += 1;
        }
        byte[] token = BuildToken(hashOid, hash, nonce);

        var responseWriter = new AsnWriter(AsnEncodingRules.DER);
        using (responseWriter.PushSequence())
        {
            using (responseWriter.PushSequence())
            {
                responseWriter.WriteInteger(0);
            }

            responseWriter.WriteEncodedValue(token);
        }

        return responseWriter.Encode();
    }

    /// <summary>Builds a timestamp token over a supplied datum for direct <c>ITimestampClient</c> test doubles.</summary>
    /// <param name="dataToTimestamp">The raw bytes the client was asked to timestamp.</param>
    /// <param name="hashAlgorithm">The requested message-imprint hash algorithm.</param>
    /// <param name="omitSignedAttributes">Whether to create an unsigned-attributes negative fixture.</param>
    /// <returns>A signed RFC 3161 CMS token.</returns>
    public static byte[] CreateTokenForData(
        ReadOnlySpan<byte> dataToTimestamp, HashAlgorithmName hashAlgorithm, bool omitSignedAttributes = false)
    {
        (string oid, byte[] hash) = hashAlgorithm switch
        {
            _ when hashAlgorithm == HashAlgorithmName.SHA256 => ("2.16.840.1.101.3.4.2.1", SHA256.HashData(dataToTimestamp)),
            _ when hashAlgorithm == HashAlgorithmName.SHA384 => ("2.16.840.1.101.3.4.2.2", SHA384.HashData(dataToTimestamp)),
            _ when hashAlgorithm == HashAlgorithmName.SHA512 => ("2.16.840.1.101.3.4.2.3", SHA512.HashData(dataToTimestamp)),
            _ when hashAlgorithm == HashAlgorithmName.SHA3_256 => ("2.16.840.1.101.3.4.2.8", SHA3_256.HashData(dataToTimestamp)),
            _ when hashAlgorithm == HashAlgorithmName.SHA3_384 => ("2.16.840.1.101.3.4.2.9", SHA3_384.HashData(dataToTimestamp)),
            _ when hashAlgorithm == HashAlgorithmName.SHA3_512 => ("2.16.840.1.101.3.4.2.10", SHA3_512.HashData(dataToTimestamp)),
            _ => throw new NotSupportedException($"Test timestamp token does not support '{hashAlgorithm.Name}'.")
        };

        return BuildToken(oid, hash, System.Numerics.BigInteger.Zero, omitSignedAttributes);
    }

    private static byte[] BuildToken(string hashOid, byte[] hash, System.Numerics.BigInteger nonce,
        bool omitSignedAttributes = false)
    {
        var tstInfoWriter = new AsnWriter(AsnEncodingRules.DER);
        using (tstInfoWriter.PushSequence())
        {
            tstInfoWriter.WriteInteger(1);
            tstInfoWriter.WriteObjectIdentifier("1.2.3.4");
            using (tstInfoWriter.PushSequence())
            {
                using (tstInfoWriter.PushSequence())
                {
                    tstInfoWriter.WriteObjectIdentifier(hashOid);
                    tstInfoWriter.WriteNull();
                }

                tstInfoWriter.WriteOctetString(hash);
            }

            tstInfoWriter.WriteInteger(1);
            tstInfoWriter.WriteGeneralizedTime(new DateTimeOffset(2024, 1, 1, 0, 0, 0, TimeSpan.Zero));
            tstInfoWriter.WriteInteger(nonce);
        }

        byte[] tstInfo = tstInfoWriter.Encode();
        HashAlgorithmName hashAlgorithm = hashOid switch
        {
            "2.16.840.1.101.3.4.2.1" => HashAlgorithmName.SHA256,
            "2.16.840.1.101.3.4.2.2" => HashAlgorithmName.SHA384,
            "2.16.840.1.101.3.4.2.3" => HashAlgorithmName.SHA512,
            "2.16.840.1.101.3.4.2.8" => HashAlgorithmName.SHA3_256,
            "2.16.840.1.101.3.4.2.9" => HashAlgorithmName.SHA3_384,
            "2.16.840.1.101.3.4.2.10" => HashAlgorithmName.SHA3_512,
            _ => throw new NotSupportedException($"Test timestamp token does not support '{hashOid}'.")
        };
        byte[] digest = CryptoHash(tstInfo, hashAlgorithm);
        using RSA certificateKey = RSA.Create(2048);
        var certificateRequest = new CertificateRequest("CN=Test Timestamp Authority", certificateKey,
            HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var usages = new OidCollection { new Oid("1.3.6.1.5.5.7.3.8") };
        certificateRequest.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(usages, critical: true));
        using var tsaCertificate = certificateRequest.CreateSelfSigned(
            new DateTimeOffset(2023, 1, 1, 0, 0, 0, TimeSpan.Zero),
            new DateTimeOffset(2030, 1, 1, 0, 0, 0, TimeSpan.Zero));
        var attributes = new AsnWriter(AsnEncodingRules.DER);
        using (attributes.PushSetOf())
        {
            using (attributes.PushSequence())
            {
                attributes.WriteObjectIdentifier("1.2.840.113549.1.9.3");
                using (attributes.PushSetOf())
                {
                    attributes.WriteObjectIdentifier("1.2.840.113549.1.9.16.1.4");
                }
            }

            using (attributes.PushSequence())
            {
                attributes.WriteObjectIdentifier("1.2.840.113549.1.9.4");
                using (attributes.PushSetOf())
                {
                    attributes.WriteOctetString(digest);
                }
            }
            using (attributes.PushSequence())
            {
                attributes.WriteObjectIdentifier("1.2.840.113549.1.9.16.2.12");
                using (attributes.PushSetOf())
                using (attributes.PushSequence())
                using (attributes.PushSequence())
                using (attributes.PushSequence())
                {
                    attributes.WriteOctetString(SHA1.HashData(tsaCertificate.RawData));
                }
            }
            using (attributes.PushSequence())
            {
                attributes.WriteObjectIdentifier("1.2.840.113549.1.9.16.2.47");
                using (attributes.PushSetOf())
                using (attributes.PushSequence())
                using (attributes.PushSequence())
                using (attributes.PushSequence())
                {
                    attributes.WriteOctetString(SHA256.HashData(tsaCertificate.RawData));
                }
            }
        }

        byte[] signedAttributes = attributes.Encode();
        byte[] signature = certificateKey.SignData(
            omitSignedAttributes ? tstInfo : signedAttributes, hashAlgorithm, RSASignaturePadding.Pkcs1);
        signedAttributes[0] = 0xA0;

        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSequence())
        {
            writer.WriteObjectIdentifier("1.2.840.113549.1.7.2");
            using (writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0, true)))
            using (writer.PushSequence())
            {
                // RFC 5652 requires version 3 when eContentType is not id-data.
                writer.WriteInteger(3);
                using (writer.PushSetOf())
                {
                    WriteAlgorithm(writer, hashOid);
                }

                using (writer.PushSequence())
                {
                    writer.WriteObjectIdentifier("1.2.840.113549.1.9.16.1.4");
                    using (writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0, true)))
                    {
                        writer.WriteOctetString(tstInfo);
                    }
                }

                using (writer.PushSetOf(new Asn1Tag(TagClass.ContextSpecific, 0, true)))
                {
                    writer.WriteEncodedValue(tsaCertificate.RawData);
                }

                using (writer.PushSetOf())
                using (writer.PushSequence())
                {
                    writer.WriteInteger(1);
                    using (writer.PushSequence())
                    {
                        writer.WriteEncodedValue(tsaCertificate.IssuerName.RawData);
                        writer.WriteInteger(new BigInteger(tsaCertificate.SerialNumberBytes.Span,
                            isUnsigned: true, isBigEndian: true));
                    }

                    WriteAlgorithm(writer, hashOid);
                    if (!omitSignedAttributes)
                    {
                        writer.WriteEncodedValue(signedAttributes);
                    }
                    WriteAlgorithm(writer, hashAlgorithm == HashAlgorithmName.SHA256
                        ? "1.2.840.113549.1.1.11"
                        : hashAlgorithm == HashAlgorithmName.SHA384
                            ? "1.2.840.113549.1.1.12"
                            : hashAlgorithm == HashAlgorithmName.SHA512
                                ? "1.2.840.113549.1.1.13"
                                : hashAlgorithm == HashAlgorithmName.SHA3_256
                                    ? "2.16.840.1.101.3.4.3.14"
                                    : hashAlgorithm == HashAlgorithmName.SHA3_384
                                        ? "2.16.840.1.101.3.4.3.15" : "2.16.840.1.101.3.4.3.16");
                    writer.WriteOctetString(signature);
                }
            }
        }

        return writer.Encode();
    }

    private static void WriteAlgorithm(AsnWriter writer, string oid)
    {
        using (writer.PushSequence())
        {
            writer.WriteObjectIdentifier(oid);
            writer.WriteNull();
        }
    }

    private static byte[] CryptoHash(byte[] data, HashAlgorithmName algorithm)
    {
        return algorithm switch
        {
            _ when algorithm == HashAlgorithmName.SHA256 => SHA256.HashData(data),
            _ when algorithm == HashAlgorithmName.SHA384 => SHA384.HashData(data),
            _ when algorithm == HashAlgorithmName.SHA512 => SHA512.HashData(data),
            _ when algorithm == HashAlgorithmName.SHA3_256 => SHA3_256.HashData(data),
            _ when algorithm == HashAlgorithmName.SHA3_384 => SHA3_384.HashData(data),
            _ when algorithm == HashAlgorithmName.SHA3_512 => SHA3_512.HashData(data),
            _ => throw new NotSupportedException()
        };
    }
}
