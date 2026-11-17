using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SimpleSign.Sandbox.Pki;

namespace SimpleSign.Sandbox.Services;

/// <summary>
/// An OCSP responder (RFC 6960, compatible with RFC 2560 clients) for the Sandbox's CAs: reads the
/// CertIDs of a request, answers good, revoked (with date and reason) or unknown, echoes the nonce,
/// and signs with the CA, a delegated responder or, as a failure, an unauthorized one.
/// </summary>
internal sealed class OcspResponder(SandboxPki pki)
{
    private const string NonceOid = "1.3.6.1.5.5.7.48.1.2";
    private const string BasicResponseOid = "1.3.6.1.5.5.7.48.1.1";
    private const string Sha1Oid = "1.3.14.3.2.26";
    private const string Sha256Oid = "2.16.840.1.101.3.4.2.1";
    private const string Sha256WithRsaOid = "1.2.840.113549.1.1.11";

    /// <summary>One CertID of a request: as it was encoded (echoed in the response) and its parts.</summary>
    private sealed record CertId(byte[] Encoded, string HashOid, byte[] NameHash, byte[] KeyHash, byte[] Serial);

    /// <summary>The OCSPResponse for a request to the responder of <paramref name="caId"/>.</summary>
    /// <exception cref="AsnContentException">The body is not an OCSPRequest.</exception>
    public byte[] Respond(string caId, byte[] request, SandboxFaults faults)
    {
        if (faults.Ocsp == OcspFault.TryLater)
        {
            return Status(3);
        }

        var (certIds, nonce) = Parse(request);
        var authority = pki.Authority(caId);
        var now = DateTimeOffset.UtcNow;
        // thisUpdate an hour back, as responders that pre-produce their answers do: an embedded response is
        // checked with thisUpdate not after the signing time, and a client may claim a signing time a
        // few minutes back (the TestBench's "time" option claims five).
        var (thisUpdate, nextUpdate) = faults.Ocsp == OcspFault.Expired ? (now.AddDays(-8), now.AddDays(-1)) : (now.AddHours(-1), now.AddDays(1));

        // Who signs: the CA, its delegated responder, or (as a failure) a responder nobody authorized.
        X509Certificate2 signer = authority.Certificate;
        RSA? ownedKey = null;
        RSA key = authority.Key;
        bool includeSigner = false;
        if (faults.Ocsp == OcspFault.Unauthorized)
        {
            (signer, key, includeSigner) = (pki.RogueOcspResponder, pki.RogueOcspKey, true);
        }
        else if (faults.OcspSigner == OcspSigner.Delegated && caId == SandboxPki.IntermediateId)
        {
            signer = pki.Certificate("ocsp-responder").Certificate;
            ownedKey = signer.GetRSAPrivateKey()!;
            (key, includeSigner) = (ownedKey, true);
        }

        try
        {
            var data = new AsnWriter(AsnEncodingRules.DER);
            using (data.PushSequence())
            {
                // responderID byName: [1] EXPLICIT Name.
                using (data.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 1, true)))
                {
                    data.WriteEncodedValue(signer.SubjectName.RawData);
                }

                data.WriteGeneralizedTime(now, omitFractionalSeconds: true);
                using (data.PushSequence())
                {
                    foreach (var certId in certIds)
                    {
                        WriteSingleResponse(data, certId, faults.Ocsp == OcspFault.Unknown || !IssuedBy(certId, authority.Certificate)
                            ? RevocationStatus.Unknown
                            : pki.OcspStatus(caId, certId.Serial), thisUpdate, nextUpdate);
                    }
                }

                if (nonce is not null)
                {
                    using (data.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 1, true)))
                    using (data.PushSequence())
                    {
                        data.WriteEncodedValue(nonce);
                    }
                }
            }

            byte[] tbs = data.Encode();
            byte[] signature = key.SignData(tbs, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            var basic = new AsnWriter(AsnEncodingRules.DER);
            using (basic.PushSequence())
            {
                basic.WriteEncodedValue(tbs);
                using (basic.PushSequence())
                {
                    basic.WriteObjectIdentifier(Sha256WithRsaOid);
                    basic.WriteNull();
                }

                basic.WriteBitString(signature);
                if (includeSigner)
                {
                    using (basic.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0, true)))
                    using (basic.PushSequence())
                    {
                        basic.WriteEncodedValue(signer.RawData);
                    }
                }
            }

            var response = new AsnWriter(AsnEncodingRules.DER);
            using (response.PushSequence())
            {
                response.WriteEnumeratedValue(OcspResponseStatus.Successful);
                using (response.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0, true)))
                using (response.PushSequence())
                {
                    response.WriteObjectIdentifier(BasicResponseOid);
                    response.WriteOctetString(basic.Encode());
                }
            }

            return response.Encode();
        }
        finally
        {
            ownedKey?.Dispose();
        }
    }

    /// <summary>A response without a body: malformedRequest (1), internalError (2), tryLater (3)…</summary>
    public static byte[] Status(int status)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSequence())
        {
            writer.WriteEnumeratedValue((OcspResponseStatus)status);
        }

        return writer.Encode();
    }

    private static void WriteSingleResponse(AsnWriter writer, CertId certId, RevocationStatus status, DateTimeOffset thisUpdate, DateTimeOffset nextUpdate)
    {
        using (writer.PushSequence())
        {
            writer.WriteEncodedValue(certId.Encoded);
            if (!status.Known)
            {
                writer.WriteNull(new Asn1Tag(TagClass.ContextSpecific, 2));
            }
            else if (status.RevokedAt is { } revokedAt)
            {
                using (writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 1, true)))
                {
                    writer.WriteGeneralizedTime(revokedAt, omitFractionalSeconds: true);
                    using (writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0, true)))
                    {
                        writer.WriteEnumeratedValue(status.Reason);
                    }
                }
            }
            else
            {
                writer.WriteNull(new Asn1Tag(TagClass.ContextSpecific, 0));
            }

            writer.WriteGeneralizedTime(thisUpdate, omitFractionalSeconds: true);
            using (writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0, true)))
            {
                writer.WriteGeneralizedTime(nextUpdate, omitFractionalSeconds: true);
            }
        }
    }

    /// <summary>Whether the CertID names <paramref name="issuer"/> (issuerKeyHash with the CertID's hash).</summary>
    private static bool IssuedBy(CertId certId, X509Certificate2 issuer)
    {
        byte[] key = issuer.PublicKey.EncodedKeyValue.RawData;
#pragma warning disable CA5350 // RFC 6960 CertIDs commonly use SHA-1.
        byte[]? expected = certId.HashOid switch
        {
            Sha1Oid => SHA1.HashData(key),
            Sha256Oid => SHA256.HashData(key),
            _ => null,
        };
#pragma warning restore CA5350
        return expected is not null && expected.AsSpan().SequenceEqual(certId.KeyHash);
    }

    private static (List<CertId> CertIds, byte[]? Nonce) Parse(byte[] request)
    {
        var tbs = new AsnReader(request, AsnEncodingRules.BER).ReadSequence().ReadSequence();
        if (tbs.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 0)))
        {
            tbs.ReadEncodedValue(); // version
        }

        if (tbs.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 1)))
        {
            tbs.ReadEncodedValue(); // requestorName
        }

        var certIds = new List<CertId>();
        var list = tbs.ReadSequence();
        while (list.HasData)
        {
            var single = list.ReadSequence();
            byte[] encoded = single.PeekEncodedValue().ToArray();
            var certId = single.ReadSequence();
            string hashOid = certId.ReadSequence().ReadObjectIdentifier();
            certIds.Add(new CertId(encoded, hashOid, certId.ReadOctetString(), certId.ReadOctetString(), certId.ReadIntegerBytes().ToArray()));
        }

        byte[]? nonce = null;
        if (tbs.HasData && tbs.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 2)))
        {
            var extensions = tbs.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 2, true)).ReadSequence();
            while (extensions.HasData)
            {
                byte[] encoded = extensions.PeekEncodedValue().ToArray();
                if (extensions.ReadSequence().ReadObjectIdentifier() == NonceOid)
                {
                    nonce = encoded;
                }
            }
        }

        return (certIds, nonce);
    }

    private enum OcspResponseStatus
    {
        Successful = 0,
        MalformedRequest = 1,
        InternalError = 2,
        TryLater = 3,
    }
}
