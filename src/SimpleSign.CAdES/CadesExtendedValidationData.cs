using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SimpleSign.Core.Constants;
using SimpleSign.Core.Crypto;
using SimpleSign.Core.Revocation;

namespace SimpleSign.CAdES;

/// <summary>
/// The CAdES extended forms of RFC 5126 / ETSI TS 101 733 that ICP-Brasil's AD-RV, AD-RC and
/// AD-RA policies mandate.
/// </summary>
public enum CadesExtendedForm
{
    /// <summary>No extended validation data.</summary>
    None,

    /// <summary>CAdES-C + CAdES-X type 1: complete-certificate-references, complete-revocation-references and an escTimeStamp (ICP-Brasil AD-RV).</summary>
    CompleteReferences,

    /// <summary>CAdES-X Long type 1: the references, the escTimeStamp and certificate-values / revocation-values (ICP-Brasil AD-RC).</summary>
    ExtendedLong,

    /// <summary>CAdES-A: references and values plus an archive-time-stamp v2 (ICP-Brasil AD-RA).</summary>
    Archive,
}

/// <summary>
/// Builds the RFC 5126 attributes of the extended forms: complete-certificate-references (§5.7.3),
/// complete-revocation-references (§5.7.4), certificate-values (§5.7.5), revocation-values (§5.7.6),
/// the escTimeStamp input (§5.11.3) and the archive-time-stamp v2 input (§6.4.1).
/// </summary>
internal static class CadesExtendedValidationData
{
    private static readonly Asn1Tag Context0 = new(TagClass.ContextSpecific, 0, true);
    private static readonly Asn1Tag Context1 = new(TagClass.ContextSpecific, 1, true);
    private static readonly Asn1Tag Context4 = new(TagClass.ContextSpecific, 4, true);

    /// <summary>The certification path, signer first, root last, built from the collected certificates.</summary>
    internal static List<X509Certificate2> BuildPath(X509Certificate2 signer, IEnumerable<byte[]> certificates)
    {
        using var chain = new X509Chain();
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        chain.ChainPolicy.VerificationFlags = X509VerificationFlags.AllFlags;
        foreach (byte[] raw in certificates)
        {
            chain.ChainPolicy.ExtraStore.Add(CertificateLoader.LoadCertificate(raw));
        }

        chain.Build(signer);
        return [.. chain.ChainElements.Select(e => e.Certificate)];
    }

    /// <summary>CompleteCertificateRefs ::= SEQUENCE OF OtherCertID — every certificate of the path but the signer's.</summary>
    internal static CmsAttribute CompleteCertificateRefs(IReadOnlyList<X509Certificate2> path)
    {
        var w = new AsnWriter(AsnEncodingRules.DER);
        using (w.PushSequence())
        {
            foreach (var certificate in path.Skip(1))
            {
                using (w.PushSequence()) // OtherCertID
                {
                    WriteOtherHash(w, SHA256.HashData(certificate.RawData));
                    using (w.PushSequence()) // IssuerSerial
                    {
                        using (w.PushSequence()) // GeneralNames
                        {
                            using (w.PushSequence(Context4)) // directoryName [4] EXPLICIT Name
                            {
                                w.WriteEncodedValue(certificate.IssuerName.RawData);
                            }
                        }

                        w.WriteInteger(certificate.SerialNumberBytes.Span);
                    }
                }
            }
        }

        return CmsAttribute.Raw(Oids.CertificateRefs, w.Encode());
    }

    /// <summary>
    /// CompleteRevocationRefs ::= SEQUENCE OF CrlOcspRef — one entry per certificate of the path
    /// except the root, in path order, referencing the CRLs and OCSP responses that cover it.
    /// </summary>
    internal static CmsAttribute CompleteRevocationRefs(
        IReadOnlyList<X509Certificate2> path, IReadOnlyList<byte[]> crls, IReadOnlyList<byte[]> ocspResponses)
    {
        var ocsp = new OcspClient(SimpleSign.Core.Http.DefaultHttpClientProvider.Instance.GetClient());
        var w = new AsnWriter(AsnEncodingRules.DER);
        using (w.PushSequence())
        {
            for (int i = 0; i < Math.Max(1, path.Count - 1); i++)
            {
                var certificate = path[i];
                var issuer = i + 1 < path.Count ? path[i + 1] : null;
                var coveringCrls = crls.Where(c => issuer is not null && CrlClient.IsSerialInCrl(certificate, c, issuer) is not null).ToList();
                var coveringOcsp = ocspResponses.Where(r => Covers(ocsp, certificate, issuer, r)).ToList();
                using (w.PushSequence()) // CrlOcspRef
                {
                    if (coveringCrls.Count > 0)
                    {
                        using (w.PushSequence(Context0)) // crlids [0] CRLListID
                        {
                            using (w.PushSequence()) // CRLListID
                            {
                                using (w.PushSequence()) // crls SEQUENCE OF CrlValidatedID
                                {
                                    foreach (byte[] crl in coveringCrls)
                                    {
                                        WriteCrlValidatedId(w, crl);
                                    }
                                }
                            }
                        }
                    }

                    if (coveringOcsp.Count > 0)
                    {
                        using (w.PushSequence(Context1)) // ocspids [1] OcspListID
                        {
                            using (w.PushSequence()) // OcspListID
                            {
                                using (w.PushSequence()) // ocspResponses SEQUENCE OF OcspResponsesID
                                {
                                    foreach (byte[] response in coveringOcsp)
                                    {
                                        WriteOcspResponsesId(w, BasicResponse(response));
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        return CmsAttribute.Raw(Oids.RevocationRefs, w.Encode());
    }

    /// <summary>CertificateValues ::= SEQUENCE OF Certificate — the certificates of the path but the signer's.</summary>
    internal static CmsAttribute CertificateValues(IReadOnlyList<X509Certificate2> path)
    {
        var w = new AsnWriter(AsnEncodingRules.DER);
        using (w.PushSequence())
        {
            foreach (var certificate in path.Skip(1))
            {
                w.WriteEncodedValue(certificate.RawData);
            }
        }

        return CmsAttribute.Raw(Oids.CertValues, w.Encode());
    }

    /// <summary>RevocationValues ::= SEQUENCE { crlVals [0] SEQUENCE OF CertificateList, ocspVals [1] SEQUENCE OF BasicOCSPResponse }.</summary>
    internal static CmsAttribute RevocationValues(IReadOnlyList<byte[]> crls, IReadOnlyList<byte[]> ocspResponses)
    {
        var w = new AsnWriter(AsnEncodingRules.DER);
        using (w.PushSequence())
        {
            if (crls.Count > 0)
            {
                using (w.PushSequence(Context0))
                {
                    using (w.PushSequence())
                    {
                        foreach (byte[] crl in crls)
                        {
                            w.WriteEncodedValue(crl);
                        }
                    }
                }
            }

            if (ocspResponses.Count > 0)
            {
                using (w.PushSequence(Context1))
                {
                    using (w.PushSequence())
                    {
                        foreach (byte[] response in ocspResponses)
                        {
                            w.WriteEncodedValue(BasicResponse(response));
                        }
                    }
                }
            }
        }

        return CmsAttribute.Raw(Oids.RevocationValues, w.Encode());
    }

    /// <summary>
    /// escTimeStamp message-imprint input (RFC 5126 §5.11.3): the signature value octets followed by
    /// the DER encodings of the signature-time-stamp, complete-certificate-references and
    /// complete-revocation-references attributes, as they appear in the first signer.
    /// </summary>
    internal static byte[] EscTimeStampInput(byte[] cms)
    {
        var signer = FirstSignerInfo(cms);
        var attributes = UnsignedAttributes(signer);
        using var buffer = new MemoryStream();
        buffer.Write(SignatureValue(signer));
        foreach (string oid in new[] { Oids.SignatureTimestampToken, Oids.CertificateRefs, Oids.RevocationRefs })
        {
            foreach (var (attributeOid, encoded) in attributes)
            {
                if (attributeOid == oid)
                {
                    buffer.Write(encoded);
                }
            }
        }

        return buffer.ToArray();
    }

    /// <summary>
    /// archive-time-stamp v2 message-imprint input (RFC 5126 §6.4.1): encapContentInfo, the external
    /// content of a detached signature, the certificates and crls fields of SignedData, and every
    /// field of the first SignerInfo (the unsigned attributes without earlier archive time-stamps).
    /// </summary>
    internal static byte[] ArchiveTimeStampV2Input(byte[] cms, byte[]? externalContent)
    {
        var sd = SignedData(cms);
        _ = sd.ReadInteger(); // version
        _ = sd.ReadSetOf(skipSortOrderValidation: true); // digestAlgorithms
        using var buffer = new MemoryStream();
        var encap = sd.ReadEncodedValue();
        buffer.Write(encap.Span);
        bool detached = !new AsnReader(encap, AsnEncodingRules.BER).ReadSequence().ReadObjectIdentifierAndHasMore();
        if (detached && externalContent is not null)
        {
            buffer.Write(externalContent);
        }

        if (sd.HasData && sd.PeekTag() == Context0)
        {
            buffer.Write(sd.ReadEncodedValue().Span); // certificates
        }

        if (sd.HasData && sd.PeekTag() == Context1)
        {
            buffer.Write(sd.ReadEncodedValue().Span); // crls
        }

        var signer = sd.ReadSetOf(skipSortOrderValidation: true).ReadSequence();
        while (signer.HasData)
        {
            if (signer.PeekTag() == Context1)
            {
                var kept = new List<byte[]>();
                var unsigned = signer.ReadSetOf(true, Context1);
                while (unsigned.HasData)
                {
                    byte[] attribute = unsigned.ReadEncodedValue().ToArray();
                    string oid = new AsnReader(attribute, AsnEncodingRules.BER).ReadSequence().ReadObjectIdentifier();
                    if (oid is not (Oids.ArchiveTimeStamp or Oids.ArchiveTimeStampV3))
                    {
                        kept.Add(attribute);
                    }
                }

                var w = new AsnWriter(AsnEncodingRules.BER);
                using (w.PushSetOf(Context1))
                {
                    foreach (byte[] attribute in kept)
                    {
                        w.WriteEncodedValue(attribute);
                    }
                }

                buffer.Write(w.Encode());
            }
            else
            {
                buffer.Write(signer.ReadEncodedValue().Span);
            }
        }

        return buffer.ToArray();
    }

    private static bool ReadObjectIdentifierAndHasMore(this AsnReader encapContentInfo)
    {
        _ = encapContentInfo.ReadObjectIdentifier();
        return encapContentInfo.HasData;
    }

    private static bool Covers(OcspClient client, X509Certificate2 certificate, X509Certificate2? issuer, byte[] response)
    {
        try
        {
            return client.CheckEmbeddedOcspResponse(certificate, issuer, response, null) is not null;
        }
        catch (Exception ex) when (ex is AsnContentException or CryptographicException or InvalidDataException)
        {
            return false;
        }
    }

    private static void WriteOtherHash(AsnWriter w, byte[] sha256)
    {
        using (w.PushSequence()) // OtherHashAlgAndValue
        {
            using (w.PushSequence())
            {
                w.WriteObjectIdentifier(Oids.Sha256);
            }

            w.WriteOctetString(sha256);
        }
    }

    /// <summary>CrlValidatedID ::= SEQUENCE { crlHash OtherHash, crlIdentifier CrlIdentifier OPTIONAL }.</summary>
    private static void WriteCrlValidatedId(AsnWriter w, byte[] crl)
    {
        var tbs = new AsnReader(crl, AsnEncodingRules.BER).ReadSequence().ReadSequence();
        if (tbs.PeekTag() == Asn1Tag.Integer)
        {
            _ = tbs.ReadInteger();
        }

        _ = tbs.ReadSequence(); // signature
        byte[] issuer = tbs.ReadEncodedValue().ToArray();
        DateTimeOffset thisUpdate = tbs.PeekTag().TagValue == (int)UniversalTagNumber.UtcTime ? tbs.ReadUtcTime() : tbs.ReadGeneralizedTime();

        using (w.PushSequence())
        {
            WriteOtherHash(w, SHA256.HashData(crl));
            using (w.PushSequence()) // CrlIdentifier { crlissuer Name, crlIssuedTime UTCTime }
            {
                w.WriteEncodedValue(issuer);
                w.WriteUtcTime(thisUpdate);
            }
        }
    }

    /// <summary>OcspResponsesID ::= SEQUENCE { ocspIdentifier { responderID, producedAt }, ocspRepHash OtherHash }.</summary>
    private static void WriteOcspResponsesId(AsnWriter w, byte[] basicResponse)
    {
        var tbs = new AsnReader(basicResponse, AsnEncodingRules.BER).ReadSequence().ReadSequence();
        if (tbs.PeekTag() == Context0)
        {
            _ = tbs.ReadEncodedValue(); // version
        }

        byte[] responderId = tbs.ReadEncodedValue().ToArray();
        DateTimeOffset producedAt = tbs.ReadGeneralizedTime();
        using (w.PushSequence())
        {
            using (w.PushSequence())
            {
                w.WriteEncodedValue(responderId);
                w.WriteGeneralizedTime(producedAt);
            }

            WriteOtherHash(w, SHA256.HashData(basicResponse));
        }
    }

    /// <summary>The BasicOCSPResponse inside an OCSPResponse (or the input when it already is one).</summary>
    internal static byte[] BasicResponse(byte[] response)
    {
        var outer = new AsnReader(response, AsnEncodingRules.BER).ReadSequence();
        if (outer.PeekTag().TagValue != (int)UniversalTagNumber.Enumerated)
        {
            return response; // already a BasicOCSPResponse
        }

        _ = outer.ReadEnumeratedBytes();
        var responseBytes = outer.ReadSequence(Context0).ReadSequence();
        _ = responseBytes.ReadObjectIdentifier();
        return responseBytes.ReadOctetString();
    }

    private static AsnReader SignedData(byte[] cms)
    {
        var contentInfo = new AsnReader(cms, AsnEncodingRules.BER).ReadSequence();
        _ = contentInfo.ReadObjectIdentifier();
        return contentInfo.ReadSequence(Context0).ReadSequence();
    }

    private static AsnReader FirstSignerInfo(byte[] cms)
    {
        var sd = SignedData(cms);
        _ = sd.ReadInteger();
        _ = sd.ReadSetOf(skipSortOrderValidation: true);
        _ = sd.ReadEncodedValue();
        while (sd.PeekTag() == Context0 || sd.PeekTag() == Context1)
        {
            _ = sd.ReadEncodedValue();
        }

        return sd.ReadSetOf(skipSortOrderValidation: true).ReadSequence();
    }

    private static byte[] SignatureValue(AsnReader signerInfo)
    {
        var copy = signerInfo.Clone();
        _ = copy.ReadInteger();
        _ = copy.ReadEncodedValue(); // sid
        _ = copy.ReadEncodedValue(); // digestAlgorithm
        if (copy.PeekTag() == Context0)
        {
            _ = copy.ReadEncodedValue();
        }

        _ = copy.ReadEncodedValue(); // signatureAlgorithm
        return copy.ReadOctetString();
    }

    private static List<(string Oid, byte[] Encoded)> UnsignedAttributes(AsnReader signerInfo)
    {
        var copy = signerInfo.Clone();
        var result = new List<(string, byte[])>();
        while (copy.HasData)
        {
            if (copy.PeekTag() != Context1)
            {
                _ = copy.ReadEncodedValue();
                continue;
            }

            var set = copy.ReadSetOf(true, Context1);
            while (set.HasData)
            {
                byte[] attribute = set.ReadEncodedValue().ToArray();
                result.Add((new AsnReader(attribute, AsnEncodingRules.BER).ReadSequence().ReadObjectIdentifier(), attribute));
            }
        }

        return result;
    }
}
