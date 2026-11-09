using System.Formats.Asn1;
using System.Numerics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SimpleSign.Core.Crypto;
using SimpleSign.Core.Revocation;

namespace SimpleSign.Core.Validation.Policy;

/// <summary>The kind of a revocation token.</summary>
internal enum RevocationTokenKind
{
    Crl,
    Ocsp,
}

/// <summary>The status a revocation token gives a certificate.</summary>
internal enum RevocationTokenStatus
{
    Good,
    Revoked,
    Unknown,
}

/// <summary>
/// A CRL or OCSP response about one certificate of a chain, in the terms of the <c>Revocation</c> constraints and of
/// the revocation quality constraints of the certificates (<c>CRLNextUpdatePresent</c>, <c>NotOnHold</c>…).
/// </summary>
internal sealed record RevocationTokenFacts
{
    public required RevocationTokenKind Kind { get; init; }

    /// <summary>The certificate the token is about.</summary>
    public required X509Certificate2 Certificate { get; init; }

    /// <summary>The CRL or OCSP response as read.</summary>
    public required byte[] Data { get; init; }

    /// <summary>Who signed the token (the CRL issuer, the OCSP responder); null when it was not found.</summary>
    public X509Certificate2? Issuer { get; init; }

    /// <summary>The issuer's chain, the issuer first; empty when the issuer was not found.</summary>
    public IReadOnlyList<X509Certificate2> IssuerChain { get; init; } = [];

    public RevocationTokenStatus Status { get; init; }

    public DateTimeOffset? RevocationTime { get; init; }

    /// <summary>The CRLReason (RFC 5280 §5.3.1); 6 is certificateHold.</summary>
    public int? Reason { get; init; }

    public DateTimeOffset? ThisUpdate { get; init; }

    public DateTimeOffset? NextUpdate { get; init; }

    /// <summary>
    /// From when the token keeps the status of expired certificates: the CRL's expiredCertsOnCRL or the OCSP response's
    /// archiveCutoff; null when it says nothing.
    /// </summary>
    public DateTimeOffset? ExpiredCertificatesSince { get; init; }

    /// <summary>The OCSP producedAt; for a CRL, its thisUpdate.</summary>
    public DateTimeOffset? ProducedAt { get; init; }

    /// <summary>Whether the token's signature verifies with its issuer's key.</summary>
    public bool SignatureValid { get; init; }

    /// <summary>Whether the OCSP ResponderID designates the responder; null for a CRL.</summary>
    public bool? ResponderIdMatches { get; init; }

    /// <summary>The token's signature algorithm OID.</summary>
    public string? SignatureAlgorithmOid { get; init; }

    /// <summary>A short name for the messages ("OCSP of 'Leaf'").</summary>
    public string Label => $"{(Kind == RevocationTokenKind.Crl ? "CRL" : "OCSP")} of '{Certificate.GetNameInfo(X509NameType.SimpleName, false)}'";
}

/// <summary>Reads CRLs and OCSP responses into <see cref="RevocationTokenFacts"/>.</summary>
internal static class RevocationTokenReader
{
    private const string ReasonCode = "2.5.29.21";
    private const string ExpiredCertsOnCrl = "2.5.29.60";
    private const string ArchiveCutoff = "1.3.6.1.5.5.7.48.1.6";

    /// <summary>
    /// The tokens among <paramref name="crls"/> and <paramref name="ocsps"/> that are about a certificate of the chain
    /// (signing certificate first, anchor last).
    /// </summary>
    public static List<RevocationTokenFacts> Read(IReadOnlyList<X509Certificate2> chain, IReadOnlyList<byte[]> crls, IReadOnlyList<byte[]> ocsps)
    {
        var tokens = new List<RevocationTokenFacts>();
        for (int i = 0; i + 1 < chain.Count; i++)
        {
            var certificate = chain[i];
            var issuer = chain[i + 1];
            var issuerChain = chain.Skip(i + 1).ToList();
            foreach (byte[] crl in crls)
            {
                if (Crl(certificate, issuer, issuerChain, crl) is { } token)
                {
                    tokens.Add(token);
                }
            }

            foreach (byte[] ocsp in ocsps)
            {
                if (Ocsp(certificate, issuer, issuerChain, ocsp) is { } token)
                {
                    tokens.Add(token);
                }
            }
        }

        return tokens;
    }

    /// <summary>The CRL's facts for <paramref name="certificate"/>; null when the CRL is not its issuer's.</summary>
    internal static RevocationTokenFacts? Crl(X509Certificate2 certificate, X509Certificate2 issuer, IReadOnlyList<X509Certificate2> issuerChain, byte[] data)
    {
        try
        {
            var crl = new AsnReader(data, AsnEncodingRules.BER).ReadSequence();
            byte[] tbsRaw = crl.PeekEncodedValue().ToArray();
            var tbs = crl.ReadSequence();
            var algorithm = crl.ReadSequence();
            string algorithmOid = algorithm.ReadObjectIdentifier();
            byte[]? parameters = algorithm.HasData ? algorithm.ReadEncodedValue().ToArray() : null;
            byte[] signature = crl.ReadBitString(out _);
            if (tbs.PeekTag() == Asn1Tag.Integer)
            {
                tbs.ReadEncodedValue();
            }

            tbs.ReadSequence();
            byte[] crlIssuer = tbs.ReadEncodedValue().ToArray();
            if (!CrlClient.IssuerMatchesCertificate(crlIssuer, certificate.IssuerName))
            {
                return null;
            }

            var thisUpdate = Time(tbs);
            DateTimeOffset? nextUpdate = tbs.HasData && IsTime(tbs.PeekTag()) ? Time(tbs) : null;
            var status = RevocationTokenStatus.Good;
            DateTimeOffset? revoked = null;
            int? reason = null;
            if (tbs.HasData && tbs.PeekTag() == Asn1Tag.Sequence)
            {
                var serial = new BigInteger(certificate.SerialNumberBytes.Span, isUnsigned: false, isBigEndian: true);
                var entries = tbs.ReadSequence();
                while (entries.HasData)
                {
                    var entry = entries.ReadSequence();
                    if (status == RevocationTokenStatus.Revoked || entry.ReadInteger() != serial)
                    {
                        continue;
                    }

                    status = RevocationTokenStatus.Revoked;
                    revoked = Time(entry);
                    if (entry.HasData)
                    {
                        reason = ReadReason(entry.ReadSequence());
                    }
                }
            }

            DateTimeOffset? expiredSince = null;
            if (tbs.HasData && tbs.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 0)))
            {
                expiredSince = ExtensionTime(tbs.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0, isConstructed: true)).ReadSequence(), ExpiredCertsOnCrl);
            }

            return new RevocationTokenFacts
            {
                Kind = RevocationTokenKind.Crl,
                Certificate = certificate,
                Data = data,
                Issuer = issuer,
                IssuerChain = issuerChain,
                Status = status,
                RevocationTime = revoked,
                Reason = reason,
                ThisUpdate = thisUpdate,
                NextUpdate = nextUpdate,
                ProducedAt = thisUpdate,
                ExpiredCertificatesSince = expiredSince,
                SignatureValid = CrlClient.VerifyCrlSignature(issuer, tbsRaw, signature, algorithmOid, parameters),
                SignatureAlgorithmOid = algorithmOid,
            };
        }
        catch (Exception ex) when (ex is AsnContentException or CryptographicException)
        {
            return null;
        }
    }

    /// <summary>The OCSP response's facts for <paramref name="certificate"/>; null when it has no answer about it.</summary>
    internal static RevocationTokenFacts? Ocsp(X509Certificate2 certificate, X509Certificate2 issuer, IReadOnlyList<X509Certificate2> issuerChain, byte[] data)
    {
        try
        {
            var basic = BasicResponse(data);
            byte[] tbsRaw = basic.PeekEncodedValue().ToArray();
            var tbs = basic.ReadSequence();
            var algorithm = basic.ReadSequence();
            string algorithmOid = algorithm.ReadObjectIdentifier();
            byte[]? parameters = algorithm.HasData ? algorithm.ReadEncodedValue().ToArray() : null;
            byte[] signature = basic.ReadBitString(out _);
            var certificates = new List<X509Certificate2>();
            if (basic.HasData && basic.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 0)))
            {
                var list = basic.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0, isConstructed: true)).ReadSequence();
                while (list.HasData)
                {
                    certificates.Add(CertificateLoader.LoadCertificate(list.ReadEncodedValue().ToArray()));
                }
            }

            if (tbs.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 0)))
            {
                tbs.ReadEncodedValue();
            }

            tbs.ReadEncodedValue(); // responderID
            var producedAt = tbs.ReadGeneralizedTime();
            var responses = tbs.ReadSequence();
            DateTimeOffset? archiveCutoff = null;
            if (tbs.HasData && tbs.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 1)))
            {
                archiveCutoff = ExtensionTime(tbs.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 1, isConstructed: true)).ReadSequence(), ArchiveCutoff);
            }

#pragma warning disable CA5350 // CertID hashes are SHA-1 in practice (RFC 6960)
            byte[] nameHash = SHA1.HashData(certificate.IssuerName.RawData);
#pragma warning restore CA5350
            while (responses.HasData)
            {
                var single = responses.ReadSequence();
                var certId = single.ReadSequence();
                certId.ReadSequence();
                byte[] issuerNameHash = certId.ReadOctetString();
                certId.ReadOctetString();
                if (!issuerNameHash.AsSpan().SequenceEqual(nameHash) || !certId.ReadIntegerBytes().Span.SequenceEqual(certificate.SerialNumberBytes.Span))
                {
                    continue;
                }

                var statusTag = single.PeekTag();
                var status = RevocationTokenStatus.Unknown;
                DateTimeOffset? revoked = null;
                int? reason = null;
                if (statusTag.HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 0)))
                {
                    status = RevocationTokenStatus.Good;
                    single.ReadEncodedValue();
                }
                else if (statusTag.HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 1)))
                {
                    status = RevocationTokenStatus.Revoked;
                    var info = single.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 1, isConstructed: true));
                    revoked = info.ReadGeneralizedTime();
                    if (info.HasData)
                    {
                        reason = info.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0, isConstructed: true))
                            .ReadEnumeratedBytes().Span[^1];
                    }
                }
                else
                {
                    single.ReadEncodedValue();
                }

                var thisUpdate = single.ReadGeneralizedTime();
                DateTimeOffset? nextUpdate = single.HasData && single.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 0))
                    ? single.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0, isConstructed: true)).ReadGeneralizedTime()
                    : null;
                var responder = certificates.FirstOrDefault(c => OcspClient.ResponderIdMatches(tbsRaw, c))
                    ?? (OcspClient.ResponderIdMatches(tbsRaw, issuer) ? issuer : null);
                var chain = responder is null ? []
                    : responder.RawData.AsSpan().SequenceEqual(issuer.RawData) ? issuerChain
                    : [responder, .. issuerChain];
                return new RevocationTokenFacts
                {
                    Kind = RevocationTokenKind.Ocsp,
                    Certificate = certificate,
                    Data = data,
                    Issuer = responder,
                    IssuerChain = chain,
                    Status = status,
                    RevocationTime = revoked,
                    Reason = reason,
                    ThisUpdate = thisUpdate,
                    NextUpdate = nextUpdate,
                    ProducedAt = producedAt,
                    ExpiredCertificatesSince = archiveCutoff,
                    SignatureValid = responder is not null && OcspClient.VerifyOcspSignature(responder, tbsRaw, signature, algorithmOid, parameters),
                    ResponderIdMatches = responder is not null,
                    SignatureAlgorithmOid = algorithmOid,
                };
            }

            return null;
        }
        catch (Exception ex) when (ex is AsnContentException or CryptographicException or InvalidDataException)
        {
            return null;
        }
    }

    /// <summary>The BasicOCSPResponse of an OCSPResponse, or of a BasicOCSPResponse given as is (CAdES/XAdES revocation values).</summary>
    private static AsnReader BasicResponse(byte[] data)
    {
        var outer = new AsnReader(data, AsnEncodingRules.BER).ReadSequence();
        if (outer.PeekTag() == Asn1Tag.Sequence)
        {
            return new AsnReader(data, AsnEncodingRules.BER).ReadSequence();
        }

        outer.ReadEnumeratedBytes();
        var bytes = outer.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0, isConstructed: true)).ReadSequence();
        bytes.ReadObjectIdentifier();
        return new AsnReader(bytes.ReadOctetString(), AsnEncodingRules.BER).ReadSequence();
    }

    private static int? ReadReason(AsnReader extensions)
    {
        while (extensions.HasData)
        {
            var extension = extensions.ReadSequence();
            if (extension.ReadObjectIdentifier() != ReasonCode)
            {
                continue;
            }

            if (extension.PeekTag() == Asn1Tag.Boolean)
            {
                extension.ReadBoolean();
            }

            return new AsnReader(extension.ReadOctetString(), AsnEncodingRules.DER).ReadEnumeratedBytes().Span[^1];
        }

        return null;
    }

    /// <summary>The time value of the extension <paramref name="oid"/> (GeneralizedTime), or null.</summary>
    private static DateTimeOffset? ExtensionTime(AsnReader extensions, string oid)
    {
        while (extensions.HasData)
        {
            var extension = extensions.ReadSequence();
            if (extension.ReadObjectIdentifier() != oid)
            {
                continue;
            }

            if (extension.PeekTag() == Asn1Tag.Boolean)
            {
                extension.ReadBoolean();
            }

            return new AsnReader(extension.ReadOctetString(), AsnEncodingRules.DER).ReadGeneralizedTime();
        }

        return null;
    }

    private static bool IsTime(Asn1Tag tag) => tag == Asn1Tag.UtcTime || tag == Asn1Tag.GeneralizedTime;

    private static DateTimeOffset Time(AsnReader reader) =>
        reader.PeekTag() == Asn1Tag.UtcTime ? reader.ReadUtcTime() : reader.ReadGeneralizedTime();
}
