using System.Formats.Asn1;
using System.Security.Cryptography.X509Certificates;

namespace SimpleSign.Core.Validation.Policy;

/// <summary>What a timestamp token covers.</summary>
internal enum TimestampTokenKind
{
    /// <summary>A signature timestamp (level T): its time is the signature's proof of existence.</summary>
    Signature,

    /// <summary>An archive timestamp (level LTA) over the signature and its validation data.</summary>
    Archive,

    /// <summary>A content timestamp: taken over the signed data before the signature.</summary>
    Content,
}

/// <summary>A timestamp token of a signature, with what the format validator established about it.</summary>
/// <param name="Kind">Signature or archive timestamp.</param>
/// <param name="Token">The DER RFC 3161 token (a CMS SignedData).</param>
/// <param name="ImprintValid">Whether the token covers what it should (its messageImprint); null when not checked.</param>
/// <param name="Trusted">Whether the TSA chains to a trust anchor; null when not checked.</param>
/// <param name="AtsHashIndexValid">For a CAdES archive-time-stamp-v3, whether its ats-hash-index is present and right; null otherwise.</param>
internal sealed record TimestampTokenFacts(TimestampTokenKind Kind, byte[] Token, bool? ImprintValid, bool? Trusted, bool? AtsHashIndexValid = null)
{
    /// <summary>A short name for the messages.</summary>
    public string Label => Kind switch
    {
        TimestampTokenKind.Signature => "signature timestamp",
        TimestampTokenKind.Archive => "archive timestamp",
        _ => "content timestamp",
    };
}

/// <summary>The fields of a TSTInfo EN 319 422 profiles: the TSA policy, whether accuracy is given, and ordering.</summary>
internal sealed record TstInfoProfile(string? Policy, bool AccuracyPresent, bool Ordering);

/// <summary>Reads the TSTInfo of a timestamp token.</summary>
internal static class TstInfoReader
{
    /// <summary>The policy, accuracy and ordering of a timestamp token's TSTInfo (RFC 3161 §2.4.2); null when it cannot be read.</summary>
    public static TstInfoProfile? ProfileFromToken(byte[] token)
    {
        try
        {
            var signedData = new AsnReader(token, AsnEncodingRules.BER).ReadSequence();
            signedData.ReadObjectIdentifier();
            var content = signedData.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0, isConstructed: true)).ReadSequence();
            content.ReadInteger();
            content.ReadSetOf(skipSortOrderValidation: true);
            var encapsulated = content.ReadSequence();
            encapsulated.ReadObjectIdentifier();
            var info = new AsnReader(encapsulated.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0, isConstructed: true)).ReadOctetString(),
                AsnEncodingRules.DER).ReadSequence();
            info.ReadInteger(); // version
            string policy = info.ReadObjectIdentifier();
            info.ReadSequence(); // messageImprint
            info.ReadIntegerBytes(); // serialNumber
            info.ReadGeneralizedTime(); // genTime
            bool accuracy = false;
            bool ordering = false;
            if (info.HasData && info.PeekTag().HasSameClassAndValue(Asn1Tag.Sequence))
            {
                info.ReadSequence(); // accuracy
                accuracy = true;
            }

            if (info.HasData && info.PeekTag().HasSameClassAndValue(Asn1Tag.Boolean))
            {
                ordering = info.ReadBoolean();
            }

            return new TstInfoProfile(policy, accuracy, ordering);
        }
        catch (AsnContentException)
        {
            return null;
        }
    }

    /// <summary>The genTime and TSA name of a timestamp token (a CMS ContentInfo with a TSTInfo).</summary>
    public static (DateTimeOffset? GenTime, X500DistinguishedName? Tsa, bool TsaPresent) FromToken(byte[] token)
    {
        try
        {
            var signedData = new AsnReader(token, AsnEncodingRules.BER).ReadSequence();
            signedData.ReadObjectIdentifier();
            var content = signedData.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0, isConstructed: true)).ReadSequence();
            content.ReadInteger();
            content.ReadSetOf(skipSortOrderValidation: true);
            var encapsulated = content.ReadSequence();
            encapsulated.ReadObjectIdentifier();
            return Read(encapsulated.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0, isConstructed: true)).ReadOctetString());
        }
        catch (AsnContentException)
        {
            return (null, null, false);
        }
    }

    /// <summary>
    /// The genTime and the TSA name (the <c>tsa</c> field, a directoryName) of the TSTInfo carried by
    /// <paramref name="eContent"/>; the name is null when absent or not a directory name.
    /// </summary>
    public static (DateTimeOffset? GenTime, X500DistinguishedName? Tsa, bool TsaPresent) Read(byte[]? eContent)
    {
        if (eContent is null)
        {
            return (null, null, false);
        }

        try
        {
            var info = new AsnReader(eContent, AsnEncodingRules.DER).ReadSequence();
            info.ReadInteger(); // version
            info.ReadObjectIdentifier(); // policy
            info.ReadSequence(); // messageImprint
            info.ReadIntegerBytes(); // serialNumber
            var genTime = info.ReadGeneralizedTime();
            while (info.HasData)
            {
                var tag = info.PeekTag();
                if (tag.HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 0)))
                {
                    var name = info.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0, isConstructed: true));
                    var nameTag = name.PeekTag();
                    if (nameTag.HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 4)))
                    {
                        var directory = name.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 4, isConstructed: true));
                        return (genTime, new X500DistinguishedName(directory.ReadEncodedValue().Span), true);
                    }

                    return (genTime, null, true);
                }

                info.ReadEncodedValue();
            }

            return (genTime, null, false);
        }
        catch (AsnContentException)
        {
            return (null, null, false);
        }
    }
}

/// <summary>Whether the TSA of a timestamp token chains to trust anchors, at the token's time.</summary>
internal static class TimestampTrust
{
    /// <summary>True or false; null when there are no anchors to judge with or the token cannot be read.</summary>
    public static bool? ChainsTo(byte[] token, IEnumerable<X509Certificate2>? anchors)
    {
        var roots = anchors?.ToList();
        if (roots is not { Count: > 0 })
        {
            return null;
        }

        var certificates = TimestampValidator.ReadTokenCertificates(token);
        if (certificates.Count == 0)
        {
            return null;
        }

        using var chain = new X509Chain();
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        chain.ChainPolicy.DisableCertificateDownloads = true;
        if (TstInfoReader.FromToken(token).GenTime is { } genTime)
        {
            chain.ChainPolicy.VerificationTime = genTime.UtcDateTime;
        }

        chain.ChainPolicy.CustomTrustStore.AddRange(roots.ToArray());
        chain.ChainPolicy.ExtraStore.AddRange(certificates.Skip(1).Concat(roots).ToArray());
        try
        {
            return chain.Build(certificates[0]);
        }
        catch (System.Security.Cryptography.CryptographicException)
        {
            return false;
        }
    }
}
