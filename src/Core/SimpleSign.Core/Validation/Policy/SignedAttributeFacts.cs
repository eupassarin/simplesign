using System.Formats.Asn1;
using System.Security.Cryptography.X509Certificates;
using SimpleSign.Core.Constants;
using SimpleSign.Core.Policies;

namespace SimpleSign.Core.Validation.Policy;

/// <summary>A reference to a certificate in the signed attributes (ESSCertID(v2), XAdES Cert): its digest and, when given, its issuer and serial number.</summary>
/// <param name="DigestAlgorithm">The policy name of the digest algorithm (<c>SHA256</c>…).</param>
/// <param name="Digest">The certificate's digest.</param>
/// <param name="Issuer">The issuer of the referenced certificate, or null when the reference has none.</param>
/// <param name="SerialNumber">The serial number (big-endian), or null when the reference has none.</param>
internal sealed record CertificateReference(string DigestAlgorithm, byte[] Digest, X500DistinguishedName? Issuer, byte[]? SerialNumber)
{
    /// <summary>Whether this reference designates <paramref name="certificate"/> by its digest.</summary>
    public bool DigestMatches(X509Certificate2 certificate)
    {
        var name = HashAlgorithmOf(DigestAlgorithm);
        if (name is null)
        {
            return false;
        }

        using var hasher = System.Security.Cryptography.IncrementalHash.CreateHash(name.Value);
        hasher.AppendData(certificate.RawData);
        return hasher.GetHashAndReset().AsSpan().SequenceEqual(Digest);
    }

    /// <summary>Whether the issuer and serial number of this reference are those of <paramref name="certificate"/>; null when the reference has none.</summary>
    public bool? IssuerSerialMatches(X509Certificate2 certificate) =>
        Issuer is null || SerialNumber is null
            ? null
            : (Issuer.RawData.AsSpan().SequenceEqual(certificate.IssuerName.RawData)
                    || string.Equals(Issuer.Name, certificate.IssuerName.Name, StringComparison.OrdinalIgnoreCase))
                && SerialNumber.AsSpan().SequenceEqual(certificate.SerialNumberBytes.Span);

    private static System.Security.Cryptography.HashAlgorithmName? HashAlgorithmOf(string name) => name switch
    {
        "SHA1" => System.Security.Cryptography.HashAlgorithmName.SHA1,
        "SHA256" => System.Security.Cryptography.HashAlgorithmName.SHA256,
        "SHA384" => System.Security.Cryptography.HashAlgorithmName.SHA384,
        "SHA512" => System.Security.Cryptography.HashAlgorithmName.SHA512,
        "SHA3-256" => System.Security.Cryptography.HashAlgorithmName.SHA3_256,
        "SHA3-384" => System.Security.Cryptography.HashAlgorithmName.SHA3_384,
        "SHA3-512" => System.Security.Cryptography.HashAlgorithmName.SHA3_512,
        _ => null,
    };
}

/// <summary>
/// The signed attributes (CAdES/PAdES) or signed properties (XAdES) of a signature, in the terms of the
/// <c>SignedAttributes</c> constraints. A null list or value was not looked for; an empty one was looked for and is absent.
/// </summary>
internal sealed record SignedAttributeFacts
{
    /// <summary>How many signing-certificate attributes (or properties) the signature has.</summary>
    public int SigningCertificateAttributes { get; init; }

    /// <summary>The certificate references of the signing-certificate attribute, the signing certificate first.</summary>
    public IReadOnlyList<CertificateReference> CertificateReferences { get; init; } = [];

    /// <summary>Whether the message-digest attribute (CAdES) or the SignedProperties (XAdES) is present.</summary>
    public bool MessageDigestOrSignedPropertiesPresent { get; init; }

    /// <summary>The content-type attribute (CMS) or the MimeType of the signed data (XAdES), or null.</summary>
    public string? ContentType { get; init; }

    /// <summary>The content type named by the content-hints attribute, or null when it is absent.</summary>
    public string? ContentHints { get; init; }

    /// <summary>The content-identifier attribute (hexadecimal), or null when it is absent.</summary>
    public string? ContentIdentifier { get; init; }

    /// <summary>The commitment types (OIDs or URIs).</summary>
    public IReadOnlyList<string> CommitmentTypes { get; init; } = [];

    /// <summary>Whether the signer location is present.</summary>
    public bool SignerLocation { get; init; }

    /// <summary>The roles the signer claims (the values as text).</summary>
    public IReadOnlyList<string> ClaimedRoles { get; init; } = [];

    /// <summary>How many certified roles (attribute certificates) the signature carries.</summary>
    public int CertifiedRoles { get; init; }

    /// <summary>Whether a content timestamp (CAdES content-time-stamp, XAdES data objects timestamp) is present.</summary>
    public bool ContentTimestamp { get; init; }

    /// <summary>The facts of CMS signed attributes (the DER SET of a SignerInfo); null when the signer info has none.</summary>
    public static SignedAttributeFacts? FromCms(byte[]? signedAttributes)
    {
        if (signedAttributes is null)
        {
            return null;
        }

        int signingCertificates = 0;
        var references = new List<CertificateReference>();
        bool messageDigest = false;
        string? contentType = null, contentHints = null, contentIdentifier = null;
        var commitments = new List<string>();
        bool location = false;
        bool contentTimestamp = false;
        var claimed = new List<string>();
        int certified = 0;
        try
        {
            var set = new AsnReader(signedAttributes, AsnEncodingRules.DER).ReadSetOf(skipSortOrderValidation: true);
            while (set.HasData)
            {
                var attribute = set.ReadSequence();
                string type = attribute.ReadObjectIdentifier();
                var values = attribute.ReadSetOf(skipSortOrderValidation: true);
                while (values.HasData)
                {
                    var value = values.ReadEncodedValue();
                    if (type == Oids.MessageDigest)
                    {
                        messageDigest = true;
                        continue;
                    }

                    if (type == Oids.ContentTimestamp)
                    {
                        contentTimestamp = true;
                        continue;
                    }

                    try
                    {
                        Read(type, value);
                    }
                    catch (AsnContentException)
                    {
                        // One unreadable attribute does not hide the others.
                    }
                }
            }
        }
        catch (AsnContentException)
        {
            // Malformed attributes: what was read so far stands; the signature check reports the rest.
        }

        void Read(string type, ReadOnlyMemory<byte> value)
        {
            switch (type)
            {
                case Oids.SigningCertificate:
                    signingCertificates++;
                    references.AddRange(ReadEssCertIds(value, v2: false));
                    break;
                case Oids.SigningCertificateV2:
                    signingCertificates++;
                    references.AddRange(ReadEssCertIds(value, v2: true));
                    break;
                case Oids.ContentType:
                    contentType = new AsnReader(value, AsnEncodingRules.BER).ReadObjectIdentifier();
                    break;
                case Oids.ContentHints:
                    contentHints = ReadContentHints(value);
                    break;
                case ContentIdentifierOid:
                    contentIdentifier = Convert.ToHexString(new AsnReader(value, AsnEncodingRules.BER).ReadOctetString());
                    break;
                case Oids.CommitmentTypeIndication:
                    commitments.Add(new AsnReader(value, AsnEncodingRules.BER).ReadSequence().ReadObjectIdentifier());
                    break;
                case Oids.SignerLocation:
                    location = true;
                    break;
                case Oids.SignerAttributesV2:
                case SignerAttributesOid:
                    ReadSignerAttributes(value, claimed, ref certified);
                    break;
            }
        }

        return new SignedAttributeFacts
        {
            SigningCertificateAttributes = signingCertificates,
            CertificateReferences = references,
            MessageDigestOrSignedPropertiesPresent = messageDigest,
            ContentType = contentType,
            ContentHints = contentHints,
            ContentIdentifier = contentIdentifier,
            CommitmentTypes = commitments,
            SignerLocation = location,
            ClaimedRoles = claimed,
            CertifiedRoles = certified,
            ContentTimestamp = contentTimestamp,
        };
    }

    private const string ContentIdentifierOid = "1.2.840.113549.1.9.16.2.7";
    private const string SignerAttributesOid = "1.2.840.113549.1.9.16.2.18";

    /// <summary>SigningCertificate(V2) ::= SEQUENCE { certs SEQUENCE OF ESSCertID(v2), policies OPTIONAL }.</summary>
    private static IEnumerable<CertificateReference> ReadEssCertIds(ReadOnlyMemory<byte> value, bool v2)
    {
        var certs = new AsnReader(value, AsnEncodingRules.BER).ReadSequence().ReadSequence();
        var list = new List<CertificateReference>();
        while (certs.HasData)
        {
            var id = certs.ReadSequence();
            string algorithm = v2 ? "SHA256" : "SHA1";
            if (v2 && id.PeekTag().HasSameClassAndValue(Asn1Tag.Sequence))
            {
                algorithm = CryptographicRules.DigestName(id.ReadSequence().ReadObjectIdentifier());
            }

            byte[] hash = id.ReadOctetString();
            X500DistinguishedName? issuer = null;
            byte[]? serial = null;
            if (id.HasData)
            {
                var issuerSerial = id.ReadSequence();
                var names = issuerSerial.ReadSequence();
                while (names.HasData)
                {
                    var tag = names.PeekTag();
                    if (tag.HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 4)))
                    {
                        var directory = names.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 4, isConstructed: true));
                        issuer = new X500DistinguishedName(directory.ReadEncodedValue().Span);
                    }
                    else
                    {
                        names.ReadEncodedValue();
                    }
                }

                serial = issuerSerial.ReadIntegerBytes().ToArray();
            }

            list.Add(new CertificateReference(algorithm, hash, issuer, serial));
        }

        return list;
    }

    /// <summary>ContentHints ::= SEQUENCE { contentDescription UTF8String OPTIONAL, contentType OBJECT IDENTIFIER }.</summary>
    private static string ReadContentHints(ReadOnlyMemory<byte> value)
    {
        var hints = new AsnReader(value, AsnEncodingRules.BER).ReadSequence();
        if (hints.PeekTag() != Asn1Tag.ObjectIdentifier)
        {
            hints.ReadEncodedValue(); // contentDescription
        }

        return hints.ReadObjectIdentifier();
    }

    /// <summary>
    /// SignerAttributes(V2) ::= SEQUENCE OF CHOICE { claimedAttributes [0], certifiedAttributes(V2) [1], signedAssertions [2] },
    /// explicit tags (EN 319 122-1).
    /// </summary>
    private static void ReadSignerAttributes(ReadOnlyMemory<byte> value, List<string> claimed, ref int certified)
    {
        var choices = new AsnReader(value, AsnEncodingRules.BER).ReadSequence();
        while (choices.HasData)
        {
            var tag = choices.PeekTag();
            if (tag.HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 0)))
            {
                var attributes = choices.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0, isConstructed: true)).ReadSequence();
                while (attributes.HasData)
                {
                    var attribute = attributes.ReadSequence();
                    attribute.ReadObjectIdentifier();
                    var values = attribute.ReadSetOf(skipSortOrderValidation: true);
                    while (values.HasData)
                    {
                        if (Role(values) is { } role)
                        {
                            claimed.Add(role);
                        }
                    }
                }
            }
            else
            {
                if (tag.HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 1)))
                {
                    certified++;
                }

                choices.ReadEncodedValue();
            }
        }
    }

    /// <summary>A role value: a DirectoryString, or the URI of a RoleSyntax roleName (X.509 attribute certificate syntax).</summary>
    private static string? Role(AsnReader values)
    {
        var tag = values.PeekTag();
        if (tag.TagClass == TagClass.Universal && (UniversalTagNumber)tag.TagValue is UniversalTagNumber.UTF8String
            or UniversalTagNumber.PrintableString or UniversalTagNumber.BMPString or UniversalTagNumber.T61String or UniversalTagNumber.IA5String)
        {
            return values.ReadCharacterString((UniversalTagNumber)tag.TagValue);
        }

        if (tag != Asn1Tag.Sequence)
        {
            values.ReadEncodedValue();
            return null;
        }

        var roleSyntax = values.ReadSequence();
        var uri = new Asn1Tag(TagClass.ContextSpecific, 6);
        while (roleSyntax.HasData)
        {
            var fieldTag = roleSyntax.PeekTag();
            var field = roleSyntax.ReadSequence(fieldTag);
            if (fieldTag.HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 1)) && field.HasData && field.PeekTag().HasSameClassAndValue(uri))
            {
                return field.ReadCharacterString(UniversalTagNumber.IA5String, uri);
            }
        }

        return null;
    }
}

/// <summary>Reads the structure of a CMS SignedData that the policy constraints ask about.</summary>
internal static class CmsStructure
{
    /// <summary>How many SignerInfos a CMS ContentInfo (DER or BER, trailing padding ignored) has; null when it cannot be read.</summary>
    public static int? SignerInfoCount(ReadOnlyMemory<byte> contentInfo)
    {
        try
        {
            var content = new AsnReader(contentInfo, AsnEncodingRules.BER).ReadSequence();
            content.ReadObjectIdentifier();
            var signedData = content.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0, isConstructed: true)).ReadSequence();
            signedData.ReadInteger();
            signedData.ReadSetOf(skipSortOrderValidation: true);
            signedData.ReadSequence();
            while (signedData.HasData && signedData.PeekTag().TagClass == TagClass.ContextSpecific)
            {
                signedData.ReadEncodedValue();
            }

            var signerInfos = signedData.ReadSetOf(skipSortOrderValidation: true);
            int count = 0;
            while (signerInfos.HasData)
            {
                signerInfos.ReadEncodedValue();
                count++;
            }

            return count;
        }
        catch (AsnContentException)
        {
            return null;
        }
    }
}
