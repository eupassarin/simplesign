using System.Formats.Asn1;
using SimpleSign.Core.Constants;
using SimpleSign.Core.Crypto;

namespace SimpleSign.CAdES;

/// <summary>
/// Where the signer was when signing: the signer-location attribute (ETSI EN 319 122-1 §5.2.5).
/// At least one of the three fields must be set.
/// </summary>
public sealed record CadesSignerLocation
{
    /// <summary>The country, as X.520 names one (for example "BR").</summary>
    public string? CountryName { get; init; }

    /// <summary>The locality, as X.520 names one (for example a city).</summary>
    public string? LocalityName { get; init; }

    /// <summary>The postal address, one to six lines. Empty: no postal address.</summary>
    public IReadOnlyList<string> PostalAddress { get; init; } = [];
}

/// <summary>
/// Describes the signed content: the content-hints attribute (IETF RFC 2634 §2.9,
/// ETSI EN 319 122-1 §5.2.4.1).
/// </summary>
public sealed record CadesContentHints
{
    /// <summary>
    /// A description of the content. When the content is defined by a MIME type, this is the place
    /// for the encoding and the intended presentation application (IETF RFC 2045). Null: none.
    /// </summary>
    public string? Description { get; init; }

    /// <summary>The OID of the content type. Default: id-data (<see cref="Oids.Data"/>).</summary>
    public string ContentTypeOid { get; init; } = Oids.Data;
}

/// <summary>
/// An assertion about the signer that a third party signed, carried in signer-attributes-v2
/// (ETSI EN 319 122-1 §5.2.6.1, signedAssertions). The library stores and reads it; it does not
/// verify the third party's signature.
/// </summary>
/// <param name="Oid">The OID that identifies the kind of assertion.</param>
/// <param name="Value">The DER-encoded assertion value, or empty when the kind has none.</param>
public sealed record CadesSignedAssertion(string Oid, ReadOnlyMemory<byte> Value)
{
    /// <summary>
    /// A signed SAML assertion (§5.2.6.3): the bytes of the assertion as SAML defines it, stored as
    /// an OCTET STRING under id-ets-signedSAML.
    /// </summary>
    /// <remarks>
    /// EU DSS 6.3 reads signed assertions only in a form of its own (a PrintableString). It
    /// validates a signature that carries this one, but leaves the signer roles of that signature
    /// out of its report.
    /// </remarks>
    /// <param name="assertion">The bytes of the signed SAML assertion.</param>
    /// <returns>The assertion, ready for <see cref="CadesSignerBuilder.WithSignedAssertions"/>.</returns>
    public static CadesSignedAssertion Saml(ReadOnlySpan<byte> assertion)
    {
        if (assertion.IsEmpty)
        {
            throw new ArgumentException("The SAML assertion is empty.", nameof(assertion));
        }

        var writer = new AsnWriter(AsnEncodingRules.DER);
        writer.WriteOctetString(assertion);
        return new CadesSignedAssertion(Oids.SignedSamlAssertion, writer.Encode());
    }

    /// <summary>The bytes of a signed SAML assertion (the content of its OCTET STRING); null for another kind or a malformed value.</summary>
    public byte[]? SamlAssertion()
    {
        if (Oid != Oids.SignedSamlAssertion)
        {
            return null;
        }

        try
        {
            return new AsnReader(Value, AsnEncodingRules.BER).ReadOctetString();
        }
        catch (AsnContentException)
        {
            return null;
        }
    }
}

/// <summary>
/// The optional CAdES signed attributes that describe the signer and the signed data, as read from
/// a signature: signer-location, content-hints, mime-type and the roles the signer claims.
/// </summary>
public sealed record CadesSignedAttributes
{
    /// <summary>The signer-location attribute (§5.2.5); null when there is none.</summary>
    public CadesSignerLocation? SignerLocation { get; init; }

    /// <summary>The content-hints attribute (§5.2.4.1); null when there is none.</summary>
    public CadesContentHints? ContentHints { get; init; }

    /// <summary>The mime-type attribute (§5.2.4.2); null when there is none.</summary>
    public string? MimeType { get; init; }

    /// <summary>The roles the signer claims in signer-attributes-v2 (§5.2.6.1); empty when there are none.</summary>
    public IReadOnlyList<string> ClaimedRoles { get; init; } = [];

    /// <summary>
    /// The X.509 attribute certificates in signer-attributes-v2 (certifiedAttributesV2), DER-encoded;
    /// empty when there are none. They are read, not verified.
    /// </summary>
    public IReadOnlyList<ReadOnlyMemory<byte>> AttributeCertificates { get; init; } = [];

    /// <summary>The assertions signed by third parties in signer-attributes-v2 (signedAssertions); empty when there are none.</summary>
    public IReadOnlyList<CadesSignedAssertion> SignedAssertions { get; init; } = [];

    /// <summary>
    /// Reads the attributes from DER-encoded signed attributes (<see cref="CmsSignedData.SignedAttrs"/>).
    /// A malformed attribute is skipped; the others are still read.
    /// </summary>
    /// <param name="signedAttrs">The signed attributes (SET OF Attribute).</param>
    /// <returns>The attributes found; every property is empty when there are none.</returns>
    public static CadesSignedAttributes Read(ReadOnlySpan<byte> signedAttrs)
    {
        CadesSignerLocation? location = null;
        CadesContentHints? hints = null;
        string? mimeType = null;
        IReadOnlyList<string> roles = [];
        IReadOnlyList<ReadOnlyMemory<byte>> attributeCertificates = [];
        IReadOnlyList<CadesSignedAssertion> signedAssertions = [];

        try
        {
            var set = new AsnReader(signedAttrs.ToArray(), AsnEncodingRules.BER).ReadSetOf(skipSortOrderValidation: true);
            while (set.HasData)
            {
                var attribute = set.ReadSequence();
                string oid = attribute.ReadObjectIdentifier();
                if (oid is not (Oids.SignerLocation or Oids.ContentHints or Oids.MimeType or Oids.SignerAttributesV2))
                {
                    continue;
                }

                try
                {
                    var values = attribute.ReadSetOf(skipSortOrderValidation: true);
                    switch (oid)
                    {
                        case Oids.SignerLocation:
                            location = ReadSignerLocation(values.ReadSequence());
                            break;
                        case Oids.ContentHints:
                            hints = ReadContentHints(values.ReadSequence());
                            break;
                        case Oids.MimeType:
                            mimeType = values.ReadCharacterString(UniversalTagNumber.UTF8String);
                            break;
                        default:
                            (roles, attributeCertificates, signedAssertions) = ReadSignerAttributes(values.ReadSequence());
                            break;
                    }
                }
                catch (AsnContentException)
                {
                    // This attribute is malformed: leave it out and keep the others.
                }
            }
        }
        catch (AsnContentException)
        {
            // Not a SET OF Attribute: nothing more to read.
        }

        return new CadesSignedAttributes
        {
            SignerLocation = location,
            ContentHints = hints,
            MimeType = mimeType,
            ClaimedRoles = roles,
            AttributeCertificates = attributeCertificates,
            SignedAssertions = signedAssertions,
        };
    }

    /// <summary>
    /// <code>
    /// SignerLocation ::= SEQUENCE { -- at least one of the following shall be present
    ///   countryName   [0] DirectoryString OPTIONAL,
    ///   localityName  [1] DirectoryString OPTIONAL,
    ///   postalAddress [2] PostalAddress OPTIONAL }
    /// PostalAddress ::= SEQUENCE SIZE(1..6) OF DirectoryString
    /// </code>
    /// The module uses explicit tags.
    /// </summary>
    internal static CmsAttribute EncodeSignerLocation(CadesSignerLocation location)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSequence())
        {
            if (!string.IsNullOrWhiteSpace(location.CountryName))
            {
                using (writer.PushSequence(Context(0)))
                {
                    writer.WriteCharacterString(UniversalTagNumber.UTF8String, location.CountryName.Trim());
                }
            }

            if (!string.IsNullOrWhiteSpace(location.LocalityName))
            {
                using (writer.PushSequence(Context(1)))
                {
                    writer.WriteCharacterString(UniversalTagNumber.UTF8String, location.LocalityName.Trim());
                }
            }

            if (location.PostalAddress.Count > 0)
            {
                using (writer.PushSequence(Context(2)))
                using (writer.PushSequence())
                {
                    foreach (string line in location.PostalAddress)
                    {
                        writer.WriteCharacterString(UniversalTagNumber.UTF8String, line.Trim());
                    }
                }
            }
        }

        return CmsAttribute.Create(Oids.SignerLocation, writer.Encode());
    }

    /// <summary>
    /// <code>
    /// ContentHints ::= SEQUENCE {
    ///   contentDescription UTF8String (SIZE (1..MAX)) OPTIONAL,
    ///   contentType ContentType }
    /// </code>
    /// </summary>
    internal static CmsAttribute EncodeContentHints(CadesContentHints hints)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSequence())
        {
            if (!string.IsNullOrEmpty(hints.Description))
            {
                writer.WriteCharacterString(UniversalTagNumber.UTF8String, hints.Description);
            }

            writer.WriteObjectIdentifier(hints.ContentTypeOid);
        }

        return CmsAttribute.Create(Oids.ContentHints, writer.Encode());
    }

    /// <summary><c>MimeType ::= UTF8String</c></summary>
    internal static CmsAttribute EncodeMimeType(string mimeType)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        writer.WriteCharacterString(UniversalTagNumber.UTF8String, mimeType);
        return CmsAttribute.Create(Oids.MimeType, writer.Encode());
    }

    /// <summary>The claimed roles alone, as <see cref="EncodeSignerAttributes"/> writes them.</summary>
    internal static CmsAttribute EncodeClaimedRoles(IReadOnlyList<string> roles) => EncodeSignerAttributes(roles, [], []);

    /// <summary>
    /// <code>
    /// SignerAttributeV2 ::= SEQUENCE {
    ///   claimedAttributes     [0] ClaimedAttributes OPTIONAL,
    ///   certifiedAttributesV2 [1] CertifiedAttributesV2 OPTIONAL,
    ///   signedAssertions      [2] SignedAssertions OPTIONAL }
    /// ClaimedAttributes ::= SEQUENCE OF Attribute
    /// CertifiedAttributesV2 ::= SEQUENCE OF CHOICE {
    ///   attributeCertificate      [0] AttributeCertificate,
    ///   otherAttributeCertificate [1] OtherAttributeCertificate }
    /// SignedAssertions ::= SEQUENCE OF SignedAssertion
    /// SignedAssertion ::= SEQUENCE { signedAssertionID OBJECT IDENTIFIER, signedAssertion ANY OPTIONAL }
    /// </code>
    /// The module uses explicit tags. Each role is one Attribute of type id-at-role whose value is
    /// the role as a UTF8String. At least one of the three lists must have an item: an empty
    /// signer-attributes-v2 shall not be created.
    /// </summary>
    internal static CmsAttribute EncodeSignerAttributes(
        IReadOnlyList<string> roles,
        IReadOnlyList<ReadOnlyMemory<byte>> attributeCertificates,
        IReadOnlyList<CadesSignedAssertion> signedAssertions)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSequence())
        {
            if (roles.Count > 0)
            {
                using (writer.PushSequence(Context(0)))
                using (writer.PushSequence())
                {
                    foreach (string role in roles)
                    {
                        using (writer.PushSequence())
                        {
                            writer.WriteObjectIdentifier(Oids.RoleAttribute);
                            using (writer.PushSetOf())
                            {
                                writer.WriteCharacterString(UniversalTagNumber.UTF8String, role);
                            }
                        }
                    }
                }
            }

            if (attributeCertificates.Count > 0)
            {
                using (writer.PushSequence(Context(1)))
                using (writer.PushSequence())
                {
                    foreach (ReadOnlyMemory<byte> attributeCertificate in attributeCertificates)
                    {
                        using (writer.PushSequence(Context(0)))
                        {
                            writer.WriteEncodedValue(attributeCertificate.Span);
                        }
                    }
                }
            }

            if (signedAssertions.Count > 0)
            {
                using (writer.PushSequence(Context(2)))
                using (writer.PushSequence())
                {
                    foreach (CadesSignedAssertion assertion in signedAssertions)
                    {
                        using (writer.PushSequence())
                        {
                            writer.WriteObjectIdentifier(assertion.Oid);
                            if (!assertion.Value.IsEmpty)
                            {
                                writer.WriteEncodedValue(assertion.Value.Span);
                            }
                        }
                    }
                }
            }
        }

        return CmsAttribute.Create(Oids.SignerAttributesV2, writer.Encode());
    }

    private static Asn1Tag Context(int number) => new(TagClass.ContextSpecific, number, isConstructed: true);

    private static CadesSignerLocation ReadSignerLocation(AsnReader location)
    {
        string? country = null;
        string? locality = null;
        var postal = new List<string>();
        while (location.HasData)
        {
            Asn1Tag tag = location.PeekTag();
            var field = location.ReadSequence(tag);
            if (tag.HasSameClassAndValue(Context(0)))
            {
                country = ReadString(field);
            }
            else if (tag.HasSameClassAndValue(Context(1)))
            {
                locality = ReadString(field);
            }
            else if (tag.HasSameClassAndValue(Context(2)))
            {
                var lines = field.ReadSequence();
                while (lines.HasData)
                {
                    if (ReadString(lines) is { } line)
                    {
                        postal.Add(line);
                    }
                }
            }
        }

        return new CadesSignerLocation { CountryName = country, LocalityName = locality, PostalAddress = postal.AsReadOnly() };
    }

    private static CadesContentHints ReadContentHints(AsnReader hints)
    {
        string? description = hints.PeekTag() == Asn1Tag.ObjectIdentifier ? null : ReadString(hints);
        return new CadesContentHints { Description = description, ContentTypeOid = hints.ReadObjectIdentifier() };
    }

    private static (IReadOnlyList<string> Roles, IReadOnlyList<ReadOnlyMemory<byte>> AttributeCertificates, IReadOnlyList<CadesSignedAssertion> SignedAssertions)
        ReadSignerAttributes(AsnReader signerAttributes)
    {
        var roles = new List<string>();
        var attributeCertificates = new List<ReadOnlyMemory<byte>>();
        var signedAssertions = new List<CadesSignedAssertion>();
        while (signerAttributes.HasData)
        {
            Asn1Tag tag = signerAttributes.PeekTag();
            var items = signerAttributes.ReadSequence(tag).ReadSequence();
            if (tag.HasSameClassAndValue(Context(0)))
            {
                while (items.HasData)
                {
                    var attribute = items.ReadSequence();
                    _ = attribute.ReadObjectIdentifier();
                    var values = attribute.ReadSetOf(skipSortOrderValidation: true);
                    if (values.HasData && ReadRole(values) is { } role)
                    {
                        roles.Add(role);
                    }
                }
            }
            else if (tag.HasSameClassAndValue(Context(1)))
            {
                while (items.HasData)
                {
                    // Only X.509 attribute certificates ([0]) are returned; other syntaxes ([1]) are skipped.
                    Asn1Tag choice = items.PeekTag();
                    var certified = items.ReadSequence(choice);
                    if (choice.HasSameClassAndValue(Context(0)))
                    {
                        attributeCertificates.Add(certified.ReadEncodedValue().ToArray());
                    }
                }
            }
            else if (tag.HasSameClassAndValue(Context(2)))
            {
                while (items.HasData)
                {
                    var assertion = items.ReadSequence();
                    string oid = assertion.ReadObjectIdentifier();
                    signedAssertions.Add(new CadesSignedAssertion(
                        oid, assertion.HasData ? assertion.ReadEncodedValue().ToArray() : ReadOnlyMemory<byte>.Empty));
                }
            }
        }

        return (roles.AsReadOnly(), attributeCertificates.AsReadOnly(), signedAssertions.AsReadOnly());
    }

    /// <summary>
    /// A role is either a plain string or an X.509 RoleSyntax
    /// (<c>SEQUENCE { roleAuthority [0] GeneralNames OPTIONAL, roleName [1] GeneralName }</c>)
    /// whose name is a URI.
    /// </summary>
    private static string? ReadRole(AsnReader values)
    {
        if (values.PeekTag() != Asn1Tag.Sequence)
        {
            return ReadString(values);
        }

        var roleSyntax = values.ReadSequence();
        while (roleSyntax.HasData)
        {
            Asn1Tag tag = roleSyntax.PeekTag();
            var field = roleSyntax.ReadSequence(tag);
            var uri = new Asn1Tag(TagClass.ContextSpecific, 6);
            if (tag.HasSameClassAndValue(Context(1)) && field.HasData && field.PeekTag().HasSameClassAndValue(uri))
            {
                return field.ReadCharacterString(UniversalTagNumber.IA5String, uri);
            }
        }

        return null;
    }

    /// <summary>Reads a DirectoryString in any of the encodings the BCL decodes; another type is skipped.</summary>
    private static string? ReadString(AsnReader reader)
    {
        Asn1Tag tag = reader.PeekTag();
        if (tag.TagClass == TagClass.Universal && (UniversalTagNumber)tag.TagValue is
            UniversalTagNumber.UTF8String or UniversalTagNumber.PrintableString or UniversalTagNumber.BMPString or
            UniversalTagNumber.T61String or UniversalTagNumber.IA5String)
        {
            return reader.ReadCharacterString((UniversalTagNumber)tag.TagValue);
        }

        _ = reader.ReadEncodedValue();
        return null;
    }
}
