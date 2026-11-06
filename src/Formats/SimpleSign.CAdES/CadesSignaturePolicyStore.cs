using System.Formats.Asn1;
using SimpleSign.Core.Constants;
using SimpleSign.Core.Crypto;

namespace SimpleSign.CAdES;

/// <summary>
/// The signature-policy-store unsigned attribute (ETSI EN 319 122-1 §5.2.10): the policy document
/// a signer carries, or the URI of a local store that holds it.
/// </summary>
public static class CadesSignaturePolicyStore
{
    /// <summary>Reads the signature-policy-store of a signer.</summary>
    /// <param name="signer">The signer, as <see cref="CmsParser"/> returns it.</param>
    /// <returns>The store, or <see langword="null"/> when the signer has none or it is malformed.</returns>
    public static SignaturePolicyStore? Read(CmsSignedData signer)
    {
        ArgumentNullException.ThrowIfNull(signer);
        if (signer.UnsignedAttributes is null
            || !signer.UnsignedAttributes.TryGetValue(Oids.SignaturePolicyStore, out byte[][]? values)
            || values.Length == 0)
        {
            return null;
        }

        try
        {
            var store = new AsnReader(values[0], AsnEncodingRules.BER).ReadSequence();
            string specification = store.PeekTag() == Asn1Tag.ObjectIdentifier
                ? store.ReadObjectIdentifier()
                : store.ReadCharacterString(UniversalTagNumber.IA5String);
            return store.PeekTag().HasSameClassAndValue(Asn1Tag.PrimitiveOctetString)
                ? SignaturePolicyStore.FromDocument(specification, store.ReadOctetString())
                : SignaturePolicyStore.FromLocalUri(specification, store.ReadCharacterString(UniversalTagNumber.IA5String));
        }
        catch (Exception ex) when (ex is AsnContentException or ArgumentException)
        {
            return null;
        }
    }

    /// <summary>
    /// <code>
    /// SignaturePolicyStore ::= SEQUENCE {
    ///   spDocSpec  SPDocSpecification,
    ///   spDocument SignaturePolicyDocument }
    /// SPDocSpecification ::= CHOICE { oid OBJECT IDENTIFIER, uri IA5String }
    /// SignaturePolicyDocument ::= CHOICE { sigPolicyEncoded OCTET STRING, sigPolicyLocalURI IA5String }
    /// </code>
    /// </summary>
    internal static CmsAttribute Encode(SignaturePolicyStore store)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSequence())
        {
            if (store.SpecificationIsOid)
            {
                writer.WriteObjectIdentifier(store.Specification);
            }
            else
            {
                writer.WriteCharacterString(UniversalTagNumber.IA5String, store.Specification);
            }

            if (store.LocalUri is not null)
            {
                writer.WriteCharacterString(UniversalTagNumber.IA5String, store.LocalUri);
            }
            else
            {
                writer.WriteOctetString(store.Document.Span);
            }
        }

        return CmsAttribute.Create(Oids.SignaturePolicyStore, writer.Encode());
    }
}
