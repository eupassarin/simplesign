using System.Formats.Asn1;
using SimpleSign.Core.Constants;
using SimpleSign.Core.Signing;

namespace SimpleSign.Core.Crypto;

/// <summary>
/// Represents a pre-encoded CMS signed attribute (OID + DER value).
/// Used to inject custom CAdES attributes into the CMS SignedData.
/// </summary>
public sealed class CmsAttribute
{
    /// <summary>The OID of the attribute.</summary>
    public string Oid { get; }

    /// <summary>The DER-encoded value (the content of SET OF { value }).</summary>
    public byte[] DerValue { get; }

    private CmsAttribute(string oid, byte[] derValue)
    {
        Oid = oid;
        DerValue = derValue;
    }

    /// <summary>
    /// Creates a commitment-type-indication attribute (RFC 5126 §5.11.1).
    /// <code>
    /// CommitmentTypeIndication ::= SEQUENCE {
    ///   commitmentTypeId  CommitmentTypeIdentifier }
    /// CommitmentTypeIdentifier ::= OID
    /// </code>
    /// </summary>
    public static CmsAttribute CommitmentTypeIndication(CommitmentType type)
    {
        string typeOid = type switch
        {
            CommitmentType.ProofOfOrigin => Oids.ProofOfOrigin,
            CommitmentType.ProofOfApproval => Oids.ProofOfApproval,
            _ => throw new ArgumentOutOfRangeException(nameof(type))
        };

        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSequence()) // CommitmentTypeIndication
        {
            writer.WriteObjectIdentifier(typeOid);
        }

        return new CmsAttribute(Oids.CommitmentTypeIndication, writer.Encode());
    }

    /// <summary>
    /// Creates a signature-policy-identifier attribute (RFC 5126 §5.8.1).
    /// <code>
    /// SignaturePolicyIdentifier ::= SEQUENCE {
    ///   signaturePolicyId    SignaturePolicyId,
    ///   sigPolicyHash        SigPolicyHash OPTIONAL }
    /// SignaturePolicyId ::= OID
    /// SigPolicyHash ::= OtherHashAlgAndValue (SEQUENCE { algorithm, hash })
    /// </code>
    /// </summary>
    /// <param name="policyOid">OID of the signature policy.</param>
    /// <param name="policyUri">Optional URI of the policy document (encoded as SigPolicyQualifier).</param>
    public static CmsAttribute SignaturePolicyIdentifier(string policyOid, string? policyUri = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(policyOid);

        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSequence()) // SignaturePolicyIdentifier
        {
            // signaturePolicyId
            writer.WriteObjectIdentifier(policyOid);

            // sigPolicyHash — empty hash (policy hash is optional for org-defined policies)
            using (writer.PushSequence()) // OtherHashAlgAndValue
            {
                using (writer.PushSequence()) // AlgorithmIdentifier
                {
                    writer.WriteObjectIdentifier(Oids.Sha256);
                    writer.WriteNull();
                }
                writer.WriteOctetString([]); // empty hash — not computed for org policies
            }

            // sigPolicyQualifiers OPTIONAL
            if (!string.IsNullOrEmpty(policyUri))
            {
                using (writer.PushSequence()) // SEQUENCE OF SigPolicyQualifierInfo
                {
                    using (writer.PushSequence()) // SigPolicyQualifierInfo
                    {
                        // id-spq-ets-uri (1.2.840.113549.1.9.16.5.1)
                        writer.WriteObjectIdentifier("1.2.840.113549.1.9.16.5.1");
                        writer.WriteCharacterString(UniversalTagNumber.IA5String, policyUri);
                    }
                }
            }
        }

        return new CmsAttribute(Oids.SignaturePolicyIdentifier, writer.Encode());
    }

    /// <summary>
    /// Creates a CmsAttribute from raw OID and DER-encoded value.
    /// </summary>
    public static CmsAttribute Raw(string oid, byte[] derValue)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(oid);
        ArgumentNullException.ThrowIfNull(derValue);
        return new CmsAttribute(oid, derValue);
    }

    /// <summary>
    /// Creates a signature manifest attribute containing JSON-encoded evidence.
    /// The data is embedded as an OCTET STRING (UTF-8 JSON) under OID 2.16.76.1.12.1.1.
    /// </summary>
    /// <param name="manifestJsonUtf8">UTF-8 encoded JSON bytes of the manifest.</param>
    public static CmsAttribute SignatureManifestAttr(byte[] manifestJsonUtf8)
    {
        ArgumentNullException.ThrowIfNull(manifestJsonUtf8);

        var writer = new AsnWriter(AsnEncodingRules.DER);
        writer.WriteOctetString(manifestJsonUtf8);

        return new CmsAttribute(Oids.SignatureManifest, writer.Encode());
    }
}
