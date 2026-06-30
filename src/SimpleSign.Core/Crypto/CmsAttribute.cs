using System.Formats.Asn1;
using System.Security.Cryptography;
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
            CommitmentType.ProofOfReceipt => Oids.ProofOfReceipt,
            CommitmentType.ProofOfDelivery => Oids.ProofOfDelivery,
            CommitmentType.ProofOfSender => Oids.ProofOfSender,
            CommitmentType.ProofOfApproval => Oids.ProofOfApproval,
            CommitmentType.ProofOfCreation => Oids.ProofOfCreation,
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

    /// <summary>
    /// Creates a certificate-refs attribute (CAdES-X/L, RFC 5126 §5.4.2).
    /// <code>
    /// CompleteCertificateRefs ::= SEQUENCE OF OtherCertID
    /// OtherCertID ::= OtherHash { issuerSerial OPTIONAL }
    /// </code>
    /// </summary>
    /// <param name="certHashes">Array of (certHash, hashAlgorithmOid, issuerSerialBytes) tuples.
    /// The <c>issuerSerial</c> must be DER-encoded <c>IssuerSerial</c> bytes when provided.</param>
    public static CmsAttribute CertificateRefs(params (byte[] Hash, string HashOid, byte[]? IssuerSerial)[] certHashes)
    {
        ArgumentNullException.ThrowIfNull(certHashes);
        if (certHashes.Length == 0)
        {
            throw new ArgumentException("At least one certificate reference must be provided.", nameof(certHashes));
        }

        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSequence()) // CompleteCertificateRefs
        {
            foreach (var (hash, hashOid, issuerSerial) in certHashes)
            {
                using (writer.PushSequence()) // OtherCertID
                {
                    using (writer.PushSequence()) // OtherHashAlgAndValue
                    {
                        using (writer.PushSequence()) // AlgorithmIdentifier
                        {
                            writer.WriteObjectIdentifier(hashOid);
                            writer.WriteNull();
                        }
                        writer.WriteOctetString(hash);
                    }
                    if (issuerSerial is not null)
                    {
                        writer.WriteEncodedValue(issuerSerial);
                    }
                }
            }
        }
        return new CmsAttribute(Oids.CertificateRefs, writer.Encode());
    }

    /// <summary>
    /// Creates a revocation-refs attribute (CAdES-X/L, RFC 5126 §5.4.3).
    /// Each CRL is SHA-256 hashed and wrapped in a <c>CrlValidatedID</c> inside a
    /// single <c>CRLListID</c>.
    /// <code>
    /// CompleteRevocationRefs ::= SEQUENCE OF CrlOcspRef
    /// CrlOcspRef ::= CHOICE { crl [0] CRLListID }
    /// CRLListID ::= SEQUENCE OF CrlValidatedID
    /// CrlValidatedID ::= SEQUENCE { crlHash  OtherHash }
    /// OtherHash ::= SEQUENCE { hashAlgorithm  AlgorithmIdentifier,
    ///                          hashValue      OCTET STRING }
    /// </code>
    /// </summary>
    /// <param name="crlDerBytes">Array of DER-encoded CRL bytes.</param>
    public static CmsAttribute RevocationRefs(params byte[][] crlDerBytes)
    {
        ArgumentNullException.ThrowIfNull(crlDerBytes);
        if (crlDerBytes.Length == 0)
        {
            throw new ArgumentException("At least one CRL must be provided.", nameof(crlDerBytes));
        }

        var writer = new AsnWriter(AsnEncodingRules.DER);

        // CompleteRevocationRefs ::= SEQUENCE OF CrlOcspRef
        using (writer.PushSequence())
        {
            // CrlOcspRef CHOICE → crl [0] EXPLICIT CRLListID
            using (writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0, true)))
            {
                // CRLListID ::= SEQUENCE OF CrlValidatedID
                using (writer.PushSequence())
                {
                    foreach (var crl in crlDerBytes)
                    {
                        byte[] crlHash = SHA256.HashData(crl);

                        // CrlValidatedID ::= SEQUENCE { crlHash OtherHash }
                        using (writer.PushSequence())
                        {
                            // OtherHash ::= SEQUENCE { hashAlgorithm, hashValue }
                            using (writer.PushSequence())
                            {
                                using (writer.PushSequence()) // AlgorithmIdentifier
                                {
                                    writer.WriteObjectIdentifier(Oids.Sha256);
                                }
                                writer.WriteOctetString(crlHash);
                            }
                        }
                    }
                }
            }
        }

        return new CmsAttribute(Oids.RevocationRefs, writer.Encode());
    }

    /// <summary>
    /// Creates a cert-values attribute (CAdES-XL, RFC 5126 §5.5.1).
    /// Embeds the full DER-encoded signer and CA certificates.
    /// </summary>
    /// <param name="certDerBytes">DER-encoded certificates. Must contain at least one certificate.</param>
    public static CmsAttribute CertValues(params byte[][] certDerBytes)
    {
        ArgumentNullException.ThrowIfNull(certDerBytes);
        if (certDerBytes.Length == 0)
        {
            throw new ArgumentException("At least one certificate must be provided.", nameof(certDerBytes));
        }
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSequence()) // CertificateValues
        {
            foreach (var certDer in certDerBytes)
            {
                writer.WriteEncodedValue(certDer);
            }
        }
        return new CmsAttribute(Oids.CertValues, writer.Encode());
    }

    /// <summary>
    /// Creates a revocation-values attribute (CAdES-XL, RFC 5126 §5.5.2).
    /// Embeds CRLs and/or OCSP responses.
    /// </summary>
    /// <param name="ocspDerResponses">DER-encoded OCSP responses.</param>
    /// <param name="crlDerBytes">DER-encoded CRLs.</param>
    /// <exception cref="ArgumentException">
    /// Both parameters are null or empty — at least one revocation source is required.
    /// </exception>
    public static CmsAttribute RevocationValues(
        byte[][]? ocspDerResponses = null,
        byte[][]? crlDerBytes = null)
    {
        if ((ocspDerResponses is null || ocspDerResponses.Length == 0)
            && (crlDerBytes is null || crlDerBytes.Length == 0))
        {
            throw new ArgumentException(
                "At least one revocation source (CRL or OCSP) must be provided.");
        }
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSequence()) // RevocationValues
        {
            // revocationValues CHOICE { crlVals, ocspVals, ... }
            if (crlDerBytes is { Length: > 0 })
            {
                using (writer.PushSequence(new System.Formats.Asn1.Asn1Tag(
                    System.Formats.Asn1.TagClass.ContextSpecific, 0, true))) // crlVals [0]
                {
                    foreach (var crl in crlDerBytes)
                    {
                        writer.WriteEncodedValue(crl);
                    }
                }
            }
            if (ocspDerResponses is { Length: > 0 })
            {
                using (writer.PushSequence(new System.Formats.Asn1.Asn1Tag(
                    System.Formats.Asn1.TagClass.ContextSpecific, 1, true))) // ocspVals [1]
                {
                    foreach (var ocsp in ocspDerResponses)
                    {
                        writer.WriteEncodedValue(ocsp);
                    }
                }
            }
        }
        return new CmsAttribute(Oids.RevocationValues, writer.Encode());
    }

    /// <summary>
    /// Creates a custom attribute from an OID and a DER-encoded attribute value.
    /// The <paramref name="derValue"/> will be wrapped in SET OF by the CMS rendering code.
    /// </summary>
    /// <param name="oid">The attribute OID.</param>
    /// <param name="derValue">The DER-encoded attribute value (content of SET OF).</param>
    public static CmsAttribute Create(string oid, byte[] derValue)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(oid);
        ArgumentNullException.ThrowIfNull(derValue);
        return new CmsAttribute(oid, derValue);
    }
}
