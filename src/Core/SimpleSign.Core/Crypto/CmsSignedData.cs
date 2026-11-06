using System.Security.Cryptography.X509Certificates;

namespace SimpleSign.Core.Crypto;

/// <summary>
/// Parsed CMS/PKCS#7 SignedData structure used for signature validation.
/// Contains the signer certificate, signed attributes, message digest, and optional timestamp token.
/// </summary>
public sealed class CmsSignedData
{
    /// <summary>OID of the digest algorithm used (e.g., SHA-256 = 2.16.840.1.101.3.4.2.1).</summary>
    public string DigestAlgorithmOid { get; init; } = string.Empty;

    /// <summary>OID of the signature algorithm (e.g., RSA-SHA256, RSA-PSS, ECDSA-SHA256).</summary>
    public string SignatureAlgorithmOid { get; init; } = string.Empty;

    /// <summary>All certificates embedded in the CMS structure.</summary>
    public IReadOnlyList<X509Certificate2> Certificates { get; init; } = [];

    /// <summary>The signer's certificate (matched by issuer/serial from SignerInfo).</summary>
    public X509Certificate2? SignerCertificate { get; init; }

    /// <summary>The messageDigest signed attribute value (hash of the document bytes).</summary>
    public byte[]? MessageDigest { get; init; }

    /// <summary>DER-encoded signedAttrs (with SET OF tag 0x31 for verification).</summary>
    public byte[]? SignedAttrs { get; init; }

    /// <summary>The cryptographic signature bytes from SignerInfo.</summary>
    public byte[]? Signature { get; init; }

    /// <summary>Signing time from the signingTime signed attribute, if present.</summary>
    public DateTimeOffset? SigningTime { get; init; }

    /// <summary>
    /// RFC 3161 timestamp token embedded as an unsigned attribute
    /// (id-aa-signatureTimeStampToken, OID 1.2.840.113549.1.9.16.2.14).
    /// Present in PAdES-B-T and higher conformance levels.
    /// </summary>
    public byte[]? SignatureTimestampToken { get; init; }

    /// <summary>
    /// Hash of the signer certificate extracted from the id-aa-signingCertificateV2 (RFC 5035)
    /// or id-aa-signingCertificate (RFC 2634 V1) signed attribute.
    /// Used to verify cryptographic binding between certificate and signature (anti-substitution).
    /// The hash algorithm is indicated by <see cref="SigningCertificateHashAlgorithmOid"/>.
    /// </summary>
    public byte[]? SigningCertificateHash { get; init; }

    /// <summary>
    /// OID of the hash algorithm used to compute <see cref="SigningCertificateHash"/>.
    /// For V1 (id-aa-signingCertificate): always SHA-1 (1.3.14.3.2.26).
    /// For V2 (id-aa-signingCertificateV2): the explicit AlgorithmIdentifier OID, or SHA-256 by default.
    /// Null when no signingCertificate attribute was found.
    /// </summary>
    public string? SigningCertificateHashAlgorithmOid { get; init; }

    /// <summary>
    /// OID of the commitment type from the id-aa-ets-commitmentType attribute (RFC 5126 §5.11.1).
    /// Common values: proofOfOrigin (1.2.840.113549.1.9.16.6.1), proofOfApproval (1.2.840.113549.1.9.16.6.5).
    /// </summary>
    public string? CommitmentTypeOid { get; init; }

    /// <summary>
    /// OID of the signature policy from the id-aa-ets-sigPolicyId attribute (RFC 5126 §5.8.1).
    /// Identifies the signature policy under which the signature was created.
    /// </summary>
    public string? SignaturePolicyOid { get; init; }

    /// <summary>
    /// Raw UTF-8 JSON bytes of the signature manifest from the SimpleSign manifest attribute (OID <see cref="SimpleSign.Core.Constants.Oids.SignatureManifest"/>).
    /// Contains signer evidence: name, masked CPF, email, IP, auth method, institution.
    /// </summary>
    public byte[]? ManifestJson { get; init; }

    /// <summary>
    /// OID of the eContentType from the encapContentInfo in the CMS SignedData.
    /// For regular signatures this is id-data (1.2.840.113549.1.7.1).
    /// For document timestamps (ETSI.RFC3161) this is id-ct-TSTInfo (1.2.840.113549.1.9.16.1.4).
    /// </summary>
    public string? EContentTypeOid { get; init; }

    /// <summary>
    /// Hash algorithm OID from TSTInfo.messageImprint, populated when
    /// <see cref="EContentTypeOid"/> == id-ct-TSTInfo.
    /// This is the algorithm used to hash the document byte range (the real document hash).
    /// </summary>
    public string? TstMessageImprintHashAlgOid { get; init; }

    /// <summary>
    /// Hashed bytes from TSTInfo.messageImprint.hashedMessage, populated when
    /// <see cref="EContentTypeOid"/> == id-ct-TSTInfo.
    /// This is the actual hash of the document byte range, NOT the CMS messageDigest.
    /// </summary>
    public byte[]? TstMessageImprintHash { get; init; }

    /// <summary>
    /// OID from the id-contentType signed attribute (OID 1.2.840.113549.1.9.3).
    /// Per RFC 5652 §5.3, this MUST be present in signedAttrs and MUST equal id-data (1.2.840.113549.1.7.1).
    /// For document timestamps (ETSI.RFC3161) this is id-ct-TSTInfo (1.2.840.113549.1.9.16.1.4).
    /// </summary>
    public string? ContentTypeOid { get; init; }

    /// <summary>
    /// All unsigned attributes parsed from SignerInfo, keyed by OID.
    /// Each OID maps to an array of DER-encoded attribute values.
    /// Null when no unsigned attributes are present.
    /// </summary>
    public IReadOnlyDictionary<string, byte[][]>? UnsignedAttributes { get; init; }

    /// <summary>
    /// Archive timestamp token (id-aa-ets-archiveTimeStampV3, OID 1.2.840.113549.1.9.16.2.48)
    /// for CAdES-B-LTA. Null when not present.
    /// </summary>
    public byte[]? ArchiveTimestampToken { get; init; }

    /// <summary>
    /// The encapsulated content (eContent) of an attached signature (.p7m), or <see langword="null"/>
    /// when the signature is detached. Document timestamps keep their TSTInfo in <see cref="TstMessageImprintHash"/>.
    /// </summary>
    public byte[]? EncapsulatedContent { get; init; }

    /// <summary>Countersignatures of this signer (id-countersignature, RFC 5652 §11.4), each over this signer's <see cref="Signature"/>.</summary>
    public IReadOnlyList<CmsSignedData> CounterSignatures { get; init; } = [];
}
