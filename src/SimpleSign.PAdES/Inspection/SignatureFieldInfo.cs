using System.Diagnostics.CodeAnalysis;
using SimpleSign.Core.Inspection;
using SimpleSign.Pdf;

namespace SimpleSign.PAdES.Inspection;

/// <summary>
/// Complete information about a single signature field in a PDF document.
/// Contains signer identity, algorithms, timestamp data, and embedded certificates.
/// </summary>
[ExcludeFromCodeCoverage]
public sealed class SignatureFieldInfo
{
    /// <summary>PDF field name (e.g., "Signature1").</summary>
    public string FieldName { get; init; } = string.Empty;

    /// <summary>SubFilter value (e.g., "adbe.pkcs7.detached" or "ETSI.CAdES.detached").</summary>
    public string? SubFilter { get; init; }

    /// <summary>Signing reason from the PDF /Reason entry.</summary>
    public string? Reason { get; init; }

    /// <summary>Signing location from the PDF /Location entry.</summary>
    public string? Location { get; init; }

    /// <summary>Contact information from the PDF /ContactInfo entry.</summary>
    public string? ContactInfo { get; init; }

    /// <summary>Signer name declared in the PDF /Name entry.</summary>
    public string? DeclaredSignerName { get; init; }

    /// <summary>Byte range that covers the signed content.</summary>
    public PdfByteRange ByteRange { get; init; } = new();

    /// <summary>Signer certificate information, if identified.</summary>
    public CertificateInfo? Signer { get; init; }

    /// <summary>All certificates embedded in the CMS structure.</summary>
    public IReadOnlyList<CertificateInfo> EmbeddedCertificates { get; init; } = [];

    /// <summary>Digest algorithm used for the document hash (e.g., SHA-256).</summary>
    public AlgorithmInfo DigestAlgorithm { get; init; } = new();

    /// <summary>Signature algorithm used (e.g., RSA-SHA256, ECDSA-SHA256).</summary>
    public AlgorithmInfo SignatureAlgorithm { get; init; } = new();

    /// <summary>Signing time from the CMS signingTime attribute, if present.</summary>
    public DateTimeOffset? SigningTime { get; init; }

    /// <summary>Signing time declared in the PDF /M entry, if present.</summary>
    public DateTimeOffset? PdfDeclaredSigningTime { get; init; }

    /// <summary>RFC 3161 timestamp information, if the signature has a timestamp token.</summary>
    public TimestampInfo? Timestamp { get; init; }

    /// <summary>Whether the CMS contains a signingCertificateV2 attribute (required by PAdES-B-B).</summary>
    public bool HasSigningCertificateV2 { get; init; }

    /// <summary>
    /// OID of the commitment type from the CAdES commitment-type-indication attribute.
    /// Present when the signature includes an AEA (Advanced Electronic Signature) per Lei 14.063.
    /// </summary>
    public string? CommitmentTypeOid { get; init; }

    /// <summary>
    /// OID of the signature policy from the CAdES signature-policy-identifier attribute.
    /// Identifies the policy under which the signature was created.
    /// </summary>
    public string? SignaturePolicyOid { get; init; }

    /// <summary>
    /// Raw UTF-8 JSON bytes of the signature manifest.
    /// Contains tamper-proof signer evidence: name, CPF, email, IP, auth method, institution.
    /// Present when the signature includes a manifest attribute (OID 2.16.76.1.12.1.1).
    /// </summary>
    public byte[]? ManifestJson { get; init; }

    /// <summary>Raw CMS/PKCS#7 bytes from the signature /Contents.</summary>
    public ReadOnlyMemory<byte> CmsRawData { get; init; }

    /// <summary>True if the digest algorithm is deprecated per ISO 32000-2.</summary>
    public bool IsDigestAlgorithmDeprecated { get; init; }

    /// <summary>True if the signature algorithm is deprecated per ISO 32000-2.</summary>
    public bool IsSignatureAlgorithmDeprecated { get; init; }

    /// <summary>Whether this is a document timestamp (SubFilter = ETSI.RFC3161) rather than a regular signature.</summary>
    public bool IsDocumentTimestamp =>
        string.Equals(SubFilter, "ETSI.RFC3161", StringComparison.OrdinalIgnoreCase);

    /// <inheritdoc />
    public override string ToString() =>
        Signer is not null
            ? $"{FieldName}: signed by {Signer.Subject}"
            : $"{FieldName}: {SubFilter ?? "unknown"}";
}
