using System.Security.Cryptography.X509Certificates;
using SimpleSign.Core.Constants;
using SimpleSign.Core.Validation;

namespace SimpleSign.PAdES.Validation;

/// <summary>Complete result of a PDF signature validation.</summary>
public sealed class SignatureValidationResult
{
    /// <summary>Validated signature field.</summary>
    public string FieldName { get; init; } = string.Empty;

    /// <summary>The document integrity is intact (hash matches).</summary>
    public bool IsIntegrityValid { get; init; }

    /// <summary>The cryptographic signature is mathematically valid.</summary>
    public bool IsSignatureValid { get; init; }

    /// <summary>The certificate chain is valid and trusted.</summary>
    public bool IsCertificateChainValid { get; init; }

    /// <summary>The certificate was not revoked at the time of signing.</summary>
    public bool IsNotRevoked { get; init; }

    /// <summary>How the revocation status was determined.</summary>
    public RevocationSource RevocationSource { get; init; }

    /// <summary>The timestamp (if present) is valid.</summary>
    public bool? HasValidTimestamp { get; init; }

    /// <summary>Signing date/time (from SigningTime or from the timestamp).</summary>
    public DateTimeOffset? SigningTime { get; init; }

    /// <summary>Signer certificate.</summary>
    public X509Certificate2? SignerCertificate { get; init; }

    /// <summary>All certificates embedded in the CMS signature (signer + intermediaries).</summary>
    public IReadOnlyList<X509Certificate2> EmbeddedCertificates { get; init; } = [];

    /// <summary>Human-readable signer name (CN from the certificate).</summary>
    public string? SignerName { get; init; }

    /// <summary>SubFilter of the signature field (e.g., "adbe.pkcs7.detached", "ETSI.CAdES.detached").</summary>
    public string? SubFilter { get; init; }

    /// <summary>
    /// Whether this result represents a document timestamp (SubFilter = ETSI.RFC3161)
    /// rather than a regular user signature. Document timestamps are infrastructure —
    /// they provide long-term archival proof. Callers should render them differently.
    /// </summary>
    public bool IsDocumentTimestamp { get; init; }

    /// <summary>OID of the digest algorithm used in the signature (e.g., "2.16.840.1.101.3.4.2.1" = SHA-256).</summary>
    public string? DigestAlgorithmOid { get; init; }

    /// <summary>Friendly name of the digest algorithm (e.g., "SHA-256").</summary>
    public string? DigestAlgorithmName => DigestAlgorithmOid switch
    {
        Oids.Sha256 => "SHA-256",
        Oids.Sha512 => "SHA-512",
        Oids.Sha384 => "SHA-384",
        Oids.Sha1 => "SHA-1 (legacy)",
        _ => DigestAlgorithmOid
    };

    /// <summary>
    /// True when this is a document timestamp whose TSA chain could not be built to a trusted root,
    /// but whose cryptographic integrity and signature are valid.
    /// In this case the archive timestamp is still considered cryptographically sound — the chain
    /// issue is advisory (the TSA root is simply not present in the local trust store).
    /// </summary>
    public bool IsChainTrustWarning { get; init; }

    /// <summary>Indicates whether the signature is considered valid as a whole.</summary>
    public bool IsValid =>
        IsIntegrityValid && IsSignatureValid && (IsCertificateChainValid || IsChainTrustWarning);

    /// <summary>Errors found during validation.</summary>
    public IReadOnlyList<string> Errors { get; init; } = [];

    /// <summary>Non-blocking warnings.</summary>
    public IReadOnlyList<string> Warnings { get; init; } = [];

    /// <inheritdoc/>
    public override string ToString() =>
        $"[{FieldName}] Valid={IsValid} | Integrity={IsIntegrityValid} | Sig={IsSignatureValid} | Chain={IsCertificateChainValid} | Revocation={IsNotRevoked}";
}
