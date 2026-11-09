using System.Security.Cryptography.X509Certificates;
using SimpleSign.Core.Constants;
using SimpleSign.Core.Extensions;

namespace SimpleSign.Core.Validation;

/// <summary>Complete result of a PDF signature validation.</summary>
public sealed class SignatureValidationResult
{
    private SignatureIndication? _indication;

    /// <summary>Validated signature field.</summary>
    public string FieldName { get; init; } = string.Empty;

    /// <summary>The document integrity is intact (hash matches).</summary>
    public bool IsIntegrityValid { get; init; }

    /// <summary>The cryptographic signature is mathematically valid.</summary>
    public bool IsSignatureValid { get; init; }

    /// <summary>Whether signature verification could not be completed due to missing material or an unsupported operation.</summary>
    internal bool IsSignatureVerificationIndeterminate { get; init; }

    /// <summary>The certificate chain is valid and trusted.</summary>
    public bool IsCertificateChainValid { get; init; }

    /// <summary>No revocation was established. Consult <see cref="RevocationSource"/> to distinguish confirmed good, unchecked, and indeterminate status.</summary>
    public bool IsNotRevoked { get; init; }

    /// <summary>How the revocation status was determined.</summary>
    public RevocationSource RevocationSource { get; init; }

    /// <summary>The signature timestamp's cryptographic integrity and message imprint are valid, independent of TSA trust.</summary>
    public bool? HasValidTimestamp { get; init; }

    /// <summary>Whether the TSA chain is trusted; null when the token is absent, invalid, or no trust policy was evaluated.</summary>
    public bool? IsTsaTrusted { get; init; }

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
        Oids.Sha3_256 => "SHA3-256",
        Oids.Sha3_384 => "SHA3-384",
        Oids.Sha3_512 => "SHA3-512",
        Oids.Sha1 => "SHA-1 (legacy)",
        _ => DigestAlgorithmOid
    };

    /// <summary>
    /// True when this is a document timestamp whose TSA chain could not be built to a trusted root,
    /// but whose cryptographic integrity and signature are valid.
    /// In this case the archive timestamp is still considered cryptographically sound — the chain
    /// issue is advisory (the TSA root is simply not present in the local trust store).
    /// Also used for regular signatures when a country-specific <see cref="IChainValidationProvider"/>
    /// overrides the standard PKI chain result.
    /// </summary>
    public bool IsChainTrustWarning { get; init; }

    /// <summary>
    /// The region code of the <see cref="IChainValidationProvider"/> that validated this signature.
    /// For example, "BR" for ICP-Brasil, "EU" for eIDAS.
    /// Null if no country-specific provider matched.
    /// </summary>
    public string? ChainValidationRegion { get; init; }

    /// <summary>
    /// The policy / assurance level determined by the country-specific chain validation provider.
    /// For example, "A3" (ICP-Brasil), "Gold" (Gov.br), "QCP-w" (eIDAS).
    /// Null if no country-specific provider matched.
    /// </summary>
    public string? PolicyLevel { get; init; }

    /// <summary>
    /// The signer's national identifier extracted from the certificate by the country-specific provider.
    /// For example, a CPF or CNPJ number (Brazil), codice fiscale (Italy), NIF (Portugal).
    /// Null if no provider extracted an ID or no country-specific provider matched.
    /// </summary>
    public string? SignerId { get; init; }

    /// <summary>
    /// The type of national identifier extracted (<see cref="SignerId"/>).
    /// For example, "CPF", "CNPJ", "NIF", "CF".
    /// Null if no identifier was extracted.
    /// </summary>
    public string? SignerIdType { get; init; }

    /// <summary>
    /// Additional metadata extracted during country-specific chain validation.
    /// Keys and values are provider-defined. Null if no provider matched.
    /// </summary>
    public IReadOnlyDictionary<string, string>? ChainValidationMetadata { get; init; }

    /// <summary>
    /// High-level validation outcome. A failed chain or indeterminate revocation is
    /// INDETERMINATE when integrity and the cryptographic signature pass; conclusive
    /// integrity, signature, or revocation failures are INVALID.
    /// </summary>
    public SignatureIndication Indication
    {
        get => _indication ?? DetermineIndication();
        internal init => _indication = value;
    }

    /// <summary>The ETSI EN 319 102-1 sub-indication of an INVALID or INDETERMINATE result, or null.</summary>
    public SignatureSubIndication? SubIndication { get; init; }

    /// <summary>The checks of the validation and their outcome, including the validation policy's constraints.</summary>
    public IReadOnlyList<ValidationConstraintResult> Constraints { get; init; } = [];

    /// <summary>The validation policy applied (its name and digest), chosen by the signature policy the signature names.</summary>
    public SimpleSign.Core.Policies.AppliedPolicy? AppliedPolicy { get; init; }

    /// <summary>The earliest time the signature is proven to exist (a trusted signature timestamp), or null.</summary>
    public DateTimeOffset? BestSignatureTime { get; init; }

    /// <summary>The timestamps and revocation data the validation used, each with the outcome of its own evaluation.</summary>
    public IReadOnlyList<ValidationObjectEntry> ValidationObjects { get; init; } = [];

    /// <summary>Errors found during validation.</summary>
    public IReadOnlyList<string> Errors { get; init; } = [];

    /// <summary>Diagnostic warnings. Consult the validation outcomes and <see cref="RevocationSource"/> when determining validity.</summary>
    public IReadOnlyList<string> Warnings { get; init; } = [];

    /// <summary>The signature as a report entry, for <see cref="ValidationReports"/>.</summary>
    /// <returns>The entry.</returns>
    public SignatureReportEntry ToReportEntry() => new()
    {
        Id = FieldName,
        Format = IsDocumentTimestamp ? "Document timestamp" : "PAdES",
        Indication = Indication,
        SubIndication = SubIndication,
        Constraints = Constraints,
        SignerCertificate = SignerCertificate,
        ClaimedSigningTime = IsDocumentTimestamp ? null : SigningTime,
        BestSignatureTime = IsDocumentTimestamp ? SigningTime : BestSignatureTime,
        Policy = AppliedPolicy,
        Errors = Errors,
        Warnings = Warnings,
        ValidationObjects = ValidationObjects,
    };

    private SignatureIndication DetermineIndication()
    {
        if (!IsIntegrityValid)
        {
            return SignatureIndication.Invalid;
        }

        if (IsSignatureVerificationIndeterminate)
        {
            return SignatureIndication.Indeterminate;
        }

        if (!IsSignatureValid)
        {
            return SignatureIndication.Invalid;
        }

        if (!IsNotRevoked && RevocationSource is not (RevocationSource.None or RevocationSource.Indeterminate))
        {
            return SignatureIndication.Invalid;
        }

        if (RevocationSource == RevocationSource.Indeterminate)
        {
            return SignatureIndication.Indeterminate;
        }

        if (!IsNotRevoked && RevocationSource == RevocationSource.None)
        {
            return SignatureIndication.Indeterminate;
        }

        if (IsDocumentTimestamp && IsChainTrustWarning && IsTsaTrusted != true)
        {
            return SignatureIndication.Indeterminate;
        }

        if (IsCertificateChainValid || IsChainTrustWarning)
        {
            return SignatureIndication.Valid;
        }

        return SignatureIndication.Indeterminate;
    }

    /// <inheritdoc/>
    public override string ToString() =>
        $"[{FieldName}] Indication={Indication} | Integrity={IsIntegrityValid} | Sig={IsSignatureValid} | Chain={IsCertificateChainValid} | Revocation={IsNotRevoked}";
}
