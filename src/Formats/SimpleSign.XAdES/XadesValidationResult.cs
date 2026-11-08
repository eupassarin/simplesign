using SimpleSign.Core.Validation.Policy;
using SimpleSign.Core.Validation;
using System.Security.Cryptography.X509Certificates;
using SimpleSign.Core.Crypto;
using SimpleSign.Core.Signing;

namespace SimpleSign.XAdES;

/// <summary>Result of a XAdES signature validation.</summary>
public sealed record XadesValidationResult
{
    /// <summary>The optional XMLDSig <c>Id</c> of the validated signature.</summary>
    public string? SignatureId { get; init; }

    /// <summary>The XMLDSig signature is mathematically valid.</summary>
    public bool IsSignatureValid { get; init; }

    /// <summary>The document integrity is intact (content hash matches).</summary>
    public bool IsIntegrityValid { get; init; }

    /// <summary>The certificate chain is valid and trusted.</summary>
    public bool IsCertificateChainValid { get; init; }

    /// <summary>The SignatureTimeStamp's cryptographic integrity and message imprint are valid, independent of TSA trust.</summary>
    public bool? HasValidSignatureTimeStamp { get; init; }

    /// <summary>
    /// The AllDataObjectsTimeStamp signed property (ETSI EN 319 132-1 §5.2.8.1) is an intact token
    /// whose message imprint covers the signed data objects; null when there is none. TSA trust is
    /// not evaluated.
    /// </summary>
    public bool? HasValidDataObjectsTimeStamp { get; init; }

    /// <summary>The time of the data objects timestamp, when it is valid: the signed data existed at this time.</summary>
    public DateTimeOffset? DataObjectsTimeStampTime { get; init; }

    /// <summary>Whether the TSA chain is trusted; null when the token is absent, invalid, or no trust policy was evaluated.</summary>
    public bool? IsTsaTrusted { get; init; }

    /// <summary>The embedded CertificateValues and RevocationValues provide applicable, authenticated revocation evidence; this does not establish certificate-chain trust.</summary>
    public bool? IsLtvDataValid { get; init; }

    /// <summary>The ArchiveTimeStamp token's cryptographic integrity and archive coverage are valid, independent of TSA trust.</summary>
    public bool? HasValidArchiveTimeStamp { get; init; }

    /// <summary>
    /// The SigAndRefsTimeStamp (XAdES-X) token is intact and covers the signature value, the
    /// signature timestamp and the complete references; null when there is none.
    /// </summary>
    public bool? HasValidSigAndRefsTimeStamp { get; init; }

    /// <summary>
    /// CompleteCertificateRefs and CompleteRevocationRefs (XAdES-C) are present and every digest
    /// matches a certificate or revocation value in the signature; null when there are none.
    /// </summary>
    public bool? HasValidCompleteReferences { get; init; }

    /// <summary>The signer certificate.</summary>
    public X509Certificate2? SignerCertificate { get; init; }

    /// <summary>Signing time from SignedProperties.</summary>
    public DateTimeOffset? SigningTime { get; init; }

    /// <summary>
    /// The signature policy the signature declares (SignaturePolicyIdentifier), with the OID
    /// (an OID URN is reduced to the OID), the SigPolicyHash and the SPURI; null when there is none.
    /// The hash is read, not checked: compare it with the policy (e.g. SimpleSign.Brazil).
    /// </summary>
    public SignaturePolicyReference? SignaturePolicy { get; init; }

    /// <summary>
    /// The policy document the signature carries, or the URI of the local store that holds it
    /// (SignaturePolicyStore unsigned property); null when there is none. The store is not signed:
    /// check it against <see cref="SignaturePolicy"/> with
    /// <see cref="SimpleSign.Core.Crypto.SignaturePolicyStore.MatchesHash(SignaturePolicyReference)"/>.
    /// </summary>
    public SignaturePolicyStore? SignaturePolicyStore { get; init; }

    /// <summary>The baseline level inferred from observed unsigned-property elements, even when those properties fail validation.</summary>
    /// <remarks>
    /// Structural detection is not a validated or achieved level. Consult
    /// <see cref="HasValidSignatureTimeStamp"/>, <see cref="IsLtvDataValid"/>, and
    /// <see cref="HasValidArchiveTimeStamp"/> together with base-signature and integrity checks.
    /// Certificate-chain and TSA trust are separate validation outcomes.
    /// </remarks>
    public AdesBaselineLevel DetectedLevel { get; init; }

    /// <summary>The roles the signer claims (ClaimedRoles of SignerRoleV2, or of the SignerRole it obsoletes); empty when there are none.</summary>
    public IReadOnlyList<string> ClaimedRoles { get; init; } = [];

    /// <summary>
    /// The X.509 attribute certificates in SignerRoleV2 (CertifiedRolesV2), DER-encoded; empty when
    /// there are none. They are read, not verified.
    /// </summary>
    public IReadOnlyList<ReadOnlyMemory<byte>> AttributeCertificates { get; init; } = [];

    /// <summary>
    /// The assertions third parties signed about the signer (SignedAssertions of SignerRoleV2), each
    /// as the XML of its content; empty when there are none. They are read, not verified.
    /// </summary>
    public IReadOnlyList<string> SignedAssertions { get; init; } = [];

    /// <summary>
    /// The countersignatures of this signature (CounterSignature unsigned properties,
    /// ETSI EN 319 132-1 §5.2.7.2), each validated as a signature over this one's ds:SignatureValue,
    /// with its own countersignatures under it. They are not part of <see cref="IsValid"/>:
    /// check each one.
    /// </summary>
    public IReadOnlyList<XadesValidationResult> CounterSignatures { get; init; } = [];

    /// <summary>Errors found during validation.</summary>
    public IReadOnlyList<string> Errors { get; init; } = [];

    /// <summary>Non-blocking warnings.</summary>
    public IReadOnlyList<string> Warnings { get; init; } = [];

    /// <summary>The signature as a report entry, for <see cref="ValidationReports"/>.</summary>
    /// <returns>The entry.</returns>
    public SignatureReportEntry ToReportEntry() => new()
    {
        Id = SignatureId ?? "signature-1",
        Format = "XAdES",
        Indication = Indication,
        SubIndication = SubIndication,
        Constraints = Constraints,
        SignerCertificate = SignerCertificate,
        ClaimedSigningTime = SigningTime,
        BestSignatureTime = BestSignatureTime,
        Policy = AppliedPolicy,
        Errors = Errors,
        Warnings = Warnings,
    };

    /// <summary>True when all fundamental checks pass, the validation policy's constraints included.</summary>
    public bool IsValid =>
        IsIntegrityValid && IsSignatureValid && IsCertificateChainValid && Indication == SignatureIndication.Valid;

    private SignatureIndication? _indication;

    /// <summary>
    /// The ETSI EN 319 102-1 indication, including the validation policy's constraints. Without an
    /// evaluation (a document that could not be read) it follows the integrity, signature and chain checks.
    /// </summary>
    public SignatureIndication Indication
    {
        get => _indication ?? (IsIntegrityValid && IsSignatureValid
            ? (IsCertificateChainValid ? SignatureIndication.Valid : SignatureIndication.Indeterminate)
            : SignatureIndication.Invalid);
        init => _indication = value;
    }

    /// <summary>The ETSI EN 319 102-1 sub-indication of an INVALID or INDETERMINATE result, or null.</summary>
    public SignatureSubIndication? SubIndication { get; init; }

    /// <summary>The checks of the validation and their outcome, including the validation policy's constraints.</summary>
    public IReadOnlyList<ValidationConstraintResult> Constraints { get; init; } = [];

    /// <summary>The validation policy applied (its name and digest), chosen by the signature policy the signature names.</summary>
    public SimpleSign.Core.Policies.AppliedPolicy? AppliedPolicy { get; init; }

    /// <summary>The earliest time the signature is proven to exist (a trusted signature timestamp), or null.</summary>
    public DateTimeOffset? BestSignatureTime { get; init; }

    /// <summary>
    /// Whether the signing certificate chain is not revoked: null when revocation was not checked by
    /// <c>ValidateAsync</c>; false when a certificate is revoked or the status is unknown (see <see cref="RevocationSource"/>).
    /// </summary>
    public bool? IsNotRevoked { get; init; }

    /// <summary>How revocation was established (<see cref="RevocationSource.CertificateChain"/>) or why it was not.</summary>
    public RevocationSource RevocationSource { get; init; }

    /// <summary>What the validation found, for the revocation step of <c>ValidateAsync</c>.</summary>
    internal ValidationFacts? Facts { get; init; }

    /// <summary>The certificates that may complete the signer and TSA chains (embedded certificates, trust anchors).</summary>
    internal IReadOnlyList<X509Certificate2> ChainCandidates { get; init; } = [];

    /// <summary>The CRLs the signature carries (RevocationValues), for the revocation step.</summary>
    internal IReadOnlyList<byte[]> EmbeddedCrls { get; init; } = [];

    /// <summary>The OCSP responses the signature carries (RevocationValues), for the revocation step.</summary>
    internal IReadOnlyList<byte[]> EmbeddedOcsps { get; init; } = [];

    /// <summary>The signature timestamp token, for the TSA revocation check.</summary>
    internal byte[]? SignatureTimestampToken { get; init; }
}
