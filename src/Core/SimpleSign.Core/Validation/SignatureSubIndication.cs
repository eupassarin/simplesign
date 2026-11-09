namespace SimpleSign.Core.Validation;

/// <summary>
/// Why a signature is <see cref="SignatureIndication.Invalid"/> or <see cref="SignatureIndication.Indeterminate"/>,
/// with the names of ETSI EN 319 102-1 §5.1.3 (the subset this library can establish).
/// </summary>
public enum SignatureSubIndication
{
    /// <summary>FORMAT_FAILURE: the signature is not conformant to its format.</summary>
    FormatFailure,

    /// <summary>HASH_FAILURE: the signed data does not match the digest in the signature.</summary>
    HashFailure,

    /// <summary>SIG_CRYPTO_FAILURE: the signature value does not verify with the signing certificate's public key.</summary>
    SigCryptoFailure,

    /// <summary>
    /// REVOKED: the signing certificate is revoked. Without a proof that the signature existed before the
    /// revocation, a revoked certificate gives <see cref="RevokedNoPoe"/> (EN 319 102-1 §5.2.6) instead.
    /// </summary>
    Revoked,

    /// <summary>NOT_YET_VALID: the signing certificate was not yet valid at the signing time.</summary>
    NotYetValid,

    /// <summary>SIG_CONSTRAINTS_FAILURE: a constraint of the validation policy on the signature or its signing certificate failed.</summary>
    SigConstraintsFailure,

    /// <summary>CHAIN_CONSTRAINTS_FAILURE: a constraint of the validation policy on the certificate chain failed.</summary>
    ChainConstraintsFailure,

    /// <summary>CRYPTO_CONSTRAINTS_FAILURE: the signature uses an algorithm or key the policy does not accept.</summary>
    CryptoConstraintsFailure,

    /// <summary>CRYPTO_CONSTRAINTS_FAILURE_NO_POE: an algorithm is no longer accepted and nothing proves the signature existed before.</summary>
    CryptoConstraintsFailureNoPoe,

    /// <summary>NO_SIGNING_CERTIFICATE_FOUND: the signing certificate cannot be identified.</summary>
    NoSigningCertificateFound,

    /// <summary>NO_CERTIFICATE_CHAIN_FOUND: no chain to a trust anchor could be built.</summary>
    NoCertificateChainFound,

    /// <summary>OUT_OF_BOUNDS_NO_POE: the signing certificate expired and nothing proves the signature existed before.</summary>
    OutOfBoundsNoPoe,

    /// <summary>REVOKED_NO_POE: a certificate is revoked and nothing proves the signature existed before the revocation.</summary>
    RevokedNoPoe,

    /// <summary>TRY_LATER: the revocation data is not fresh enough (or the certificate is on hold); newer data may settle it later.</summary>
    TryLater,

    /// <summary>TIMESTAMP_ORDER_FAILURE: the timestamps are not in the order the format requires.</summary>
    TimestampOrderFailure,

    /// <summary>SIGNED_DATA_NOT_FOUND: the signed data cannot be obtained.</summary>
    SignedDataNotFound,

    /// <summary>SIGNATURE_POLICY_NOT_AVAILABLE: the signature policy document cannot be obtained.</summary>
    SignaturePolicyNotAvailable,

    /// <summary>
    /// CERTIFICATE_CHAIN_GENERAL_FAILURE: the chain could not be validated for a reason no other sub-indication
    /// names, such as no acceptable revocation data for a certificate of the chain.
    /// </summary>
    CertificateChainGeneralFailure,

    /// <summary>REVOKED_CA_NO_POE: a CA certificate of the chain is revoked and nothing proves the signature existed before the revocation.</summary>
    RevokedCaNoPoe,
}
