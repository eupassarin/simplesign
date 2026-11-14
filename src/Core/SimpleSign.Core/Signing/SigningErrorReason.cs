namespace SimpleSign.Core.Signing;

/// <summary>
/// Stable machine-readable reason codes for <see cref="SigningException"/>.
/// </summary>
public enum SigningErrorReason
{
    /// <summary>No signing credential was configured.</summary>
    CredentialMissing = 0,

    /// <summary>The signing certificate is missing a usable private key.</summary>
    PrivateKeyMissing = 1,

    /// <summary>The signing certificate is not within its validity period.</summary>
    CertificateExpired = 2,

    /// <summary>The signing certificate is not valid at the configured signing time.</summary>
    CertificateNotCurrentlyValid = 12,

    /// <summary>The configured external signer failed to produce a signature.</summary>
    ExternalSignerFailure = 13,

    /// <summary>The signature/hash algorithm combination is unsupported or incompatible.</summary>
    AlgorithmIncompatible = 3,

    /// <summary>The requested baseline level cannot be produced.</summary>
    LevelNotAchievable = 4,

    /// <summary>The requested baseline level dependencies are incomplete.</summary>
    LevelDependenciesMissing = 5,

    /// <summary>The external signer returned an empty or null signature.</summary>
    ExternalSignerReturnedEmpty = 6,

    /// <summary>The external signer returned a signature that does not verify with the configured certificate.</summary>
    ExternalSignerReturnedInvalidSignature = 14,

    /// <summary>The byte-only terminal was used with a best-effort level profile.</summary>
    DowngradeRequiresDetailedResult = 7,

    /// <summary>The document cannot be signed (e.g. DocMDP-locked).</summary>
    DocumentNotSignable = 8,

    /// <summary>The document is encrypted.</summary>
    DocumentEncrypted = 9,

    /// <summary>A network-dependent signing step failed.</summary>
    NetworkFailure = 10,

    /// <summary>An unspecified signing failure occurred.</summary>
    Unspecified = 11,

    /// <summary>A certificate of the signing chain is revoked.</summary>
    CertificateRevoked = 15,

    /// <summary>The revocation status of a certificate of the signing chain could not be established.</summary>
    RevocationStatusUnknown = 16,

    /// <summary>A certificate of the signing chain, other than the signing certificate, is outside its validity period.</summary>
    ChainCertificateNotValid = 17,

    /// <summary>The signing certificate does not allow digital signatures (key usage digitalSignature or nonRepudiation).</summary>
    KeyUsageNotPermitted = 18,

    /// <summary>The hash algorithm or elliptic curve is not allowed by the signing policy.</summary>
    AlgorithmNotPermitted = 19,

    /// <summary>The signing key is smaller than the signing policy allows.</summary>
    KeyTooWeak = 20,

    /// <summary>
    /// The signing certificate does not chain to any of the trust anchors given to the signer
    /// (<c>SigningCertificate/ProspectiveCertificateChain</c> of the signing policy).
    /// </summary>
    UntrustedRoot = 21,

    /// <summary>
    /// A timestamp obtained while signing is not from the expected TSA (<see cref="TimestampOptions.ExpectedTsaCertificate"/>)
    /// or its TSA certificate does not chain to a trust anchor (<c>Timestamp/ProspectiveCertificateChain</c>).
    /// </summary>
    TimestampUntrusted = 22,

    /// <summary>The TSA certificate of a timestamp obtained while signing is not valid at the time of the timestamp (<c>Timestamp/NotExpired</c>).</summary>
    TimestampCertificateNotValid = 23,

    /// <summary>A certificate of the TSA chain of a timestamp obtained while signing is revoked (<c>Timestamp/NotRevoked</c>).</summary>
    TimestampCertificateRevoked = 24,

    /// <summary>The revocation status of the TSA chain could not be established (<c>Timestamp/RevocationDataAvailable</c>).</summary>
    TimestampRevocationStatusUnknown = 25,

    /// <summary>
    /// The signing certificate is not a qualified certificate (no QcCompliance statement, <c>SigningCertificate/QcCompliance</c>)
    /// or its key is not declared to be on a qualified signature creation device (no QcSSCD, <c>SigningCertificate/QcSSCD</c>).
    /// </summary>
    CertificateNotQualified = 26,
}
