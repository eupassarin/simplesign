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

    /// <summary>The signature/hash algorithm combination is unsupported or incompatible.</summary>
    AlgorithmIncompatible = 3,

    /// <summary>The requested baseline level cannot be produced.</summary>
    LevelNotAchievable = 4,

    /// <summary>The requested baseline level dependencies are incomplete.</summary>
    LevelDependenciesMissing = 5,

    /// <summary>The external signer returned an empty or null signature.</summary>
    ExternalSignerReturnedEmpty = 6,

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
}
