namespace SimpleSign.Core.Validation;

/// <summary>Which source of revocation data is asked first.</summary>
public enum RevocationStrategy
{
    /// <summary>OCSP first, then the CRL (the default).</summary>
    OcspFirst,

    /// <summary>The CRL first, then OCSP.</summary>
    CrlFirst,
}

/// <summary>How much of a signature a validation looks at.</summary>
public enum ValidationLevel
{
    /// <summary>The signature itself and the certificate chain: no timestamps, no revocation, no long-term data.</summary>
    BasicSignatures,

    /// <summary>Also the signature timestamps, whose time is the proof of existence.</summary>
    Timestamps,

    /// <summary>Also the revocation of the chains and the long-term validation data (B-LT).</summary>
    LongTermData,

    /// <summary>Also the archive timestamps (B-LTA). The default.</summary>
    ArchivalData,
}

/// <summary>
/// How the validators fetch and use validation data. What a
/// validation requires (levels FAIL, WARN, INFORM) is the policy's; these options say how the data is obtained.
/// </summary>
public sealed record VerifierOptions
{
    /// <summary>The default options: OCSP first with fallback to the CRL, AIA downloads, no revocation for untrusted chains.</summary>
    public static VerifierOptions Default { get; } = new();

    /// <summary>Which revocation source is asked first. Default: <see cref="RevocationStrategy.OcspFirst"/>.</summary>
    public RevocationStrategy RevocationStrategy { get; init; } = RevocationStrategy.OcspFirst;

    /// <summary>Whether the other source is asked when the first gives no answer. Default: <see langword="true"/>.</summary>
    public bool RevocationFallback { get; init; } = true;

    /// <summary>Whether missing issuer certificates are downloaded from the AIA caIssuers locations. Default: <see langword="true"/>.</summary>
    public bool UseAia { get; init; } = true;

    /// <summary>
    /// Whether revocation is checked for a chain that does not reach a trust anchor. Off by default: an
    /// untrusted chain could make the validator query any address its certificates name.
    /// </summary>
    public bool CheckRevocationForUntrustedChains { get; init; }
}
