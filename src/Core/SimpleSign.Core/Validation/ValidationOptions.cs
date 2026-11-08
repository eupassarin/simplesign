namespace SimpleSign.Core.Validation;

/// <summary>Options for the validation engine.</summary>
public sealed class ValidationOptions
{
    /// <summary>Checks revocation (CRL/OCSP). Requires network access. Default: true.</summary>
    public bool CheckRevocation { get; init; } = true;

    /// <summary>Includes system root certificates as trust anchors. Default: true.</summary>
    public bool TrustSystemRoots { get; init; } = true;

    /// <summary>Additional root certificates for trust (e.g., ICP-Brasil chain).</summary>
    public IReadOnlyList<System.Security.Cryptography.X509Certificates.X509Certificate2>? TrustedRoots { get; init; }

    /// <summary>Timeout for AIA downloads, revocation checks (CRL/OCSP), and certificate-chain URL retrieval. Default: 10 seconds.</summary>
    public TimeSpan NetworkTimeout { get; init; } = TimeSpan.FromSeconds(10);

    /// <summary>
    /// The validation policy: accepted algorithms and key sizes, constraints on the signing certificate.
    /// Default: <see cref="Policies.ValidationPolicy.Default"/> (the EU DSS default constraints). Load one with <see cref="Policies.ValidationPolicy.Load"/>.
    /// </summary>
    public Policies.ValidationPolicy Policy { get; init; } = Policies.ValidationPolicy.Default;

    /// <summary>
    /// Chooses the validation policy for each signature by the signature policy it names; when set, it replaces
    /// <see cref="Policy"/>. Null: <see cref="Policy"/> for every signature.
    /// </summary>
    public Policies.IPolicyProvider? PolicyProvider { get; init; }

    /// <summary>The policy for a signature that names <paramref name="signaturePolicyOid"/> (or none).</summary>
    internal Policies.ValidationPolicy PolicyFor(string? signaturePolicyOid) =>
        PolicyProvider?.ValidationFor(signaturePolicyOid) ?? Policy;

    /// <summary>How validation data is fetched: revocation strategy and fallback, AIA, untrusted chains. Default: <see cref="VerifierOptions.Default"/>.</summary>
    public VerifierOptions Verifier { get; init; } = VerifierOptions.Default;

    /// <summary>How much of each signature is validated. Default: <see cref="ValidationLevel.ArchivalData"/>.</summary>
    public ValidationLevel Level { get; init; } = ValidationLevel.ArchivalData;

    /// <summary>Whether signature timestamps are validated (and give a proof of existence).</summary>
    internal bool ValidatesTimestamps => Level >= ValidationLevel.Timestamps;

    /// <summary>Whether revocation is checked: <see cref="CheckRevocation"/> and a level that includes long-term data.</summary>
    internal bool ChecksRevocation => CheckRevocation && Level >= ValidationLevel.LongTermData;

    /// <summary>Whether revocation is checked for a chain that is or is not trusted.</summary>
    internal bool ChecksRevocationFor(bool chainTrusted) => ChecksRevocation && (chainTrusted || Verifier.CheckRevocationForUntrustedChains);

    /// <summary>Whether long-term validation data is validated.</summary>
    internal bool ValidatesLongTermData => Level >= ValidationLevel.LongTermData;

    /// <summary>Whether archive timestamps are validated.</summary>
    internal bool ValidatesArchivalData => Level >= ValidationLevel.ArchivalData;

    /// <summary>Default instance with all options at their default values.</summary>
    public static ValidationOptions Default { get; } = new();
}
