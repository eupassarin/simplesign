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

    /// <summary>Timeout for network operations (CRL/OCSP). Default: 10 seconds.</summary>
    public TimeSpan NetworkTimeout { get; init; } = TimeSpan.FromSeconds(10);

    /// <summary>Default instance with all options at their default values.</summary>
    public static ValidationOptions Default { get; } = new();
}
