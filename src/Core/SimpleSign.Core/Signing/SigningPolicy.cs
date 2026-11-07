using System.Security.Cryptography;

namespace SimpleSign.Core.Signing;

/// <summary>
/// The checks a signer applies to its certificate, its chain and its algorithms before it signs.
/// A failed check throws a <see cref="SigningException"/> and nothing is signed.
/// </summary>
/// <remarks>
/// <see cref="Default"/> runs the checks that need no network: validity of every certificate of the
/// chain, the key usage of the signing certificate, the key size and the hash algorithm.
/// <see cref="Strict"/> adds the revocation of the whole chain as it stands now
/// (<see cref="Revocation.IChainRevocationChecker.CheckCurrentAsync"/>): the OCSP responders first,
/// then the CRLs downloaded again, so a CRL cached before a revocation does not decide.
/// </remarks>
public sealed record SigningPolicy
{
    /// <summary>The local checks: chain validity, key usage, key size and hash algorithm.</summary>
    public static SigningPolicy Default { get; } = new();

    /// <summary>The local checks plus the revocation of every certificate of the chain.</summary>
    public static SigningPolicy Strict { get; } = new() { CheckRevocation = true };

    /// <summary>
    /// Only the validity of the signing certificate itself, as before signing policies existed.
    /// Meant for tests and migrations, not for production signatures.
    /// </summary>
    public static SigningPolicy Minimal { get; } = new()
    {
        ValidateChainValidity = false,
        RequireSigningKeyUsage = false,
        MinimumRsaKeySize = 0,
        AllowedHashAlgorithms = [],
        AllowedEllipticCurves = [],
    };

    /// <summary>
    /// Whether every certificate of the chain, not only the signing certificate, must be within its
    /// validity period. Default: <see langword="true"/>.
    /// </summary>
    public bool ValidateChainValidity { get; init; } = true;

    /// <summary>
    /// Whether the signing certificate must carry the key usage extension with digitalSignature or
    /// nonRepudiation (contentCommitment) set. Default: <see langword="true"/>.
    /// </summary>
    public bool RequireSigningKeyUsage { get; init; } = true;

    /// <summary>The smallest RSA modulus, in bits, accepted for the signing key. Zero disables the check. Default: 2048.</summary>
    public int MinimumRsaKeySize { get; init; } = 2048;

    /// <summary>
    /// The hash algorithms a signature may use. Empty allows every algorithm the signer supports.
    /// Default: SHA-256, SHA-384, SHA-512, SHA3-256, SHA3-384 and SHA3-512.
    /// </summary>
    public IReadOnlyCollection<HashAlgorithmName> AllowedHashAlgorithms { get; init; } =
    [
        HashAlgorithmName.SHA256, HashAlgorithmName.SHA384, HashAlgorithmName.SHA512,
        HashAlgorithmName.SHA3_256, HashAlgorithmName.SHA3_384, HashAlgorithmName.SHA3_512,
    ];

    /// <summary>
    /// The OIDs of the elliptic curves an ECDSA signing key may use. Empty allows every curve.
    /// Default: NIST P-256, P-384 and P-521 and brainpoolP256r1, brainpoolP384r1 and brainpoolP512r1.
    /// </summary>
    public IReadOnlyCollection<string> AllowedEllipticCurves { get; init; } =
    [
        "1.2.840.10045.3.1.7", "1.3.132.0.34", "1.3.132.0.35",
        "1.3.36.3.3.2.8.1.1.7", "1.3.36.3.3.2.8.1.1.11", "1.3.36.3.3.2.8.1.1.13",
    ];

    /// <summary>
    /// Whether the revocation of every certificate of the chain (except the trust anchor) is checked
    /// before signing. A revoked certificate, or one whose status cannot be established, stops the
    /// signature. Needs the issuer of each certificate in the chain. Default: <see langword="false"/>.
    /// </summary>
    public bool CheckRevocation { get; init; }
}
