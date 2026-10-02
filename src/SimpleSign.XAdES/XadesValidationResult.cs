using System.Security.Cryptography.X509Certificates;
using SimpleSign.Core.Signing;

namespace SimpleSign.XAdES;

/// <summary>Result of a XAdES signature validation.</summary>
public sealed class XadesValidationResult
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

    /// <summary>Whether the TSA chain is trusted; null when the token is absent, invalid, or no trust policy was evaluated.</summary>
    public bool? IsTsaTrusted { get; init; }

    /// <summary>The embedded CertificateValues and RevocationValues provide applicable, authenticated revocation evidence; this does not establish certificate-chain trust.</summary>
    public bool? IsLtvDataValid { get; init; }

    /// <summary>The ArchiveTimeStamp token's cryptographic integrity and archive coverage are valid, independent of TSA trust.</summary>
    public bool? HasValidArchiveTimeStamp { get; init; }

    /// <summary>The signer certificate.</summary>
    public X509Certificate2? SignerCertificate { get; init; }

    /// <summary>Signing time from SignedProperties.</summary>
    public DateTimeOffset? SigningTime { get; init; }

    /// <summary>The baseline level inferred from observed unsigned-property elements, even when those properties fail validation.</summary>
    /// <remarks>
    /// Structural detection is not a validated or achieved level. Consult
    /// <see cref="HasValidSignatureTimeStamp"/>, <see cref="IsLtvDataValid"/>, and
    /// <see cref="HasValidArchiveTimeStamp"/> together with base-signature and integrity checks.
    /// Certificate-chain and TSA trust are separate validation outcomes.
    /// </remarks>
    public AdesBaselineLevel DetectedLevel { get; init; }

    /// <summary>Errors found during validation.</summary>
    public IReadOnlyList<string> Errors { get; init; } = [];

    /// <summary>Non-blocking warnings.</summary>
    public IReadOnlyList<string> Warnings { get; init; } = [];

    /// <summary>True when all fundamental checks pass.</summary>
    public bool IsValid =>
        IsIntegrityValid && IsSignatureValid && IsCertificateChainValid;
}
