using System.Security.Cryptography.X509Certificates;

namespace SimpleSign.XAdES;

/// <summary>Result of a XAdES signature validation.</summary>
public sealed class XadesValidationResult
{
    /// <summary>The XMLDSig signature is mathematically valid.</summary>
    public bool IsSignatureValid { get; init; }

    /// <summary>The document integrity is intact (content hash matches).</summary>
    public bool IsIntegrityValid { get; init; }

    /// <summary>The certificate chain is valid and trusted.</summary>
    public bool IsCertificateChainValid { get; init; }

    /// <summary>The SignatureTimeStamp (if present) is valid.</summary>
    public bool? HasValidSignatureTimeStamp { get; init; }

    /// <summary>The LTV data (CertificateValues + RevocationValues) is valid.</summary>
    public bool? IsLtvDataValid { get; init; }

    /// <summary>The ArchiveTimeStamp (if present) is valid.</summary>
    public bool? HasValidArchiveTimeStamp { get; init; }

    /// <summary>The signer certificate.</summary>
    public X509Certificate2? SignerCertificate { get; init; }

    /// <summary>Signing time from SignedProperties.</summary>
    public DateTimeOffset? SigningTime { get; init; }

    /// <summary>Detected XAdES conformance level.</summary>
    public XadesLevel DetectedLevel { get; init; }

    /// <summary>Errors found during validation.</summary>
    public IReadOnlyList<string> Errors { get; init; } = [];

    /// <summary>Non-blocking warnings.</summary>
    public IReadOnlyList<string> Warnings { get; init; } = [];

    /// <summary>True when all fundamental checks pass.</summary>
    public bool IsValid =>
        IsIntegrityValid && IsSignatureValid && IsCertificateChainValid;
}
