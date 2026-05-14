using System.Security.Cryptography.X509Certificates;

namespace SimpleSign.Brasil.IcpBrasil;

/// <summary>ICP-Brasil chain validation result.</summary>
public sealed class IcpBrasilValidationResult
{
    /// <summary>Indicates whether the certificate chain is valid and trusted.</summary>
    public bool IsChainValid { get; init; }
    /// <summary>Indicates whether the certificate is issued by ICP-Brasil.</summary>
    public bool IsIcpBrasilCertificate { get; init; }
    /// <summary>Detected ICP-Brasil signature policy (AD-RB, AD-RT, AD-RV, AD-RC, or AD-RA).</summary>
    public IcpBrasilPolicy? DetectedPolicy { get; init; }
    /// <summary>Certificate level (A1–A4 for authentication, S1–S4 for confidentiality).</summary>
    public IcpBrasilCertificateLevel? CertificateLevel { get; init; }
    /// <summary>Certificate chain elements with individual validation results.</summary>
    public IReadOnlyList<IcpBrasilChainElement> ChainElements { get; init; } = [];
    /// <summary>Bundled AC Raiz (root CA) certificates used for chain building.</summary>
    public IReadOnlyList<X509Certificate2> AcRaizCertificates { get; init; } = [];
    /// <summary>Validation errors found during chain validation.</summary>
    public IReadOnlyList<string> Errors { get; init; } = [];
    /// <summary>Non-blocking warnings found during chain validation.</summary>
    public IReadOnlyList<string> Warnings { get; init; } = [];

    /// <summary>Indicates whether the overall validation passed (chain valid and no errors).</summary>
    public bool IsValid => IsChainValid && Errors.Count == 0;
}
