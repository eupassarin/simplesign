using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SimpleSign.Core.Signing;

namespace SimpleSign.XAdES;

/// <summary>Options for <see cref="XadesSigner"/> signing methods.</summary>
public sealed class XadesSigningOptions
{
    /// <summary>Hash algorithm. Default: SHA-256.</summary>
    public HashAlgorithmName HashAlgorithm { get; init; } = HashAlgorithmName.SHA256;

    /// <summary>Explicit signing time. Default: UTC now.</summary>
    public DateTimeOffset? SigningTime { get; init; }

    /// <summary>Extra certificates (intermediate chain) to embed.</summary>
    public IReadOnlyList<X509Certificate2>? ExtraCertificates { get; init; }

    /// <summary>Explicit signature algorithm OID. If null, auto-detected from the cert.</summary>
    public string? SignatureAlgorithmOid { get; init; }

    /// <summary>TSA URL for timestamp (XAdES-B-T+). Null to skip timestamping.</summary>
    public string? TsaUrl { get; init; }

    /// <summary>HttpClient for TSA requests. If null, a default instance is used.</summary>
    public HttpClient? TsaHttpClient { get; init; }

    /// <summary>HttpClient for OCSP/CRL fetching (XAdES-B-LT). If null, TsaHttpClient is used.</summary>
    public HttpClient? RevocationHttpClient { get; init; }

    /// <summary>XAdES conformance level. Default: B-B.</summary>
    public XadesLevel Level { get; init; } = XadesLevel.Basic;

    /// <summary>XAdES signature packaging form. Default: Enveloped.</summary>
    public XadesForm Form { get; init; } = XadesForm.Enveloped;

    /// <summary>Commitment type indication (e.g., ProofOfOrigin, ProofOfApproval).</summary>
    public CommitmentType? CommitmentType { get; init; }

    /// <summary>Signature policy OID.</summary>
    public string? SignaturePolicyOid { get; init; }

    /// <summary>Signature policy URI.</summary>
    public string? SignaturePolicyUri { get; init; }

    /// <summary>Signer role claims (e.g., "Manager", "Approver").</summary>
    public IReadOnlyList<string>? SignerRoles { get; init; }

    /// <summary>Data URI for Detached form signatures. Required when Form is Detached.</summary>
    public string? DataUri { get; init; }

    /// <summary>Data object format (object reference URI + MIME type).</summary>
    public DataObjectFormat? DataObjectFormat { get; init; }
}
