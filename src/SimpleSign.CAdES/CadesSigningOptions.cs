using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SimpleSign.Core.Signing;

namespace SimpleSign.CAdES;

/// <summary>Options for <see cref="CadesSigner"/> signing methods.</summary>
public sealed class CadesSigningOptions
{
    /// <summary>Hash algorithm. Default: SHA-256.</summary>
    public HashAlgorithmName HashAlgorithm { get; init; } = HashAlgorithmName.SHA256;

    /// <summary>Explicit signing time. Default: UTC now.</summary>
    public DateTimeOffset? SigningTime { get; init; }

    /// <summary>Extra certificates (intermediate chain) to embed.</summary>
    public IReadOnlyList<X509Certificate2>? ExtraCertificates { get; init; }

    /// <summary>Explicit signature algorithm OID. If null, auto-detected from the cert.</summary>
    public string? SignatureAlgorithmOid { get; init; }

    /// <summary>TSA URL for timestamp (CAdES-B-T). Null to skip timestamping.</summary>
    public string? TsaUrl { get; init; }

    /// <summary>HttpClient for TSA requests. If null, a default instance is used.</summary>
    public HttpClient? TsaHttpClient { get; init; }

    /// <summary>HttpClient for OCSP/CRL fetching (CAdES-B-LT). If null, <c>TsaHttpClient</c> is used; if that is also null, a default instance is used.</summary>
    public HttpClient? RevocationHttpClient { get; init; }

    /// <summary>Commitment type indication (e.g., ProofOfOrigin, ProofOfApproval).</summary>
    public CommitmentType? CommitmentType { get; init; }

    /// <summary>Signature policy OID.</summary>
    public string? SignaturePolicyOid { get; init; }

    /// <summary>Signature policy URI.</summary>
    public string? SignaturePolicyUri { get; init; }

    /// <summary>CAdES conformance level. Default: B-B.</summary>
    public CadesLevel Level { get; init; } = CadesLevel.Basic;

    /// <summary>Content type: Detached (no data embedded, .p7s) or Enveloped (data embedded, .p7m). Default: Detached.</summary>
    public CadesContentType ContentType { get; init; } = CadesContentType.Detached;
}
