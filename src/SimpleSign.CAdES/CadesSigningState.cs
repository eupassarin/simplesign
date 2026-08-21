using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;
using SimpleSign.Core.Crypto;
using SimpleSign.Core.Http;
using SimpleSign.Core.Signing;

namespace SimpleSign.CAdES;

/// <summary>Internal discriminated union for the mutually exclusive signing credentials.</summary>
internal abstract record CadesSigningCredential;

/// <summary>Local signing with a certificate that owns its private key.</summary>
internal sealed record CadesLocalCredential(
    X509Certificate2 Certificate,
    IReadOnlyList<X509Certificate2> Chain) : CadesSigningCredential;

/// <summary>External signing via an <see cref="IExternalSigner"/>.</summary>
internal sealed record CadesExternalCredential(
    X509Certificate2 Certificate,
    IReadOnlyList<X509Certificate2> Chain,
    IExternalSigner Signer) : CadesSigningCredential;

/// <summary>
/// Immutable bundle of injected implementation collaborators carried through every clone.
/// </summary>
internal sealed record CadesDependencies(
    ITimestampClientFactory? TsaFactory,
    ICmsParser? CmsParser,
    ILogger Logger,
    IHttpClientProvider HttpClientProvider);

/// <summary>Immutable signing configuration for the CAdES builder.</summary>
internal sealed record CadesSigningOptions(
    CadesSigningCredential? Credential,
    HashAlgorithmName HashAlgorithm,
    bool HashAlgorithmExplicitlySet,
    string? SignatureAlgorithmOid,
    DateTimeOffset? SigningTime,
    AdesBaselineProfile Profile,
    string? OperationId,
    CommitmentType? CommitmentType,
    string? SignaturePolicyOid,
    string? SignaturePolicyUri,
    CadesContentType ContentType,
    CadesDependencies Dependencies);
