using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;
using SimpleSign.Core.Crypto;
using SimpleSign.Core.Http;
using SimpleSign.Core.Signing;

namespace SimpleSign.XAdES;

/// <summary>Internal discriminated union for the mutually exclusive signing credentials.</summary>
internal abstract record XadesSigningCredential;

/// <summary>Local signing with a certificate that owns its private key.</summary>
internal sealed record XadesLocalCredential(
    X509Certificate2 Certificate,
    IReadOnlyList<X509Certificate2> Chain) : XadesSigningCredential;

/// <summary>External signing via an <see cref="IExternalSigner"/>.</summary>
internal sealed record XadesExternalCredential(
    X509Certificate2 Certificate,
    IReadOnlyList<X509Certificate2> Chain,
    IExternalSigner Signer) : XadesSigningCredential;

/// <summary>
/// Immutable bundle of injected implementation collaborators carried through every clone.
/// </summary>
internal sealed record XadesDependencies(
    ITimestampClientFactory? TsaFactory,
    ILogger Logger,
    IHttpClientProvider HttpClientProvider);

/// <summary>Immutable signing configuration for the XAdES builder.</summary>
internal sealed record XadesSigningOptions(
    XadesSigningCredential? Credential,
    HashAlgorithmName HashAlgorithm,
    bool HashAlgorithmExplicitlySet,
    string? SignatureAlgorithmOid,
    DateTimeOffset? SigningTime,
    AdesBaselineProfile Profile,
    XadesForm Form,
    string? DataUri,
    CommitmentType? CommitmentType,
    string? SignaturePolicyOid,
    string? SignaturePolicyUri,
    IReadOnlyList<string>? SignerRoles,
    DataObjectFormat? DataObjectFormat,
    string? OperationId,
    XadesDependencies Dependencies);
