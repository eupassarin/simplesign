using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;
using SimpleSign.Core.Crypto;
using SimpleSign.Core.Extensions;
using SimpleSign.Core.Http;
using SimpleSign.Core.Signing;

namespace SimpleSign.PAdES.Signing;

/// <summary>Internal discriminated union for the mutually exclusive signing credentials.</summary>
internal abstract record SigningCredential;

/// <summary>Local signing with a certificate that owns its private key.</summary>
internal sealed record LocalCredential(
    X509Certificate2 Certificate,
    IReadOnlyList<X509Certificate2> Chain) : SigningCredential;

/// <summary>External signing via an <see cref="IExternalSigner"/>.</summary>
internal sealed record ExternalCredential(
    X509Certificate2 Certificate,
    IReadOnlyList<X509Certificate2> Chain,
    IExternalSigner Signer) : SigningCredential;

/// <summary>
/// Immutable bundle of injected implementation collaborators. Fluent configuration
/// replaces only the options record and carries this bundle unchanged, so test seams
/// and DI-provided services survive every fluent call.
/// </summary>
internal sealed record PadesDependencies(
    ITimestampClientFactory? TsaFactory,
    ILtvEmbedder? LtvEmbedder,
    ILogger Logger,
    IHttpClientProvider HttpClientProvider);

/// <summary>
/// Immutable signing configuration for the PAdES builder. One state value; every
/// fluent call replaces a single property via record <c>with</c> expressions.
/// </summary>
internal sealed record PadesSigningOptions(
    SigningCredential? Credential,
    HashAlgorithmName HashAlgorithm,
    bool HashAlgorithmExplicitlySet,
    string? SignatureAlgorithmOid,
    DateTimeOffset? SigningTime,
    SignatureFieldOptions Field,
    SignatureMetadata? Metadata,
    bool PadesAttributes,
    bool EnforcePdfA,
    string? OperationId,
    AdesBaselineProfile Profile,
    IReadOnlyList<ICountryExtension> CountryExtensions,
    PadesDependencies Dependencies);
