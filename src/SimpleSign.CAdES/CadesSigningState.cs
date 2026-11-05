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
    CadesDependencies Dependencies)
{
    /// <summary>A signature policy with its hash; takes precedence over <see cref="SignaturePolicyOid"/>.</summary>
    public SignaturePolicyReference? SignaturePolicy { get; init; }

    /// <summary>When set, the new signer is added to this existing CMS (co-signature).</summary>
    public byte[]? CoSignTarget { get; init; }

    /// <summary>When set, the new signer countersigns signer <see cref="CounterSignIndex"/> of this CMS.</summary>
    public byte[]? CounterSignTarget { get; init; }

    /// <summary>The signer of <see cref="CounterSignTarget"/> to countersign.</summary>
    public int CounterSignIndex { get; init; }

    /// <summary>The RFC 5126 extended form to add after the signature timestamp.</summary>
    public CadesExtendedForm ExtendedForm { get; init; }

    /// <summary>Whether this signs a countersignature (no content-type attribute, RFC 5652 §11.4).</summary>
    public bool IsCounterSignature => CounterSignTarget is not null;
}
