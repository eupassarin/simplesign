using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;
using SimpleSign.Core.Crypto;
using SimpleSign.Core.Http;
using SimpleSign.Core.Policies;
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
    IHttpClientProvider HttpClientProvider)
{
    /// <summary>Checks the revocation of the chain before signing; when null, one is created from the HTTP provider.</summary>
    public SimpleSign.Core.Revocation.IChainRevocationChecker? ChainRevocationChecker { get; init; }
}

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

    /// <summary>The signer-location attribute to add, or null.</summary>
    public CadesSignerLocation? SignerLocation { get; init; }

    /// <summary>The content-hints attribute to add, or null.</summary>
    public CadesContentHints? ContentHints { get; init; }

    /// <summary>The mime-type attribute to add, or null.</summary>
    public string? MimeType { get; init; }

    /// <summary>The roles the signer claims (signer-attributes-v2), or null.</summary>
    public IReadOnlyList<string>? SignerRoles { get; init; }

    /// <summary>The X.509 attribute certificates of the signer (signer-attributes-v2, certifiedAttributesV2), or null.</summary>
    public IReadOnlyList<ReadOnlyMemory<byte>>? AttributeCertificates { get; init; }

    /// <summary>The assertions signed by third parties (signer-attributes-v2, signedAssertions), or null.</summary>
    public IReadOnlyList<CadesSignedAssertion>? SignedAssertions { get; init; }

    /// <summary>The TSA that timestamps the content before it is signed (content-time-stamp), or null.</summary>
    public TimestampOptions? ContentTimestamp { get; init; }

    /// <summary>The signature-policy-store unsigned attribute to add, or null.</summary>
    public SignaturePolicyStore? PolicyStore { get; init; }

    /// <summary>The checks run on the certificate, chain and algorithms before signing.</summary>
    public SigningPolicy SigningPolicy { get; init; } = SigningPolicy.Default;

    /// <summary>Whether this signs a countersignature (no content-type attribute, RFC 5652 §11.4).</summary>
    public bool IsCounterSignature => CounterSignTarget is not null;
}
