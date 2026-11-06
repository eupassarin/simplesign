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
    SignaturePolicyReference? SignaturePolicy,
    XadesSigningCertificateForm SigningCertificateForm,
    XadesExtendedForm ExtendedForm,
    IReadOnlyList<string>? SignerRoles,
    DataObjectFormat? DataObjectFormat,
    string? OperationId,
    XadesDependencies Dependencies)
{
    /// <summary>The SignatureProductionPlaceV2 property to add, or null.</summary>
    public SignatureProductionPlace? ProductionPlace { get; init; }

    /// <summary>The TSA that timestamps the signed data objects before signing (AllDataObjectsTimeStamp), or null.</summary>
    public TimestampOptions? DataObjectsTimestamp { get; init; }

    /// <summary>The data objects signed besides the document, or null.</summary>
    public IReadOnlyList<XadesDataObject>? AdditionalDataObjects { get; init; }

    /// <summary>The X.509 attribute certificates of the signer (CertifiedRolesV2), or null.</summary>
    public IReadOnlyList<ReadOnlyMemory<byte>>? AttributeCertificates { get; init; }

    /// <summary>The assertions third parties signed about the signer (SignedAssertions), each one XML element, or null.</summary>
    public IReadOnlyList<string>? SignedAssertions { get; init; }

    /// <summary>The signer roles of all three kinds, or null when there are none.</summary>
    public XadesSignerRoles? Roles =>
        SignerRoles is { Count: > 0 } || AttributeCertificates is { Count: > 0 } || SignedAssertions is { Count: > 0 }
            ? new XadesSignerRoles(SignerRoles ?? [], AttributeCertificates ?? [], SignedAssertions ?? [])
            : null;

    /// <summary>Whether the builder countersigns a signature of the document instead of signing the document.</summary>
    public bool IsCounterSignature { get; init; }

    /// <summary>The Id of the signature to countersign; null for the only signature of the document.</summary>
    public string? CounterSignTargetId { get; init; }

    /// <summary>The canonicalization of SignedInfo and of the references.</summary>
    public XadesCanonicalization Canonicalization { get; init; }

    /// <summary>The SignaturePolicyStore unsigned property to add, or null.</summary>
    public SignaturePolicyStore? PolicyStore { get; init; }
}
