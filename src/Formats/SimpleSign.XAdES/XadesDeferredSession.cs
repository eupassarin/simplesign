using System.Text.Json.Serialization;
using SimpleSign.Core.Signing;

namespace SimpleSign.XAdES;

/// <summary>
/// What a two-phase XAdES signature keeps between its phases: the document already assembled with an empty
/// ds:SignatureValue, the canonical SignedInfo that was handed out to be signed, and what phase two needs to
/// finish the requested level. Options that change the signed bytes are not kept one by one: they are
/// already inside <see cref="PreparedXml"/>.
/// </summary>
/// <remarks>
/// A field added later must be optional and left out when it has its default value, so a reader of an
/// earlier version, which ignores what it does not know, still completes the session.
/// </remarks>
internal sealed class XadesDeferredSession
{
    /// <summary>The format name written in the session envelope.</summary>
    internal const string Format = "XAdES";

    /// <summary>The canonical ds:SignedInfo: the bytes the external signer signs.</summary>
    public required byte[] SignedInfo { get; init; }

    /// <summary>The document with the signature assembled and its ds:SignatureValue empty.</summary>
    public required byte[] PreparedXml { get; init; }

    /// <summary>The Id of the ds:Signature being made.</summary>
    public required string SignatureId { get; init; }

    /// <summary>The signed document of the detached form, which is not inside <see cref="PreparedXml"/>.</summary>
    public byte[]? DetachedContent { get; init; }

    /// <summary>The additional data objects kept outside the signature, by the URI of their reference.</summary>
    public XadesDeferredExternalObject[]? ExternalDataObjects { get; init; }

    /// <summary>The SHA-256 of the document given to sign (hex), for the audit record of phase two.</summary>
    public string? InputSha256 { get; init; }

    /// <summary>The signer certificate (DER).</summary>
    public required byte[] CertificateDer { get; init; }

    /// <summary>The certificates given with the signer certificate (DER), in the order given.</summary>
    public byte[][]? ExtraCertificatesDer { get; init; }

    /// <summary>The name of the resolved digest algorithm (e.g. SHA256).</summary>
    public required string HashAlgorithm { get; init; }

    /// <summary>The resolved signature algorithm OID.</summary>
    public required string SignatureAlgorithmOid { get; init; }

    /// <summary>The claimed signing time written in the signed properties.</summary>
    public DateTimeOffset SigningTime { get; init; }

    /// <summary>The baseline level requested.</summary>
    public AdesBaselineLevel RequestedLevel { get; init; }

    /// <summary>Whether a level that cannot be reached fails or returns a lower level.</summary>
    public SigningLevelFailureBehavior LevelFailureBehavior { get; init; }

    /// <summary>The signature TSA endpoint, for B-T and above.</summary>
    public string? TimestampEndpoint { get; init; }

    /// <summary>The archive TSA endpoint, when B-LTA uses one of its own.</summary>
    public string? ArchiveTimestampEndpoint { get; init; }

    /// <summary>The revocation source tried first when collecting B-LT data.</summary>
    public RevocationPreference RevocationPreference { get; init; }

    /// <summary>The OCSP clock skew tolerance in seconds, when it is not the default.</summary>
    public double? ClockSkewSeconds { get; init; }

    /// <summary>The XAdES extended form to add after the signature timestamp.</summary>
    public XadesExtendedForm ExtendedForm { get; init; }

    /// <summary>The operation id given in phase one, for the audit record and the logs of phase two.</summary>
    public string? OperationId { get; init; }

    /// <summary>Whether the signature being made countersigns a signature of the document.</summary>
    public bool CounterSignature { get; init; }

    /// <summary>Serializes the session, authenticated with <paramref name="key"/>.</summary>
    internal byte[] Protect(byte[] key) =>
        DeferredSessionEnvelope.Protect(this, XadesDeferredSessionJsonContext.Default.XadesDeferredSession, Format, key);

    /// <summary>Reads a session after verifying its HMAC with <paramref name="key"/>.</summary>
    internal static XadesDeferredSession Read(byte[] data, byte[] key) =>
        DeferredSessionEnvelope.Unprotect(data, XadesDeferredSessionJsonContext.Default.XadesDeferredSession, Format, key);
}

/// <summary>A data object signed by reference and kept outside the signature.</summary>
internal sealed class XadesDeferredExternalObject
{
    /// <summary>The URI of the ds:Reference.</summary>
    public required string Uri { get; init; }

    /// <summary>The data the reference digests.</summary>
    public required byte[] Content { get; init; }
}

[JsonSourceGenerationOptions(DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingDefault)]
[JsonSerializable(typeof(XadesDeferredSession))]
internal sealed partial class XadesDeferredSessionJsonContext : JsonSerializerContext;
