using System.Text.Json.Serialization;
using SimpleSign.Core.Signing;

namespace SimpleSign.CAdES;

/// <summary>
/// What a two-phase CAdES signature keeps between its phases: the signed attributes that were handed out
/// to be signed, the content, and what phase two needs to finish the requested level. Options that change
/// the signed bytes are not kept one by one: they are already inside <see cref="SignedAttributes"/>.
/// </summary>
/// <remarks>
/// A field added later must be optional and left out when it has its default value, so a reader of an
/// earlier version, which ignores what it does not know, still completes the session.
/// </remarks>
internal sealed class CadesDeferredSession
{
    /// <summary>The format name written in the session envelope.</summary>
    internal const string Format = "CAdES";

    /// <summary>The DER signed attributes: the bytes the external signer signs.</summary>
    public required byte[] SignedAttributes { get; init; }

    /// <summary>
    /// The signed content: encapsulated in an attached signature, read back for a detached one. Null when it
    /// was kept out of the session: phase two is then given it again, and <see cref="ContentSha256"/> checks it.
    /// </summary>
    public byte[]? Content { get; init; }

    /// <summary>The SHA-256 of the content, when the content is not in the session.</summary>
    public byte[]? ContentSha256 { get; init; }

    /// <summary>Whether the content is encapsulated in the signature (.p7m).</summary>
    public bool Attached { get; init; }

    /// <summary>The signer certificate (DER).</summary>
    public required byte[] CertificateDer { get; init; }

    /// <summary>The certificates given with the signer certificate (DER), in the order given.</summary>
    public byte[][]? ExtraCertificatesDer { get; init; }

    /// <summary>The name of the resolved digest algorithm (e.g. SHA256).</summary>
    public required string HashAlgorithm { get; init; }

    /// <summary>The resolved signature algorithm OID.</summary>
    public required string SignatureAlgorithmOid { get; init; }

    /// <summary>The claimed signing time written in the signed attributes.</summary>
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

    /// <summary>The RFC 5126 extended form to add after the signature timestamp.</summary>
    public CadesExtendedForm ExtendedForm { get; init; }

    /// <summary>The DER value of the signature-policy-store unsigned attribute, when one was configured.</summary>
    public byte[]? PolicyStoreAttribute { get; init; }

    /// <summary>The operation id given in phase one, for the audit record and the logs of phase two.</summary>
    public string? OperationId { get; init; }

    /// <summary>The existing signature the new signer is added to (co-signature), or null.</summary>
    public byte[]? CoSignTarget { get; init; }

    /// <summary>The existing signature one of whose signers is countersigned, or null. <see cref="Content"/> is then that signer's signature value.</summary>
    public byte[]? CounterSignTarget { get; init; }

    /// <summary>The signer of <see cref="CounterSignTarget"/> that is countersigned.</summary>
    public int CounterSignIndex { get; init; }

    /// <summary>Serializes the session, authenticated with <paramref name="key"/>.</summary>
    internal byte[] Protect(byte[] key) =>
        DeferredSessionEnvelope.Protect(this, CadesDeferredSessionJsonContext.Default.CadesDeferredSession, Format, key);

    /// <summary>Reads a session after verifying its HMAC with <paramref name="key"/>.</summary>
    internal static CadesDeferredSession Read(byte[] data, byte[] key) =>
        DeferredSessionEnvelope.Unprotect(data, CadesDeferredSessionJsonContext.Default.CadesDeferredSession, Format, key);
}

[JsonSourceGenerationOptions(DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingDefault)]
[JsonSerializable(typeof(CadesDeferredSession))]
internal sealed partial class CadesDeferredSessionJsonContext : JsonSerializerContext;
