using System.Security.Cryptography;
using SimpleSign.Core.Signing;

namespace SimpleSign.CAdES;

/// <summary>
/// What phase one of a two-phase CAdES signature returns: the bytes to sign with the key held elsewhere,
/// and the session to keep on the server until the signature arrives.
/// </summary>
public sealed class CadesDeferredPrepareResult
{
    /// <summary>
    /// The DER-encoded signed attributes. The external signer signs these bytes (it hashes them with
    /// <see cref="DigestAlgorithm"/>); they are not a document hash.
    /// </summary>
    public required byte[] DataToSign { get; init; }

    /// <summary>
    /// The serialized session, authenticated with the session integrity key. Keep it on the server and
    /// resume it with <see cref="CadesDeferredSigner.Resume(byte[], byte[])"/>.
    /// </summary>
    public required byte[] SessionData { get; init; }

    /// <summary>The name of the digest algorithm the signer applies (e.g. "SHA256").</summary>
    public required string DigestAlgorithm { get; init; }

    /// <summary>The OID of the signature algorithm the signer must produce.</summary>
    public required string SignatureAlgorithmOid { get; init; }

    /// <summary>The WARN constraints of the signing policy the certificate or the algorithms did not meet.</summary>
    public IReadOnlyList<SigningWarning> Warnings { get; init; } = [];

    /// <summary>The PSS parameters the signer must use, for an RSASSA-PSS signature.</summary>
    internal RsaPssParameters? RsaPssParameters { get; init; }

    /// <summary>The operation id given to the builder.</summary>
    internal string? OperationId { get; init; }

    /// <summary>
    /// The same request an <see cref="IExternalSigner"/> receives in one-call signing: the data to sign, the
    /// resolved algorithms and, for RSASSA-PSS, the complete parameters. Hand it to the signer that holds the key.
    /// </summary>
    /// <returns>The signing request.</returns>
    public ExternalSigningRequest ToSigningRequest() =>
        new(DataToSign, new HashAlgorithmName(DigestAlgorithm), SignatureAlgorithmOid,
            ExternalSigningPayloadKind.CmsSignedAttributes, OperationId, RsaPssParameters);
}
