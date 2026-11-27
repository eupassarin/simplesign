using System.Security.Cryptography;
using SimpleSign.Core.Signing;

namespace SimpleSign.XAdES;

/// <summary>
/// What phase one of a two-phase XML-DSig signature returns: the canonical SignedInfo to sign with the key held
/// elsewhere (A3 token, local agent, HSM), and the session to keep on the server until the signature arrives.
/// </summary>
public sealed class XmlDsigDeferredPrepareResult
{
    /// <summary>The canonical ds:SignedInfo. The signer hashes these bytes with <see cref="DigestAlgorithm"/> and signs.</summary>
    public required byte[] DataToSign { get; init; }

    /// <summary>The serialized session, authenticated with the session integrity key; resume it with <see cref="XmlDsigDeferredSigner.Resume"/>.</summary>
    public required byte[] SessionData { get; init; }

    /// <summary>The name of the digest algorithm the signer applies (e.g. "SHA1" for the NF-e).</summary>
    public required string DigestAlgorithm { get; init; }

    /// <summary>The OID of the signature algorithm the signer must produce.</summary>
    public required string SignatureAlgorithmOid { get; init; }

    /// <summary>The URI of the Reference of the signature being made (<c>#NFe…</c>).</summary>
    public required string ReferenceUri { get; init; }

    /// <summary>The WARN constraints of the signing policy the certificate or the algorithms did not meet.</summary>
    public IReadOnlyList<SigningWarning> Warnings { get; init; } = [];

    /// <summary>The operation id given to the builder.</summary>
    internal string? OperationId { get; init; }

    /// <summary>The request an <see cref="IExternalSigner"/> receives in one-call signing; hand it to the signer that holds the key.</summary>
    /// <returns>The signing request.</returns>
    public ExternalSigningRequest ToSigningRequest() =>
        new(DataToSign, new HashAlgorithmName(DigestAlgorithm), SignatureAlgorithmOid,
            ExternalSigningPayloadKind.XmlCanonicalizedSignedInfo, OperationId);
}
