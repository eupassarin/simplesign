using System.Security.Cryptography;

namespace SimpleSign.Core.Signing;

/// <summary>
/// Identifies the kind of payload handed to an <see cref="IExternalSigner"/>.
/// </summary>
public enum ExternalSigningPayloadKind
{
    /// <summary>DER-encoded CMS signed attributes (PAdES and CAdES).</summary>
    CmsSignedAttributes = 0,

    /// <summary>Canonicalized XML <c>SignedInfo</c> bytes (XAdES).</summary>
    XmlCanonicalizedSignedInfo = 1,
}

/// <summary>
/// An explicit, self-describing external signing request. Adapters for HSMs, cloud KMS,
/// and A3 tokens can safely implement the contract without container-specific guesswork.
/// </summary>
public sealed record ExternalSigningRequest
{
    /// <summary>The bytes to sign (CMS signed attributes or canonicalized XML <c>SignedInfo</c>).</summary>
    public ReadOnlyMemory<byte> DataToSign { get; }

    /// <summary>The fully resolved hash algorithm used to compute the message imprint.</summary>
    public HashAlgorithmName HashAlgorithm { get; }

    /// <summary>The signature algorithm OID the signer must produce.</summary>
    public string SignatureAlgorithmOid { get; }

    /// <summary>The kind of payload carried in <see cref="DataToSign"/>.</summary>
    public ExternalSigningPayloadKind PayloadKind { get; }

    /// <summary>Optional operation ID for log correlation.</summary>
    public string? OperationId { get; }

    /// <summary>Creates a new external signing request.</summary>
    /// <param name="dataToSign">The bytes to sign.</param>
    /// <param name="hashAlgorithm">The resolved hash algorithm.</param>
    /// <param name="signatureAlgorithmOid">The signature algorithm OID to produce.</param>
    /// <param name="payloadKind">The kind of payload.</param>
    /// <param name="operationId">Optional operation ID.</param>
    /// <exception cref="ArgumentException"><paramref name="signatureAlgorithmOid"/> is null or whitespace.</exception>
    public ExternalSigningRequest(
        ReadOnlyMemory<byte> dataToSign,
        HashAlgorithmName hashAlgorithm,
        string signatureAlgorithmOid,
        ExternalSigningPayloadKind payloadKind,
        string? operationId = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(signatureAlgorithmOid);
        DataToSign = dataToSign;
        HashAlgorithm = hashAlgorithm;
        SignatureAlgorithmOid = signatureAlgorithmOid;
        PayloadKind = payloadKind;
        OperationId = operationId;
    }
}

/// <summary>
/// Signs the payload of an <see cref="ExternalSigningRequest"/> and returns the raw
/// signature bytes (not a CMS or XML container).
/// </summary>
/// <remarks>
/// Raw signature encodings: RSA produces a PKCS#1 v1.5 signature; ECDSA produces an
/// ASN.1 DER SEQUENCE { r, s } (RFC 3279); EdDSA produces raw signature bytes.
/// </remarks>
public interface IExternalSigner
{
    /// <summary>Signs the request payload and returns the raw signature bytes.</summary>
    /// <param name="request">The fully resolved signing request.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The raw signature bytes.</returns>
    ValueTask<ReadOnlyMemory<byte>> SignAsync(
        ExternalSigningRequest request,
        CancellationToken cancellationToken);
}
