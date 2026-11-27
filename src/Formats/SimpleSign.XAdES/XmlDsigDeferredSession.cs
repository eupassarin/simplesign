using System.Text.Json.Serialization;
using SimpleSign.Core.Signing;

namespace SimpleSign.XAdES;

/// <summary>
/// What a two-phase XML-DSig signature keeps between its phases: the document with the signature in place and no
/// SignatureValue yet, the canonical SignedInfo handed out to be signed, and the certificate and algorithms.
/// </summary>
/// <remarks>
/// A field added later must be optional and left out at its default, so a reader of an earlier version, which
/// ignores what it does not know, still completes the session (ADR 0028).
/// </remarks>
internal sealed class XmlDsigDeferredSession
{
    /// <summary>The format name written in the session envelope.</summary>
    internal const string Format = "XMLDSig";

    /// <summary>The canonical ds:SignedInfo: the bytes the external signer signs.</summary>
    public required byte[] SignedInfo { get; init; }

    /// <summary>The document with the ds:Signature in place, holding only its SignedInfo.</summary>
    public required byte[] PreparedXml { get; init; }

    /// <summary>The URI of the signature's Reference, which finds it in <see cref="PreparedXml"/>.</summary>
    public required string ReferenceUri { get; init; }

    /// <summary>The DER of the signer certificate.</summary>
    public required byte[] CertificateDer { get; init; }

    /// <summary>The digest algorithm name (SHA1, SHA256…).</summary>
    public required string HashAlgorithm { get; init; }

    /// <summary>The signature algorithm OID.</summary>
    public required string SignatureAlgorithmOid { get; init; }

    /// <summary>The SHA-256 of the document given in phase one, for the audit record.</summary>
    public string? InputSha256 { get; init; }

    /// <summary>The operation id given in phase one.</summary>
    public string? OperationId { get; init; }

    /// <summary>Serializes the session, authenticated with <paramref name="key"/>.</summary>
    internal byte[] Protect(byte[] key) =>
        DeferredSessionEnvelope.Protect(this, XmlDsigDeferredSessionJsonContext.Default.XmlDsigDeferredSession, Format, key);

    /// <summary>Reads a session after verifying its HMAC with <paramref name="key"/>.</summary>
    internal static XmlDsigDeferredSession Read(byte[] data, byte[] key) =>
        DeferredSessionEnvelope.Unprotect(data, XmlDsigDeferredSessionJsonContext.Default.XmlDsigDeferredSession, Format, key);
}

[JsonSourceGenerationOptions(DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingDefault)]
[JsonSerializable(typeof(XmlDsigDeferredSession))]
internal sealed partial class XmlDsigDeferredSessionJsonContext : JsonSerializerContext;
