using System.Text.Json;
using System.Text.Json.Serialization;

namespace SimpleSign.PAdES.Signing;

/// <summary>
/// Serializable state for a deferred (two-phase) signing operation.
/// Created by <see cref="DeferredSigner.PrepareAsync"/> and consumed by <see cref="DeferredSigner.CompleteAsync"/>.
/// Store this in Redis, a database, or any persistent storage between HTTP requests.
/// </summary>
public sealed class DeferredSigningSession
{
    /// <summary>DER-encoded signed attributes — the data that was (or will be) signed externally.</summary>
    public required byte[] SignedAttributes { get; init; }

    /// <summary>The prepared PDF bytes with signature placeholder.</summary>
    public required byte[] PreparedPdf { get; init; }

    /// <summary>Start offset of the first byte range (always 0 for PAdES).</summary>
    public required long ByteRangeOffset1 { get; init; }

    /// <summary>Length of the first byte range.</summary>
    public required long ByteRangeLength1 { get; init; }

    /// <summary>Start offset of the second byte range.</summary>
    public required long ByteRangeOffset2 { get; init; }

    /// <summary>Length of the second byte range.</summary>
    public required long ByteRangeLength2 { get; init; }

    /// <summary>Byte offset where the hex-encoded CMS should be written.</summary>
    public required long ContentsHexOffset { get; init; }

    /// <summary>Number of bytes reserved for the CMS (half the hex character count).</summary>
    public required int ContentsReservedBytes { get; init; }

    /// <summary>DER-encoded signer certificate (public key only).</summary>
    public required byte[] CertificateDer { get; init; }

    /// <summary>DER-encoded extra certificates (chain). Null if no chain was provided.</summary>
    public byte[][]? ExtraCertificatesDer { get; init; }

    /// <summary>Digest algorithm OID (e.g., "2.16.840.1.101.3.4.2.1" for SHA-256).</summary>
    public required string DigestOid { get; init; }

    /// <summary>Signature algorithm OID (e.g., "1.2.840.113549.1.1.11" for RSA-SHA256).</summary>
    public required string SignatureAlgorithmOid { get; init; }

    /// <summary>UTC signing time embedded in the signed attributes.</summary>
    public required DateTimeOffset SigningTime { get; init; }

    /// <summary>PDF object number of the signature dictionary.</summary>
    public required int SigDictObjectNumber { get; init; }

    /// <summary>Serializes this session to a byte array for storage (JSON UTF-8).</summary>
    public byte[] Serialize() =>
        JsonSerializer.SerializeToUtf8Bytes(this, DeferredSessionJsonContext.Default.DeferredSigningSession);

    /// <summary>Deserializes a session from a byte array.</summary>
    public static DeferredSigningSession Deserialize(byte[] data)
    {
        ArgumentNullException.ThrowIfNull(data);
        return JsonSerializer.Deserialize(data, DeferredSessionJsonContext.Default.DeferredSigningSession)
               ?? throw new ArgumentException("Invalid or empty session data.", nameof(data));
    }

    /// <summary>Deserializes a session from a read-only span.</summary>
    public static DeferredSigningSession Deserialize(ReadOnlySpan<byte> data) =>
        JsonSerializer.Deserialize(data, DeferredSessionJsonContext.Default.DeferredSigningSession)
        ?? throw new ArgumentException("Invalid or empty session data.");
}

[JsonSerializable(typeof(DeferredSigningSession))]
internal sealed partial class DeferredSessionJsonContext : JsonSerializerContext;
