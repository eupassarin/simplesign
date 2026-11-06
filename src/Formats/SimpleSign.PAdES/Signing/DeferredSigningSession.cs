using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using SimpleSign.Core.Signing;

namespace SimpleSign.PAdES.Signing;

/// <summary>
/// Serializable state for a deferred (two-phase) signing operation.
/// Created by <see cref="DeferredSignerBuilder.PrepareAsync(CancellationToken)"/> and consumed by
/// <see cref="DeferredSignerBuilder.CompleteAsync(byte[], CancellationToken)"/> after
/// <see cref="DeferredSigner.Resume(byte[], byte[])"/>.
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

    /// <summary>
    /// Requested baseline level persisted for phase two. HTTP providers are runtime
    /// dependencies and are intentionally not serialized with the session.
    /// </summary>
    public AdesBaselineLevel RequestedLevel { get; init; } = AdesBaselineLevel.Basic;

    /// <summary>Strict or best-effort policy selected for the deferred operation.</summary>
    public SigningLevelFailureBehavior LevelFailureBehavior { get; init; } = SigningLevelFailureBehavior.Throw;

    /// <summary>Signature TSA endpoint for B-T and higher, when requested.</summary>
    public string? TimestampEndpoint { get; init; }

    /// <summary>Dedicated archive TSA endpoint for B-LTA, when configured.</summary>
    public string? ArchiveTimestampEndpoint { get; init; }

    /// <summary>HMAC-SHA256 over the session payload, keyed with a server-side secret.</summary>
    public byte[]? Hmac { get; set; }

    /// <summary>
    /// Serializes this session to a byte array for storage (JSON UTF-8) and signs it with HMAC-SHA256.
    /// </summary>
    /// <param name="hmacKey">Server-owned HMAC key with at least 256 bits of entropy.</param>
    /// <returns>The integrity-protected serialized session.</returns>
    /// <exception cref="ArgumentException">Thrown when <paramref name="hmacKey"/> is shorter than 32 bytes.</exception>
    public byte[] Serialize(byte[] hmacKey)
    {
        ValidateHmacKey(hmacKey);
        Hmac = null; // clear before computing
        byte[] payload = JsonSerializer.SerializeToUtf8Bytes(this, DeferredSessionJsonContext.Default.DeferredSigningSession);

        Hmac = HMACSHA256.HashData(hmacKey, payload);
        // Re-serialize with HMAC included.
        payload = JsonSerializer.SerializeToUtf8Bytes(this, DeferredSessionJsonContext.Default.DeferredSigningSession);

        return payload;
    }

    /// <summary>Deserializes a session from a byte array after verifying mandatory HMAC integrity.</summary>
    /// <param name="data">Serialized session bytes.</param>
    /// <param name="hmacKey">Server-owned HMAC key used during serialization.</param>
    /// <returns>The verified session.</returns>
    public static DeferredSigningSession Deserialize(byte[] data, byte[] hmacKey)
    {
        ArgumentNullException.ThrowIfNull(data);
        ValidateHmacKey(hmacKey);
        var session = JsonSerializer.Deserialize(data, DeferredSessionJsonContext.Default.DeferredSigningSession)
               ?? throw new ArgumentException("Invalid or empty session data.", nameof(data));

        VerifyHmac(session, hmacKey);

        return session;
    }

    /// <summary>Deserializes a session from a read-only span after verifying mandatory HMAC integrity.</summary>
    /// <param name="data">Serialized session bytes.</param>
    /// <param name="hmacKey">Server-owned HMAC key used during serialization.</param>
    /// <returns>The verified session.</returns>
    public static DeferredSigningSession Deserialize(ReadOnlySpan<byte> data, byte[] hmacKey)
    {
        ValidateHmacKey(hmacKey);
        var session = JsonSerializer.Deserialize(data, DeferredSessionJsonContext.Default.DeferredSigningSession)
            ?? throw new ArgumentException("Invalid or empty session data.");

        VerifyHmac(session, hmacKey);

        return session;
    }

    private static void VerifyHmac(DeferredSigningSession session, byte[] hmacKey)
    {
        byte[]? receivedHmac = session.Hmac;
        if (receivedHmac is null || receivedHmac.Length == 0)
        {
            throw new CryptographicException("Session integrity check failed: HMAC is missing. Session may have been tampered with.");
        }

        // Recompute HMAC over payload without the HMAC field
        session.Hmac = null;
        byte[] payload = JsonSerializer.SerializeToUtf8Bytes(session, DeferredSessionJsonContext.Default.DeferredSigningSession);
        byte[] expectedHmac = HMACSHA256.HashData(hmacKey, payload);

        // Restore for caller
        session.Hmac = receivedHmac;

        if (!CryptographicOperations.FixedTimeEquals(expectedHmac, receivedHmac))
        {
            throw new CryptographicException("Session integrity check failed: HMAC mismatch. Session data has been tampered with.");
        }
    }

    private static void ValidateHmacKey(byte[] hmacKey)
    {
        ArgumentNullException.ThrowIfNull(hmacKey);
        if (hmacKey.Length < 32)
        {
            throw new ArgumentException("The deferred session HMAC key must contain at least 32 bytes.", nameof(hmacKey));
        }
    }
}

[JsonSerializable(typeof(DeferredSigningSession))]
internal sealed partial class DeferredSessionJsonContext : JsonSerializerContext;
