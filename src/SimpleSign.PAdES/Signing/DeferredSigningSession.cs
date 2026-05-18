using System.Security.Cryptography;
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

    /// <summary>HMAC-SHA256 over the session payload, keyed with a server-side secret. Prevents client tampering.</summary>
    public byte[]? Hmac { get; set; }

    /// <summary>
    /// Serializes this session to a byte array for storage (JSON UTF-8), optionally signing with HMAC.
    /// </summary>
    /// <param name="hmacKey">Optional 256-bit HMAC key. When provided, the session is integrity-protected.</param>
    public byte[] Serialize(byte[]? hmacKey = null)
    {
        Hmac = null; // clear before computing
        byte[] payload = JsonSerializer.SerializeToUtf8Bytes(this, DeferredSessionJsonContext.Default.DeferredSigningSession);

        if (hmacKey is not null && hmacKey.Length > 0)
        {
            Hmac = HMACSHA256.HashData(hmacKey, payload);
            // Re-serialize with HMAC included
            payload = JsonSerializer.SerializeToUtf8Bytes(this, DeferredSessionJsonContext.Default.DeferredSigningSession);
        }

        return payload;
    }

    /// <summary>Deserializes a session from a byte array, optionally verifying HMAC integrity.</summary>
    /// <param name="data">Serialized session bytes.</param>
    /// <param name="hmacKey">Optional HMAC key. When provided, integrity is verified and tampering throws.</param>
    public static DeferredSigningSession Deserialize(byte[] data, byte[]? hmacKey = null)
    {
        ArgumentNullException.ThrowIfNull(data);
        var session = JsonSerializer.Deserialize(data, DeferredSessionJsonContext.Default.DeferredSigningSession)
               ?? throw new ArgumentException("Invalid or empty session data.", nameof(data));

        if (hmacKey is not null && hmacKey.Length > 0)
        {
            VerifyHmac(session, hmacKey);
        }

        return session;
    }

    /// <summary>Deserializes a session from a read-only span, optionally verifying HMAC integrity.</summary>
    public static DeferredSigningSession Deserialize(ReadOnlySpan<byte> data, byte[]? hmacKey = null)
    {
        var session = JsonSerializer.Deserialize(data, DeferredSessionJsonContext.Default.DeferredSigningSession)
            ?? throw new ArgumentException("Invalid or empty session data.");

        if (hmacKey is not null && hmacKey.Length > 0)
        {
            VerifyHmac(session, hmacKey);
        }

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
}

[JsonSerializable(typeof(DeferredSigningSession))]
internal sealed partial class DeferredSessionJsonContext : JsonSerializerContext;
