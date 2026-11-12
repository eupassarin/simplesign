using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization.Metadata;

namespace SimpleSign.Core.Signing;

/// <summary>
/// Writes and reads the session of a two-phase (deferred) signature: a JSON object holding the
/// session and an HMAC-SHA256 over the session bytes exactly as they are stored.
/// </summary>
/// <remarks>
/// The HMAC covers the stored bytes and not a new serialization of the session, so a session written
/// by one version of the library verifies in another: a field added later does not change the bytes
/// an older session has, and a reader that does not know a field ignores it. The format name and the
/// envelope version are part of the HMAC input, so a session of one format cannot be resumed as
/// another.
/// </remarks>
internal static class DeferredSessionEnvelope
{
    /// <summary>The shortest session integrity key accepted, in bytes.</summary>
    internal const int MinimumKeyLength = 32;

    private const int Version = 1;
    private const string FormatProperty = "format";
    private const string VersionProperty = "version";
    private const string HmacProperty = "hmac";
    private const string SessionProperty = "session";

    /// <summary>Throws unless <paramref name="key"/> has at least <see cref="MinimumKeyLength"/> bytes.</summary>
    internal static void ValidateKey(byte[] key, string parameterName)
    {
        ArgumentNullException.ThrowIfNull(key, parameterName);
        if (key.Length < MinimumKeyLength)
        {
            throw new ArgumentException("The deferred session HMAC key must contain at least 32 bytes.", parameterName);
        }
    }

    /// <summary>Serializes <paramref name="session"/> and authenticates it with <paramref name="key"/>.</summary>
    internal static byte[] Protect<T>(T session, JsonTypeInfo<T> typeInfo, string format, byte[] key)
    {
        ValidateKey(key, nameof(key));
        byte[] payload = JsonSerializer.SerializeToUtf8Bytes(session, typeInfo);
        byte[] hmac = ComputeHmac(key, format, Version, payload);

        using var stream = new MemoryStream(payload.Length + 128);
        using (var writer = new Utf8JsonWriter(stream))
        {
            writer.WriteStartObject();
            writer.WriteString(FormatProperty, format);
            writer.WriteNumber(VersionProperty, Version);
            writer.WriteBase64String(HmacProperty, hmac);
            writer.WritePropertyName(SessionProperty);
            writer.WriteRawValue(payload, skipInputValidation: true);
            writer.WriteEndObject();
        }

        return stream.ToArray();
    }

    /// <summary>Verifies the HMAC of <paramref name="data"/> and returns the session it holds.</summary>
    /// <exception cref="ArgumentException">The data is not a session of <paramref name="format"/>, or its version is not supported.</exception>
    /// <exception cref="CryptographicException">The HMAC is missing or does not match: the session was changed or the key is another one.</exception>
    internal static T Unprotect<T>(byte[] data, JsonTypeInfo<T> typeInfo, string format, byte[] key)
    {
        ArgumentNullException.ThrowIfNull(data);
        ValidateKey(key, nameof(key));

        JsonDocument document;
        try
        {
            document = JsonDocument.Parse(data);
        }
        catch (JsonException ex)
        {
            throw new ArgumentException($"The data is not a {format} deferred signing session.", nameof(data), ex);
        }

        using (document)
        {
            JsonElement root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object
                || !root.TryGetProperty(FormatProperty, out JsonElement formatElement)
                || formatElement.ValueKind != JsonValueKind.String
                || !string.Equals(formatElement.GetString(), format, StringComparison.Ordinal)
                || !root.TryGetProperty(SessionProperty, out JsonElement sessionElement)
                || sessionElement.ValueKind != JsonValueKind.Object)
            {
                throw new ArgumentException($"The data is not a {format} deferred signing session.", nameof(data));
            }

            if (!root.TryGetProperty(VersionProperty, out JsonElement versionElement)
                || !versionElement.TryGetInt32(out int version)
                || version != Version)
            {
                throw new ArgumentException(
                    $"The {format} deferred signing session was written in a format this version of the library does not read.",
                    nameof(data));
            }

            if (!root.TryGetProperty(HmacProperty, out JsonElement hmacElement)
                || hmacElement.ValueKind != JsonValueKind.String
                || !hmacElement.TryGetBytesFromBase64(out byte[]? received)
                || received.Length == 0)
            {
                throw new CryptographicException("Session integrity check failed: HMAC is missing. Session may have been tampered with.");
            }

            byte[] payload = Encoding.UTF8.GetBytes(sessionElement.GetRawText());
            byte[] expected = ComputeHmac(key, format, version, payload);
            if (!CryptographicOperations.FixedTimeEquals(expected, received))
            {
                throw new CryptographicException("Session integrity check failed: HMAC mismatch. Session data has been tampered with.");
            }

            try
            {
                return JsonSerializer.Deserialize(payload, typeInfo)
                    ?? throw new ArgumentException($"The {format} deferred signing session is empty.", nameof(data));
            }
            catch (JsonException ex)
            {
                throw new ArgumentException($"The {format} deferred signing session cannot be read.", nameof(data), ex);
            }
        }
    }

    private static byte[] ComputeHmac(byte[] key, string format, int version, byte[] payload)
    {
        using var hmac = IncrementalHash.CreateHMAC(HashAlgorithmName.SHA256, key);
        hmac.AppendData(Encoding.UTF8.GetBytes($"SimpleSign.DeferredSession\n{format}\n{version.ToString(System.Globalization.CultureInfo.InvariantCulture)}\n"));
        hmac.AppendData(payload);
        return hmac.GetHashAndReset();
    }
}
