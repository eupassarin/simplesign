using System.Formats.Asn1;
using System.Security.Cryptography;

namespace SimpleSign.Core.Crypto;

/// <summary>
/// Converts ECDSA signatures between the raw IEEE P1363 form (<c>r||s</c>, used by PKCS#11 and
/// some remote signing services) and the DER <c>SEQUENCE { r, s }</c> form CMS needs (RFC 3279).
/// </summary>
internal static class EcdsaSignatureEncoding
{
    /// <summary>Converts a raw <c>r||s</c> signature to DER.</summary>
    /// <exception cref="CryptographicException">The raw signature has an odd or zero length.</exception>
    internal static byte[] RawToDer(ReadOnlySpan<byte> raw)
    {
        if (raw.Length == 0 || raw.Length % 2 != 0)
        {
            throw new CryptographicException($"Malformed raw ECDSA signature ({raw.Length} bytes).");
        }

        int half = raw.Length / 2;
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSequence())
        {
            writer.WriteIntegerUnsigned(TrimLeadingZeros(raw[..half]));
            writer.WriteIntegerUnsigned(TrimLeadingZeros(raw[half..]));
        }

        return writer.Encode();
    }

    /// <summary>
    /// Returns the signature as DER: unchanged when it already is a DER <c>SEQUENCE</c> of two
    /// INTEGERs, otherwise converted from raw <c>r||s</c>.
    /// </summary>
    internal static byte[] ToDer(byte[] signature) => IsDerSequence(signature) ? signature : RawToDer(signature);

    /// <summary>Whether <paramref name="signature"/> is exactly one DER <c>SEQUENCE { INTEGER, INTEGER }</c>.</summary>
    internal static bool IsDerSequence(byte[] signature)
    {
        try
        {
            var reader = new AsnReader(signature, AsnEncodingRules.DER);
            var sequence = reader.ReadSequence();
            _ = sequence.ReadIntegerBytes();
            _ = sequence.ReadIntegerBytes();
            return !sequence.HasData && !reader.HasData;
        }
        catch (AsnContentException)
        {
            return false;
        }
    }

    private static ReadOnlySpan<byte> TrimLeadingZeros(ReadOnlySpan<byte> value)
    {
        int start = 0;
        while (start < value.Length - 1 && value[start] == 0)
        {
            start++;
        }

        return value[start..];
    }
}
