using SimpleSign.Core.Constants;

namespace SimpleSign.Core.Crypto;

/// <summary>
/// DER (Distinguished Encoding Rules — subset of ASN.1) encoding utilities.
/// Used to serialize OIDs and other primitives into CMS/PKCS structures and X.509 extensions.
/// </summary>
internal static class DerEncoder
{
    /// <summary>
    /// Encodes an OID in dotted decimal notation (e.g., "2.16.76.1.3.1") to DER bytes.
    /// TAG 0x06 + length + content encoded in base-128.
    /// Uses stackalloc to avoid intermediate allocations.
    /// </summary>
    public static byte[] EncodeOid(string oid)
    {
        // Max OID content: even very long OIDs fit in 128 bytes
        Span<byte> content = stackalloc byte[128];
        int contentLen = 0;

        int pos = 0;
        ulong first = ParseNextArc(oid, ref pos);
        ulong second = ParseNextArc(oid, ref pos);
        content[contentLen++] = (byte)(40 * first + second);

        while (pos < oid.Length)
        {
            ulong value = ParseNextArc(oid, ref pos);

            // Base-128 encode: write bytes in reverse, then flip
            int arcStart = contentLen;
            content[contentLen++] = (byte)(value & Asn1Tags.Base128ValueMask);
            value >>= 7;
            while (value > 0)
            {
                content[contentLen++] = (byte)((value & Asn1Tags.Base128ValueMask) | Asn1Tags.Base128ContinuationBit);
                value >>= 7;
            }
            content[arcStart..contentLen].Reverse();
        }

        var result = new byte[2 + contentLen];
        result[0] = Asn1Tags.ObjectIdentifier;
        result[1] = (byte)contentLen;
        content[..contentLen].CopyTo(result.AsSpan(2));
        return result;
    }

    private static ulong ParseNextArc(string oid, ref int pos)
    {
        ulong value = 0;
        while (pos < oid.Length && oid[pos] != '.')
        {
            value = value * 10 + (ulong)(oid[pos] - '0');
            pos++;
        }
        if (pos < oid.Length)
        {
            pos++; // skip '.'
        }
        return value;
    }
}
