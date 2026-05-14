using System.Formats.Asn1;

namespace SimpleSign.Core.Constants;

/// <summary>
/// ASN.1 DER tag constants and well-known OID arc prefixes.
/// </summary>
internal static class Asn1Tags
{
    /// <summary>OBJECT IDENTIFIER tag (0x06).</summary>
    internal const byte ObjectIdentifier = 0x06;

    /// <summary>SET OF tag (0x31) — used to restore signedAttrs from [0] IMPLICIT.</summary>
    internal const byte SetOf = 0x31;

    /// <summary>[0] IMPLICIT context-specific tag (0xA0) — used in CMS for optional fields.</summary>
    internal const byte ContextSpecific0Constructed = 0xA0;

    /// <summary>Base-128 low 7 bits mask for OID encoding.</summary>
    internal const byte Base128ValueMask = 0x7F;

    /// <summary>Base-128 continuation bit for OID encoding.</summary>
    internal const byte Base128ContinuationBit = 0x80;

    /// <summary>Zlib FDICT flag bit mask (RFC 1950) — indicates preset dictionary.</summary>
    internal const byte ZlibFdictMask = 0x20;

    #region DER-encoded OID arc prefixes

    // These arc prefixes are computed from the canonical OID strings via AsnWriter at
    // type-load time. This eliminates the risk of hand-coded byte arrays drifting from
    // the OIDs they claim to represent (a real bug we hit when the hand-coded arc was
    // 0x60 0x92 0x4C → arc 2380, instead of the canonical 0x60 0x4C → arc 76).

    /// <summary>DER encoding of OID arc 2.16.76.1 (ICP-Brasil root).</summary>
    internal static ReadOnlySpan<byte> IcpBrasilArc => _icpBrasilArc;

    /// <summary>DER encoding of OID arc 2.16.76.1.2 (ICP-Brasil certificate level).</summary>
    internal static ReadOnlySpan<byte> IcpBrasilLevelArc => _icpBrasilLevelArc;

    /// <summary>DER encoding of OID arc 2.16.76.3 (Gov.br root).</summary>
    internal static ReadOnlySpan<byte> GovBrArc => _govBrArc;

    /// <summary>DER encoding of OID arc 2.16.76.3.2 (Gov.br assurance level).</summary>
    internal static ReadOnlySpan<byte> GovBrAssuranceLevelArc => _govBrAssuranceLevelArc;

    private static readonly byte[] _icpBrasilArc = ComputeOidArcBytes("2.16.76.1");
    private static readonly byte[] _icpBrasilLevelArc = ComputeOidArcBytes("2.16.76.1.2");
    private static readonly byte[] _govBrArc = ComputeOidArcBytes("2.16.76.3");
    private static readonly byte[] _govBrAssuranceLevelArc = ComputeOidArcBytes("2.16.76.3.2");

    /// <summary>
    /// Returns the DER-encoded OID arc *value* (without the leading tag+length bytes),
    /// suitable for substring searches inside a CertificatePolicies extension's RawData.
    /// </summary>
    private static byte[] ComputeOidArcBytes(string oid)
    {
        var w = new AsnWriter(AsnEncodingRules.DER);
        w.WriteObjectIdentifier(oid);
        var encoded = w.Encode();
        // Skip the OID tag (0x06) + length byte to keep just the value bytes.
        // OIDs <= 127 bytes (always, in our case) use 1-byte length encoding.
        return encoded[2..];
    }

    #endregion
}
