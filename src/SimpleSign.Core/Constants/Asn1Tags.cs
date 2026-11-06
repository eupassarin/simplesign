
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
}
