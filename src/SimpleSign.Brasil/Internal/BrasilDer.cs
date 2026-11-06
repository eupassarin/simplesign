using System.Formats.Asn1;
using System.Security.Cryptography.X509Certificates;

namespace SimpleSign.Brasil.Internal;

/// <summary>DER helpers and the OID arcs of ICP-Brasil (2.16.76.1) and Gov.br (2.16.76.3).</summary>
internal static class BrasilDer
{
    /// <summary>DER value bytes of arc 2.16.76.1 (ICP-Brasil), for searches in a CertificatePolicies extension.</summary>
    internal static ReadOnlySpan<byte> IcpBrasilArc => _icpBrasilArc;

    /// <summary>DER value bytes of arc 2.16.76.3 (Gov.br).</summary>
    internal static ReadOnlySpan<byte> GovBrArc => _govBrArc;

    /// <summary>DER value bytes of arc 2.16.76.3.2 (Gov.br assurance level).</summary>
    internal static ReadOnlySpan<byte> GovBrAssuranceLevelArc => _govBrAssuranceLevelArc;

    private static readonly byte[] _icpBrasilArc = OidValueBytes("2.16.76.1");
    private static readonly byte[] _govBrArc = OidValueBytes("2.16.76.3");
    private static readonly byte[] _govBrAssuranceLevelArc = OidValueBytes("2.16.76.3.2");

    /// <summary>Encodes an OID in dotted notation as a complete DER OBJECT IDENTIFIER (tag, length, value).</summary>
    internal static byte[] EncodeOid(string oid)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        writer.WriteObjectIdentifier(oid);
        return writer.Encode();
    }

    /// <summary>Loads a DER-encoded certificate on every target framework.</summary>
    internal static X509Certificate2 LoadCertificate(byte[] der) =>
#if NET9_0_OR_GREATER
        X509CertificateLoader.LoadCertificate(der);
#else
#pragma warning disable CA5403 // the bytes come from the caller (ITI downloads, signatures), not a constant
        new(der);
#pragma warning restore CA5403
#endif

    // The OID value bytes without tag and length (arcs are short, so the length is one byte).
    private static byte[] OidValueBytes(string oid) => EncodeOid(oid)[2..];
}
