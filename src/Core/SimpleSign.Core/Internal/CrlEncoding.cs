using System.Security.Cryptography;
using System.Text;

namespace SimpleSign.Core.Internal;

/// <summary>
/// The encoding of a downloaded CRL. RFC 5280 §4.2.1.13 says a CRL fetched over HTTP is DER, but some servers
/// (FreeTSA, for one) serve it as PEM (<c>-----BEGIN X509 CRL-----</c>, RFC 7468 §5). Such a CRL is turned into
/// DER as it is downloaded, so what is parsed, cached and embedded (PAdES DSS, CAdES/XAdES revocation values) is DER.
/// </summary>
internal static class CrlEncoding
{
    private const string Label = "X509 CRL";

    /// <summary>
    /// The DER encoding of a downloaded CRL: <paramref name="crl"/> itself when it is not PEM, the decoded content of
    /// its first <c>X509 CRL</c> block when it is. A PEM text without such a block is returned unchanged (and then
    /// fails to parse as DER, as before).
    /// </summary>
    /// <param name="crl">The bytes the server sent, or null.</param>
    /// <returns>The DER CRL, or null when <paramref name="crl"/> is null.</returns>
    public static byte[]? ToDer(byte[]? crl)
    {
        // A DER CRL starts with a SEQUENCE (0x30); PEM is text, starting with '-' or with explanatory text and whitespace.
        if (crl is null || crl.Length == 0 || crl[0] == 0x30)
        {
            return crl;
        }

        string text;
        try
        {
            text = new UTF8Encoding(false, true).GetString(crl);
        }
        catch (DecoderFallbackException)
        {
            return crl;
        }

        ReadOnlySpan<char> remaining = text;
        while (PemEncoding.TryFind(remaining, out var fields))
        {
            if (remaining[fields.Label].SequenceEqual(Label))
            {
                return Convert.FromBase64String(remaining[fields.Base64Data].ToString());
            }

            remaining = remaining[fields.Location.End..];
        }

        return crl;
    }
}
