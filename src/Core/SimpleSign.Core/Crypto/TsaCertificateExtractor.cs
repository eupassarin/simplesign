using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace SimpleSign.Core.Crypto;

/// <summary>
/// Extracts certificates embedded in RFC 3161 timestamp tokens.
/// TSA tokens are CMS SignedData structures that commonly include
/// the TSA signing certificate (and sometimes intermediate CAs)
/// in their certificates [0] field.
/// These must be included in the PDF DSS for offline validation.
/// </summary>
internal static class TsaCertificateExtractor
{
    /// <summary>
    /// Parses a DER-encoded RFC 3161 timestamp token and returns all
    /// X.509 certificates found in it.
    /// Returns an empty list (never throws) for null, empty, or malformed inputs.
    /// </summary>
    /// <param name="timestampTokenBytes">Raw DER bytes of the RFC 3161 token (ContentInfo wrapping SignedData).</param>
    /// <returns>List of certificates found in the token. Caller owns and must dispose them.</returns>
    internal static IReadOnlyList<X509Certificate2> ExtractCertificates(byte[]? timestampTokenBytes)
    {
        if (timestampTokenBytes is null or { Length: 0 })
        {
            return [];
        }

        try
        {
            return ExtractCertificatesCore(timestampTokenBytes);
        }
        catch (Exception ex) when (ex is AsnContentException or CryptographicException or InvalidOperationException or IndexOutOfRangeException)
        {
            // Malformed token — return empty list per contract
            return [];
        }
    }

    private static List<X509Certificate2> ExtractCertificatesCore(byte[] tokenBytes)
    {
        var certs = new List<X509Certificate2>();

        // RFC 3161 token structure:
        // ContentInfo ::= SEQUENCE { contentType OID, content [0] EXPLICIT ANY }
        // content = SignedData ::= SEQUENCE { version, digestAlgorithms, encapContentInfo, certificates [0] IMPLICIT, ... }
        var reader = new AsnReader(tokenBytes, AsnEncodingRules.BER);
        var contentInfo = reader.ReadSequence();

        // contentType — should be id-signedData (1.2.840.113549.1.7.2) but we don't validate
        contentInfo.ReadObjectIdentifier();

        // content [0] EXPLICIT
        if (!contentInfo.HasData)
        {
            return certs;
        }

        var contentWrapper = contentInfo.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0, true));
        var signedData = contentWrapper.ReadSequence();

        // version INTEGER
        signedData.ReadEncodedValue();

        // digestAlgorithms SET OF
        signedData.ReadEncodedValue();

        // encapContentInfo SEQUENCE
        signedData.ReadEncodedValue();

        // certificates [0] IMPLICIT SET OF Certificate (OPTIONAL)
        if (!signedData.HasData)
        {
            return certs;
        }

        var nextTag = signedData.PeekTag();
        if (nextTag.TagClass == TagClass.ContextSpecific && nextTag.TagValue == 0)
        {
            var certsSet = signedData.ReadSetOf(new Asn1Tag(TagClass.ContextSpecific, 0, true));
            while (certsSet.HasData)
            {
                try
                {
                    byte[] certBytes = certsSet.ReadEncodedValue().ToArray();
                    var cert = CertificateLoader.LoadCertificate(certBytes);
                    certs.Add(cert);
                }
                catch (CryptographicException)
                {
                    // Element already consumed by ReadEncodedValue above — just skip
                }
            }
        }

        return certs;
    }
}
