using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Xml;
using SimpleSign.Core.Constants;

namespace SimpleSign.Core.Signing;

/// <summary>Why <see cref="DataToSignInspector.Inspect"/> refused the bytes.</summary>
public enum DataToSignRefusal
{
    /// <summary>No bytes.</summary>
    Empty,

    /// <summary>Larger than <see cref="DataToSignInspector.MaxLength"/>.</summary>
    TooLarge,

    /// <summary>Neither DER CMS signed attributes nor an XML-DSig <c>SignedInfo</c>.</summary>
    NotRecognized,

    /// <summary>A DER <c>SET OF Attribute</c> that cannot be read, or with an attribute given twice.</summary>
    MalformedSignedAttributes,

    /// <summary>Signed attributes without a single <c>contentType</c> value.</summary>
    MissingContentType,

    /// <summary>Signed attributes without a single <c>messageDigest</c> value.</summary>
    MissingMessageDigest,

    /// <summary>The <c>signingCertificateV2</c> (or <c>signingCertificate</c>) attribute names another certificate.</summary>
    SigningCertificateMismatch,

    /// <summary>XML that is not a well-formed, canonical <c>ds:SignedInfo</c> with its methods.</summary>
    MalformedSignedInfo,

    /// <summary>A <c>SignedInfo</c> without a <c>Reference</c> carrying a digest.</summary>
    NoReferences,
}

/// <summary>A digest found in the bytes to sign.</summary>
/// <param name="Algorithm">
/// The digest algorithm; null when unknown. For CMS signed attributes it is inferred from the length of the
/// <c>messageDigest</c> (20, 32, 48, 64 bytes → SHA-1, SHA-256, SHA-384, SHA-512), since the attributes do not name it.
/// </param>
/// <param name="Value">The digest.</param>
/// <param name="Uri">The <c>URI</c> of the XML-DSig reference; null for CMS signed attributes.</param>
/// <param name="Type">The <c>Type</c> of the XML-DSig reference, such as the XAdES <c>SignedProperties</c> type; null when absent.</param>
public sealed record DataToSignDigest(HashAlgorithmName? Algorithm, ReadOnlyMemory<byte> Value, string? Uri = null, string? Type = null)
{
    /// <summary>A short form for a consent dialog: the algorithm and the first and last four bytes, such as <c>SHA256 1A2B3C4D…5E6F7A8B</c>.</summary>
    /// <returns>The short form.</returns>
    public string ToShortString()
    {
        string hex = Convert.ToHexString(Value.Span);
        string shortHex = hex.Length <= 16 ? hex : hex[..8] + "…" + hex[^8..];
        return Algorithm is { Name: { } name } ? name + " " + shortHex : shortHex;
    }
}

/// <summary>What <see cref="DataToSignInspector.Inspect"/> found.</summary>
public sealed record DataToSignInspection
{
    /// <summary>Whether the bytes are signed attributes or a <c>SignedInfo</c> fit to be signed.</summary>
    public bool IsAccepted => Refusal is null;

    /// <summary>What the bytes are; null when not recognized.</summary>
    public ExternalSigningPayloadKind? Kind { get; init; }

    /// <summary>Why they were refused; null when accepted.</summary>
    public DataToSignRefusal? Refusal { get; init; }

    /// <summary>What was found wrong; null when accepted.</summary>
    public string? Message { get; init; }

    /// <summary>
    /// The digests the signature will cover: the <c>messageDigest</c> of CMS signed attributes, or the digest of each
    /// reference of a <c>SignedInfo</c>.
    /// </summary>
    public IReadOnlyList<DataToSignDigest> Digests { get; init; } = [];

    /// <summary>The <c>contentType</c> of CMS signed attributes (an OID); null otherwise.</summary>
    public string? ContentType { get; init; }

    /// <summary>The <c>SignatureMethod</c> algorithm of a <c>SignedInfo</c>; null otherwise.</summary>
    public string? SignatureMethod { get; init; }

    /// <summary>
    /// Whether the <c>signingCertificateV2</c> or <c>signingCertificate</c> attribute names the given certificate:
    /// true when it does, null when there is no such attribute, no certificate was given, or the bytes are a
    /// <c>SignedInfo</c> (whose certificate reference is in the signed properties, covered by a digest only).
    /// </summary>
    public bool? SigningCertificateMatches { get; init; }
}

/// <summary>
/// Recognizes what a signer is asked to sign before it signs: DER CMS signed attributes (PAdES, CAdES) or the canonical
/// XML-DSig <c>SignedInfo</c> (XAdES, XML-DSig) — the two <see cref="ExternalSigningPayloadKind"/>s. A local signing
/// agent that receives bytes from a page uses it to refuse anything else (a raw hash, a document, a challenge of
/// another protocol) and to show the user the digest being signed.
/// </summary>
/// <remarks>
/// It checks the structure, not where the data came from: the digest shown to the user is what ties the signature to
/// the document. The XML is read with DTDs prohibited and no resolver.
/// </remarks>
public static class DataToSignInspector
{
    /// <summary>The largest input inspected (1 MiB); signed attributes and a SignedInfo are a few kilobytes.</summary>
    public const int MaxLength = 1024 * 1024;

    private const string DsigNamespace = "http://www.w3.org/2000/09/xmldsig#";

    /// <summary>Inspects the bytes a signer is asked to sign.</summary>
    /// <param name="data">The bytes to sign.</param>
    /// <param name="certificate">
    /// The signing certificate, to check the <c>signingCertificateV2</c>/<c>signingCertificate</c> attribute of signed
    /// attributes; null to skip that check.
    /// </param>
    /// <returns>The kind, the digests and, when refused, the reason.</returns>
    public static DataToSignInspection Inspect(ReadOnlySpan<byte> data, X509Certificate2? certificate = null)
    {
        if (data.IsEmpty)
        {
            return Refuse(DataToSignRefusal.Empty, "Nothing to sign.");
        }

        if (data.Length > MaxLength)
        {
            return Refuse(DataToSignRefusal.TooLarge, $"The data to sign has {data.Length} bytes; at most {MaxLength} are accepted.");
        }

        return data[0] switch
        {
            0x31 => InspectSignedAttributes(data.ToArray(), certificate),
            (byte)'<' => InspectSignedInfo(data),
            _ => Refuse(DataToSignRefusal.NotRecognized,
                "The data to sign is neither DER CMS signed attributes nor an XML-DSig SignedInfo."),
        };
    }

    private static DataToSignInspection InspectSignedAttributes(byte[] data, X509Certificate2? certificate)
    {
        const ExternalSigningPayloadKind kind = ExternalSigningPayloadKind.CmsSignedAttributes;
        var attributes = new Dictionary<string, List<ReadOnlyMemory<byte>>>(StringComparer.Ordinal);
        try
        {
            var reader = new AsnReader(data, AsnEncodingRules.DER);
            var set = reader.ReadSetOf(skipSortOrderValidation: true);
            reader.ThrowIfNotEmpty();
            while (set.HasData)
            {
                var attribute = set.ReadSequence();
                string type = attribute.ReadObjectIdentifier();
                var values = attribute.ReadSetOf(skipSortOrderValidation: true);
                attribute.ThrowIfNotEmpty();
                if (attributes.ContainsKey(type))
                {
                    return Refuse(DataToSignRefusal.MalformedSignedAttributes, $"The signed attribute {type} is given twice.", kind);
                }

                var list = new List<ReadOnlyMemory<byte>>();
                while (values.HasData)
                {
                    list.Add(values.ReadEncodedValue());
                }

                attributes[type] = list;
            }
        }
        catch (AsnContentException ex)
        {
            return Refuse(DataToSignRefusal.MalformedSignedAttributes, "The signed attributes are not valid DER: " + ex.Message, kind);
        }

        try
        {
            if (!attributes.TryGetValue(Oids.ContentType, out var contentTypes) || contentTypes.Count != 1)
            {
                return Refuse(DataToSignRefusal.MissingContentType, "The signed attributes have no single contentType.", kind);
            }

            if (!attributes.TryGetValue(Oids.MessageDigest, out var digests) || digests.Count != 1)
            {
                return Refuse(DataToSignRefusal.MissingMessageDigest, "The signed attributes have no single messageDigest.", kind);
            }

            string contentType = new AsnReader(contentTypes[0], AsnEncodingRules.DER).ReadObjectIdentifier();
            byte[] messageDigest = new AsnReader(digests[0], AsnEncodingRules.DER).ReadOctetString();
            bool? matches = null;
            if (certificate is not null)
            {
                matches = attributes.TryGetValue(Oids.SigningCertificateV2, out var v2) ? MatchesV2(v2, certificate)
                    : attributes.TryGetValue(Oids.SigningCertificate, out var v1) ? MatchesV1(v1, certificate)
                    : null;
                if (matches == false)
                {
                    return Refuse(DataToSignRefusal.SigningCertificateMismatch,
                        "The signingCertificate attribute of the signed attributes names another certificate.", kind);
                }
            }

            return new DataToSignInspection
            {
                Kind = kind,
                ContentType = contentType,
                Digests = [new DataToSignDigest(HashByLength(messageDigest.Length), messageDigest)],
                SigningCertificateMatches = matches,
            };
        }
        catch (AsnContentException ex)
        {
            return Refuse(DataToSignRefusal.MalformedSignedAttributes, "A signed attribute cannot be read: " + ex.Message, kind);
        }
    }

    /// <summary>SigningCertificateV2 ::= SEQUENCE { certs SEQUENCE OF ESSCertIDv2, … }; the first ESSCertIDv2 is the signer's.</summary>
    private static bool MatchesV2(List<ReadOnlyMemory<byte>> values, X509Certificate2 certificate)
    {
        if (values.Count != 1)
        {
            return false;
        }

        var certs = new AsnReader(values[0], AsnEncodingRules.DER).ReadSequence().ReadSequence();
        var essCertId = certs.ReadSequence();
        var hash = HashAlgorithmName.SHA256;
        if (essCertId.PeekTag().HasSameClassAndValue(Asn1Tag.Sequence))
        {
            var algorithm = essCertId.ReadSequence();
            if (HashByOid(algorithm.ReadObjectIdentifier()) is not { } named)
            {
                return false;
            }

            hash = named;
        }

        byte[] certHash = essCertId.ReadOctetString();
        return certHash.AsSpan().SequenceEqual(certificate.GetCertHash(hash));
    }

    /// <summary>SigningCertificate ::= SEQUENCE { certs SEQUENCE OF ESSCertID, … }; ESSCertID's hash is SHA-1.</summary>
    private static bool MatchesV1(List<ReadOnlyMemory<byte>> values, X509Certificate2 certificate)
    {
        if (values.Count != 1)
        {
            return false;
        }

        var certs = new AsnReader(values[0], AsnEncodingRules.DER).ReadSequence().ReadSequence();
        byte[] certHash = certs.ReadSequence().ReadOctetString();
#pragma warning disable CA5350 // ESSCertID is defined with SHA-1; it identifies the certificate, it is not a signature.
        return certHash.AsSpan().SequenceEqual(certificate.GetCertHash(HashAlgorithmName.SHA1));
#pragma warning restore CA5350
    }

    private static DataToSignInspection InspectSignedInfo(ReadOnlySpan<byte> data)
    {
        const ExternalSigningPayloadKind kind = ExternalSigningPayloadKind.XmlCanonicalizedSignedInfo;
        if (data.StartsWith("<?xml"u8))
        {
            return Refuse(DataToSignRefusal.MalformedSignedInfo, "A canonical SignedInfo has no XML declaration.", kind);
        }

        var document = new XmlDocument { PreserveWhitespace = true, XmlResolver = null };
        try
        {
            var settings = new XmlReaderSettings
            {
                DtdProcessing = DtdProcessing.Prohibit,
                XmlResolver = null,
                MaxCharactersInDocument = MaxLength,
            };
            using var stream = new MemoryStream(data.ToArray(), writable: false);
            using var reader = XmlReader.Create(new StreamReader(stream, new UTF8Encoding(false, throwOnInvalidBytes: true)), settings);
            document.Load(reader);
        }
        catch (Exception ex) when (ex is XmlException or DecoderFallbackException)
        {
            return Refuse(DataToSignRefusal.MalformedSignedInfo, "The data to sign is not well-formed XML: " + ex.Message, kind);
        }

        var root = document.DocumentElement;
        if (root is null || root.LocalName != "SignedInfo" || root.NamespaceURI != DsigNamespace)
        {
            return Refuse(DataToSignRefusal.MalformedSignedInfo, "The XML to sign is not a ds:SignedInfo element.", kind);
        }

        var elements = root.ChildNodes.OfType<XmlElement>().ToList();
        if (elements.Any(e => e.NamespaceURI != DsigNamespace))
        {
            return Refuse(DataToSignRefusal.MalformedSignedInfo, "The SignedInfo has an element outside the XML-DSig namespace.", kind);
        }

        if (elements.Count < 2 || elements[0].LocalName != "CanonicalizationMethod" || elements[1].LocalName != "SignatureMethod"
            || Algorithm(elements[0]) is null || Algorithm(elements[1]) is not { } signatureMethod)
        {
            return Refuse(DataToSignRefusal.MalformedSignedInfo,
                "The SignedInfo must start with CanonicalizationMethod and SignatureMethod, each with its Algorithm.", kind);
        }

        var digests = new List<DataToSignDigest>();
        foreach (var reference in elements.Skip(2))
        {
            if (reference.LocalName != "Reference")
            {
                return Refuse(DataToSignRefusal.MalformedSignedInfo, $"Unexpected element ds:{reference.LocalName} in the SignedInfo.", kind);
            }

            var parts = reference.ChildNodes.OfType<XmlElement>().Where(e => e.NamespaceURI == DsigNamespace).ToList();
            var method = parts.FirstOrDefault(e => e.LocalName == "DigestMethod");
            var value = parts.FirstOrDefault(e => e.LocalName == "DigestValue");
            if (method is null || Algorithm(method) is not { } digestMethod || value is null)
            {
                return Refuse(DataToSignRefusal.MalformedSignedInfo, "A Reference of the SignedInfo has no DigestMethod or DigestValue.", kind);
            }

            byte[] digest;
            try
            {
                digest = Convert.FromBase64String(value.InnerText.Trim());
            }
            catch (FormatException)
            {
                return Refuse(DataToSignRefusal.MalformedSignedInfo, "A DigestValue of the SignedInfo is not base64.", kind);
            }

            if (digest.Length == 0)
            {
                return Refuse(DataToSignRefusal.MalformedSignedInfo, "A DigestValue of the SignedInfo is empty.", kind);
            }

            digests.Add(new DataToSignDigest(
                HashByUri(digestMethod), digest,
                reference.HasAttribute("URI") ? reference.GetAttribute("URI") : null,
                reference.HasAttribute("Type") ? reference.GetAttribute("Type") : null));
        }

        return digests.Count == 0
            ? Refuse(DataToSignRefusal.NoReferences, "The SignedInfo has no Reference.", kind)
            : new DataToSignInspection { Kind = kind, Digests = digests, SignatureMethod = signatureMethod };
    }

    private static string? Algorithm(XmlElement element) =>
        element.GetAttribute("Algorithm") is { Length: > 0 } algorithm ? algorithm : null;

    private static HashAlgorithmName? HashByLength(int length) => length switch
    {
        20 => HashAlgorithmName.SHA1,
        32 => HashAlgorithmName.SHA256,
        48 => HashAlgorithmName.SHA384,
        64 => HashAlgorithmName.SHA512,
        _ => null,
    };

    private static HashAlgorithmName? HashByOid(string oid) => oid switch
    {
        Oids.Sha1 => HashAlgorithmName.SHA1,
        Oids.Sha256 => HashAlgorithmName.SHA256,
        Oids.Sha384 => HashAlgorithmName.SHA384,
        Oids.Sha512 => HashAlgorithmName.SHA512,
        Oids.Sha3_256 => HashAlgorithmName.SHA3_256,
        Oids.Sha3_384 => HashAlgorithmName.SHA3_384,
        Oids.Sha3_512 => HashAlgorithmName.SHA3_512,
        _ => null,
    };

    private static HashAlgorithmName? HashByUri(string uri) => uri switch
    {
        "http://www.w3.org/2000/09/xmldsig#sha1" => HashAlgorithmName.SHA1,
        "http://www.w3.org/2001/04/xmlenc#sha256" => HashAlgorithmName.SHA256,
        "http://www.w3.org/2001/04/xmldsig-more#sha384" => HashAlgorithmName.SHA384,
        "http://www.w3.org/2001/04/xmlenc#sha512" => HashAlgorithmName.SHA512,
        "http://www.w3.org/2007/05/xmldsig-more#sha3-256" => HashAlgorithmName.SHA3_256,
        "http://www.w3.org/2007/05/xmldsig-more#sha3-384" => HashAlgorithmName.SHA3_384,
        "http://www.w3.org/2007/05/xmldsig-more#sha3-512" => HashAlgorithmName.SHA3_512,
        _ => null,
    };

    private static DataToSignInspection Refuse(DataToSignRefusal refusal, string message, ExternalSigningPayloadKind? kind = null) =>
        new() { Kind = kind, Refusal = refusal, Message = message };
}
