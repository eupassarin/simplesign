using System.Formats.Asn1;
using System.Globalization;
using System.Numerics;
using System.Security.Cryptography.X509Certificates;
using System.Xml;
using SimpleSign.Core.Validation.Policy;

namespace SimpleSign.XAdES;

/// <summary>Reads the signed properties of a XAdES signature in the terms of the <c>SignedAttributes</c> constraints.</summary>
internal static class XadesSignedAttributeFacts
{
    private const string Signed = "ds:Object/xades:QualifyingProperties/xades:SignedProperties/";

    /// <summary>The facts of the signed properties; the claimed roles and attribute certificates come from <c>SignerRoleV2</c>.</summary>
    internal static SignedAttributeFacts Read(
        XmlElement signature, XmlNamespaceManager ns, IReadOnlyList<string> claimedRoles, int attributeCertificates)
    {
        var signingCertificates = signature.SelectNodes(
            Signed + "xades:SignedSignatureProperties/xades:SigningCertificateV2 | " + Signed + "xades:SignedSignatureProperties/xades:SigningCertificate", ns);
        var references = new List<CertificateReference>();
        foreach (XmlElement holder in signingCertificates?.OfType<XmlElement>() ?? [])
        {
            foreach (XmlElement cert in holder.SelectNodes("xades:Cert", ns)?.OfType<XmlElement>() ?? [])
            {
                if (Reference(cert, ns) is { } reference)
                {
                    references.Add(reference);
                }
            }
        }

        var commitments = signature.SelectNodes(
            Signed + "xades:SignedDataObjectProperties/xades:CommitmentTypeIndication/xades:CommitmentTypeId/xades:Identifier", ns);
        string? mimeType = signature.SelectSingleNode(
            Signed + "xades:SignedDataObjectProperties/xades:DataObjectFormat/xades:MimeType", ns)?.InnerText.Trim();

        return new SignedAttributeFacts
        {
            SigningCertificateAttributes = signingCertificates?.Count ?? 0,
            CertificateReferences = references,
            MessageDigestOrSignedPropertiesPresent = signature.SelectSingleNode(Signed.TrimEnd('/'), ns) is not null,
            ContentType = string.IsNullOrEmpty(mimeType) ? null : mimeType,
            CommitmentTypes = [.. commitments?.OfType<XmlElement>().Select(e => e.InnerText.Trim()) ?? []],
            SignerLocation = signature.SelectSingleNode(
                Signed + "xades:SignedSignatureProperties/xades:SignatureProductionPlaceV2 | "
                + Signed + "xades:SignedSignatureProperties/xades:SignatureProductionPlace", ns) is not null,
            ClaimedRoles = claimedRoles,
            CertifiedRoles = attributeCertificates,
        };
    }

    /// <summary>A <c>xades:Cert</c>: CertDigest, and IssuerSerialV2 (DER IssuerSerial) or IssuerSerial (name and decimal serial).</summary>
    private static CertificateReference? Reference(XmlElement cert, XmlNamespaceManager ns)
    {
        if (cert.SelectSingleNode("xades:CertDigest/ds:DigestValue", ns) is not { } value)
        {
            return null;
        }

        byte[] digest;
        try
        {
            digest = Convert.FromBase64String(value.InnerText.Trim());
        }
        catch (FormatException)
        {
            return null;
        }

        string algorithm = DigestName((cert.SelectSingleNode("xades:CertDigest/ds:DigestMethod", ns) as XmlElement)?.GetAttribute("Algorithm"));
        X500DistinguishedName? issuer = null;
        byte[]? serial = null;
        try
        {
            if (cert.SelectSingleNode("xades:IssuerSerialV2", ns) is { } v2)
            {
                var issuerSerial = new AsnReader(Convert.FromBase64String(v2.InnerText.Trim()), AsnEncodingRules.DER).ReadSequence();
                var names = issuerSerial.ReadSequence();
                while (names.HasData)
                {
                    if (names.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 4)))
                    {
                        issuer = new X500DistinguishedName(names.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 4, isConstructed: true)).ReadEncodedValue().Span);
                    }
                    else
                    {
                        names.ReadEncodedValue();
                    }
                }

                serial = issuerSerial.ReadIntegerBytes().ToArray();
            }
            else if (cert.SelectSingleNode("xades:IssuerSerial", ns) is { } v1
                && v1.SelectSingleNode("ds:X509IssuerName", ns)?.InnerText is { } name
                && v1.SelectSingleNode("ds:X509SerialNumber", ns)?.InnerText is { } number)
            {
                issuer = new X500DistinguishedName(name.Trim());
                serial = BigInteger.Parse(number.Trim(), CultureInfo.InvariantCulture).ToByteArray(isUnsigned: false, isBigEndian: true);
            }
        }
        catch (Exception ex) when (ex is FormatException or AsnContentException or System.Security.Cryptography.CryptographicException)
        {
            // An unreadable issuer and serial leaves only the digest.
        }

        return new CertificateReference(algorithm, digest, issuer, serial);
    }

    /// <summary>The policy name of an XML Signature digest URI.</summary>
    private static string DigestName(string? uri) => uri switch
    {
        null or "" => "SHA256",
        _ when uri.EndsWith("#sha1", StringComparison.Ordinal) => "SHA1",
        _ when uri.EndsWith("#sha224", StringComparison.Ordinal) => "SHA224",
        _ when uri.EndsWith("#sha256", StringComparison.Ordinal) => "SHA256",
        _ when uri.EndsWith("#sha384", StringComparison.Ordinal) => "SHA384",
        _ when uri.EndsWith("#sha512", StringComparison.Ordinal) => "SHA512",
        _ when uri.EndsWith("#sha3-256", StringComparison.Ordinal) => "SHA3-256",
        _ when uri.EndsWith("#sha3-384", StringComparison.Ordinal) => "SHA3-384",
        _ when uri.EndsWith("#sha3-512", StringComparison.Ordinal) => "SHA3-512",
        _ => uri,
    };
}
