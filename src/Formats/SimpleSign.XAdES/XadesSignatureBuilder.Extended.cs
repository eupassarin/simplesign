using System.Formats.Asn1;
using System.Globalization;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Xml;
using SimpleSign.Core.Revocation;
using SimpleSign.Core.Constants;
using SimpleSign.XAdES.Constants;

namespace SimpleSign.XAdES;

/// <summary>
/// The XAdES extended forms of ETSI TS 101 903 v1.3.2 that ICP-Brasil's AD-RV, AD-RC and AD-RA
/// XML policies mandate.
/// </summary>
public enum XadesExtendedForm
{
    /// <summary>No extended validation data.</summary>
    None,

    /// <summary>XAdES-C + XAdES-X type 1: CompleteCertificateRefs, CompleteRevocationRefs and a SigAndRefsTimeStamp (ICP-Brasil AD-RV).</summary>
    CompleteReferences,

    /// <summary>XAdES-X-L: the references, the SigAndRefsTimeStamp, CertificateValues and RevocationValues (ICP-Brasil AD-RC).</summary>
    ExtendedLong,

    /// <summary>XAdES-A: references and values plus an ArchiveTimeStamp (ICP-Brasil AD-RA).</summary>
    Archive,
}

/// <summary>The XAdES-C, XAdES-X and XAdES-X-L unsigned properties (ETSI TS 101 903 v1.3.2 §7.4–§7.6).</summary>
internal static partial class XadesSignatureBuilder
{
    private const string CompleteCertificateRefsIdPrefix = "CCR-";
    private const string CompleteRevocationRefsIdPrefix = "CRR-";
    private const string SigAndRefsTimeStampIdPrefix = "SRTS-";

    /// <summary>
    /// Appends CompleteCertificateRefs (every certificate of the path but the signer's) and
    /// CompleteRevocationRefs (the CRLs and OCSP responses that cover the path), SHA-256 digests.
    /// </summary>
    internal static byte[] EmbedCompleteReferences(
        byte[] signedXml, IReadOnlyList<X509Certificate2> path, IReadOnlyList<byte[]> crls, IReadOnlyList<byte[]> ocspResponses, string? signatureId)
    {
        var doc = LoadDocument(signedXml);
        var ns = CreateNamespaceManager(doc);
        var unsignedProps = EnsureUnsignedSignatureProperties(doc, ResolveSignature(doc, ns, signatureId), ns);
        string suffix = Guid.NewGuid().ToString("N")[..8];

        var certificateRefs = doc.CreateElement("CompleteCertificateRefs", XadesUris.XadesNamespace);
        certificateRefs.SetAttribute("Id", CompleteCertificateRefsIdPrefix + suffix);
        var certRefs = doc.CreateElement("CertRefs", XadesUris.XadesNamespace);
        foreach (var certificate in path.Skip(1))
        {
            var cert = doc.CreateElement("Cert", XadesUris.XadesNamespace);
            var certDigest = doc.CreateElement("CertDigest", XadesUris.XadesNamespace);
            AppendDigest(doc, certDigest, certificate.RawData);
            var issuerSerial = doc.CreateElement("IssuerSerial", XadesUris.XadesNamespace);
            AppendText(doc, issuerSerial, "X509IssuerName", XmlDSigUrls.DsNamespace, certificate.IssuerName.Name);
            AppendText(doc, issuerSerial, "X509SerialNumber", XmlDSigUrls.DsNamespace,
                new System.Numerics.BigInteger(certificate.GetSerialNumber(), isUnsigned: true).ToString(CultureInfo.InvariantCulture));
            cert.AppendChild(certDigest);
            cert.AppendChild(issuerSerial);
            certRefs.AppendChild(cert);
        }

        certificateRefs.AppendChild(certRefs);
        unsignedProps.AppendChild(certificateRefs);

        var (coveringCrls, coveringOcsp) = CoveringEvidence(path, crls, ocspResponses);
        var revocationRefs = doc.CreateElement("CompleteRevocationRefs", XadesUris.XadesNamespace);
        revocationRefs.SetAttribute("Id", CompleteRevocationRefsIdPrefix + suffix);
        if (coveringCrls.Count > 0)
        {
            var crlRefs = doc.CreateElement("CRLRefs", XadesUris.XadesNamespace);
            foreach (byte[] crl in coveringCrls)
            {
                var (issuer, thisUpdate) = RevocationEvidence.ReadCrlIdentifier(crl);
                var crlRef = doc.CreateElement("CRLRef", XadesUris.XadesNamespace);
                var digest = doc.CreateElement("DigestAlgAndValue", XadesUris.XadesNamespace);
                AppendDigest(doc, digest, crl);
                crlRef.AppendChild(digest);
                var identifier = doc.CreateElement("CRLIdentifier", XadesUris.XadesNamespace);
                AppendText(doc, identifier, "Issuer", XadesUris.XadesNamespace, new X500DistinguishedName(issuer).Name);
                AppendText(doc, identifier, "IssueTime", XadesUris.XadesNamespace, XmlTime(thisUpdate));
                crlRef.AppendChild(identifier);
                crlRefs.AppendChild(crlRef);
            }

            revocationRefs.AppendChild(crlRefs);
        }

        if (coveringOcsp.Count > 0)
        {
            var ocspRefs = doc.CreateElement("OCSPRefs", XadesUris.XadesNamespace);
            foreach (byte[] response in coveringOcsp)
            {
                byte[] basic = RevocationEvidence.BasicResponse(response);
                var (responderId, producedAt) = RevocationEvidence.ReadOcspIdentifier(basic);
                var ocspRef = doc.CreateElement("OCSPRef", XadesUris.XadesNamespace);
                var identifier = doc.CreateElement("OCSPIdentifier", XadesUris.XadesNamespace);
                identifier.AppendChild(ResponderIdElement(doc, responderId));
                AppendText(doc, identifier, "ProducedAt", XadesUris.XadesNamespace, XmlTime(producedAt));
                ocspRef.AppendChild(identifier);
                var digest = doc.CreateElement("DigestAlgAndValue", XadesUris.XadesNamespace);
                AppendDigest(doc, digest, basic);
                ocspRef.AppendChild(digest);
                ocspRefs.AppendChild(ocspRef);
            }

            revocationRefs.AppendChild(ocspRefs);
        }

        unsignedProps.AppendChild(revocationRefs);
        return Save(doc);
    }

    /// <summary>
    /// The SigAndRefsTimeStamp input (implicit mode, ETSI TS 101 903 §7.5.1): the exclusive-c14n of
    /// ds:SignatureValue, then of each SignatureTimeStamp, CompleteCertificateRefs and
    /// CompleteRevocationRefs, in document order, concatenated.
    /// </summary>
    internal static byte[] CreateSigAndRefsTimeStampInput(byte[] signedXml, string? signatureId)
    {
        var doc = LoadDocument(signedXml);
        var ns = CreateNamespaceManager(doc);
        return CreateSigAndRefsTimeStampInput(ResolveSignature(doc, ns, signatureId), ns);
    }

    /// <summary>The SigAndRefsTimeStamp input of <paramref name="signature"/>.</summary>
    internal static byte[] CreateSigAndRefsTimeStampInput(XmlElement signature, XmlNamespaceManager ns)
    {
        if (signature.SelectSingleNode("ds:SignatureValue", ns) is not XmlElement signatureValue)
        {
            throw new InvalidOperationException("SignatureValue not found in signed XML.");
        }

        using var input = new MemoryStream();
        input.Write(CanonicalizeElement(signatureValue));
        var properties = signature.SelectNodes(
            "ds:Object/xades:QualifyingProperties/xades:UnsignedProperties/xades:UnsignedSignatureProperties/*", ns);
        foreach (XmlElement property in properties?.OfType<XmlElement>() ?? [])
        {
            if (property.NamespaceURI == XadesUris.XadesNamespace
                && property.LocalName is "SignatureTimeStamp" or "CompleteCertificateRefs" or "CompleteRevocationRefs"
                    or "AttributeCertificateRefs" or "AttributeRevocationRefs")
            {
                input.Write(CanonicalizeElement(property));
            }
        }

        return input.ToArray();
    }

    /// <summary>Appends a SigAndRefsTimeStamp (exclusive c14n) with the token.</summary>
    internal static byte[] EmbedSigAndRefsTimeStamp(byte[] signedXml, byte[] token, string? signatureId)
    {
        var doc = LoadDocument(signedXml);
        var ns = CreateNamespaceManager(doc);
        var unsignedProps = EnsureUnsignedSignatureProperties(doc, ResolveSignature(doc, ns, signatureId), ns);
        var timestamp = doc.CreateElement("SigAndRefsTimeStamp", XadesUris.XadesNamespace);
        timestamp.SetAttribute("Id", SigAndRefsTimeStampIdPrefix + Guid.NewGuid().ToString("N")[..8]);
        var c14n = doc.CreateElement("CanonicalizationMethod", XmlDSigUrls.DsNamespace);
        c14n.SetAttribute("Algorithm", XmlDSigUrls.ExcC14N);
        timestamp.AppendChild(c14n);
        AppendText(doc, timestamp, "EncapsulatedTimeStamp", XadesUris.XadesNamespace, Convert.ToBase64String(token));
        unsignedProps.AppendChild(timestamp);
        return Save(doc);
    }

    /// <summary>The SigAndRefsTimeStamp token of the signature, or null.</summary>
    internal static byte[]? ExtractSigAndRefsTimeStamp(byte[] signedXml, string? signatureId)
    {
        var doc = LoadDocument(signedXml);
        var ns = CreateNamespaceManager(doc);
        XmlElement signature;
        try
        {
            signature = ResolveSignature(doc, ns, signatureId);
        }
        catch (InvalidOperationException)
        {
            return null;
        }

        var token = signature.SelectSingleNode(
            "ds:Object/xades:QualifyingProperties/xades:UnsignedProperties/xades:UnsignedSignatureProperties/xades:SigAndRefsTimeStamp/xades:EncapsulatedTimeStamp", ns);
        return token is null || string.IsNullOrWhiteSpace(token.InnerText) ? null : Convert.FromBase64String(token.InnerText);
    }

    /// <summary>
    /// Checks the references against the embedded values: every CertRefs digest matches a
    /// certificate in CertificateValues or KeyInfo, every CRL/OCSP reference digest matches a value
    /// in RevocationValues. Without values (XAdES-C/X), only the structure is checked.
    /// </summary>
    internal static bool ValidateCompleteReferences(XmlElement signature, XmlNamespaceManager ns, List<string> warnings)
    {
        const string usp = "ds:Object/xades:QualifyingProperties/xades:UnsignedProperties/xades:UnsignedSignatureProperties/";
        if (signature.SelectSingleNode(usp + "xades:CompleteCertificateRefs", ns) is not XmlElement certificateRefs
            || signature.SelectSingleNode(usp + "xades:CompleteRevocationRefs", ns) is not XmlElement revocationRefs)
        {
            warnings.Add("XAdES-C: CompleteCertificateRefs or CompleteRevocationRefs is missing.");
            return false;
        }

        var certificates = Base64Values(signature, ns, usp + "xades:CertificateValues/xades:EncapsulatedX509Certificate")
            .Concat(Base64Values(signature, ns, "ds:KeyInfo/ds:X509Data/ds:X509Certificate")).ToList();
        var revocations = Base64Values(signature, ns, usp + "xades:RevocationValues/xades:CRLValues/xades:EncapsulatedCRLValue")
            .Concat(Base64Values(signature, ns, usp + "xades:RevocationValues/xades:OCSPValues/xades:EncapsulatedOCSPValue")
                .Select(RevocationEvidence.BasicResponse))
            .ToList();
        bool hasValues = signature.SelectSingleNode(usp + "xades:RevocationValues", ns) is not null;

        bool valid = true;
        foreach (XmlElement digest in certificateRefs.SelectNodes("xades:CertRefs/xades:Cert/xades:CertDigest", ns)?.OfType<XmlElement>() ?? [])
        {
            if (!MatchesAny(digest, ns, certificates))
            {
                warnings.Add("XAdES-C: a CompleteCertificateRefs digest matches no certificate in the signature.");
                valid = false;
            }
        }

        if (hasValues)
        {
            foreach (XmlElement digest in revocationRefs.SelectNodes(".//xades:DigestAlgAndValue", ns)?.OfType<XmlElement>() ?? [])
            {
                if (!MatchesAny(digest, ns, revocations))
                {
                    warnings.Add("XAdES-C: a CompleteRevocationRefs digest matches no CRL or OCSP value in RevocationValues.");
                    valid = false;
                }
            }
        }

        return valid;
    }

    private static (List<byte[]> Crls, List<byte[]> Ocsp) CoveringEvidence(
        IReadOnlyList<X509Certificate2> path, IReadOnlyList<byte[]> crls, IReadOnlyList<byte[]> ocspResponses)
    {
        var ocsp = RevocationEvidence.MatchingOcspClient();
        var coveringCrls = new List<byte[]>();
        var coveringOcsp = new List<byte[]>();
        for (int i = 0; i < Math.Max(1, path.Count - 1); i++)
        {
            var issuer = i + 1 < path.Count ? path[i + 1] : null;
            var (c, o) = RevocationEvidence.CoveringEvidence(ocsp, path[i], issuer, crls, ocspResponses);
            coveringCrls.AddRange(c.Where(x => !coveringCrls.Any(y => y.AsSpan().SequenceEqual(x))));
            coveringOcsp.AddRange(o.Where(x => !coveringOcsp.Any(y => y.AsSpan().SequenceEqual(x))));
        }

        return (coveringCrls, coveringOcsp);
    }

    /// <summary>ResponderID ::= CHOICE { byName [1] Name, byKey [2] KeyHash }.</summary>
    private static XmlElement ResponderIdElement(XmlDocument doc, byte[] responderId)
    {
        var element = doc.CreateElement("ResponderID", XadesUris.XadesNamespace);
        var reader = new AsnReader(responderId, AsnEncodingRules.BER);
        var tag = reader.PeekTag();
        var inner = reader.ReadSequence(tag);
        if (tag.TagValue == 2)
        {
            AppendText(doc, element, "ByKey", XadesUris.XadesNamespace, Convert.ToBase64String(inner.ReadOctetString()));
        }
        else
        {
            AppendText(doc, element, "ByName", XadesUris.XadesNamespace, new X500DistinguishedName(inner.ReadEncodedValue().Span).Name);
        }

        return element;
    }

    private static bool MatchesAny(XmlElement digestContainer, XmlNamespaceManager ns, List<byte[]> candidates)
    {
        if (digestContainer.SelectSingleNode("ds:DigestValue", ns) is not XmlElement value)
        {
            return false;
        }

        HashAlgorithmName algorithm;
        byte[] expected;
        try
        {
            string uri = (digestContainer.SelectSingleNode("ds:DigestMethod", ns) as XmlElement)?.GetAttribute("Algorithm") ?? XmlDSigUrls.Sha256Digest;
            algorithm = XmlDSigUrls.GetHashAlgorithmFromUri(uri);
            expected = Convert.FromBase64String(value.InnerText.Trim());
        }
        catch (Exception ex) when (ex is FormatException or NotSupportedException)
        {
            return false;
        }

        return candidates.Any(c => CryptographicOperations.FixedTimeEquals(Core.Crypto.CryptoUtility.ComputeHash(c, algorithm), expected));
    }

    private static IEnumerable<byte[]> Base64Values(XmlElement signature, XmlNamespaceManager ns, string xpath)
    {
        foreach (XmlNode node in signature.SelectNodes(xpath, ns)?.Cast<XmlNode>() ?? [])
        {
            byte[]? value;
            try
            {
                value = Convert.FromBase64String(node.InnerText.Trim());
            }
            catch (FormatException)
            {
                value = null;
            }

            if (value is not null)
            {
                yield return value;
            }
        }
    }

    private static void AppendDigest(XmlDocument doc, XmlElement parent, byte[] data)
    {
        var method = doc.CreateElement("DigestMethod", XmlDSigUrls.DsNamespace);
        method.SetAttribute("Algorithm", XmlDSigUrls.Sha256Digest);
        parent.AppendChild(method);
        AppendText(doc, parent, "DigestValue", XmlDSigUrls.DsNamespace, Convert.ToBase64String(SHA256.HashData(data)));
    }

    private static void AppendText(XmlDocument doc, XmlElement parent, string name, string ns, string text)
    {
        var element = doc.CreateElement(name, ns);
        element.InnerText = text;
        parent.AppendChild(element);
    }

    private static string XmlTime(DateTimeOffset time) =>
        time.UtcDateTime.ToString("yyyy-MM-ddTHH:mm:ssZ", CultureInfo.InvariantCulture);

    private static byte[] Save(XmlDocument doc)
    {
        using var ms = new MemoryStream();
        doc.Save(ms);
        return ms.ToArray();
    }
}
