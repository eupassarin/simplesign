using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Xml;
using SimpleSign.Core.Constants;
using SimpleSign.Core.Crypto;
using SimpleSign.Core.Revocation;
using SimpleSign.Core.Validation;
using SimpleSign.XAdES.Constants;

namespace SimpleSign.XAdES;

internal static partial class XadesSignatureBuilder
{
    internal static bool HasLtvData(byte[] signedXml, LtvEvidence expectedEvidence)
    {
        ArgumentNullException.ThrowIfNull(expectedEvidence);
        if (!expectedEvidence.HasCompleteCoverage)
        {
            return false;
        }

        try
        {
            var doc = new XmlDocument { PreserveWhitespace = true };
            doc.Load(new MemoryStream(signedXml));
            var ns = new XmlNamespaceManager(doc.NameTable);
            ns.AddNamespace("xades", XadesUris.XadesNamespace);

            IReadOnlyList<byte[]> certificates = DecodeEmbeddedValues(
                doc.SelectNodes("//xades:CertificateValues/xades:EncapsulatedX509Certificate", ns));
            IReadOnlyList<byte[]> ocspResponses = DecodeEmbeddedValues(
                doc.SelectNodes("//xades:RevocationValues/xades:OCSPValues/xades:EncapsulatedOCSPValue", ns));
            IReadOnlyList<byte[]> crls = DecodeEmbeddedValues(
                doc.SelectNodes("//xades:RevocationValues/xades:CRLValues/xades:EncapsulatedCRLValue", ns));

            return ContainsAll(certificates, expectedEvidence.CertificateRawData) &&
                ContainsAll(ocspResponses, expectedEvidence.OcspResponses) &&
                ContainsAll(crls, expectedEvidence.Crls) &&
                (expectedEvidence.OcspResponses.Count > 0 || expectedEvidence.Crls.Count > 0) &&
                HasAuthenticatedEvidence(certificates, ocspResponses, crls);
        }
        catch (Exception ex) when (ex is FormatException or XmlException or CryptographicException
            or AsnContentException or InvalidDataException)
        {
            return false;
        }
    }

    private static bool HasAuthenticatedEvidence(
        IReadOnlyList<byte[]> certificateBytes,
        IReadOnlyList<byte[]> ocspResponses,
        IReadOnlyList<byte[]> crls)
    {
        var certificates = new List<X509Certificate2>();
        try
        {
            foreach (byte[] raw in certificateBytes)
            {
                certificates.Add(CertificateLoader.LoadCertificate(raw));
            }

            return EmbeddedRevocationEvidence.CoversAll(
                certificates, ocspResponses, crls, DateTimeOffset.UtcNow, RevocationEvidence.MatchingOcspClient());
        }
        finally
        {
            foreach (var certificate in certificates)
            {
                certificate.Dispose();
            }
        }
    }

    private static IReadOnlyList<byte[]> DecodeEmbeddedValues(XmlNodeList? nodes)
    {
        if (nodes is null)
        {
            return [];
        }

        var values = new List<byte[]>(nodes.Count);
        foreach (XmlElement node in nodes.OfType<XmlElement>())
        {
            if (!string.IsNullOrWhiteSpace(node.InnerText))
            {
                values.Add(Convert.FromBase64String(node.InnerText.Trim()));
            }
        }

        return values;
    }

    private static bool ContainsAll(IReadOnlyList<byte[]> embeddedValues, IReadOnlyList<byte[]> expectedValues)
    {
        foreach (byte[] expected in expectedValues)
        {
            if (!embeddedValues.Any(value => value.AsSpan().SequenceEqual(expected)))
            {
                return false;
            }
        }

        return true;
    }

    internal static byte[] EmbedLtvData(byte[] signedXml, LtvEvidence ltvData,
        string? signatureId = null)
    {
        var doc = new XmlDocument { PreserveWhitespace = true };
        doc.Load(new MemoryStream(signedXml));
        var ns = new XmlNamespaceManager(doc.NameTable);
        ns.AddNamespace("ds", XmlDSigUrls.DsNamespace);
        ns.AddNamespace("xades", XadesUris.XadesNamespace);

        XmlElement signature = ResolveSignature(doc, ns, signatureId);

        var unsignedProps = EnsureUnsignedSignatureProperties(doc, signature, ns);
        string idSuffix = Guid.NewGuid().ToString("N")[..8];

        if (ltvData.CertificateRawData.Count > 0)
        {
            var certValues = doc.CreateElement("CertificateValues", XadesUris.XadesNamespace);
            certValues.SetAttribute("Id", XadesUris.CertificateValuesIdPrefix + idSuffix);
            foreach (var certBytes in ltvData.CertificateRawData)
            {
                var encCert = doc.CreateElement("EncapsulatedX509Certificate", XadesUris.XadesNamespace);
                encCert.InnerText = Convert.ToBase64String(certBytes);
                certValues.AppendChild(encCert);
            }
            unsignedProps.AppendChild(certValues);
        }

        if (ltvData.OcspResponses.Count > 0 || ltvData.Crls.Count > 0)
        {
            var revValues = doc.CreateElement("RevocationValues", XadesUris.XadesNamespace);
            revValues.SetAttribute("Id", XadesUris.RevocationValuesIdPrefix + idSuffix);

            if (ltvData.OcspResponses.Count > 0)
            {
                var ocspRefs = doc.CreateElement("OCSPValues", XadesUris.XadesNamespace);
                foreach (var ocspBytes in ltvData.OcspResponses)
                {
                    var encOcsp = doc.CreateElement("EncapsulatedOCSPValue", XadesUris.XadesNamespace);
                    encOcsp.InnerText = Convert.ToBase64String(ocspBytes);
                    ocspRefs.AppendChild(encOcsp);
                }
                revValues.AppendChild(ocspRefs);
            }

            if (ltvData.Crls.Count > 0)
            {
                var crlRefs = doc.CreateElement("CRLValues", XadesUris.XadesNamespace);
                foreach (var crlBytes in ltvData.Crls)
                {
                    var encCrl = doc.CreateElement("EncapsulatedCRLValue", XadesUris.XadesNamespace);
                    encCrl.InnerText = Convert.ToBase64String(crlBytes);
                    crlRefs.AppendChild(encCrl);
                }
                revValues.AppendChild(crlRefs);
            }

            unsignedProps.AppendChild(revValues);
        }

        using var ms = new MemoryStream();
        doc.Save(ms);
        return ms.ToArray();
    }
}
