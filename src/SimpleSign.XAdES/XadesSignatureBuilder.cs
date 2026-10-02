using System.Diagnostics.CodeAnalysis;
using System.Formats.Asn1;
using System.Globalization;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Xml;
using Microsoft.Extensions.Logging;
using SimpleSign.CAdES;
using SimpleSign.Core.Constants;
using SimpleSign.Core.Crypto;
using SimpleSign.Core.Signing;
using SimpleSign.Core.Revocation;
using SimpleSign.Core.Validation;
using SimpleSign.XAdES.Constants;

namespace SimpleSign.XAdES;

[RequiresUnreferencedCode("XAdES uses System.Security.Cryptography.Xml which is not AOT-compatible.")]
[RequiresDynamicCode("XAdES uses System.Security.Cryptography.Xml which is not AOT-compatible.")]
internal static class XadesSignatureBuilder
{
    internal static byte[] BuildSignature(
        byte[] xmlData,
        X509Certificate2 certificate,
        HashAlgorithmName hashAlgorithm,
        DateTimeOffset signingTime,
        IReadOnlyList<X509Certificate2>? extraCertificates,
        CommitmentType? commitmentType,
        string? signaturePolicyOid,
        string? signaturePolicyUri,
        string signatureAlgorithmOid,
        XadesForm form,
        IReadOnlyList<string>? signerRoles,
        DataObjectFormat? dataObjectFormat,
        ILogger logger,
        string? dataUri = null)
    {
        if (form != XadesForm.Enveloped)
        {
            return BuildStandaloneSignature(xmlData, certificate, hashAlgorithm, signingTime,
                extraCertificates, commitmentType, signaturePolicyOid, signaturePolicyUri,
                signatureAlgorithmOid, form, dataUri, signerRoles, dataObjectFormat, logger);
        }

        var xmlDoc = new XmlDocument { PreserveWhitespace = true };
        xmlDoc.Load(new MemoryStream(xmlData));

        if (xmlDoc.DocumentElement is null)
        {
            throw new ArgumentException("XML data does not contain a root element.", nameof(xmlData));
        }

        string signatureId = XadesUris.SignatureIdPrefix + Guid.NewGuid().ToString("N")[..8];
        string signedPropertiesId = XadesUris.SignedPropertiesIdPrefix + Guid.NewGuid().ToString("N")[..8];

        var signedProperties = CreateSignedProperties(
            xmlDoc, certificate, hashAlgorithm, signingTime,
            signedPropertiesId, signatureId, commitmentType,
            signaturePolicyOid, signaturePolicyUri, signerRoles, dataObjectFormat);

        var qualifyingProps = CreateQualifyingProperties(xmlDoc, signatureId, signedProperties);

        var objectElement = xmlDoc.CreateElement("Object", XmlDSigUrls.DsNamespace);
        objectElement.AppendChild(qualifyingProps);

        // Pre-add a temporary Signature so SignedProperties is resolvable by ID
        var tempSig = xmlDoc.CreateElement("Signature", XmlDSigUrls.DsNamespace);
        tempSig.SetAttribute("Id", signatureId);
        tempSig.AppendChild(xmlDoc.ImportNode(objectElement, true));
        xmlDoc.DocumentElement!.AppendChild(tempSig);

        // --- Compute reference digests manually ---
        // XmlDsigEnvelopedSignatureTransform is a no-op in .NET 10, so we
        // cannot rely on SignedXml.ComputeSignature() for the document digest.

        // 1. Document reference: canonicalize doc. For enveloped, remove all Signature elements.
        byte[] docDigest = ComputeDocumentDigest(xmlDoc, hashAlgorithm, form);

        // 2. SignedProperties reference: canonicalize element by Id
        byte[] signedPropsDigest = ComputeElementDigest(xmlDoc, signedPropertiesId, hashAlgorithm);

        // --- Build SignedInfo with correct digest values ---
        var signedInfo = xmlDoc.CreateElement("SignedInfo", XmlDSigUrls.DsNamespace);

        var cm = xmlDoc.CreateElement("CanonicalizationMethod", XmlDSigUrls.DsNamespace);
        cm.SetAttribute("Algorithm", XmlDSigUrls.ExcC14N);
        signedInfo.AppendChild(cm);

        var sm = xmlDoc.CreateElement("SignatureMethod", XmlDSigUrls.DsNamespace);
        sm.SetAttribute("Algorithm", GetSignatureMethodUri(signatureAlgorithmOid, hashAlgorithm));
        signedInfo.AppendChild(sm);

        // Document reference
        bool enveloped = form == XadesForm.Enveloped;
        signedInfo.AppendChild(CreateDocRef(xmlDoc, "", hashAlgorithm, enveloped, docDigest));

        // SignedProperties reference
        signedInfo.AppendChild(CreateDocRef(xmlDoc, "#" + signedPropertiesId, hashAlgorithm,
            enveloped: false, signedPropsDigest, signedPropsType: true));

        // --- Canonicalize SignedInfo and compute signature ---
        var siDoc = new XmlDocument { PreserveWhitespace = true };
        siDoc.AppendChild(siDoc.ImportNode(signedInfo, true));
        byte[] signedInfoCanonical = CanonicalizeXml(siDoc);
        byte[] signedInfoHash = HashData(hashAlgorithm, signedInfoCanonical);

        // Sign
        byte[] signatureValueBytes = SignHash(signedInfoHash, hashAlgorithm, signatureAlgorithmOid, certificate);

        // --- Build final Signature element ---
        var realSig = xmlDoc.CreateElement("Signature", XmlDSigUrls.DsNamespace);
        realSig.SetAttribute("Id", signatureId);
        realSig.AppendChild(xmlDoc.ImportNode(signedInfo, true));

        var svEl = xmlDoc.CreateElement("SignatureValue", XmlDSigUrls.DsNamespace);
        svEl.InnerText = Convert.ToBase64String(signatureValueBytes);
        realSig.AppendChild(svEl);

        var keyInfo = xmlDoc.CreateElement("KeyInfo", XmlDSigUrls.DsNamespace);
        var x509Data = xmlDoc.CreateElement("X509Data", XmlDSigUrls.DsNamespace);
        var x509Cert = xmlDoc.CreateElement("X509Certificate", XmlDSigUrls.DsNamespace);
        x509Cert.InnerText = Convert.ToBase64String(certificate.RawData);
        x509Data.AppendChild(x509Cert);
        if (extraCertificates is not null)
        {
            foreach (var cert in extraCertificates)
            {
                var extraCertEl = xmlDoc.CreateElement("X509Certificate", XmlDSigUrls.DsNamespace);
                extraCertEl.InnerText = Convert.ToBase64String(cert.RawData);
                x509Data.AppendChild(extraCertEl);
            }
        }
        keyInfo.AppendChild(x509Data);
        realSig.AppendChild(keyInfo);

        realSig.AppendChild(xmlDoc.ImportNode(objectElement, true));

        // Replace tempSig with realSig
        xmlDoc.DocumentElement!.RemoveChild(tempSig);
        xmlDoc.DocumentElement!.AppendChild(realSig);

        using var ms = new MemoryStream();
        xmlDoc.Save(ms);
        return ms.ToArray();
    }

    internal static byte[] BuildSignedInfoToHash(
        byte[] xmlData,
        X509Certificate2 certificate,
        HashAlgorithmName hashAlgorithm,
        DateTimeOffset signingTime,
        XadesForm form,
        CommitmentType? commitmentType,
        string? signaturePolicyOid,
        string? signaturePolicyUri,
        string signatureAlgorithmOid,
        IReadOnlyList<string>? signerRoles,
        DataObjectFormat? dataObjectFormat,
        out string signedPropertiesId,
        out byte[] signedInfoXmlBytes,
        out string? dataObjectId,
        string? dataUri = null)
    {
        if (form != XadesForm.Enveloped)
        {
            return BuildStandaloneSignedInfoToHash(xmlData, certificate, hashAlgorithm, signingTime,
                form, commitmentType, signaturePolicyOid, signaturePolicyUri, signatureAlgorithmOid,
                signerRoles, dataObjectFormat, out signedPropertiesId, out signedInfoXmlBytes,
                out dataObjectId, dataUri);
        }

        dataObjectId = null;

        signedPropertiesId = "SignedProperties-" + Guid.NewGuid().ToString("N")[..8];
        string signatureId = XadesUris.SignatureIdPrefix + Guid.NewGuid().ToString("N")[..8];

        // Create a temporary document with all elements so digests can be computed
        var xmlDoc = new XmlDocument { PreserveWhitespace = true };
        xmlDoc.Load(new MemoryStream(xmlData));

        if (xmlDoc.DocumentElement is null)
        {
            throw new ArgumentException("XML data does not contain a root element.", nameof(xmlData));
        }

        var signedProperties = CreateSignedProperties(
            xmlDoc, certificate, hashAlgorithm, signingTime,
            signedPropertiesId, signatureId, commitmentType,
            signaturePolicyOid, signaturePolicyUri, signerRoles, dataObjectFormat);

        var qualifyingProps = CreateQualifyingProperties(xmlDoc, signatureId, signedProperties);
        var objectElement = xmlDoc.CreateElement("Object", XmlDSigUrls.DsNamespace);
        objectElement.AppendChild(qualifyingProps);

        // Pre-add a temporary Signature so SignedProperties is resolvable by ID
        var tempSig = xmlDoc.CreateElement("Signature", XmlDSigUrls.DsNamespace);
        tempSig.SetAttribute("Id", signatureId);
        tempSig.AppendChild(xmlDoc.ImportNode(objectElement, true));
        xmlDoc.DocumentElement!.AppendChild(tempSig);

        // Compute actual digest values
        byte[] docDigest = ComputeDocumentDigest(xmlDoc, hashAlgorithm, form);
        byte[] signedPropsDigest = ComputeElementDigest(xmlDoc, signedPropertiesId, hashAlgorithm);

        // Build SignedInfo with the real digest values
        var siDoc = new XmlDocument();
        var siElement = siDoc.CreateElement("SignedInfo", XmlDSigUrls.DsNamespace);

        var cmElement = siDoc.CreateElement("CanonicalizationMethod", XmlDSigUrls.DsNamespace);
        cmElement.SetAttribute("Algorithm", XmlDSigUrls.ExcC14N);
        siElement.AppendChild(cmElement);

        var smElement = siDoc.CreateElement("SignatureMethod", XmlDSigUrls.DsNamespace);
        smElement.SetAttribute("Algorithm", GetSignatureMethodUri(signatureAlgorithmOid, hashAlgorithm));
        siElement.AppendChild(smElement);

        // Document reference with actual digest
        siElement.AppendChild(CreateDocRef(siDoc, "", hashAlgorithm, form == XadesForm.Enveloped, docDigest));

        // SignedProperties reference with actual digest
        siElement.AppendChild(CreateDocRef(siDoc, "#" + signedPropertiesId, hashAlgorithm,
            enveloped: false, signedPropsDigest, signedPropsType: true));

        // Save the InnerXml for embedding (children without wrapping SignedInfo element)
        signedInfoXmlBytes = Encoding.UTF8.GetBytes(siElement.InnerXml);

        var finalSiDoc = new XmlDocument { PreserveWhitespace = true };
        finalSiDoc.AppendChild(finalSiDoc.ImportNode(siElement, true));
        byte[] canonical = CanonicalizeXml(finalSiDoc);

        return canonical;
    }

    internal static byte[] CompleteWithExternalSignature(
        byte[] xmlData,
        X509Certificate2 certificate,
        HashAlgorithmName hashAlgorithm,
        DateTimeOffset signingTime,
        IReadOnlyList<X509Certificate2>? extraCertificates,
        CommitmentType? commitmentType,
        string? signaturePolicyOid,
        string? signaturePolicyUri,
        string signatureAlgorithmOid,
        byte[] signedInfoBytes,
        byte[] signatureValue,
        string signedPropertiesId,
        IReadOnlyList<string>? signerRoles,
        DataObjectFormat? dataObjectFormat,
        XadesForm form = XadesForm.Enveloped,
        string? dataUri = null,
        string? dataObjectId = null)
    {
        if (form != XadesForm.Enveloped)
        {
            return CompleteStandaloneExternalSignature(xmlData, certificate, hashAlgorithm, signingTime,
                extraCertificates, commitmentType, signaturePolicyOid, signaturePolicyUri,
                signatureAlgorithmOid, signedInfoBytes, signatureValue, signedPropertiesId,
                signerRoles, dataObjectFormat, form, dataUri, dataObjectId);
        }

        var xmlDoc = new XmlDocument { PreserveWhitespace = true };
        xmlDoc.Load(new MemoryStream(xmlData));

        if (xmlDoc.DocumentElement is null)
        {
            throw new ArgumentException("XML data does not contain a root element.", nameof(xmlData));
        }

        string signatureId = XadesUris.SignatureIdPrefix + Guid.NewGuid().ToString("N")[..8];

        var sigElement = xmlDoc.CreateElement("Signature", XmlDSigUrls.DsNamespace);
        sigElement.SetAttribute("Id", signatureId);

        var siElement = xmlDoc.CreateElement("SignedInfo", XmlDSigUrls.DsNamespace);
        siElement.InnerXml = Encoding.UTF8.GetString(signedInfoBytes);
        sigElement.AppendChild(siElement);

        var sigValueElement = xmlDoc.CreateElement("SignatureValue", XmlDSigUrls.DsNamespace);
        sigValueElement.InnerText = Convert.ToBase64String(signatureValue);
        sigElement.AppendChild(sigValueElement);

        var keyInfo = new KeyInfo();
        var x509Data = new KeyInfoX509Data(certificate);
        if (extraCertificates is not null)
        {
            foreach (var cert in extraCertificates)
            {
                x509Data.AddCertificate(cert);
            }
        }
        keyInfo.AddClause(x509Data);
        var kiXml = keyInfo.GetXml();
        if (kiXml is not null)
        {
            sigElement.AppendChild(xmlDoc.ImportNode(kiXml, true));
        }

        var signedProperties = CreateSignedProperties(
            xmlDoc, certificate, hashAlgorithm, signingTime,
            signedPropertiesId, signatureId, commitmentType,
            signaturePolicyOid, signaturePolicyUri, signerRoles, dataObjectFormat);

        var qualifyingProps = CreateQualifyingProperties(xmlDoc, signatureId, signedProperties);
        var objElement = xmlDoc.CreateElement("Object", XmlDSigUrls.DsNamespace);
        objElement.AppendChild(qualifyingProps);
        sigElement.AppendChild(objElement);

        xmlDoc.DocumentElement!.AppendChild(sigElement);

        using var ms = new MemoryStream();
        xmlDoc.Save(ms);
        return ms.ToArray();
    }

    internal static byte[] ExtractSignatureValue(byte[] signedXml)
    {
        var doc = new XmlDocument();
        doc.Load(new MemoryStream(signedXml));
        var ns = new XmlNamespaceManager(doc.NameTable);
        ns.AddNamespace("ds", XmlDSigUrls.DsNamespace);

        var sigValue = doc.SelectSingleNode("//ds:Signature/ds:SignatureValue", ns);
        if (sigValue is null)
        {
            throw new InvalidOperationException("SignatureValue not found in signed XML.");
        }

        return Convert.FromBase64String(sigValue.InnerText);
    }

    /// <summary>
    /// Builds the XAdES SignatureTimeStamp input by canonicalizing the SignatureValue element.
    /// </summary>
    /// <remarks>
    /// ETSI EN 319 132-1 §5.4.1 timestamps the canonical XML element, rather than its decoded
    /// base64 value. The exclusive canonicalization used by SimpleSign is declared when embedding
    /// a newly produced SignatureTimeStamp.
    /// </remarks>
    internal static byte[] CreateSignatureTimeStampInput(byte[] signedXml) =>
        CreateSignatureTimeStampInput(signedXml, signatureId: null);

    internal static string GetLastSignatureId(byte[] signedXml)
    {
        var doc = new XmlDocument { PreserveWhitespace = true };
        doc.Load(new MemoryStream(signedXml));
        var ns = CreateNamespaceManager(doc);
        var signatures = doc.SelectNodes("//ds:Signature", ns);
        if (signatures is null || signatures.Count == 0 ||
            signatures[signatures.Count - 1] is not XmlElement signature ||
            string.IsNullOrEmpty(signature.GetAttribute("Id")))
        {
            throw new InvalidOperationException("The newly created signature has no XMLDSig Id.");
        }

        return signature.GetAttribute("Id");
    }

    /// <summary>Builds the signature-timestamp input for the identified XMLDSig signature.</summary>
    internal static byte[] CreateSignatureTimeStampInput(byte[] signedXml, string? signatureId)
    {
        var doc = new XmlDocument { PreserveWhitespace = true };
        doc.Load(new MemoryStream(signedXml));
        var ns = CreateNamespaceManager(doc);
        XmlElement signature = ResolveSignature(doc, ns, signatureId);
        if (signature.SelectSingleNode("ds:SignatureValue", ns) is not XmlElement signatureValue)
        {
            throw new InvalidOperationException("SignatureValue not found in signed XML.");
        }

        return CanonicalizeElement(signatureValue);
    }

    internal static byte[] EmbedSignatureTimeStamp(byte[] signedXml, byte[] tsToken) =>
        EmbedSignatureTimeStamp(signedXml, tsToken, signatureId: null);

    /// <summary>Embeds a signature timestamp in the identified XMLDSig signature.</summary>
    internal static byte[] EmbedSignatureTimeStamp(byte[] signedXml, byte[] tsToken, string? signatureId)
    {
        var doc = new XmlDocument { PreserveWhitespace = true };
        doc.Load(new MemoryStream(signedXml));
        var ns = CreateNamespaceManager(doc);
        XmlElement signature = ResolveSignature(doc, ns, signatureId);

        var unsignedProps = EnsureUnsignedSignatureProperties(doc, signature, ns);

        var tsElement = doc.CreateElement("SignatureTimeStamp", XadesUris.XadesNamespace);
        tsElement.SetAttribute("Id", XadesUris.SignatureTimeStampIdPrefix + Guid.NewGuid().ToString("N")[..8]);
        var canonicalizationElement = doc.CreateElement("CanonicalizationMethod", XmlDSigUrls.DsNamespace);
        canonicalizationElement.SetAttribute("Algorithm", XmlDSigUrls.ExcC14N);
        tsElement.AppendChild(canonicalizationElement);
        var encElement = doc.CreateElement("EncapsulatedTimeStamp", XadesUris.XadesNamespace);
        encElement.InnerText = Convert.ToBase64String(tsToken);
        tsElement.AppendChild(encElement);
        unsignedProps.AppendChild(tsElement);

        using var ms = new MemoryStream();
        doc.Save(ms);
        return ms.ToArray();
    }

    internal static byte[]? ExtractSignatureTimeStamp(byte[] signedXml) =>
        ExtractSignatureTimeStamp(signedXml, signatureId: null);

    /// <summary>Extracts the signature timestamp token from the identified XMLDSig signature.</summary>
    internal static byte[]? ExtractSignatureTimeStamp(byte[] signedXml, string? signatureId)
    {
        var doc = new XmlDocument { PreserveWhitespace = true };
        doc.Load(new MemoryStream(signedXml));
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

        var timestamp = signature.SelectSingleNode(
            "ds:Object/xades:QualifyingProperties/xades:UnsignedProperties/" +
            "xades:UnsignedSignatureProperties/xades:SignatureTimeStamp/xades:EncapsulatedTimeStamp", ns) ??
            signature.SelectSingleNode(
                "ds:Object/xades:QualifyingProperties/xades:UnsignedProperties/" +
                "xades:SignatureTimeStamp/xades:EncapsulatedTimeStamp", ns);
        if (timestamp is null || string.IsNullOrWhiteSpace(timestamp.InnerText))
        {
            return null;
        }

        return Convert.FromBase64String(timestamp.InnerText);
    }

    internal static bool HasLtvData(byte[] signedXml, LtvCollectionResult expectedEvidence)
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
#if NET10_0_OR_GREATER
                certificates.Add(X509CertificateLoader.LoadCertificate(raw));
#else
                certificates.Add(new X509Certificate2(raw));
#endif
            }

            using var httpClient = new HttpClient();
            return EmbeddedRevocationEvidence.CoversAll(
                certificates, ocspResponses, crls, DateTimeOffset.UtcNow, new OcspClient(httpClient));
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

    internal static byte[] EmbedLtvData(byte[] signedXml, LtvCollectionResult ltvData,
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

    internal static byte[] EmbedArchiveTimeStamp(byte[] signedXml, byte[] tsToken) =>
        EmbedArchiveTimeStamp(signedXml, tsToken, signatureId: null);

    /// <summary>Embeds an archive timestamp in the signature identified by <paramref name="signatureId"/>.</summary>
    internal static byte[] EmbedArchiveTimeStamp(byte[] signedXml, byte[] tsToken, string? signatureId)
    {
        var doc = new XmlDocument { PreserveWhitespace = true };
        doc.Load(new MemoryStream(signedXml));
        var ns = new XmlNamespaceManager(doc.NameTable);
        ns.AddNamespace("ds", XmlDSigUrls.DsNamespace);
        ns.AddNamespace("xades", XadesUris.XadesNamespace);
        ns.AddNamespace("xades141", XadesUris.Xades141Namespace);

        XmlElement signature = ResolveSignature(doc, ns, signatureId);

        var unsignedProps = EnsureUnsignedSignatureProperties(doc, signature, ns);

        var atsElement = doc.CreateElement("ArchiveTimeStamp", XadesUris.Xades141Namespace);
        atsElement.SetAttribute("Id", XadesUris.ArchiveTimeStampIdPrefix + Guid.NewGuid().ToString("N")[..8]);
        var canonicalizationMethod = doc.CreateElement("CanonicalizationMethod", XmlDSigUrls.DsNamespace);
        canonicalizationMethod.SetAttribute("Algorithm", XmlDSigUrls.ExcC14N);
        atsElement.AppendChild(canonicalizationMethod);
        var encElement = doc.CreateElement("EncapsulatedTimeStamp", XadesUris.Xades141Namespace);
        encElement.InnerText = Convert.ToBase64String(tsToken);
        atsElement.AppendChild(encElement);
        unsignedProps.AppendChild(atsElement);

        using var ms = new MemoryStream();
        doc.Save(ms);
        return ms.ToArray();
    }

    /// <summary>
    /// Builds the ArchiveTimeStamp input specified by ETSI EN 319 132-1 §5.5.2.2 or §5.5.2.3.
    /// </summary>
    /// <remarks>
    /// The current ArchiveTimeStamp must already be present in the signature so that this method can
    /// delimit the preceding unsigned properties. The ArchiveTimeStamp itself is deliberately excluded.
    /// </remarks>
    internal static byte[] CreateArchiveTimeStampInput(
        byte[] signedXml,
        byte[]? detachedData = null,
        string? signatureId = null)
    {
        var doc = new XmlDocument { PreserveWhitespace = true };
        doc.Load(new MemoryStream(signedXml));
        var ns = CreateNamespaceManager(doc);
        XmlElement signature = ResolveSignature(doc, ns, signatureId);

        XmlElement archiveTimeStamp = FindLatestArchiveTimeStamp(signature, ns)
            ?? throw new InvalidOperationException("ArchiveTimeStamp element not found.");
        string canonicalizationAlgorithm = ValidateArchiveCanonicalization(archiveTimeStamp, ns);

        var octets = new List<byte[]>();
        var references = signature.SelectNodes("ds:SignedInfo/ds:Reference", ns);
        if (references is not null)
        {
            foreach (XmlElement reference in references)
            {
                string uri = reference.GetAttribute("URI");
                octets.Add(ProcessArchiveReference(doc, reference, uri, detachedData, canonicalizationAlgorithm));
            }
        }

        if (signature.SelectSingleNode("ds:SignedInfo", ns) is not XmlElement signedInfo ||
            signature.SelectSingleNode("ds:SignatureValue", ns) is not XmlElement signatureValue)
        {
            throw new InvalidOperationException("Signature is missing SignedInfo or SignatureValue.");
        }

        octets.Add(CanonicalizeElement(signedInfo, canonicalizationAlgorithm));
        octets.Add(CanonicalizeElement(signatureValue, canonicalizationAlgorithm));
        if (signature.SelectSingleNode("ds:KeyInfo", ns) is XmlElement keyInfo)
        {
            octets.Add(CanonicalizeElement(keyInfo, canonicalizationAlgorithm));
        }

        if (archiveTimeStamp.SelectSingleNode("xades:Include | xades141:Include", ns) is not null)
        {
            AppendDistributedUnsignedProperties(
                octets,
                doc,
                archiveTimeStamp,
                ns,
                canonicalizationAlgorithm);
        }
        else
        {
            AppendPrecedingUnsignedProperties(octets, signature, archiveTimeStamp, ns, canonicalizationAlgorithm);
        }

        AppendUnreferencedObjects(octets, signature, ns, canonicalizationAlgorithm);
        return Concatenate(octets);
    }

    /// <summary>Extracts the most recent archive timestamp token from a signed XAdES document.</summary>
    internal static byte[]? ExtractArchiveTimeStamp(byte[] signedXml, string? signatureId = null)
    {
        var doc = new XmlDocument { PreserveWhitespace = true };
        doc.Load(new MemoryStream(signedXml));
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

        if (FindLatestArchiveTimeStamp(signature, ns) is not XmlElement archiveTimeStamp)
        {
            return null;
        }

        XmlNode? encapsulated = archiveTimeStamp.SelectSingleNode("xades141:EncapsulatedTimeStamp", ns) ??
            archiveTimeStamp.SelectSingleNode("xades:EncapsulatedTimeStamp", ns);
        return encapsulated is null ? null : Convert.FromBase64String(encapsulated.InnerText.Trim());
    }

    /// <summary>Verifies the archive timestamp message imprint against the ETSI-defined preimage.</summary>
    internal static bool ValidateArchiveTimeStamp(
        byte[] signedXml,
        byte[]? detachedData,
        List<string> warnings,
        string? signatureId = null)
    {
        try
        {
            byte[]? token = ExtractArchiveTimeStamp(signedXml, signatureId);
            if (token is null)
            {
                warnings.Add("XAdES-B-LTA: ArchiveTimeStamp does not contain an EncapsulatedTimeStamp.");
                return false;
            }

            if (!TimestampValidator.VerifyTokenSignature(token))
            {
                warnings.Add("XAdES-B-LTA: ArchiveTimeStamp token CMS signature is invalid.");
                return false;
            }

            CmsSignedData timestamp = CmsParser.Parse(token);
            HashAlgorithmName hashAlgorithm = GetTimestampHashAlgorithm(timestamp.TstMessageImprintHashAlgOid);
            byte[] input = CreateArchiveTimeStampInput(signedXml, detachedData, signatureId);
            TimestampClient.ValidateTimestampToken(token, input, hashAlgorithm);
            return true;
        }
        catch (Exception ex) when (ex is XmlException or FormatException or CryptographicException or
            InvalidOperationException or TimestampException or NotSupportedException)
        {
            warnings.Add($"XAdES-B-LTA: ArchiveTimeStamp validation failed: {ex.Message}");
            return false;
        }
    }

    private static XmlNamespaceManager CreateNamespaceManager(XmlDocument doc)
    {
        var ns = new XmlNamespaceManager(doc.NameTable);
        ns.AddNamespace("ds", XmlDSigUrls.DsNamespace);
        ns.AddNamespace("xades", XadesUris.XadesNamespace);
        ns.AddNamespace("xades141", XadesUris.Xades141Namespace);
        return ns;
    }

    private static XmlElement? FindLatestArchiveTimeStamp(XmlElement signature, XmlNamespaceManager ns)
    {
        XmlNodeList? nodes = signature.SelectNodes(
            "ds:Object/xades:QualifyingProperties/xades:UnsignedProperties/" +
            "xades:UnsignedSignatureProperties/xades141:ArchiveTimeStamp | " +
            "ds:Object/xades:QualifyingProperties/xades:UnsignedProperties/" +
            "xades:UnsignedSignatureProperties/xades:ArchiveTimeStamp", ns);
        return nodes is { Count: > 0 } ? nodes[nodes.Count - 1] as XmlElement : null;
    }

    private static XmlElement ResolveSignature(
        XmlDocument doc,
        XmlNamespaceManager ns,
        string? signatureId)
    {
        XmlNodeList? signatures = doc.SelectNodes("//ds:Signature", ns);
        if (signatures is null || signatures.Count == 0)
        {
            throw new InvalidOperationException("Signature element not found.");
        }

        if (!string.IsNullOrWhiteSpace(signatureId))
        {
            foreach (XmlElement candidate in signatures)
            {
                if (string.Equals(candidate.GetAttribute("Id"), signatureId, StringComparison.Ordinal))
                {
                    return candidate;
                }
            }

            throw new InvalidOperationException($"Signature '{signatureId}' was not found.");
        }

        if (signatures.Count != 1 || signatures[0] is not XmlElement signature)
        {
            throw new NotSupportedException(
                "An ArchiveTimeStamp operation on a multi-signature document must identify the target signature.");
        }

        return signature;
    }

    private static string ValidateArchiveCanonicalization(XmlElement archiveTimeStamp, XmlNamespaceManager ns)
    {
        if (archiveTimeStamp.SelectSingleNode("ds:CanonicalizationMethod", ns) is not XmlElement method)
        {
            throw new NotSupportedException("ArchiveTimeStamp must declare its canonicalization algorithm.");
        }

        string algorithm = method.GetAttribute("Algorithm");
        if (algorithm is not XmlDSigUrls.ExcC14N and not XmlDSigUrls.ExcC14NWithComments and
            not XmlDSigUrls.C14N and not XmlDSigUrls.C14NWithComments)
        {
            throw new NotSupportedException($"Unsupported ArchiveTimeStamp canonicalization algorithm '{algorithm}'.");
        }

        return algorithm;
    }

    private static byte[] ProcessArchiveReference(
        XmlDocument doc,
        XmlElement reference,
        string uri,
        byte[]? detachedData,
        string canonicalizationAlgorithm)
    {
        XmlNamespaceManager ns = CreateNamespaceManager(doc);
        string referenceCanonicalizationAlgorithm = GetReferenceCanonicalizationAlgorithm(
            reference,
            ns,
            canonicalizationAlgorithm);

        if (uri.Length == 0)
        {
            var clone = (XmlDocument)doc.CloneNode(true);
            return ApplyReferenceTransforms(clone, clone.DocumentElement!, reference, referenceCanonicalizationAlgorithm);
        }

        if (uri.StartsWith('#'))
        {
            XmlElement target = FindElementByBareNameId(doc, uri, "Archive reference");

            return ApplyReferenceTransforms(doc, target, reference, referenceCanonicalizationAlgorithm);
        }

        if (detachedData is null)
        {
            throw new InvalidOperationException("Detached data is required to validate an external archive reference.");
        }

        if (HasTransform(reference, XmlDSigUrls.Base64Transform, ns))
        {
            return Convert.FromBase64String(System.Text.Encoding.UTF8.GetString(detachedData).Trim());
        }

        XmlNodeList? detachedTransforms = reference.SelectNodes("ds:Transforms/ds:Transform", ns);
        if (detachedTransforms is null || detachedTransforms.Count == 0)
        {
            // An external XMLDSig reference without transforms produces the resource octets as-is.
            return detachedData;
        }

        var detachedDocument = new XmlDocument { PreserveWhitespace = true };
        detachedDocument.Load(new MemoryStream(detachedData));
        return ApplyReferenceTransforms(
            detachedDocument,
            detachedDocument.DocumentElement!,
            reference,
            referenceCanonicalizationAlgorithm);
    }

    private static void AppendPrecedingUnsignedProperties(
        List<byte[]> octets,
        XmlElement signature,
        XmlElement archiveTimeStamp,
        XmlNamespaceManager ns,
        string canonicalizationAlgorithm)
    {
        if (signature.SelectSingleNode(
                "ds:Object/xades:QualifyingProperties/xades:UnsignedProperties/xades:UnsignedSignatureProperties", ns)
            is not XmlElement unsignedProperties)
        {
            throw new InvalidOperationException("ArchiveTimeStamp has no UnsignedSignatureProperties parent.");
        }

        foreach (XmlNode node in unsignedProperties.ChildNodes)
        {
            if (ReferenceEquals(node, archiveTimeStamp))
            {
                break;
            }

            if (node is XmlElement property)
            {
                // EN 319 132-1 covers every preceding unsigned signature property, including
                // TimeStampValidationData, in document order.
                octets.Add(CanonicalizeElement(property, canonicalizationAlgorithm));
            }
        }
    }

    /// <summary>
    /// Appends the explicitly listed unsigned qualifying properties for the distributed
    /// ArchiveTimeStamp construction in ETSI EN 319 132-1 §5.5.2.3.
    /// </summary>
    /// <remarks>
    /// The generic XAdES Include processing model removes comments from the referenced node set
    /// before canonicalization. This implementation deliberately supports only same-document,
    /// bare-name references: resolving an external URI would introduce network and document-base
    /// semantics into archive validation and must be supplied by a future explicit resolver API.
    /// </remarks>
    private static void AppendDistributedUnsignedProperties(
        List<byte[]> octets,
        XmlDocument document,
        XmlElement archiveTimeStamp,
        XmlNamespaceManager ns,
        string canonicalizationAlgorithm)
    {
        XmlNodeList? includes = archiveTimeStamp.SelectNodes("xades:Include | xades141:Include", ns);
        if (includes is null || includes.Count == 0)
        {
            throw new InvalidOperationException("Distributed ArchiveTimeStamp has no Include elements.");
        }

        var includedIds = new HashSet<string>(StringComparer.Ordinal);
        foreach (XmlElement include in includes)
        {
            string uri = include.GetAttribute("URI");
            XmlElement property = FindElementByBareNameId(document, uri, "ArchiveTimeStamp Include");
            string id = GetElementId(property);
            if (!includedIds.Add(id))
            {
                throw new InvalidOperationException($"ArchiveTimeStamp Include '{uri}' is duplicated.");
            }

            if (!IsUnsignedSignatureQualifyingProperty(property) || ReferenceEquals(property, archiveTimeStamp))
            {
                throw new InvalidOperationException(
                    $"ArchiveTimeStamp Include '{uri}' must reference an unsigned signature qualifying property.");
            }

            if (include.HasAttribute("referencedData"))
            {
                throw new NotSupportedException(
                    "ArchiveTimeStamp Include referencedData is valid only for ds:Reference targets, " +
                    "which ETSI forbids for a distributed ArchiveTimeStamp.");
            }

            octets.Add(CanonicalizeElementWithoutComments(property, canonicalizationAlgorithm));
        }
    }

    private static XmlElement FindElementByBareNameId(XmlDocument document, string uri, string referenceKind)
    {
        if (string.IsNullOrWhiteSpace(uri) || uri[0] != '#' || uri.Length == 1 || uri.IndexOf('#', 1) >= 0)
        {
            throw new NotSupportedException(
                $"{referenceKind} URI '{uri}' must be a same-document bare-name reference.");
        }

        string id = Uri.UnescapeDataString(uri[1..]);
        XmlNodeList? elements = document.SelectNodes("//*");
        if (elements is not null)
        {
            foreach (XmlElement candidate in elements.OfType<XmlElement>())
            {
                if (string.Equals(GetElementId(candidate), id, StringComparison.Ordinal))
                {
                    return candidate;
                }
            }
        }

        throw new InvalidOperationException($"{referenceKind} target '{uri}' was not found.");
    }

    private static string GetElementId(XmlElement element)
    {
        string id = element.GetAttribute("Id");
        return id.Length != 0 ? id : element.GetAttribute("id", "http://www.w3.org/XML/1998/namespace");
    }

    private static bool IsUnsignedSignatureQualifyingProperty(XmlElement element) =>
        element.ParentNode is XmlElement parent &&
        parent.LocalName == "UnsignedSignatureProperties" &&
        parent.NamespaceURI == XadesUris.XadesNamespace;

    private static void AppendUnreferencedObjects(
        List<byte[]> octets,
        XmlElement signature,
        XmlNamespaceManager ns,
        string canonicalizationAlgorithm)
    {
        XmlNodeList? objects = signature.SelectNodes("ds:Object", ns);
        if (objects is null)
        {
            return;
        }

        foreach (XmlElement element in objects)
        {
            if (element.SelectSingleNode("xades:QualifyingProperties", ns) is not null)
            {
                continue;
            }

            // EN 319 132-1 includes every ds:Object other than QualifyingProperties.
            // Reference status only changed the pre-v1.4.1 construction.
            octets.Add(CanonicalizeElement(element, canonicalizationAlgorithm));
        }
    }

    private static byte[] ApplyReferenceTransforms(
        XmlDocument owner,
        XmlElement target,
        XmlElement reference,
        string canonicalizationAlgorithm)
    {
        XmlNamespaceManager ns = CreateNamespaceManager(owner);
        ValidateSupportedReferenceTransforms(reference, ns);
        if (HasTransform(reference, XmlDSigUrls.Base64Transform, ns))
        {
            return Convert.FromBase64String(target.InnerText.Trim());
        }

        XmlDocument working = new() { PreserveWhitespace = true };
        working.AppendChild(working.ImportNode(target, true));
        if (HasTransform(reference, XmlDSigUrls.EnvelopedSignatureTransform, ns) ||
            HasSignatureExclusionXPath(reference, ns))
        {
            RemoveSignatureElements(working);
        }

        return CanonicalizeXml(working, canonicalizationAlgorithm);
    }

    private static bool HasTransform(XmlElement reference, string algorithm, XmlNamespaceManager ns) =>
        reference.SelectSingleNode($"ds:Transforms/ds:Transform[@Algorithm='{algorithm}']", ns) is not null;

    /// <summary>
    /// Rejects reference transforms whose archive-time-stamp processing is not implemented.
    /// </summary>
    /// <remarks>
    /// Archive validation must never silently omit a transform from the XMLDSig reference
    /// pipeline. The supported subset covers the enveloped XAdES topology produced by this
    /// library and the externally supplied ETSI vectors: base64, enveloped-signature,
    /// the signature-exclusion XPath, and XML canonicalization variants.
    /// </remarks>
    private static void ValidateSupportedReferenceTransforms(XmlElement reference, XmlNamespaceManager ns)
    {
        XmlNodeList? transforms = reference.SelectNodes("ds:Transforms/ds:Transform", ns);
        if (transforms is null || transforms.Count == 0)
        {
            return;
        }

        bool hasBase64 = false;
        foreach (XmlElement transform in transforms)
        {
            string algorithm = transform.GetAttribute("Algorithm");
            if (algorithm == XmlDSigUrls.Base64Transform)
            {
                hasBase64 = true;
                continue;
            }

            if (algorithm is XmlDSigUrls.EnvelopedSignatureTransform or XmlDSigUrls.ExcC14N or
                XmlDSigUrls.ExcC14NWithComments or XmlDSigUrls.C14N or XmlDSigUrls.C14NWithComments)
            {
                continue;
            }

            if (algorithm == XmlDSigUrls.XPathTransform &&
                transform.SelectSingleNode("ds:XPath", ns)?.InnerText.Trim() ==
                    "not(ancestor-or-self::ds:Signature)")
            {
                continue;
            }

            throw new NotSupportedException($"Unsupported XMLDSig archive reference transform '{algorithm}'.");
        }

        if (hasBase64 && transforms.Count != 1)
        {
            throw new NotSupportedException(
                "The base64 XMLDSig archive reference transform is supported only as the sole transform.");
        }
    }

    private static string GetReferenceCanonicalizationAlgorithm(
        XmlElement reference,
        XmlNamespaceManager ns,
        string archiveCanonicalizationAlgorithm)
    {
        ValidateSupportedReferenceTransforms(reference, ns);
        XmlNodeList? transforms = reference.SelectNodes("ds:Transforms/ds:Transform", ns);
        if (transforms is null || transforms.Count == 0)
        {
            return archiveCanonicalizationAlgorithm;
        }

        string? referenceCanonicalizationAlgorithm = null;
        for (int index = 0; index < transforms.Count; index++)
        {
            var transform = (XmlElement)transforms[index]!;
            string algorithm = transform.GetAttribute("Algorithm");
            if (algorithm is not XmlDSigUrls.ExcC14N and not XmlDSigUrls.ExcC14NWithComments and
                not XmlDSigUrls.C14N and not XmlDSigUrls.C14NWithComments)
            {
                continue;
            }

            if (index != transforms.Count - 1)
            {
                throw new NotSupportedException(
                    "An XMLDSig canonicalization transform must be the final archive reference transform.");
            }

            referenceCanonicalizationAlgorithm = algorithm;
        }

        return referenceCanonicalizationAlgorithm ?? archiveCanonicalizationAlgorithm;
    }

    private static bool HasSignatureExclusionXPath(XmlElement reference, XmlNamespaceManager ns)
    {
        XmlNodeList? transforms = reference.SelectNodes("ds:Transforms/ds:Transform", ns);
        if (transforms is null)
        {
            return false;
        }

        foreach (XmlElement transform in transforms)
        {
            if (transform.GetAttribute("Algorithm") == XmlDSigUrls.XPathTransform &&
                transform.SelectSingleNode("ds:XPath", ns)?.InnerText.Trim() == "not(ancestor-or-self::ds:Signature)")
            {
                return true;
            }
        }

        return false;
    }

    private static void RemoveSignatureElements(XmlDocument document)
    {
        XmlNamespaceManager ns = CreateNamespaceManager(document);
        XmlNodeList? signatures = document.SelectNodes("//ds:Signature", ns);
        if (signatures is null)
        {
            return;
        }

        for (int i = signatures.Count - 1; i >= 0; i--)
        {
            XmlNode signature = signatures[i]!;
            signature.ParentNode!.RemoveChild(signature);
        }
    }

    private static byte[] CanonicalizeElement(XmlElement element, string canonicalizationAlgorithm = XmlDSigUrls.ExcC14N)
    {
        var document = new XmlDocument { PreserveWhitespace = true };
        document.AppendChild(document.ImportNode(element, true));
        return CanonicalizeXml(document, canonicalizationAlgorithm);
    }

    private static byte[] CanonicalizeElementWithoutComments(XmlElement element, string canonicalizationAlgorithm)
    {
        var document = new XmlDocument { PreserveWhitespace = true };
        document.AppendChild(document.ImportNode(element, true));
        RemoveCommentNodes(document);
        return CanonicalizeXml(document, canonicalizationAlgorithm);
    }

    private static void RemoveCommentNodes(XmlNode node)
    {
        for (int index = node.ChildNodes.Count - 1; index >= 0; index--)
        {
            XmlNode child = node.ChildNodes[index]!;
            if (child.NodeType == XmlNodeType.Comment)
            {
                node.RemoveChild(child);
                continue;
            }

            RemoveCommentNodes(child);
        }
    }

    private static HashAlgorithmName GetTimestampHashAlgorithm(string? hashAlgorithmOid) => hashAlgorithmOid switch
    {
        Oids.Sha256 => HashAlgorithmName.SHA256,
        Oids.Sha384 => HashAlgorithmName.SHA384,
        Oids.Sha512 => HashAlgorithmName.SHA512,
        Oids.Sha3_256 => HashAlgorithmName.SHA3_256,
        Oids.Sha3_384 => HashAlgorithmName.SHA3_384,
        Oids.Sha3_512 => HashAlgorithmName.SHA3_512,
        _ => throw new NotSupportedException($"ArchiveTimeStamp uses unsupported digest '{hashAlgorithmOid}'.")
    };

    private static byte[] Concatenate(IReadOnlyList<byte[]> values)
    {
        int length = values.Sum(value => value.Length);
        var output = new byte[length];
        int offset = 0;
        foreach (var value in values)
        {
            value.CopyTo(output, offset);
            offset += value.Length;
        }

        return output;
    }

    private static XmlElement CreateSignedProperties(
        XmlDocument doc,
        X509Certificate2 certificate,
        HashAlgorithmName hashAlgorithm,
        DateTimeOffset signingTime,
        string signedPropertiesId,
        string signatureId,
        CommitmentType? commitmentType,
        string? signaturePolicyOid,
        string? signaturePolicyUri,
        IReadOnlyList<string>? signerRoles,
        DataObjectFormat? dataObjectFormat)
    {
        var signedProps = doc.CreateElement("SignedProperties", XadesUris.XadesNamespace);
        signedProps.SetAttribute("Id", signedPropertiesId);

        // SignedSignatureProperties — per ETSI EN 319 132-1 §5.2.2
        var signedSigProps = doc.CreateElement("SignedSignatureProperties", XadesUris.XadesNamespace);

        var stElement = doc.CreateElement("SigningTime", XadesUris.XadesNamespace);
        stElement.InnerText = signingTime.UtcDateTime.ToString("yyyy-MM-ddTHH:mm:ssZ", CultureInfo.InvariantCulture);
        signedSigProps.AppendChild(stElement);

        signedSigProps.AppendChild(CreateSigningCertificateV2(doc, certificate, hashAlgorithm));

        // SignaturePolicyIdentifier — child of SignedSignatureProperties per §5.2.2
        if (signaturePolicyOid is not null)
        {
            var spElement = doc.CreateElement("SignaturePolicyIdentifier", XadesUris.XadesNamespace);
            var spIdElement = doc.CreateElement("SignaturePolicyId", XadesUris.XadesNamespace);
            var spOidElement = doc.CreateElement("SigPolicyId", XadesUris.XadesNamespace);
            var idElement = doc.CreateElement("Identifier", XadesUris.XadesNamespace);
            idElement.InnerText = signaturePolicyOid;
            spOidElement.AppendChild(idElement);
            spIdElement.AppendChild(spOidElement);

            if (signaturePolicyUri is not null)
            {
                var spHashElement = doc.CreateElement("SigPolicyHash", XadesUris.XadesNamespace);
                var dmElement = doc.CreateElement("DigestMethod", XmlDSigUrls.DsNamespace);
                dmElement.SetAttribute("Algorithm", GetDigestMethod(hashAlgorithm));
                var dvElement = doc.CreateElement("DigestValue", XmlDSigUrls.DsNamespace);
                byte[] policyDigest = HashData(hashAlgorithm, System.Text.Encoding.UTF8.GetBytes(signaturePolicyOid));
                dvElement.InnerText = Convert.ToBase64String(policyDigest);
                spHashElement.AppendChild(dmElement);
                spHashElement.AppendChild(dvElement);
                spIdElement.AppendChild(spHashElement);

                var spLocElement = doc.CreateElement("SigPolicyQualifiers", XadesUris.XadesNamespace);
                var spLocQual = doc.CreateElement("SigPolicyQualifier", XadesUris.XadesNamespace);
                var spRef = doc.CreateElement("SPURI", XadesUris.XadesNamespace);
                spRef.InnerText = signaturePolicyUri;
                spLocQual.AppendChild(spRef);
                spLocElement.AppendChild(spLocQual);
                spIdElement.AppendChild(spLocElement);
            }

            spElement.AppendChild(spIdElement);
            signedSigProps.AppendChild(spElement);
        }

        // SignerRole — child of SignedSignatureProperties per §5.2.2
        if (signerRoles is not null && signerRoles.Count > 0)
        {
            var srElement = doc.CreateElement("SignerRole", XadesUris.XadesNamespace);
            var claimedRoles = doc.CreateElement("ClaimedRoles", XadesUris.XadesNamespace);
            foreach (var role in signerRoles)
            {
                if (string.IsNullOrWhiteSpace(role))
                {
                    continue;
                }
                var crElement = doc.CreateElement("ClaimedRole", XadesUris.XadesNamespace);
                crElement.InnerText = role;
                claimedRoles.AppendChild(crElement);
            }
            if (claimedRoles.HasChildNodes)
            {
                srElement.AppendChild(claimedRoles);
                signedSigProps.AppendChild(srElement);
            }
        }

        signedProps.AppendChild(signedSigProps);

        // SignedDataObjectProperties — per ETSI EN 319 132-1 §5.2.3
        if (commitmentType.HasValue || dataObjectFormat is not null)
        {
            var signedDataObjProps = doc.CreateElement("SignedDataObjectProperties", XadesUris.XadesNamespace);

            // DataObjectFormat before CommitmentTypeIndication per §5.2.3 ordering
            if (dataObjectFormat is not null)
            {
                var dofElement = doc.CreateElement("DataObjectFormat", XadesUris.XadesNamespace);
                if (!string.IsNullOrEmpty(dataObjectFormat.ObjectReference))
                {
                    dofElement.SetAttribute("ObjectReference", dataObjectFormat.ObjectReference);
                }
                if (dataObjectFormat.MimeType is not null)
                {
                    var mtElement = doc.CreateElement("MimeType", XadesUris.XadesNamespace);
                    mtElement.InnerText = dataObjectFormat.MimeType;
                    dofElement.AppendChild(mtElement);
                }
                signedDataObjProps.AppendChild(dofElement);
            }

            if (commitmentType.HasValue)
            {
                var ctElement = doc.CreateElement("CommitmentTypeIndication", XadesUris.XadesNamespace);
                var ctvElement = doc.CreateElement("CommitmentTypeId", XadesUris.XadesNamespace);
                var idElement = doc.CreateElement("Identifier", XadesUris.XadesNamespace);

                string ctOid = commitmentType.Value switch
                {
                    CommitmentType.ProofOfOrigin => Oids.ProofOfOrigin,
                    CommitmentType.ProofOfReceipt => Oids.ProofOfReceipt,
                    CommitmentType.ProofOfDelivery => Oids.ProofOfDelivery,
                    CommitmentType.ProofOfSender => Oids.ProofOfSender,
                    CommitmentType.ProofOfApproval => Oids.ProofOfApproval,
                    CommitmentType.ProofOfCreation => Oids.ProofOfCreation,
                    _ => throw new ArgumentOutOfRangeException(nameof(commitmentType))
                };

                idElement.InnerText = ctOid;
                ctvElement.AppendChild(idElement);
                ctElement.AppendChild(ctvElement);
                signedDataObjProps.AppendChild(ctElement);
            }

            signedProps.AppendChild(signedDataObjProps);
        }

        return signedProps;
    }

    private static XmlElement CreateSigningCertificateV2(
        XmlDocument doc,
        X509Certificate2 certificate,
        HashAlgorithmName hashAlgorithm)
    {
        var scv2 = doc.CreateElement("SigningCertificateV2", XadesUris.XadesNamespace);

        var certElement = doc.CreateElement("Cert", XadesUris.XadesNamespace);

        var certDigest = doc.CreateElement("CertDigest", XadesUris.XadesNamespace);
        var dmElement = doc.CreateElement("DigestMethod", XmlDSigUrls.DsNamespace);
        dmElement.SetAttribute("Algorithm", GetDigestMethod(hashAlgorithm));
        var dvElement = doc.CreateElement("DigestValue", XmlDSigUrls.DsNamespace);
        byte[] certHash = CryptoUtility.ComputeHash(certificate.RawData, hashAlgorithm);
        dvElement.InnerText = Convert.ToBase64String(certHash);
        certDigest.AppendChild(dmElement);
        certDigest.AppendChild(dvElement);

        var issuerSerial = doc.CreateElement("IssuerSerialV2", XadesUris.XadesNamespace);
        issuerSerial.InnerText = Convert.ToBase64String(EncodeIssuerSerialV2(certificate));

        certElement.AppendChild(certDigest);
        certElement.AppendChild(issuerSerial);
        scv2.AppendChild(certElement);

        return scv2;
    }

    private static byte[] EncodeIssuerSerialV2(X509Certificate2 certificate)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        writer.PushSequence();

        // IssuerSerial.issuer is GeneralNames, whose only entry for an X.509
        // certificate must be the issuer DN in the directoryName choice.
        writer.PushSequence();
        var directoryNameTag = new Asn1Tag(TagClass.ContextSpecific, 4, isConstructed: true);
        writer.PushSequence(directoryNameTag);
        writer.WriteEncodedValue(certificate.IssuerName.RawData);
        writer.PopSequence(directoryNameTag);
        writer.PopSequence();

        var serial = certificate.GetSerialNumber();
        Array.Reverse(serial);
        writer.WriteIntegerUnsigned(serial);
        writer.PopSequence();
        return writer.Encode();
    }

    private static XmlElement CreateQualifyingProperties(
        XmlDocument doc,
        string signatureId,
        XmlElement signedProperties)
    {
        var qp = doc.CreateElement("QualifyingProperties", XadesUris.XadesNamespace);
        qp.SetAttribute("Target", "#" + signatureId);
        qp.AppendChild(signedProperties);
        return qp;
    }

    private static XmlElement EnsureUnsignedSignatureProperties(
        XmlDocument doc,
        XmlElement signature,
        XmlNamespaceManager ns)
    {
        // Ensure QualifyingProperties/UnsignedProperties exists
        if (signature.SelectSingleNode(
                "ds:Object/xades:QualifyingProperties/xades:UnsignedProperties", ns) is not XmlElement unsignedProps)
        {
            if (signature.SelectSingleNode(
                "ds:Object/xades:QualifyingProperties", ns) is not XmlElement qp)
            {
                qp = doc.CreateElement("QualifyingProperties", XadesUris.XadesNamespace);
                qp.SetAttribute("Target", "#" + signature.GetAttribute("Id"));
                var obj = doc.CreateElement("Object", XmlDSigUrls.DsNamespace);
                obj.AppendChild(qp);
                signature.AppendChild(obj);
            }

            unsignedProps = doc.CreateElement("UnsignedProperties", XadesUris.XadesNamespace);
            qp.AppendChild(unsignedProps);
        }

        // Ensure UnsignedProperties/UnsignedSignatureProperties exists (ETSI EN 319 132-1 §5.3)
        if (unsignedProps.SelectSingleNode(
                "xades:UnsignedSignatureProperties", ns) is not XmlElement usp)
        {
            usp = doc.CreateElement("UnsignedSignatureProperties", XadesUris.XadesNamespace);
            unsignedProps.AppendChild(usp);
        }

        return usp;
    }

    private static string GetDigestMethod(HashAlgorithmName hashAlgorithm) =>
        XmlDSigUrls.GetDigestUri(hashAlgorithm);

    private static byte[] SignHash(
        byte[] hash,
        HashAlgorithmName hashAlgorithm,
        string signatureAlgorithmOid,
        X509Certificate2 certificate)
    {
        if (signatureAlgorithmOid == Oids.RsaPss)
        {
            using RSA pssRsa = certificate.GetRSAPrivateKey()
                ?? throw new InvalidOperationException("Certificate does not have an RSA private key for RSA-PSS.");
            return pssRsa.SignHash(hash, hashAlgorithm, RSASignaturePadding.Pss);
        }

        using RSA? rsa = certificate.GetRSAPrivateKey();
        if (rsa is not null)
        {
            return rsa.SignHash(hash, hashAlgorithm, RSASignaturePadding.Pkcs1);
        }

        using ECDsa? ecdsa = certificate.GetECDsaPrivateKey();
        if (ecdsa is not null)
        {
            return ecdsa.SignHash(hash);
        }

        throw new InvalidOperationException(
            $"Certificate does not have a supported private key for algorithm '{signatureAlgorithmOid}'.");
    }

    private static string GetSignatureMethodUri(string signatureAlgorithmOid, HashAlgorithmName hashAlgorithm) =>
        XmlDSigUrls.GetSignatureMethodUri(signatureAlgorithmOid, hashAlgorithm);

    private static byte[] ComputeDocumentDigest(
        XmlDocument xmlDoc, HashAlgorithmName hashAlgorithm, XadesForm form)
    {
        var clone = (XmlDocument)xmlDoc.CloneNode(true);
        var cloneNs = new XmlNamespaceManager(clone.NameTable);
        cloneNs.AddNamespace("ds", XmlDSigUrls.DsNamespace);

        // For enveloped, Signature elements must be removed before hashing
        // (the EnvelopedSignatureTransform removes them). For Detached and
        // Enveloping forms, the reference does NOT have this transform.
        if (form == XadesForm.Enveloped)
        {
            var signatures = clone.SelectNodes("//ds:Signature", cloneNs);
            if (signatures is not null)
            {
                for (int i = signatures.Count - 1; i >= 0; i--)
                {
                    var sig = signatures[i]!;
                    sig.ParentNode!.RemoveChild(sig);
                }
            }
        }

        byte[] canonical = CanonicalizeXml(clone);
        return HashData(hashAlgorithm, canonical);
    }

    private static byte[] ComputeElementDigest(
        XmlDocument xmlDoc, string elementId, HashAlgorithmName hashAlgorithm)
    {
        if (xmlDoc.SelectSingleNode($"//*[@Id='{elementId}']") is not XmlElement element)
        {
            throw new InvalidOperationException($"Element with Id='{elementId}' not found.");
        }

        var tempDoc = new XmlDocument { PreserveWhitespace = true };
        tempDoc.AppendChild(tempDoc.ImportNode(element, true));
        byte[] canonical = CanonicalizeXml(tempDoc);
        return HashData(hashAlgorithm, canonical);
    }

    private static byte[] CanonicalizeXml(XmlDocument doc, string algorithm = XmlDSigUrls.ExcC14N)
    {
        Transform transform = algorithm switch
        {
            XmlDSigUrls.ExcC14N => new XmlDsigExcC14NTransform(),
            XmlDSigUrls.ExcC14NWithComments => new XmlDsigExcC14NTransform(includeComments: true),
            XmlDSigUrls.C14N => new XmlDsigC14NTransform(),
            XmlDSigUrls.C14NWithComments => new XmlDsigC14NTransform(includeComments: true),
            _ => throw new NotSupportedException($"Unsupported XML canonicalization algorithm '{algorithm}'."),
        };
        transform.LoadInput(doc);
        using var stream = (Stream)transform.GetOutput(typeof(Stream))!;
        using var ms = new MemoryStream();
        stream.CopyTo(ms);
        return ms.ToArray();
    }

    private static byte[] HashData(HashAlgorithmName algorithm, byte[] data)
    {
        if (algorithm == HashAlgorithmName.SHA256)
        {
            return SHA256.HashData(data);
        }
        if (algorithm == HashAlgorithmName.SHA384)
        {
            return SHA384.HashData(data);
        }
        if (algorithm == HashAlgorithmName.SHA512)
        {
            return SHA512.HashData(data);
        }
        if (algorithm == HashAlgorithmName.SHA3_256)
        {
            return SHA3_256.HashData(data);
        }
        if (algorithm == HashAlgorithmName.SHA3_384)
        {
            return SHA3_384.HashData(data);
        }
        if (algorithm == HashAlgorithmName.SHA3_512)
        {
            return SHA3_512.HashData(data);
        }
        throw new NotSupportedException($"Hash algorithm '{algorithm.Name}' is not supported.");
    }

    private static XmlElement CreateDocRef(
        XmlDocument doc,
        string uri,
        HashAlgorithmName hashAlgorithm,
        bool enveloped,
        byte[] digestValue,
        bool signedPropsType = false)
    {
        var refEl = doc.CreateElement("Reference", XmlDSigUrls.DsNamespace);
        refEl.SetAttribute("URI", uri);

        var transforms = doc.CreateElement("Transforms", XmlDSigUrls.DsNamespace);
        if (enveloped)
        {
            var t1 = doc.CreateElement("Transform", XmlDSigUrls.DsNamespace);
            t1.SetAttribute("Algorithm", XmlDSigUrls.EnvelopedSignatureTransform);
            transforms.AppendChild(t1);

            // The enveloped transform excludes only the signature currently
            // being verified. Exclude all signatures as well so adding a
            // second signature does not invalidate the first one.
            var xpathTransform = doc.CreateElement("Transform", XmlDSigUrls.DsNamespace);
            xpathTransform.SetAttribute("Algorithm", XmlDSigUrls.XPathTransform);
            var xpath = doc.CreateElement("XPath", XmlDSigUrls.DsNamespace);
            xpath.SetAttribute("xmlns:ds", XmlDSigUrls.DsNamespace);
            xpath.InnerText = "not(ancestor-or-self::ds:Signature)";
            xpathTransform.AppendChild(xpath);
            transforms.AppendChild(xpathTransform);
        }
        var t2 = doc.CreateElement("Transform", XmlDSigUrls.DsNamespace);
        t2.SetAttribute("Algorithm", XmlDSigUrls.ExcC14N);
        transforms.AppendChild(t2);
        refEl.AppendChild(transforms);

        var dm = doc.CreateElement("DigestMethod", XmlDSigUrls.DsNamespace);
        dm.SetAttribute("Algorithm", GetDigestMethod(hashAlgorithm));
        refEl.AppendChild(dm);

        var dv = doc.CreateElement("DigestValue", XmlDSigUrls.DsNamespace);
        dv.InnerText = Convert.ToBase64String(digestValue);
        refEl.AppendChild(dv);

        if (signedPropsType)
        {
            refEl.SetAttribute("Type", XadesUris.SignedPropertiesType);
        }

        return refEl;
    }

    private static byte[] BuildStandaloneSignature(
        byte[] xmlData,
        X509Certificate2 certificate,
        HashAlgorithmName hashAlgorithm,
        DateTimeOffset signingTime,
        IReadOnlyList<X509Certificate2>? extraCertificates,
        CommitmentType? commitmentType,
        string? signaturePolicyOid,
        string? signaturePolicyUri,
        string signatureAlgorithmOid,
        XadesForm form,
        string? dataUri,
        IReadOnlyList<string>? signerRoles,
        DataObjectFormat? dataObjectFormat,
        ILogger logger)
    {
        string signatureId = XadesUris.SignatureIdPrefix + Guid.NewGuid().ToString("N")[..8];
        string signedPropertiesId = XadesUris.SignedPropertiesIdPrefix + Guid.NewGuid().ToString("N")[..8];

        bool isEnveloping = form == XadesForm.Enveloping;
        if (form == XadesForm.Detached && string.IsNullOrEmpty(dataUri))
        {
            throw new ArgumentException("dataUri is required for XAdES Detached form.", nameof(dataUri));
        }

        string dataObjectId = isEnveloping ? "Object-" + Guid.NewGuid().ToString("N")[..8] : string.Empty;

        var outDoc = new XmlDocument { PreserveWhitespace = true };

        var sigEl = outDoc.CreateElement("Signature", XmlDSigUrls.DsNamespace);
        sigEl.SetAttribute("Id", signatureId);
        outDoc.AppendChild(sigEl);

        if (isEnveloping)
        {
            var dataDoc = new XmlDocument { PreserveWhitespace = true };
            dataDoc.Load(new MemoryStream(xmlData));
            var dataObject = outDoc.CreateElement("Object", XmlDSigUrls.DsNamespace);
            dataObject.SetAttribute("Id", dataObjectId);
            dataObject.AppendChild(outDoc.ImportNode(dataDoc.DocumentElement!, true));
            sigEl.AppendChild(dataObject);
        }

        var signedProperties = CreateSignedProperties(outDoc, certificate, hashAlgorithm, signingTime,
            signedPropertiesId, signatureId, commitmentType, signaturePolicyOid, signaturePolicyUri,
            signerRoles, dataObjectFormat);
        var qualifyingProps = CreateQualifyingProperties(outDoc, signatureId, signedProperties);
        var spObject = outDoc.CreateElement("Object", XmlDSigUrls.DsNamespace);
        spObject.AppendChild(qualifyingProps);
        sigEl.AppendChild(spObject);

        byte[] docDigest;
        if (form == XadesForm.Detached)
        {
            var dataDoc = new XmlDocument { PreserveWhitespace = true };
            dataDoc.Load(new MemoryStream(xmlData));
            byte[] canonicalData = CanonicalizeXml(dataDoc);
            docDigest = HashData(hashAlgorithm, canonicalData);
        }
        else
        {
            docDigest = ComputeElementDigest(outDoc, dataObjectId, hashAlgorithm);
        }

        byte[] signedPropsDigest = ComputeElementDigest(outDoc, signedPropertiesId, hashAlgorithm);

        string docRefUri = form == XadesForm.Detached
            ? dataUri!
            : "#" + dataObjectId;

        var siDoc = new XmlDocument();
        var signedInfo = siDoc.CreateElement("SignedInfo", XmlDSigUrls.DsNamespace);

        var cm = siDoc.CreateElement("CanonicalizationMethod", XmlDSigUrls.DsNamespace);
        cm.SetAttribute("Algorithm", XmlDSigUrls.ExcC14N);
        signedInfo.AppendChild(cm);

        var sm = siDoc.CreateElement("SignatureMethod", XmlDSigUrls.DsNamespace);
        sm.SetAttribute("Algorithm", GetSignatureMethodUri(signatureAlgorithmOid, hashAlgorithm));
        signedInfo.AppendChild(sm);

        signedInfo.AppendChild(CreateDocRef(siDoc, docRefUri, hashAlgorithm, enveloped: false, docDigest));

        signedInfo.AppendChild(CreateDocRef(siDoc, "#" + signedPropertiesId, hashAlgorithm,
            enveloped: false, signedPropsDigest, signedPropsType: true));

        siDoc.AppendChild(signedInfo);

        byte[] signedInfoCanonical = CanonicalizeXml(siDoc);
        byte[] signedInfoHash = HashData(hashAlgorithm, signedInfoCanonical);
        byte[] signatureValueBytes = SignHash(signedInfoHash, hashAlgorithm, signatureAlgorithmOid, certificate);

        XmlNode signedInfoNode = outDoc.ImportNode(signedInfo, true);
        sigEl.InsertBefore(signedInfoNode, sigEl.FirstChild);

        var sigValueEl = outDoc.CreateElement("SignatureValue", XmlDSigUrls.DsNamespace);
        sigValueEl.InnerText = Convert.ToBase64String(signatureValueBytes);
        sigEl.InsertAfter(sigValueEl, signedInfoNode);

        var keyInfo = outDoc.CreateElement("KeyInfo", XmlDSigUrls.DsNamespace);
        var x509Data = outDoc.CreateElement("X509Data", XmlDSigUrls.DsNamespace);
        var x509Cert = outDoc.CreateElement("X509Certificate", XmlDSigUrls.DsNamespace);
        x509Cert.InnerText = Convert.ToBase64String(certificate.RawData);
        x509Data.AppendChild(x509Cert);
        if (extraCertificates is not null)
        {
            foreach (var cert in extraCertificates)
            {
                var extraCertEl = outDoc.CreateElement("X509Certificate", XmlDSigUrls.DsNamespace);
                extraCertEl.InnerText = Convert.ToBase64String(cert.RawData);
                x509Data.AppendChild(extraCertEl);
            }
        }
        keyInfo.AppendChild(x509Data);
        sigEl.InsertAfter(keyInfo, sigValueEl);

        using var ms = new MemoryStream();
        outDoc.Save(ms);
        return ms.ToArray();
    }

    private static byte[] BuildStandaloneSignedInfoToHash(
        byte[] xmlData,
        X509Certificate2 certificate,
        HashAlgorithmName hashAlgorithm,
        DateTimeOffset signingTime,
        XadesForm form,
        CommitmentType? commitmentType,
        string? signaturePolicyOid,
        string? signaturePolicyUri,
        string signatureAlgorithmOid,
        IReadOnlyList<string>? signerRoles,
        DataObjectFormat? dataObjectFormat,
        out string signedPropertiesId,
        out byte[] signedInfoXmlBytes,
        out string? dataObjectIdOut,
        string? dataUri)
    {
        bool isEnveloping = form == XadesForm.Enveloping;

        if (form == XadesForm.Detached && string.IsNullOrEmpty(dataUri))
        {
            throw new ArgumentException("dataUri is required for XAdES Detached form.", nameof(dataUri));
        }

        signedPropertiesId = XadesUris.SignedPropertiesIdPrefix + Guid.NewGuid().ToString("N")[..8];
        string signatureId = XadesUris.SignatureIdPrefix + Guid.NewGuid().ToString("N")[..8];
        string dataObjectId = isEnveloping ? "Object-" + Guid.NewGuid().ToString("N")[..8] : string.Empty;

        var outDoc = new XmlDocument { PreserveWhitespace = true };

        var sigEl = outDoc.CreateElement("Signature", XmlDSigUrls.DsNamespace);
        sigEl.SetAttribute("Id", signatureId);
        outDoc.AppendChild(sigEl);

        if (isEnveloping)
        {
            var dataDoc = new XmlDocument { PreserveWhitespace = true };
            dataDoc.Load(new MemoryStream(xmlData));
            var dataObject = outDoc.CreateElement("Object", XmlDSigUrls.DsNamespace);
            dataObject.SetAttribute("Id", dataObjectId);
            dataObject.AppendChild(outDoc.ImportNode(dataDoc.DocumentElement!, true));
            sigEl.AppendChild(dataObject);
        }

        var signedProperties = CreateSignedProperties(outDoc, certificate, hashAlgorithm, signingTime,
            signedPropertiesId, signatureId, commitmentType, signaturePolicyOid, signaturePolicyUri,
            signerRoles, dataObjectFormat);
        var qualifyingProps = CreateQualifyingProperties(outDoc, signatureId, signedProperties);
        var spObject = outDoc.CreateElement("Object", XmlDSigUrls.DsNamespace);
        spObject.AppendChild(qualifyingProps);
        sigEl.AppendChild(spObject);

        byte[] docDigest;
        if (form == XadesForm.Detached)
        {
            var dataDoc = new XmlDocument { PreserveWhitespace = true };
            dataDoc.Load(new MemoryStream(xmlData));
            byte[] canonicalData = CanonicalizeXml(dataDoc);
            docDigest = HashData(hashAlgorithm, canonicalData);
        }
        else
        {
            docDigest = ComputeElementDigest(outDoc, dataObjectId, hashAlgorithm);
        }

        byte[] signedPropsDigest = ComputeElementDigest(outDoc, signedPropertiesId, hashAlgorithm);

        string docRefUri = form == XadesForm.Detached
            ? dataUri!
            : "#" + dataObjectId;

        var siDoc = new XmlDocument();
        var siElement = siDoc.CreateElement("SignedInfo", XmlDSigUrls.DsNamespace);

        var cmElement = siDoc.CreateElement("CanonicalizationMethod", XmlDSigUrls.DsNamespace);
        cmElement.SetAttribute("Algorithm", XmlDSigUrls.ExcC14N);
        siElement.AppendChild(cmElement);

        var smElement = siDoc.CreateElement("SignatureMethod", XmlDSigUrls.DsNamespace);
        smElement.SetAttribute("Algorithm", GetSignatureMethodUri(signatureAlgorithmOid, hashAlgorithm));
        siElement.AppendChild(smElement);

        siElement.AppendChild(CreateDocRef(siDoc, docRefUri, hashAlgorithm, enveloped: false, docDigest));

        siElement.AppendChild(CreateDocRef(siDoc, "#" + signedPropertiesId, hashAlgorithm,
            enveloped: false, signedPropsDigest, signedPropsType: true));

        signedInfoXmlBytes = Encoding.UTF8.GetBytes(siElement.InnerXml);

        dataObjectIdOut = isEnveloping ? dataObjectId : null;

        var finalSiDoc = new XmlDocument { PreserveWhitespace = true };
        finalSiDoc.AppendChild(finalSiDoc.ImportNode(siElement, true));
        byte[] canonical = CanonicalizeXml(finalSiDoc);

        return canonical;
    }

    private static byte[] CompleteStandaloneExternalSignature(
        byte[] xmlData,
        X509Certificate2 certificate,
        HashAlgorithmName hashAlgorithm,
        DateTimeOffset signingTime,
        IReadOnlyList<X509Certificate2>? extraCertificates,
        CommitmentType? commitmentType,
        string? signaturePolicyOid,
        string? signaturePolicyUri,
        string signatureAlgorithmOid,
        byte[] signedInfoBytes,
        byte[] signatureValue,
        string signedPropertiesId,
        IReadOnlyList<string>? signerRoles,
        DataObjectFormat? dataObjectFormat,
        XadesForm form,
        string? dataUri,
        string? dataObjectId)
    {
        bool isEnveloping = form == XadesForm.Enveloping;

        string signatureId = XadesUris.SignatureIdPrefix + Guid.NewGuid().ToString("N")[..8];

        var outDoc = new XmlDocument { PreserveWhitespace = true };

        var sigEl = outDoc.CreateElement("Signature", XmlDSigUrls.DsNamespace);
        sigEl.SetAttribute("Id", signatureId);
        outDoc.AppendChild(sigEl);

        if (isEnveloping)
        {
            var dataDoc = new XmlDocument { PreserveWhitespace = true };
            dataDoc.Load(new MemoryStream(xmlData));
            var dataObject = outDoc.CreateElement("Object", XmlDSigUrls.DsNamespace);
            dataObject.SetAttribute("Id", dataObjectId!);
            dataObject.AppendChild(outDoc.ImportNode(dataDoc.DocumentElement!, true));
            sigEl.AppendChild(dataObject);
        }

        var siElement = outDoc.CreateElement("SignedInfo", XmlDSigUrls.DsNamespace);
        siElement.InnerXml = Encoding.UTF8.GetString(signedInfoBytes);
        sigEl.InsertBefore(siElement, sigEl.FirstChild);

        var sigValueElement = outDoc.CreateElement("SignatureValue", XmlDSigUrls.DsNamespace);
        sigValueElement.InnerText = Convert.ToBase64String(signatureValue);
        sigEl.InsertAfter(sigValueElement, siElement);

        var keyInfo = new KeyInfo();
        var x509Data = new KeyInfoX509Data(certificate);
        if (extraCertificates is not null)
        {
            foreach (var cert in extraCertificates)
            {
                x509Data.AddCertificate(cert);
            }
        }
        keyInfo.AddClause(x509Data);
        var kiXml = keyInfo.GetXml();
        if (kiXml is not null)
        {
            sigEl.InsertAfter(outDoc.ImportNode(kiXml, true), sigValueElement);
        }

        var signedProperties = CreateSignedProperties(outDoc, certificate, hashAlgorithm, signingTime,
            signedPropertiesId, signatureId, commitmentType, signaturePolicyOid, signaturePolicyUri,
            signerRoles, dataObjectFormat);
        var qualifyingProps = CreateQualifyingProperties(outDoc, signatureId, signedProperties);
        var objElement = outDoc.CreateElement("Object", XmlDSigUrls.DsNamespace);
        objElement.AppendChild(qualifyingProps);
        sigEl.AppendChild(objElement);

        using var ms = new MemoryStream();
        outDoc.Save(ms);
        return ms.ToArray();
    }
}
