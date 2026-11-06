using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Xml;
using Microsoft.Extensions.Logging;
using SimpleSign.Core.Constants;
using SimpleSign.Core.Crypto;
using SimpleSign.Core.Signing;
using SimpleSign.XAdES.Constants;
using SimpleSign.XAdES.Internal;

namespace SimpleSign.XAdES;

[RequiresUnreferencedCode("XAdES uses System.Security.Cryptography.Xml which is not AOT-compatible.")]
[RequiresDynamicCode("XAdES uses System.Security.Cryptography.Xml which is not AOT-compatible.")]
internal static partial class XadesSignatureBuilder
{
    /// <summary>
    /// Loads the document to sign. Malformed XML is reported as an <see cref="ArgumentException"/>
    /// (like a document without a root element), not as a raw <see cref="XmlException"/>.
    /// </summary>
    private static XmlDocument LoadDocument(byte[] xmlData)
    {
        var xmlDoc = new XmlDocument { PreserveWhitespace = true };
        try
        {
            xmlDoc.Load(new MemoryStream(xmlData));
        }
        catch (XmlException ex)
        {
            throw new ArgumentException($"XML data is not well-formed: {ex.Message}", nameof(xmlData), ex);
        }

        return xmlDoc;
    }

    private static void LogSignatureSteps(
        ILogger logger,
        HashAlgorithmName hashAlgorithm,
        string signedPropertiesId,
        XadesSigningCertificateForm signingCertificateForm,
        SignaturePolicyReference? signaturePolicy,
        CommitmentType? commitmentType,
        IReadOnlyList<string>? signerRoles,
        string documentUri,
        byte[] documentDigest,
        byte[] signedPropertiesDigest,
        byte[] signedInfoCanonical,
        byte[] signatureValue)
    {
        string algorithm = hashAlgorithm.Name ?? "?";
        logger.SignedPropertiesBuilt(signedPropertiesId, signingCertificateForm.ToString(),
            signaturePolicy is not null, commitmentType is not null, signerRoles?.Count ?? 0);
        logger.ReferenceDigestComputed(algorithm, documentUri, documentDigest.Length);
        logger.ReferenceDigestComputed(algorithm, "#" + signedPropertiesId, signedPropertiesDigest.Length);
        logger.SignedInfoCanonicalized(XmlDSigUrls.ExcC14N, signedInfoCanonical.Length);
        logger.SignatureValueGenerated(signatureValue.Length);
    }

    internal static byte[] BuildSignature(
        byte[] xmlData,
        X509Certificate2 certificate,
        HashAlgorithmName hashAlgorithm,
        DateTimeOffset signingTime,
        IReadOnlyList<X509Certificate2>? extraCertificates,
        CommitmentType? commitmentType,
        SignaturePolicyReference? signaturePolicy,
        XadesSigningCertificateForm signingCertificateForm,
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
                extraCertificates, commitmentType, signaturePolicy, signingCertificateForm,
                signatureAlgorithmOid, form, dataUri, signerRoles, dataObjectFormat, logger);
        }

        var xmlDoc = LoadDocument(xmlData);

        if (xmlDoc.DocumentElement is null)
        {
            throw new ArgumentException("XML data does not contain a root element.", nameof(xmlData));
        }

        string signatureId = XadesUris.SignatureIdPrefix + Guid.NewGuid().ToString("N")[..8];
        string signedPropertiesId = XadesUris.SignedPropertiesIdPrefix + Guid.NewGuid().ToString("N")[..8];

        var signedProperties = CreateSignedProperties(
            xmlDoc, certificate, hashAlgorithm, signingTime,
            signedPropertiesId, signatureId, commitmentType,
            signaturePolicy, signingCertificateForm, signerRoles, dataObjectFormat);

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
        LogSignatureSteps(logger, hashAlgorithm, signedPropertiesId, signingCertificateForm, signaturePolicy, commitmentType,
            signerRoles, string.Empty, docDigest, signedPropsDigest, signedInfoCanonical, signatureValueBytes);

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
        SignaturePolicyReference? signaturePolicy,
        XadesSigningCertificateForm signingCertificateForm,
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
                form, commitmentType, signaturePolicy, signingCertificateForm, signatureAlgorithmOid,
                signerRoles, dataObjectFormat, out signedPropertiesId, out signedInfoXmlBytes,
                out dataObjectId, dataUri);
        }

        dataObjectId = null;

        signedPropertiesId = "SignedProperties-" + Guid.NewGuid().ToString("N")[..8];
        string signatureId = XadesUris.SignatureIdPrefix + Guid.NewGuid().ToString("N")[..8];

        // Create a temporary document with all elements so digests can be computed
        var xmlDoc = LoadDocument(xmlData);

        if (xmlDoc.DocumentElement is null)
        {
            throw new ArgumentException("XML data does not contain a root element.", nameof(xmlData));
        }

        var signedProperties = CreateSignedProperties(
            xmlDoc, certificate, hashAlgorithm, signingTime,
            signedPropertiesId, signatureId, commitmentType,
            signaturePolicy, signingCertificateForm, signerRoles, dataObjectFormat);

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
        SignaturePolicyReference? signaturePolicy,
        XadesSigningCertificateForm signingCertificateForm,
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
                extraCertificates, commitmentType, signaturePolicy, signingCertificateForm,
                signatureAlgorithmOid, signedInfoBytes, signatureValue, signedPropertiesId,
                signerRoles, dataObjectFormat, form, dataUri, dataObjectId);
        }

        var xmlDoc = LoadDocument(xmlData);

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
            signaturePolicy, signingCertificateForm, signerRoles, dataObjectFormat);

        var qualifyingProps = CreateQualifyingProperties(xmlDoc, signatureId, signedProperties);
        var objElement = xmlDoc.CreateElement("Object", XmlDSigUrls.DsNamespace);
        objElement.AppendChild(qualifyingProps);
        sigElement.AppendChild(objElement);

        xmlDoc.DocumentElement!.AppendChild(sigElement);

        using var ms = new MemoryStream();
        xmlDoc.Save(ms);
        return ms.ToArray();
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
}
