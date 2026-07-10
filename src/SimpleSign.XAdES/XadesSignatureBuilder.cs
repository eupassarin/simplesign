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

    internal static byte[] EmbedSignatureTimeStamp(byte[] signedXml, byte[] tsToken)
    {
        var doc = new XmlDocument { PreserveWhitespace = true };
        doc.Load(new MemoryStream(signedXml));
        var ns = new XmlNamespaceManager(doc.NameTable);
        ns.AddNamespace("ds", XmlDSigUrls.DsNamespace);
        ns.AddNamespace("xades", XadesUris.XadesNamespace);

        if (doc.SelectSingleNode("//ds:Signature", ns) is not XmlElement signature)
        {
            throw new InvalidOperationException("Signature element not found.");
        }

        var unsignedProps = EnsureUnsignedSignatureProperties(doc, signature, ns);

        var tsElement = doc.CreateElement("SignatureTimeStamp", XadesUris.XadesNamespace);
        tsElement.SetAttribute("Id", XadesUris.SignatureTimeStampIdPrefix + Guid.NewGuid().ToString("N")[..8]);
        var encElement = doc.CreateElement("EncapsulatedTimeStamp", XadesUris.XadesNamespace);
        encElement.InnerText = Convert.ToBase64String(tsToken);
        tsElement.AppendChild(encElement);
        unsignedProps.AppendChild(tsElement);

        using var ms = new MemoryStream();
        doc.Save(ms);
        return ms.ToArray();
    }

    internal static byte[] EmbedLtvData(byte[] signedXml, LtvCollectionResult ltvData)
    {
        var doc = new XmlDocument { PreserveWhitespace = true };
        doc.Load(new MemoryStream(signedXml));
        var ns = new XmlNamespaceManager(doc.NameTable);
        ns.AddNamespace("ds", XmlDSigUrls.DsNamespace);
        ns.AddNamespace("xades", XadesUris.XadesNamespace);

        if (doc.SelectSingleNode("//ds:Signature", ns) is not XmlElement signature)
        {
            throw new InvalidOperationException("Signature element not found.");
        }

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

    internal static byte[] EmbedArchiveTimeStamp(byte[] signedXml, byte[] tsToken)
    {
        var doc = new XmlDocument { PreserveWhitespace = true };
        doc.Load(new MemoryStream(signedXml));
        var ns = new XmlNamespaceManager(doc.NameTable);
        ns.AddNamespace("ds", XmlDSigUrls.DsNamespace);
        ns.AddNamespace("xades", XadesUris.XadesNamespace);
        ns.AddNamespace("xades141", XadesUris.Xades141Namespace);

        if (doc.SelectSingleNode("//ds:Signature", ns) is not XmlElement signature)
        {
            throw new InvalidOperationException("Signature element not found.");
        }

        var unsignedProps = EnsureUnsignedSignatureProperties(doc, signature, ns);

        var atsElement = doc.CreateElement("ArchiveTimeStamp", XadesUris.Xades141Namespace);
        atsElement.SetAttribute("Id", XadesUris.ArchiveTimeStampIdPrefix + Guid.NewGuid().ToString("N")[..8]);
        var encElement = doc.CreateElement("EncapsulatedTimeStamp", XadesUris.Xades141Namespace);
        encElement.InnerText = Convert.ToBase64String(tsToken);
        atsElement.AppendChild(encElement);
        unsignedProps.AppendChild(atsElement);

        using var ms = new MemoryStream();
        doc.Save(ms);
        return ms.ToArray();
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
        writer.WriteEncodedValue(certificate.IssuerName.RawData);
        var serial = certificate.GetSerialNumber();
        Array.Reverse(serial);
        writer.WriteInteger(serial);
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
                "xades:QualifyingProperties/xades:UnsignedProperties", ns) is not XmlElement unsignedProps)
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

    private static byte[] CanonicalizeXml(XmlDocument doc)
    {
        var transform = new XmlDsigExcC14NTransform();
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

        sigEl.InsertBefore(outDoc.ImportNode(signedInfo, true), sigEl.FirstChild);

        var sigValueEl = outDoc.CreateElement("SignatureValue", XmlDSigUrls.DsNamespace);
        sigValueEl.InnerText = Convert.ToBase64String(signatureValueBytes);
        sigEl.InsertBefore(sigValueEl, sigEl.FirstChild);

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
        sigEl.InsertBefore(keyInfo, sigEl.FirstChild);

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
        sigEl.AppendChild(siElement);

        var sigValueElement = outDoc.CreateElement("SignatureValue", XmlDSigUrls.DsNamespace);
        sigValueElement.InnerText = Convert.ToBase64String(signatureValue);
        sigEl.AppendChild(sigValueElement);

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
            sigEl.AppendChild(outDoc.ImportNode(kiXml, true));
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
