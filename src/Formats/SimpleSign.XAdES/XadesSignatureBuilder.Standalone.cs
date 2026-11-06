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

namespace SimpleSign.XAdES;

internal static partial class XadesSignatureBuilder
{
    private static byte[] BuildStandaloneSignature(
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
            signedPropertiesId, signatureId, commitmentType, signaturePolicy, signingCertificateForm,
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
        LogSignatureSteps(logger, hashAlgorithm, signedPropertiesId, signingCertificateForm, signaturePolicy, commitmentType,
            signerRoles, docRefUri, docDigest, signedPropsDigest, signedInfoCanonical, signatureValueBytes);

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
        SignaturePolicyReference? signaturePolicy,
        XadesSigningCertificateForm signingCertificateForm,
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
            signedPropertiesId, signatureId, commitmentType, signaturePolicy, signingCertificateForm,
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
        SignaturePolicyReference? signaturePolicy,
        XadesSigningCertificateForm signingCertificateForm,
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
            signedPropertiesId, signatureId, commitmentType, signaturePolicy, signingCertificateForm,
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
