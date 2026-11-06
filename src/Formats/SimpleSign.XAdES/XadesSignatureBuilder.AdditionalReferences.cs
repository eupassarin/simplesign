using System.Security.Cryptography;
using System.Xml;
using SimpleSign.Core.Constants;
using SimpleSign.XAdES.Constants;

namespace SimpleSign.XAdES;

internal static partial class XadesSignatureBuilder
{
    /// <summary>Gives each additional data object the Ids of its ds:Reference and, when embedded, of its ds:Object.</summary>
    internal static IReadOnlyList<XadesAdditionalReference>? PlanAdditionalReferences(IReadOnlyList<XadesDataObject>? dataObjects)
    {
        if (dataObjects is null || dataObjects.Count == 0)
        {
            return null;
        }

        var references = new List<XadesAdditionalReference>(dataObjects.Count);
        foreach (XadesDataObject dataObject in dataObjects)
        {
            string suffix = Guid.NewGuid().ToString("N")[..8];
            references.Add(new XadesAdditionalReference(dataObject, "Reference-" + suffix, dataObject.IsEmbedded ? "Object-" + suffix : null));
        }

        return references;
    }

    /// <summary>
    /// The Id the reference to the document takes so its DataObjectFormat can point to it (ETSI EN
    /// 319 132-1 §6.3: one DataObjectFormat for each signed data object). Null when the document gets
    /// no DataObjectFormat: the XAdES 1.3.2 form with neither a format asked for nor additional data
    /// objects, which leaves the reference without an Id as that form always had it.
    /// It is derived from the SignedProperties Id because the signature is assembled twice with an
    /// external key and both passes must agree.
    /// </summary>
    internal static string? DocumentReferenceId(
        string signedPropertiesId,
        XadesSigningCertificateForm signingCertificateForm,
        DataObjectFormat? dataObjectFormat,
        IReadOnlyList<XadesAdditionalReference>? additionalReferences)
    {
        if (signingCertificateForm == XadesSigningCertificateForm.V1 && dataObjectFormat is null && additionalReferences is not { Count: > 0 })
        {
            return null;
        }

        string suffix = signedPropertiesId.StartsWith(XadesUris.SignedPropertiesIdPrefix, StringComparison.Ordinal)
            ? signedPropertiesId[XadesUris.SignedPropertiesIdPrefix.Length..]
            : signedPropertiesId;
        return "Reference-doc-" + suffix;
    }

    /// <summary>
    /// Gives the reference to the document its Id, when it has one, and appends one ds:Reference
    /// per additional data object after it.
    /// Embedded data: <c>URI="#object"</c> with the base64 transform. External data: its URI and no
    /// transform. In both the digest is over the data itself.
    /// </summary>
    private static void AppendAdditionalReferences(
        XmlDocument doc, XmlElement signedInfo, IReadOnlyList<XadesAdditionalReference>? references, HashAlgorithmName hashAlgorithm,
        string? documentReferenceId)
    {
        // The reference appended just before this call is the one to the document.
        if (documentReferenceId is not null && signedInfo.LastChild is XmlElement documentReference)
        {
            documentReference.SetAttribute("Id", documentReferenceId);
        }

        foreach (XadesAdditionalReference reference in references ?? [])
        {
            var element = doc.CreateElement("Reference", XmlDSigUrls.DsNamespace);
            element.SetAttribute("Id", reference.ReferenceId);
            element.SetAttribute("URI", reference.ObjectId is null ? reference.DataObject.Uri : "#" + reference.ObjectId);
            if (reference.ObjectId is not null)
            {
                var transforms = doc.CreateElement("Transforms", XmlDSigUrls.DsNamespace);
                var base64 = doc.CreateElement("Transform", XmlDSigUrls.DsNamespace);
                base64.SetAttribute("Algorithm", XmlDSigUrls.Base64Transform);
                transforms.AppendChild(base64);
                element.AppendChild(transforms);
            }

            var digestMethod = doc.CreateElement("DigestMethod", XmlDSigUrls.DsNamespace);
            digestMethod.SetAttribute("Algorithm", GetDigestMethod(hashAlgorithm));
            element.AppendChild(digestMethod);
            var digestValue = doc.CreateElement("DigestValue", XmlDSigUrls.DsNamespace);
            digestValue.InnerText = Convert.ToBase64String(HashData(hashAlgorithm, reference.DataObject.Content.ToArray()));
            element.AppendChild(digestValue);
            signedInfo.AppendChild(element);
        }
    }

    /// <summary>Appends the base64 ds:Object of each embedded additional data object to the signature.</summary>
    private static void AppendAdditionalObjects(XmlDocument doc, XmlElement signature, IReadOnlyList<XadesAdditionalReference>? references)
    {
        foreach (XadesAdditionalReference reference in references ?? [])
        {
            if (reference.ObjectId is null)
            {
                continue;
            }

            var dataObject = doc.CreateElement("Object", XmlDSigUrls.DsNamespace);
            dataObject.SetAttribute("Id", reference.ObjectId);
            dataObject.SetAttribute("Encoding", XmlDSigUrls.Base64Transform);
            dataObject.InnerText = Convert.ToBase64String(reference.DataObject.Content.Span);
            signature.AppendChild(dataObject);
        }
    }

    /// <summary>
    /// Appends the DataObjectFormat of each additional data object. A baseline signature shall have
    /// one per signed data object (ETSI EN 319 132-1 §6.3); a file whose type was not given is
    /// declared as application/octet-stream.
    /// </summary>
    private static void AppendAdditionalDataObjectFormats(
        XmlDocument doc, XmlElement signedDataObjectProperties, IReadOnlyList<XadesAdditionalReference>? references)
    {
        foreach (XadesAdditionalReference reference in references ?? [])
        {
            var format = doc.CreateElement("DataObjectFormat", XadesUris.XadesNamespace);
            format.SetAttribute("ObjectReference", "#" + reference.ReferenceId);
            var mimeType = doc.CreateElement("MimeType", XadesUris.XadesNamespace);
            mimeType.InnerText = reference.DataObject.MimeType ?? "application/octet-stream";
            format.AppendChild(mimeType);
            signedDataObjectProperties.AppendChild(format);
        }
    }
}
