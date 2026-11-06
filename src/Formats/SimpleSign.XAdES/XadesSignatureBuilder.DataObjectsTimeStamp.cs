using System.Xml;
using SimpleSign.Core.Constants;
using SimpleSign.XAdES.Constants;

namespace SimpleSign.XAdES;

/// <summary>
/// The time-stamp token of an AllDataObjectsTimeStamp and, for the enveloping form, the Id of the
/// ds:Object it was computed over: the signature must wrap the data in an object with that Id.
/// </summary>
internal sealed record XadesDataObjectsTimeStamp(byte[] Token, string? DataObjectId);

internal static partial class XadesSignatureBuilder
{
    /// <summary>A fresh Id for the ds:Object that wraps the data of an enveloping signature.</summary>
    internal static string NewDataObjectId() => "Object-" + Guid.NewGuid().ToString("N")[..8];

    /// <summary>
    /// The message imprint input of AllDataObjectsTimeStamp (ETSI EN 319 132-1 §5.2.8.1): the
    /// octets of every ds:Reference of SignedInfo, processed as XMLDSig says, except the one to
    /// SignedProperties, in order: what the reference to the document digests, then the data of
    /// each additional data object.
    /// </summary>
    /// <param name="xmlData">The document to sign.</param>
    /// <param name="form">The signature form, which decides what the reference points to.</param>
    /// <param name="canonicalization">The canonicalization transform of the reference.</param>
    /// <param name="dataObjectId">The Id of the wrapping ds:Object (enveloping form only).</param>
    /// <param name="additionalReferences">The additional data objects, in the order of their references.</param>
    internal static byte[] DataObjectsTimeStampInput(
        byte[] xmlData, XadesForm form, string canonicalization, string? dataObjectId, IReadOnlyList<XadesAdditionalReference>? additionalReferences)
    {
        using var input = new MemoryStream();
        input.Write(DocumentReferenceOctets(xmlData, form, canonicalization, dataObjectId));
        foreach (XadesAdditionalReference reference in additionalReferences ?? [])
        {
            input.Write(reference.DataObject.Content.Span);
        }

        return input.ToArray();
    }

    /// <summary>What the reference to the document digests, for each signature form.</summary>
    private static byte[] DocumentReferenceOctets(byte[] xmlData, XadesForm form, string canonicalization, string? dataObjectId)
    {
        var document = LoadDocument(xmlData);
        if (document.DocumentElement is null)
        {
            throw new ArgumentException("XML data does not contain a root element.", nameof(xmlData));
        }

        if (form != XadesForm.Enveloping)
        {
            // Enveloped: the document without any signature. Detached: the external document as it is.
            if (form == XadesForm.Enveloped)
            {
                RemoveSignatureElements(document);
            }

            return CanonicalizeXml(document, canonicalization);
        }

        // Enveloping: the ds:Object that will wrap the data, directly under the ds:Signature root.
        var wrapper = new XmlDocument { PreserveWhitespace = true };
        var signature = wrapper.CreateElement("Signature", XmlDSigUrls.DsNamespace);
        wrapper.AppendChild(signature);
        var dataObject = wrapper.CreateElement("Object", XmlDSigUrls.DsNamespace);
        dataObject.SetAttribute("Id", dataObjectId);
        dataObject.AppendChild(wrapper.ImportNode(document.DocumentElement, true));
        signature.AppendChild(dataObject);
        return CanonicalizeElement(dataObject, canonicalization);
    }

    /// <summary>
    /// <code>
    /// &lt;AllDataObjectsTimeStamp&gt;
    ///   &lt;ds:CanonicalizationMethod Algorithm="…"/&gt;
    ///   &lt;EncapsulatedTimeStamp&gt;base64&lt;/EncapsulatedTimeStamp&gt;
    /// &lt;/AllDataObjectsTimeStamp&gt;
    /// </code>
    /// </summary>
    private static XmlElement CreateAllDataObjectsTimeStamp(XmlDocument doc, byte[] token)
    {
        // No Id: it is optional, and SignedProperties is built twice when the key is external
        // (once to hash, once to finish), so nothing in it may change between the two.
        var timestamp = doc.CreateElement("AllDataObjectsTimeStamp", XadesUris.XadesNamespace);

        // The references end in a canonicalization transform, so this algorithm canonicalizes
        // nothing here; §4.5 still asks new signatures to declare it.
        var canonicalization = doc.CreateElement("CanonicalizationMethod", XmlDSigUrls.DsNamespace);
        canonicalization.SetAttribute("Algorithm", XmlDSigUrls.ExcC14N);
        timestamp.AppendChild(canonicalization);

        var encapsulated = doc.CreateElement("EncapsulatedTimeStamp", XadesUris.XadesNamespace);
        encapsulated.InnerText = Convert.ToBase64String(token);
        timestamp.AppendChild(encapsulated);
        return timestamp;
    }
}
