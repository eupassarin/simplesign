using System.Xml;
using SimpleSign.Core.Crypto;
using SimpleSign.XAdES.Constants;

namespace SimpleSign.XAdES;

internal static partial class XadesSignatureBuilder
{
    /// <summary>
    /// Appends the SignaturePolicyStore unsigned property (ETSI EN 319 132-1 §5.2.10) to the
    /// identified signature. The property and SPDocSpecification live in the v1.4.1 namespace;
    /// the Identifier inside SPDocSpecification is the v1.3.2 ObjectIdentifierType one.
    /// </summary>
    internal static byte[] EmbedSignaturePolicyStore(byte[] signedXml, SignaturePolicyStore store, string? signatureId)
    {
        var doc = new XmlDocument { PreserveWhitespace = true };
        doc.Load(new MemoryStream(signedXml));
        var ns = CreateNamespaceManager(doc);
        XmlElement signature = ResolveSignature(doc, ns, signatureId);
        var unsignedProps = EnsureUnsignedSignatureProperties(doc, signature, ns);

        var storeElement = doc.CreateElement("SignaturePolicyStore", XadesUris.Xades141Namespace);
        var specification = doc.CreateElement("SPDocSpecification", XadesUris.Xades141Namespace);
        var identifier = doc.CreateElement("Identifier", XadesUris.XadesNamespace);
        if (store.SpecificationIsOid)
        {
            // An OID is written as a URN (IETF RFC 3061) and says so in the qualifier.
            identifier.SetAttribute("Qualifier", "OIDAsURN");
            identifier.InnerText = "urn:oid:" + store.Specification;
        }
        else
        {
            identifier.InnerText = store.Specification;
        }

        specification.AppendChild(identifier);
        storeElement.AppendChild(specification);

        XmlElement content;
        if (store.LocalUri is not null)
        {
            content = doc.CreateElement("SigPolDocLocalURI", XadesUris.Xades141Namespace);
            content.InnerText = store.LocalUri;
        }
        else
        {
            content = doc.CreateElement("SignaturePolicyDocument", XadesUris.Xades141Namespace);
            content.InnerText = Convert.ToBase64String(store.Document.Span);
        }

        storeElement.AppendChild(content);
        unsignedProps.AppendChild(storeElement);

        using var ms = new MemoryStream();
        doc.Save(ms);
        return ms.ToArray();
    }

    /// <summary>Reads the SignaturePolicyStore of a signature; null when there is none or it is malformed.</summary>
    internal static SignaturePolicyStore? ReadSignaturePolicyStore(XmlElement signature, XmlNamespaceManager ns)
    {
        if (signature.SelectSingleNode(
                "ds:Object/xades:QualifyingProperties/xades:UnsignedProperties/xades:UnsignedSignatureProperties/xades141:SignaturePolicyStore",
                ns) is not XmlElement store
            || store.SelectSingleNode("xades141:SPDocSpecification/xades:Identifier", ns) is not XmlElement identifier)
        {
            return null;
        }

        string specification = identifier.InnerText.Trim();
        if (specification.StartsWith("urn:oid:", StringComparison.OrdinalIgnoreCase))
        {
            specification = specification["urn:oid:".Length..];
        }

        try
        {
            if (store.SelectSingleNode("xades141:SignaturePolicyDocument", ns) is XmlElement document)
            {
                return SignaturePolicyStore.FromDocument(specification, Convert.FromBase64String(document.InnerText.Trim()));
            }

            return store.SelectSingleNode("xades141:SigPolDocLocalURI", ns) is XmlElement localUri
                ? SignaturePolicyStore.FromLocalUri(specification, localUri.InnerText)
                : null;
        }
        catch (Exception ex) when (ex is FormatException or ArgumentException)
        {
            return null;
        }
    }
}
