using System.Xml;
using SimpleSign.Core.Constants;

namespace SimpleSign.XAdES;

internal static partial class XadesSignatureBuilder
{
    private const string XmlnsNamespace = "http://www.w3.org/2000/xmlns/";
    private const string XmlNamespace = "http://www.w3.org/XML/1998/namespace";

    /// <summary>The canonicalization algorithm URI of a <see cref="XadesCanonicalization"/> choice.</summary>
    internal static string CanonicalizationUri(XadesCanonicalization canonicalization) => canonicalization switch
    {
        XadesCanonicalization.Exclusive => XmlDSigUrls.ExcC14N,
        XadesCanonicalization.Inclusive => XmlDSigUrls.C14N,
        _ => throw new ArgumentOutOfRangeException(nameof(canonicalization)),
    };

    /// <summary>
    /// Whether the algorithm is Canonical XML 1.0 (inclusive), which gives the apex of a document
    /// subset the namespace declarations and xml: attributes of its ancestors.
    /// </summary>
    internal static bool IsInclusiveCanonicalization(string algorithm) =>
        algorithm is XmlDSigUrls.C14N or XmlDSigUrls.C14NWithComments;

    /// <summary>Canonicalizes an element as a document subset: the element and everything under it.</summary>
    internal static byte[] CanonicalizeElement(XmlElement element, string canonicalizationAlgorithm = XmlDSigUrls.ExcC14N) =>
        CanonicalizeXml(CopyAsDocument(element, canonicalizationAlgorithm), canonicalizationAlgorithm);

    /// <summary>
    /// Copies an element to a document of its own, ready to be canonicalized with
    /// <paramref name="canonicalizationAlgorithm"/>. Exclusive canonicalization ignores the
    /// ancestors, so the copy is enough. Inclusive canonicalization (Canonical XML 1.0 §2.4 and
    /// §4.7) renders on the apex the namespace declarations in scope and the xml: attributes of
    /// the ancestors left out of the subset, so the copy receives them.
    /// </summary>
    internal static XmlDocument CopyAsDocument(XmlElement element, string canonicalizationAlgorithm)
    {
        var document = new XmlDocument { PreserveWhitespace = true, XmlResolver = null };
        if (!IsInclusiveCanonicalization(canonicalizationAlgorithm))
        {
            document.AppendChild(document.ImportNode(element, true));
            return document;
        }

        // Re-parse the subtree so its own namespace declarations become explicit attributes.
        var settings = new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null };
        using (var reader = XmlReader.Create(new StringReader(element.OuterXml), settings))
        {
            document.Load(reader);
        }

        // Nearest ancestor first: a declaration closer to the element hides the ones above it.
        var namespaces = new Dictionary<string, string>(StringComparer.Ordinal);
        var xmlAttributes = new Dictionary<string, string>(StringComparer.Ordinal);
        for (XmlNode? node = element.ParentNode; node is XmlElement ancestor; node = ancestor.ParentNode)
        {
            foreach (XmlAttribute attribute in ancestor.Attributes)
            {
                if (attribute.NamespaceURI == XmlnsNamespace)
                {
                    namespaces.TryAdd(attribute.Prefix.Length == 0 ? string.Empty : attribute.LocalName, attribute.Value);
                }
                else if (attribute.NamespaceURI == XmlNamespace)
                {
                    xmlAttributes.TryAdd(attribute.LocalName, attribute.Value);
                }
            }

            // An element built in memory can bind its prefix without a declaration attribute.
            namespaces.TryAdd(ancestor.Prefix, ancestor.NamespaceURI);
        }

        XmlElement copy = document.DocumentElement!;
        foreach (var (prefix, uri) in namespaces)
        {
            string name = prefix.Length == 0 ? "xmlns" : "xmlns:" + prefix;
            if (uri.Length == 0 || prefix is "xml" or "xmlns" || copy.HasAttribute(name) || (prefix.Length == 0 && copy.Prefix.Length == 0))
            {
                continue; // not in scope, redeclared by the element, or the element sets its own default namespace
            }

            var declaration = prefix.Length == 0
                ? document.CreateAttribute("xmlns")
                : document.CreateAttribute("xmlns", prefix, XmlnsNamespace);
            declaration.Value = uri;
            copy.Attributes.Append(declaration);
        }

        foreach (var (localName, value) in xmlAttributes)
        {
            if (!copy.HasAttribute(localName, XmlNamespace))
            {
                var inherited = document.CreateAttribute("xml", localName, XmlNamespace);
                inherited.Value = value;
                copy.Attributes.Append(inherited);
            }
        }

        return document;
    }

    /// <summary>
    /// The canonical SignedInfo as it will stand inside <paramref name="signature"/>, which is
    /// already in its place in the document.
    /// </summary>
    private static byte[] CanonicalizeSignedInfo(XmlElement signedInfo, XmlElement signature, string canonicalizationAlgorithm)
    {
        var placed = (XmlElement)signature.OwnerDocument.ImportNode(signedInfo, true);
        signature.PrependChild(placed);
        try
        {
            return CanonicalizeElement(placed, canonicalizationAlgorithm);
        }
        finally
        {
            signature.RemoveChild(placed);
        }
    }
}
