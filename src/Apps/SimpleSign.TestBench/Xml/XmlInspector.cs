using System.Text;
using System.Xml;
using SimpleSign.Brazil.Fiscal;

namespace SimpleSign.TestBench.Xml;

/// <summary>
/// What the rules and the page need to know about an XML file. <c>FiscalTargets</c> holds, for each
/// fiscal profile key, the Ids of the elements it would sign ("" = the whole document).
/// </summary>
public sealed record XmlFacts(
    string FileId,
    string FileName,
    long Size,
    string? Root,
    string? Namespace,
    int Signatures,
    IReadOnlyDictionary<string, IReadOnlyList<string>> FiscalTargets,
    string? Error);

/// <summary>Reads XML safely (no DTD, no external resolution) for the XML page.</summary>
internal static class XmlInspector
{
    private const string DsNamespace = "http://www.w3.org/2000/09/xmldsig#";

    public static XmlDocument Load(byte[] xml)
    {
        var settings = new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null };
        using var reader = XmlReader.Create(new MemoryStream(xml, writable: false), settings);
        var doc = new XmlDocument { PreserveWhitespace = true, XmlResolver = null };
        doc.Load(reader);
        return doc;
    }

    public static XmlFacts Inspect(string fileId, string fileName, byte[] xml)
    {
        XmlDocument doc;
        try
        {
            doc = Load(xml);
        }
        catch (XmlException ex)
        {
            return new XmlFacts(fileId, fileName, xml.LongLength, null, null, 0, new Dictionary<string, IReadOnlyList<string>>(), ex.Message);
        }

        var root = doc.DocumentElement!;
        var targets = new Dictionary<string, IReadOnlyList<string>>(StringComparer.Ordinal);
        foreach (var (key, profile) in FiscalDocumentProfile.ByName)
        {
            targets[key] = Targets(doc, profile);
        }

        return new XmlFacts(fileId, fileName, xml.LongLength, root.LocalName, string.IsNullOrEmpty(root.NamespaceURI) ? null : root.NamespaceURI,
            doc.GetElementsByTagName("Signature", DsNamespace).Count, targets, null);
    }

    /// <summary>The Ids of the elements a fiscal profile signs; "" for a whole-document profile (eSocial).</summary>
    internal static IReadOnlyList<string> Targets(XmlDocument doc, FiscalDocumentProfile profile)
    {
        if (profile.SignedElement is null)
        {
            return [""];
        }

        var ids = new List<string>();
        foreach (XmlElement element in doc.GetElementsByTagName("*"))
        {
            if ((profile.SignedElement == "*" ? element.ParentNode == doc.DocumentElement : element.LocalName == profile.SignedElement)
                && element.GetAttribute(profile.IdAttribute!) is { Length: > 0 } id)
            {
                ids.Add(id);
            }
        }

        return ids;
    }

    /// <summary>The last ds:Signature, indented, with long base64 values shortened (for display).</summary>
    public static string? SignatureXml(byte[] xml)
    {
        try
        {
            var doc = Load(xml);
            var signatures = doc.GetElementsByTagName("Signature", DsNamespace);
            if (signatures.Count == 0)
            {
                return null;
            }

            var signature = (XmlElement)signatures[signatures.Count - 1]!.CloneNode(deep: true);
            foreach (XmlNode node in signature.SelectNodes("descendant-or-self::*")!)
            {
                if (node is XmlElement { HasChildNodes: true, FirstChild: XmlText text } && node.ChildNodes.Count == 1 && text.Value!.Trim().Length > 72)
                {
                    string value = text.Value.Trim();
                    text.Value = $"{value[..32]}…{value[^16..]} ({value.Length} chars)";
                }
            }

            return Indent(signature);
        }
        catch (XmlException)
        {
            return null;
        }
    }

    /// <summary>The start of the document, indented (for display).</summary>
    public static string Preview(byte[] xml, int maxChars = 6000)
    {
        string text;
        try
        {
            var doc = Load(xml);
            var signatures = doc.GetElementsByTagName("Signature", DsNamespace);
            for (int i = signatures.Count - 1; i >= 0; i--)
            {
                var node = signatures[i]!;
                if (node.ParentNode is XmlElement parent)
                {
                    // Enveloped: the document is shown without it. Detached / enveloping: the signature is the document.
                    parent.ReplaceChild(doc.CreateComment(" ds:Signature (shown separately) "), node);
                }
            }

            text = Indent(doc.DocumentElement!);
        }
        catch (XmlException)
        {
            text = Encoding.UTF8.GetString(xml);
        }

        return text.Length > maxChars ? text[..maxChars] + "\n…" : text;
    }

    private static string Indent(XmlElement element)
    {
        var builder = new StringBuilder();
        var settings = new XmlWriterSettings { Indent = true, IndentChars = "  ", OmitXmlDeclaration = true, NewLineHandling = NewLineHandling.Replace };
        using (var writer = XmlWriter.Create(builder, settings))
        {
            var copy = new XmlDocument { PreserveWhitespace = false };
            copy.LoadXml(element.OuterXml);
            copy.DocumentElement!.WriteTo(writer);
        }

        return builder.ToString();
    }
}
