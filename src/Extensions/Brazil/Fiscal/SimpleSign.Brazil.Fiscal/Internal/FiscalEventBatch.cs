using System.Text;
using System.Xml;

namespace SimpleSign.Brazil.Fiscal.Internal;

/// <summary>One event of an eSocial or EFD-Reinf batch.</summary>
/// <param name="Id">The Id of its <c>evento</c> (<c>Id</c> or <c>id</c>), or null.</param>
/// <param name="Xml">The event (the first element inside <c>evento</c>) as a document of its own, or null when <c>evento</c> is empty.</param>
internal sealed record FiscalBatchEvent(string? Id, byte[]? Xml);

/// <summary>
/// The batch of eSocial and EFD-Reinf (<c>envioLoteEventos</c>). Each event is signed on its own, as a document,
/// before it goes in the batch, and the batch itself is not signed: a signature of an event (<c>URI=""</c> in eSocial)
/// means that event, not the batch. Read by local names, whatever the version's namespace:
/// <c>&lt;eSocial|Reinf&gt;&lt;envioLoteEventos&gt;&lt;eventos&gt;&lt;evento Id&gt;&lt;eSocial|Reinf&gt;…</c>.
/// </summary>
internal static class FiscalEventBatch
{
    /// <summary>The element that makes a document a batch: a child of the root.</summary>
    internal const string BatchElement = "envioLoteEventos";

    private const string DsNamespace = "http://www.w3.org/2000/09/xmldsig#";

    /// <summary>Reads XML keeping its whitespace, with DTDs prohibited and no external resolution; null when it cannot be read.</summary>
    internal static XmlDocument? Load(ReadOnlyMemory<byte> xml)
    {
        var document = new XmlDocument { PreserveWhitespace = true, XmlResolver = null };
        try
        {
            using var stream = new MemoryStream(xml.ToArray(), writable: false);
            using var reader = XmlReader.Create(stream, new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null });
            document.Load(reader);
        }
        catch (XmlException)
        {
            return null;
        }

        return document.DocumentElement is null ? null : document;
    }

    /// <summary>The <c>envioLoteEventos</c> of <paramref name="document"/>, or null when it is not a batch.</summary>
    internal static XmlElement? Batch(XmlDocument document) =>
        document.DocumentElement?.ChildNodes.OfType<XmlElement>().FirstOrDefault(e => e.LocalName == BatchElement);

    /// <summary>Whether <paramref name="xml"/> is an eSocial or EFD-Reinf batch.</summary>
    internal static bool IsBatch(ReadOnlyMemory<byte> xml) => Load(xml) is { } document && Batch(document) is not null;

    /// <summary>The events of <paramref name="batch"/>, in document order.</summary>
    internal static List<FiscalBatchEvent> Events(XmlElement batch) =>
        [.. Children(batch, "eventos").SelectMany(e => Children(e, "evento"))
            .Select(e => new FiscalBatchEvent(Id(e), e.ChildNodes.OfType<XmlElement>().FirstOrDefault() is { } inner ? Standalone(inner) : null))];

    /// <summary>How many ds:Signature of <paramref name="document"/> are outside its events (a signature of the batch itself).</summary>
    internal static int SignaturesOutsideEvents(XmlDocument document) =>
        document.GetElementsByTagName("Signature", DsNamespace).OfType<XmlElement>().Count(s => !InEvent(s));

    private static IEnumerable<XmlElement> Children(XmlElement parent, string localName) =>
        parent.ChildNodes.OfType<XmlElement>().Where(e => e.LocalName == localName);

    private static string? Id(XmlElement evento) =>
        evento.GetAttribute("Id") is { Length: > 0 } id ? id
        : evento.GetAttribute("id") is { Length: > 0 } lower ? lower
        : null;

    private static bool InEvent(XmlElement signature)
    {
        for (XmlNode? node = signature.ParentNode; node is XmlElement element; node = element.ParentNode)
        {
            if (element.LocalName == "evento" && element.ParentNode?.LocalName == "eventos")
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// The event as the document it was when signed: the element with its subtree, its whitespace kept, written as
    /// UTF-8 without a declaration (the canonicalization of <c>URI=""</c> leaves the declaration out anyway).
    /// </summary>
    private static byte[] Standalone(XmlElement element)
    {
        var document = new XmlDocument { PreserveWhitespace = true, XmlResolver = null };
        document.AppendChild(document.ImportNode(element, deep: true));
        using var stream = new MemoryStream();
        var settings = new XmlWriterSettings
        {
            Encoding = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false),
            OmitXmlDeclaration = true,
            Indent = false,
        };
        using (var writer = XmlWriter.Create(stream, settings))
        {
            document.Save(writer);
        }

        return stream.ToArray();
    }
}
