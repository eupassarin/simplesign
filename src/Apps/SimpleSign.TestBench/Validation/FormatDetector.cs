using System.Xml;
using SimpleSign.TestBench.Localization;
using SimpleSign.TestBench.Runs;

namespace SimpleSign.TestBench.Validation;

/// <summary>Tells which signature format a file holds, so validation needs no format choice.</summary>
internal static class FormatDetector
{
    private const string DsNamespace = "http://www.w3.org/2000/09/xmldsig#";

    /// <summary>The format of <paramref name="content"/>: pades, cades or xades.</summary>
    /// <exception cref="ArgumentException">The file is not a PDF, an XML document or a DER structure.</exception>
    public static string Detect(byte[] content)
    {
        ArgumentNullException.ThrowIfNull(content);
        var start = content.AsSpan(0, Math.Min(content.Length, 1024));
        if (start.IndexOf("%PDF-"u8) >= 0)
        {
            return RunFormats.Pades;
        }

        // XML: an optional byte order mark and white space, then "<".
        var text = start.StartsWith((ReadOnlySpan<byte>)[0xEF, 0xBB, 0xBF]) ? start[3..] : start;
        text = text.TrimStart(" \t\r\n"u8);
        if (!text.IsEmpty && text[0] == (byte)'<')
        {
            return RunFormats.Xades;
        }

        // CMS: a DER SEQUENCE, or the same in PEM.
        if ((!start.IsEmpty && start[0] == 0x30) || text.StartsWith("-----BEGIN"u8))
        {
            return RunFormats.Cades;
        }

        throw new ArgumentException(L.T("This file is not a PDF, an XML document or a CMS signature (.p7s, .p7m)."), nameof(content));
    }

    /// <summary>
    /// The URI by which a detached XML signature refers to its data (the first Reference that is
    /// not a same-document reference), or null. An external validator matches the original
    /// document to the reference by this name.
    /// </summary>
    public static string? DetachedReferenceUri(byte[] xml)
    {
        try
        {
            var document = new XmlDocument { XmlResolver = null };
            using var stream = new MemoryStream(xml, writable: false);
            using var reader = XmlReader.Create(stream, new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null });
            document.Load(reader);
            foreach (XmlElement reference in document.GetElementsByTagName("Reference", DsNamespace))
            {
                string uri = reference.GetAttribute("URI");
                if (uri.Length > 0 && uri[0] != '#')
                {
                    return uri;
                }
            }
        }
        catch (XmlException)
        {
            // Not XML: there is no reference to name.
        }

        return null;
    }
}
