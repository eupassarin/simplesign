namespace SimpleSign.Peru.Iofe.Accredited.Internal;

/// <summary>Tells the format of a signed document from its first bytes.</summary>
internal static class IofeFormats
{
    private static ReadOnlySpan<byte> PdfHeader => "%PDF-"u8;

    /// <summary>PDF when the header is in the first kilobyte, XML when the first character is <c>&lt;</c>, CMS otherwise.</summary>
    internal static IofeDocumentFormat Detect(ReadOnlySpan<byte> document)
    {
        if (document[..Math.Min(document.Length, 1024)].IndexOf(PdfHeader) >= 0)
        {
            return IofeDocumentFormat.Pdf;
        }

        ReadOnlySpan<byte> text = document;
        if (text.StartsWith((ReadOnlySpan<byte>)[0xEF, 0xBB, 0xBF]))
        {
            text = text[3..];
        }

        int first = text.IndexOfAnyExcept(" \t\r\n"u8);
        return first >= 0 && text[first] == (byte)'<' ? IofeDocumentFormat.Xml : IofeDocumentFormat.Cms;
    }
}
