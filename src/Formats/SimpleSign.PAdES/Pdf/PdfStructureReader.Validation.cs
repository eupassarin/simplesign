using SimpleSign.PAdES.Pdf.Enums;
using SimpleSign.PAdES.Pdf.Exceptions;

using SimpleSign.PAdES.Pdf.Model;

namespace SimpleSign.PAdES.Pdf;

public sealed partial class PdfStructureReader
{
    #region PDF Header Validation

    private static void ValidatePdfHeader(ReadOnlySpan<byte> data)
    {
        if (!data.StartsWith(PdfHeaderMarker))
        {
            throw new PdfStructureException("Not a valid PDF file (missing %PDF- header).");
        }
    }

    /// <summary>
    /// Throws <see cref="EncryptedPdfException"/> if the PDF trailer contains an /Encrypt entry.
    /// </summary>
    private static void ThrowIfEncrypted(PdfDocument document)
    {
        if (document.IsEncrypted)
        {
            throw new EncryptedPdfException(
                "This PDF is encrypted. SimpleSign cannot sign or validate encrypted PDFs. " +
                "Decrypt the PDF first using a tool like Adobe Acrobat or qpdf.");
        }
    }

    /// <summary>
    /// The PDF/A level the catalog's XMP metadata stream (ISO 19005-1 §6.7.11) declares, read through the object model
    /// (ADR 0032); <see cref="PdfALevel.None"/> without one, or when it cannot be decoded.
    /// </summary>
    internal static PdfALevel PdfALevelOf(PdfRevisionView view)
    {
        if (view.Resolve(view.Catalog?.Get("Metadata")) is not PdfStream metadata)
        {
            return PdfALevel.None;
        }

        try
        {
            return ParsePdfALevelFromXmp(view.Document.DecodeStream(metadata, view.Revision));
        }
        catch (Exception ex) when (ex is PdfFilterException or PdfUnsupportedFilterException)
        {
            return PdfALevel.None;
        }
    }

    /// <summary>
    /// Reads <c>pdfaid:part</c> and <c>pdfaid:conformance</c> from XMP. XMP (ISO 16684-1 §7.9.2.2) writes a simple
    /// property either as an element (<c>&lt;pdfaid:part&gt;3&lt;/pdfaid:part&gt;</c>) or as an attribute of
    /// <c>rdf:Description</c> (<c>pdfaid:part="3"</c>); both are read. <see cref="PdfALevel.None"/> when there is no part.
    /// </summary>
    private static PdfALevel ParsePdfALevelFromXmp(ReadOnlySpan<byte> span)
    {
        int partStart = FindXmpPropertyValue(span, "pdfaid:part"u8, 0);
        if (partStart < 0)
        {
            return PdfALevel.None;
        }

        if (partStart >= span.Length)
        {
            return PdfALevel.Unknown;
        }

        int part = span[partStart] - '0';

        // Conformance is optional for PDF/A-4; when absent, B is assumed, as before.
        int confStart = FindXmpPropertyValue(span, "pdfaid:conformance"u8, 0);
        char conformance = confStart >= 0 && confStart < span.Length
            ? char.ToUpperInvariant((char)span[confStart])
            : 'B';

        return (part, conformance) switch
        {
            (1, 'A') => PdfALevel.A1a,
            (1, 'B') => PdfALevel.A1b,
            (2, 'A') => PdfALevel.A2a,
            (2, 'B') => PdfALevel.A2b,
            (2, 'U') => PdfALevel.A2u,
            (3, 'A') => PdfALevel.A3a,
            (3, 'B') => PdfALevel.A3b,
            (3, 'U') => PdfALevel.A3u,
            (4, 'A') => PdfALevel.A4a,
            (4, 'B') => PdfALevel.A4b,
            (4, 'U') => PdfALevel.A4u,
            (4, 'E') => PdfALevel.A4e,
            _ => PdfALevel.Unknown
        };
    }

    /// <summary>
    /// Index of the first character of an XMP property's value, written as an element (<c>name&gt;value</c>) or as an
    /// attribute (<c>name="value"</c> or <c>name='value'</c>); -1 when the property is absent. Whitespace after the
    /// tag or quote is skipped, so the index points at the value itself (or at the end of the data).
    /// </summary>
    private static int FindXmpPropertyValue(ReadOnlySpan<byte> span, ReadOnlySpan<byte> name, int startAt)
    {
        int pos = startAt;
        while (pos < span.Length)
        {
            int found = span[pos..].IndexOf(name);
            int idx = found < 0 ? -1 : pos + found;
            if (idx < 0)
            {
                return -1;
            }

            int i = SkipXmlWhitespace(span, idx + name.Length);
            if (i < span.Length && span[i] == (byte)'>')
            {
                return SkipXmlWhitespace(span, i + 1);
            }

            if (i < span.Length && span[i] == (byte)'=')
            {
                i = SkipXmlWhitespace(span, i + 1);
                if (i < span.Length && span[i] is (byte)'"' or (byte)'\'')
                {
                    return SkipXmlWhitespace(span, i + 1);
                }
            }

            pos = idx + 1;
        }

        return -1;
    }

    private static int SkipXmlWhitespace(ReadOnlySpan<byte> span, int i)
    {
        while (i < span.Length && span[i] is (byte)' ' or (byte)'\t' or (byte)'\r' or (byte)'\n')
        {
            i++;
        }

        return i;
    }
    #endregion
}
