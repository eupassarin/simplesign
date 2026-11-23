using System.Text;
using SimpleSign.PAdES.Pdf.Model;
using SimpleSign.PAdES.Pdf.Writing;

namespace SimpleSign.PAdES.Tests.Pdf;

/// <summary>What tests check in a PDF, read through the object model (ADR 0032).</summary>
internal static class ModelProbe
{
    /// <summary>Whether the latest cross-reference section is a stream.</summary>
    public static bool UsesXrefStream(byte[] pdf) => PdfDocument.Open(pdf).Latest.Sections[0].Kind == PdfXrefSectionKind.Stream;

    /// <summary>The catalog's object number; 0 when there is none.</summary>
    public static int Root(byte[] pdf) => PdfDocument.Open(pdf).RootId?.Number ?? 0;

    /// <summary>
    /// Where an object is in the file, from its <c>N G obj</c> to the end of its <c>endobj</c>, as the cross-reference
    /// lists it; (-1, -1) when it is in an object stream or not there.
    /// </summary>
    public static (int Start, int End) ObjectRange(byte[] pdf, int number)
    {
        var document = PdfDocument.Open(pdf);
        return document.Lookup(number) is { Type: PdfXrefEntryType.InUse } && document.GetObject(number) is { } obj
            ? ((int)obj.Source.Offset, (int)obj.Source.End)
            : (-1, -1);
    }

    /// <summary>An object as the file writes it (<c>N G obj</c> … <c>endobj</c>), or as its object stream does; null when it is not there.</summary>
    public static string? ObjectText(byte[] pdf, int number)
    {
        var document = PdfDocument.Open(pdf);
        return document.GetObject(number) is { } obj
            ? Encoding.Latin1.GetString(PdfObjectSource.Of(document, number, obj, keepHeader: true).ObjectBytes)
            : null;
    }
}
