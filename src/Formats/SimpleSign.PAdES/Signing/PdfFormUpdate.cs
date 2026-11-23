using System.Globalization;
using System.Text;
using SimpleSign.PAdES.Pdf.Model;
using SimpleSign.PAdES.Pdf.Writing;

namespace SimpleSign.PAdES.Signing;

/// <summary>
/// The edits the writers make to a document's form when they add a field (ADR 0032): the AcroForm object rebuilt with
/// the field, and the page with the field in its <c>/Annots</c>, each as the writers have always written them.
/// </summary>
internal static class PdfFormUpdate
{
    private static readonly PdfName s_annots = PdfName.Of("Annots");
    private static readonly PdfName s_sigFlags = PdfName.Of("SigFlags");

    /// <summary>
    /// The AcroForm object written: <c>/Fields</c> with the new field, <c>/SigFlags 3</c>, then every other entry of
    /// the existing AcroForm as the file writes it (<c>/Type</c> left out).
    /// </summary>
    public static byte[] AcroFormObject(PdfDocument document, int number, PdfDictionary? existing, ReadOnlyMemory<byte> source, string fieldRef)
    {
        var fields = new List<string>();
        if (existing is not null && document.Resolve(existing.Get(PdfName.Fields)) is PdfArray array)
        {
            fields.AddRange(array.Select(PdfObjectSerializer.ToText));
        }

        fields.Add(fieldRef);
        var text = new StringBuilder(string.Create(CultureInfo.InvariantCulture, $"{number} 0 obj\n<< /Fields [{string.Join(" ", fields)}]\n   /SigFlags 3\n"));
        foreach (var entry in existing?.RawEntries ?? [])
        {
            if (entry.Key.Equals(PdfName.Fields) || entry.Key.Equals(s_sigFlags) || entry.Key.Equals(PdfName.Type))
            {
                continue;
            }

            string written = entry.Source is { } range && range.End <= source.Length
                ? Encoding.Latin1.GetString(source.Span.Slice((int)range.Offset, range.Length))
                : $"{PdfObjectSerializer.ToText(entry.Key)} {PdfObjectSerializer.ToText(entry.Value)}";
            text.Append("   ").Append(written).Append('\n');
        }

        text.Append(">>\nendobj\n");
        return Encoding.Latin1.GetBytes(text.ToString());
    }

    /// <summary>
    /// The page written again with the field appended to its <c>/Annots</c>: in place when the array is inline; an
    /// array object referenced is written inline with its items and the field; and an <c>/Annots</c> added otherwise.
    /// </summary>
    public static byte[] PageWithAnnotation(PdfDocument document, int number, PdfIndirectObject page, string fieldRef)
    {
        var patch = new PdfDictionaryPatch(PdfObjectSource.Of(document, number, page).ObjectBytes);
        switch (patch.Dictionary.Get(s_annots))
        {
            case PdfArray { Source: not null }:
                patch.AppendToArray([s_annots.Value], fieldRef, spaceWhenEmpty: true);
                break;
            case PdfReference reference:
                string items = document.GetObject(reference.Id) is { Value: PdfArray { Source: { } range } } annots
                    ? ArrayItemsAsWritten(PdfObjectSource.Of(document, reference.Id.Number, annots).Buffer.Span, range)
                    : "";
                patch.Set(s_annots.Value, items.Length == 0 ? $"[{fieldRef}]" : $"[{items} {fieldRef}]");
                break;
            default:
                patch.Set(s_annots.Value, $"[{fieldRef}]");
                break;
        }

        return patch.ToBytes();
    }

    /// <summary>The items of an array as the file writes them, between its brackets, trimmed.</summary>
    private static string ArrayItemsAsWritten(ReadOnlySpan<byte> buffer, PdfSourceRange range) =>
        range.End <= buffer.Length && range.Length >= 2
            ? Encoding.Latin1.GetString(buffer.Slice((int)range.Offset + 1, range.Length - 2)).Trim()
            : "";

    public static byte[] WithFinalLineFeed(byte[] bytes) =>
        bytes.Length > 0 && bytes[^1] == (byte)'\n' ? bytes : [.. bytes, (byte)'\n'];
}
