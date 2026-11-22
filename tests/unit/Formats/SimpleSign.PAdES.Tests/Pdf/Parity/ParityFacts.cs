using System.Globalization;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using Shouldly;
using SimpleSign.PAdES.Pdf;
using SimpleSign.PAdES.Pdf.Exceptions;
using SimpleSign.PAdES.Pdf.Model;

namespace SimpleSign.PAdES.Tests.Pdf.Parity;

/// <summary>
/// The facts about a PDF that both readers can give, as strings keyed by name (ADR 0032, parity harness):
/// <list type="bullet">
/// <item><c>error</c>: the exception the reader raised;</item>
/// <item><c>root</c>, <c>next-object-number</c>, <c>xref-stream</c> (the last section is a stream), <c>linearized</c>;</item>
/// <item><c>xref/N</c>: where the cross-reference puts object N (<c>@offset</c> or <c>compressed</c>);</item>
/// <item><c>object/N</c>: object N's value, canonical (dictionary keys sorted, strings in hex, streams hashed).</item>
/// </list>
/// </summary>
internal sealed class FactSet
{
    public SortedDictionary<string, string> Facts { get; } = new(StringComparer.Ordinal);

    /// <summary>Where the legacy reader found each object's text (<c>N 0 obj</c>), when it did.</summary>
    public Dictionary<int, int> ObjectStarts { get; } = [];

    public string? this[string key] => Facts.TryGetValue(key, out var value) ? value : null;

    public void Add(string key, string value) => Facts[key] = value;
}

/// <summary>The facts as the scanning code (the legacy reader) gives them.</summary>
internal static class LegacyFacts
{
    private delegate List<PdfCrossRef> ParseXref(ReadOnlySpan<byte> data);

    private static readonly ParseXref s_parseXref = typeof(PdfStructureReader)
        .GetMethod("ParseCrossReferenceTable", BindingFlags.NonPublic | BindingFlags.Static)
        .ShouldNotBeNull()
        .CreateDelegate<ParseXref>();

    /// <param name="data">The file.</param>
    /// <param name="model">Used only to resolve an indirect <c>/Length</c> when parsing the text the legacy reader found.</param>
    public static FactSet Read(byte[] data, PdfDocument model)
    {
        var facts = new FactSet();
        facts.Add("root", PdfStructureParser.FindRootObjectNumber(data).ToString(CultureInfo.InvariantCulture));
        facts.Add("next-object-number", PdfStructureParser.DetermineNextObjectNumber(data).ToString(CultureInfo.InvariantCulture));
        facts.Add("xref-stream", PdfStructureParser.UsesXRefStreams(data) ? "true" : "false");
        facts.Add("linearized", PdfStructureReader.IsLinearized(data) ? "true" : "false");

        List<PdfCrossRef> xref;
        try
        {
            xref = s_parseXref(data);
        }
        catch (PdfStructureException ex)
        {
            facts.Add("error", nameof(PdfStructureException) + ": " + ex.Message);
            return facts;
        }

        var context = new PdfParseContext();
        foreach (var entry in xref)
        {
            facts.Add($"xref/{entry.ObjectNumber}", entry.Offset < 0 ? "compressed" : $"@{entry.Offset}");

            if (entry.Offset >= 0)
            {
                var (start, _) = PdfStructureParser.FindObjectBytes(data, entry.ObjectNumber);
                if (start < 0)
                {
                    facts.Add($"object/{entry.ObjectNumber}", "missing");
                    continue;
                }

                facts.ObjectStarts[entry.ObjectNumber] = start;
                var parsed = PdfParser.ParseIndirectObject(data, start, context, id => LengthOf(model, id));
                facts.Add($"object/{entry.ObjectNumber}", Canonical.Of(parsed?.Value));
            }
            else
            {
                string? text = PdfStructureParser.ExtractObjectFromObjStm(data, entry.ObjectNumber);
                facts.Add(
                    $"object/{entry.ObjectNumber}",
                    text is null ? "missing" : Canonical.Of(PdfParser.ParseObject(Encoding.Latin1.GetBytes(text), context)));
            }
        }

        return facts;
    }

    private static long? LengthOf(PdfDocument model, PdfObjectId id) =>
        model.GetObject(id)?.Value is PdfInteger integer ? integer.Value : null;
}

/// <summary>The facts as the object model gives them.</summary>
internal static class ModelFacts
{
    public static FactSet Read(PdfDocument doc)
    {
        var facts = new FactSet();
        facts.Add("root", doc.RootId?.Number.ToString(CultureInfo.InvariantCulture) ?? "none");
        facts.Add("next-object-number", doc.NextObjectNumber.ToString(CultureInfo.InvariantCulture));
        facts.Add("xref-stream", doc.Latest.Sections[0].Kind == PdfXrefSectionKind.Stream ? "true" : "false");
        facts.Add("linearized", doc.IsLinearized ? "true" : "false");

        foreach (int number in doc.ObjectNumbers())
        {
            var entry = doc.Lookup(number);
            var obj = doc.GetObject(number);
            if (entry is { Type: PdfXrefEntryType.InUse } inUse)
            {
                facts.Add($"xref/{number}", $"@{inUse.Offset}");
            }
            else if (entry is { Type: PdfXrefEntryType.Compressed })
            {
                facts.Add($"xref/{number}", obj is null ? "compressed (unreadable)" : "compressed");
            }

            facts.Add($"object/{number}", obj is null ? "missing" : Canonical.Of(obj.Value));
        }

        return facts;
    }
}

/// <summary>A canonical text of an object, for comparing two readings of it.</summary>
internal static class Canonical
{
    public static string Of(PdfObject? value) => value switch
    {
        null or PdfNull => "null",
        PdfBoolean b => b.Value ? "true" : "false",
        PdfInteger i => i.Value.ToString(CultureInfo.InvariantCulture),
        PdfReal r => r.Value.ToString("R", CultureInfo.InvariantCulture),
        PdfString s => "<" + Convert.ToHexString(s.Bytes.Span) + ">",
        PdfName n => "/" + n.Value,
        PdfArray a => "[" + string.Join(" ", a.Select(Of)) + "]",
        PdfDictionary d => "<<" + string.Join(" ", d.OrderBy(e => e.Key.Value, StringComparer.Ordinal).Select(e => $"/{e.Key.Value} {Of(e.Value)}")) + ">>",
        PdfStream st => Of(st.Dictionary) + " stream " + Convert.ToHexString(SHA256.HashData(st.Encoded.Span))[..16],
        PdfReference r => $"{r.Id.Number} {r.Id.Generation} R",
        _ => value.ToString() ?? "?",
    };
}
