using System.Globalization;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Logging;
using Shouldly;
using SimpleSign.PAdES.Pdf;
using SimpleSign.PAdES.Pdf.Exceptions;
using SimpleSign.PAdES.Pdf.Model;
using SimpleSign.PAdES.Validation;

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

        AddViewFacts(data, facts);
        return facts;
    }

    private delegate DateTimeOffset? ParseDate(string text, ILogger? logger);

    private static readonly ParseDate s_parseDate = typeof(PdfStructureReader)
        .GetMethod("ParsePdfDate", BindingFlags.NonPublic | BindingFlags.Static)
        .ShouldNotBeNull()
        .CreateDelegate<ParseDate>();

    /// <summary>A PDF date as the legacy reader parses it, for both readers' facts.</summary>
    public static string Date(string? text) => text is null ? "-" : s_parseDate(text, null)?.ToString("O", CultureInfo.InvariantCulture) ?? "-";

    /// <summary>The facts of the latest revision's view: pages, fields, signatures, DSS, attachments, DocMDP.</summary>
    private static void AddViewFacts(byte[] data, FactSet facts)
    {
        // Pages: the catalog's /Pages /Kids, as the legacy signers look them up.
        var pages = new List<int>();
        for (int n = 1; n <= 2000; n++)
        {
            int number = PdfStructureParser.FindNthPageObjNum(data, n);
            if (number <= 0)
            {
                break;
            }

            pages.Add(number);
        }

        facts.Add("pages", string.Join(" ", pages));
        for (int i = 0; i < pages.Count; i++)
        {
            if (ObjectText(data, pages[i]) is { } page)
            {
                facts.Add($"page/{i + 1}/box", Box(
                    PdfStructureParser.ParseMediaBoxWidth(data, page),
                    PdfStructureParser.ParsePageHeight(data, page),
                    PdfStructureParser.ParsePageRotation(data, page)));
            }
        }

        // The AcroForm's /Fields.
        int root = PdfStructureParser.FindRootObjectNumber(data);
        int acroForm = PdfStructureParser.FindAcroFormObjNum(data, root);
        List<string> fields = [];
        if (acroForm > 0 && ObjectText(data, acroForm) is { } acroFormText)
        {
            fields = PdfStructureParser.ParseFieldsArray(acroFormText);
            if (fields.Count == 0)
            {
                fields = PdfStructureParser.ResolveIndirectFields(data, acroFormText);
            }
        }
        else if (acroForm == 0)
        {
            fields = PdfStructureParser.ExtractInlineAcroFormFields(data, root);
        }

        facts.Add("acroform/fields", string.Join(" ", fields.Select(f => string.Join(" ", f.Split(' ', StringSplitOptions.RemoveEmptyEntries)))));

        // Signatures.
        try
        {
            using var stream = new MemoryStream(data);
            foreach (var signature in PdfStructureReader.ReadSignatureFieldsAsync(stream).GetAwaiter().GetResult())
            {
                var range = signature.ByteRange;
                AddSignature(
                    facts, signature.SigDictObjectNumber, signature.FieldName, [range.Offset1, range.Length1, range.Offset2, range.Length2],
                    signature.ContentsBytes, signature.Filter, signature.SubFilter, signature.Reason, signature.Location,
                    signature.ContactInfo, signature.SignerName, signature.PdfSigningTime?.ToString("O", CultureInfo.InvariantCulture) ?? "-");
            }
        }
        catch (EncryptedPdfException)
        {
            facts.Add("signatures", "encrypted");
        }
        catch (PdfStructureException)
        {
            facts.Add("signatures", "no header");
        }

        // DocMDP.
        facts.Add("docmdp", PdfStructureReader.GetDocMdpPermissionLevel(data).ToString(CultureInfo.InvariantCulture));

        // DSS.
        var dss = DssExtractor.ParseExistingDss(data);
        AddDss(facts, dss.CertObjRefs, dss.OcspObjRefs, dss.CrlObjRefs, dss.VriEntries.Select(e => (e.Key, e.Value)));

        // Embedded files.
        try
        {
            facts.Add("embedded-files", string.Join(" | ", PdfEmbeddedFiles.Read(data).Select(f => f.Name)));
        }
        catch (EncryptedPdfException)
        {
            facts.Add("embedded-files", "encrypted");
        }
        catch (PdfStructureException ex)
        {
            facts.Add("embedded-files", "error: " + ex.Message);
        }
    }

    /// <summary>The empty signature field the legacy signer would fill, by partial name.</summary>
    public static string EmptyField(byte[] data, string partialName)
    {
        try
        {
            int number = PdfStructureParser.FindEmptySignatureField(data, partialName);
            return number < 0 ? "not found" : number.ToString(CultureInfo.InvariantCulture);
        }
        catch (InvalidOperationException)
        {
            return "signed";
        }
    }

    /// <summary>An object's text: its <c>N 0 obj</c> found as the legacy reader finds it, or its text in an object stream.</summary>
    private static string? ObjectText(byte[] data, int number)
    {
        var (start, end) = PdfStructureParser.FindObjectBytes(data, number);
        return start >= 0 ? Encoding.Latin1.GetString(data, start, end - start) : PdfStructureParser.ExtractObjectFromObjStm(data, number);
    }

    public static string Box(double width, double height, int rotate) =>
        string.Create(CultureInfo.InvariantCulture, $"{width:F2}x{height:F2} r{rotate}");

    public static void AddSignature(
        FactSet facts, int number, string name, long[] byteRange, ReadOnlySpan<byte> contents, string? filter, string? subFilter,
        string? reason, string? location, string? contact, string? signer, string time)
    {
        string key = $"signature/{number}/";
        facts.Add(key + "name", name);
        facts.Add(key + "range", string.Join(" ", byteRange));
        facts.Add(key + "contents", Convert.ToHexString(SHA256.HashData(contents))[..16]);
        // An empty string is no value: the legacy reader returns null for (), the model the empty text.
        facts.Add(key + "Filter", Value(filter));
        facts.Add(key + "SubFilter", Value(subFilter));
        facts.Add(key + "Reason", Value(reason));
        facts.Add(key + "Location", Value(location));
        facts.Add(key + "ContactInfo", Value(contact));
        facts.Add(key + "Name", Value(signer));
        facts.Add(key + "M", time);
    }

    private static string Value(string? text) => string.IsNullOrEmpty(text) ? "-" : text;

    public static void AddDss(FactSet facts, IEnumerable<int> certs, IEnumerable<int> ocsps, IEnumerable<int> crls, IEnumerable<(string Key, int Value)> vri)
    {
        facts.Add("dss/Certs", string.Join(",", certs));
        facts.Add("dss/OCSPs", string.Join(",", ocsps));
        facts.Add("dss/CRLs", string.Join(",", crls));
        facts.Add("dss/VRI", string.Join(",", vri.Select(e => $"{e.Key.ToUpperInvariant()}={e.Value}").Order(StringComparer.Ordinal)));
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

        AddViewFacts(doc, facts);
        return facts;
    }

    private static void AddViewFacts(PdfDocument doc, FactSet facts)
    {
        var view = doc.View();
        facts.Add("pages", string.Join(" ", view.Pages.Select(p => p.Id is { } id ? id.Number.ToString(CultureInfo.InvariantCulture) : "inline")));
        foreach (var page in view.Pages)
        {
            var box = Numbers(page.CropBox) ?? Numbers(page.MediaBox);
            double width = box is null ? 612 : Math.Abs(box[2] - box[0]);
            double height = box is null ? 792 : Math.Abs(box[3] - box[1]);
            facts.Add($"page/{page.Index + 1}/box", LegacyFacts.Box(width, height, ((page.Rotate % 360) + 360) % 360));
        }

        facts.Add("acroform/fields", string.Join(" ", view.RootFields.Select(f => f.Id is { } id ? $"{id.Number} {id.Generation} R" : "inline")));

        if (doc.IsEncrypted)
        {
            facts.Add("signatures", "encrypted");
        }
        else if (!doc.Data.Span.StartsWith("%PDF-"u8))
        {
            // The public reader keeps refusing a file that does not start with the header.
            facts.Add("signatures", "no header");
        }
        else
        {
            foreach (var signature in view.Signatures.Where(s => !s.IsUsageRights))
            {
                int number = signature.Id?.Number ?? signature.Field?.Id?.Number ?? 0;
                string name = string.IsNullOrEmpty(signature.Field?.FullName) ? $"Signature_{number}" : signature.Field.FullName;
                LegacyFacts.AddSignature(
                    facts, number, name, signature.ByteRange ?? [0, 0, 0, 0], signature.Contents.Span,
                    signature.Name("Filter"), signature.Name("SubFilter"), signature.Text("Reason"), signature.Text("Location"),
                    signature.Text("ContactInfo"), signature.Text("Name"), LegacyFacts.Date(signature.Text("M")));
            }
        }

        int? p = view.DocMdpPermissions;
        facts.Add("docmdp", view.CertificationSignature is null ? "0" : (p is >= 1 and <= 3 ? p.Value : 1).ToString(CultureInfo.InvariantCulture));

        var dss = view.Dss;
        var vri = view.Resolve(dss?.Get("VRI")) as PdfDictionary;
        LegacyFacts.AddDss(
            facts, Refs(view, dss?.Get("Certs")), Refs(view, dss?.Get("OCSPs")), Refs(view, dss?.Get("CRLs")),
            vri?.Where(e => e.Value is PdfReference).Select(e => (e.Key.Value, ((PdfReference)e.Value).Id.Number)) ?? []);

        facts.Add("embedded-files", doc.IsEncrypted ? "encrypted" : string.Join(" | ", view.NameTree("EmbeddedFiles").Select(e => e.Key.Text)));
    }

    private static IEnumerable<int> Refs(PdfRevisionView view, PdfObject? array) =>
        view.Resolve(array) is PdfArray items ? items.OfType<PdfReference>().Select(r => r.Id.Number) : [];

    private static double[]? Numbers(PdfArray? array) =>
        array is { Count: 4 } && array.All(item => item is PdfInteger or PdfReal)
            ? [.. array.Select(item => item is PdfInteger i ? i.Value : ((PdfReal)item).Value)]
            : null;
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
