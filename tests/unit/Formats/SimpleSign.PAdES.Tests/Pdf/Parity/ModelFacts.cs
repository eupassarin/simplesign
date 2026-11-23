using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using SimpleSign.Core.Validation.Policy;
using SimpleSign.PAdES.Inspection;
using SimpleSign.PAdES.Pdf;
using SimpleSign.PAdES.Pdf.Exceptions;
using SimpleSign.PAdES.Pdf.Model;
using SimpleSign.PAdES.Validation;

namespace SimpleSign.PAdES.Tests.Pdf.Parity;

/// <summary>
/// The facts the object model gives about a PDF, as strings keyed by name (ADR 0032), snapshotted per document:
/// <list type="bullet">
/// <item><c>root</c>, <c>next-object-number</c>, <c>xref-stream</c> (the last section is a stream), <c>linearized</c>;</item>
/// <item><c>xref/N</c>: where the cross-reference puts object N (<c>@offset</c> or <c>compressed</c>);</item>
/// <item><c>object/N</c>: object N's value, canonical (dictionary keys sorted, strings in hex, streams hashed);</item>
/// <item>the pages, fields, signatures, DSS, attachments, text, DocMDP and PDF/A level, and what changed after each
/// signature.</item>
/// </list>
/// </summary>
internal sealed class FactSet
{
    public SortedDictionary<string, string> Facts { get; } = new(StringComparer.Ordinal);

    public string? this[string key] => Facts.TryGetValue(key, out var value) ? value : null;

    public void Add(string key, string value) => Facts[key] = value;

    /// <summary>The facts, one per line: <c>key = value</c>.</summary>
    public override string ToString() => string.Join("\n", Facts.Select(f => $"{f.Key} = {f.Value}")) + "\n";
}

/// <summary>How the facts are written.</summary>
internal static class FactWriter
{
    /// <summary>The embedded files a reader gives: names and a hash of each one's data, or the error it raises.</summary>
    public static void AddEmbeddedFiles(FactSet facts, Func<IReadOnlyList<PdfEmbeddedFile>> read)
    {
        string value;
        try
        {
            value = string.Join(" | ", read().Select(f => $"{f.Name} {Convert.ToHexString(SHA256.HashData(f.Data.Span))[..12]}"));
        }
        catch (EncryptedPdfException)
        {
            value = "encrypted";
        }
        catch (PdfStructureException ex)
        {
            value = "error: " + ex.Message;
        }

        facts.Add("embedded-files", value);
    }

    /// <summary>The text of each page a reader gives, and a hash of where each character is (to a hundredth).</summary>
    public static void AddPageTexts(FactSet facts, Func<List<(string Text, List<(float X, float Y)> Origins)?>> read)
    {
        List<(string Text, List<(float X, float Y)> Origins)?> pages;
        try
        {
            pages = read();
        }
        catch (PdfStructureException ex)
        {
            facts.Add("text", "error: " + ex.Message);
            return;
        }

        facts.Add("text/pages", pages.Count.ToString(CultureInfo.InvariantCulture));
        for (int i = 0; i < pages.Count; i++)
        {
            if (pages[i] is not { } page)
            {
                facts.Add($"text/{i + 1}", "unreadable");
                continue;
            }

            var (text, origins) = page;
            string places = string.Join(";", origins.Select(o => string.Create(CultureInfo.InvariantCulture, $"{o.X:F2},{o.Y:F2}")));
            facts.Add($"text/{i + 1}", $"{text.Length} chars, {Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(text)))[..12]}: {(text.Length > 60 ? text[..60] : text)}");
            facts.Add($"text/{i + 1}/origins", Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(places)))[..12]);
        }
    }

    public static string Box(double width, double height, int rotate) =>
        string.Create(CultureInfo.InvariantCulture, $"{width:F2}x{height:F2} r{rotate}");

    /// <summary>The signature fields a reader gives: how many, in what order, and each one's facts.</summary>
    public static void AddSignatures(FactSet facts, IReadOnlyList<PdfSignatureField> fields)
    {
        facts.Add("signatures/order", string.Join(" ", fields.Select(f => f.SigDictObjectNumber)));
        foreach (var signature in fields)
        {
            var range = signature.ByteRange;
            AddSignature(
                facts, signature.SigDictObjectNumber, signature.FieldName, [range.Offset1, range.Length1, range.Offset2, range.Length2],
                signature.ContentsBytes, signature.Filter, signature.SubFilter, signature.Reason, signature.Location,
                signature.ContactInfo, signature.SignerName, signature.PdfSigningTime?.ToString("O", CultureInfo.InvariantCulture) ?? "-");
        }
    }

    public static void AddSignature(
        FactSet facts, int number, string name, long[] byteRange, ReadOnlySpan<byte> contents, string? filter, string? subFilter,
        string? reason, string? location, string? contact, string? signer, string time)
    {
        string key = $"signature/{number}/";
        facts.Add(key + "name", name);
        facts.Add(key + "range", string.Join(" ", byteRange));
        facts.Add(key + "contents", Convert.ToHexString(SHA256.HashData(contents))[..16]);
        facts.Add(key + "Filter", Value(filter));
        facts.Add(key + "SubFilter", Value(subFilter));
        facts.Add(key + "Reason", Value(reason));
        facts.Add(key + "Location", Value(location));
        facts.Add(key + "ContactInfo", Value(contact));
        facts.Add(key + "Name", Value(signer));
        facts.Add(key + "M", time);
    }

    /// <summary>The DSS data a validator gets: what is there, and a hash of each array's and each VRI entry's data.</summary>
    public static void AddDssData(FactSet facts, DssValidationData dss)
    {
        facts.Add("dss-data/present", dss.Present ? "true" : "false");
        facts.Add("dss-data/keys", string.Join(",", dss.Keys.Order(StringComparer.Ordinal)));
        facts.Add("dss-data/Certs", Hashes(dss.GlobalCerts));
        facts.Add("dss-data/OCSPs", Hashes(dss.GlobalOcsps));
        facts.Add("dss-data/CRLs", Hashes(dss.GlobalCrls));
        foreach (var (key, entry) in dss.VriEntries)
        {
            facts.Add($"dss-data/VRI/{key}", $"Cert {Hashes(entry.Certs)} | OCSP {Hashes(entry.Ocsps)} | CRL {Hashes(entry.Crls)} | keys {string.Join(",", entry.Keys.Order(StringComparer.Ordinal))}");
        }
    }

    /// <summary>What inspection reports about the DSS.</summary>
    public static void AddDssSummary(FactSet facts, DssInfo? info) =>
        facts.Add("dss-summary", info is null ? "none" : string.Create(CultureInfo.InvariantCulture,
            $"CRLs {info.CrlCount} OCSPs {info.OcspResponseCount} Certs {info.CertificateCount} VRI {info.HasVri}/{info.VriEntryCount}/{info.VriHasTimestamps} | {string.Join("; ", info.VriWarnings)}"));

    private static string Hashes(IReadOnlyList<byte[]> items) =>
        $"{items.Count}: {Convert.ToHexString(SHA256.HashData([.. items.SelectMany(i => SHA256.HashData(i))]))[..12]}";

    private static string Value(string? text) => string.IsNullOrEmpty(text) ? "-" : text;

    public static void AddDss(FactSet facts, IEnumerable<int> certs, IEnumerable<int> ocsps, IEnumerable<int> crls, IEnumerable<(string Key, int Value)> vri)
    {
        facts.Add("dss/Certs", string.Join(",", certs));
        facts.Add("dss/OCSPs", string.Join(",", ocsps));
        facts.Add("dss/CRLs", string.Join(",", crls));
        facts.Add("dss/VRI", string.Join(",", vri.Select(e => $"{e.Key.ToUpperInvariant()}={e.Value}").Order(StringComparer.Ordinal)));
    }
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
        AddChangesAndEmptyFields(doc, facts);
        return facts;
    }

    /// <summary>What changed after each signature, and the empty signature fields a signer can fill.</summary>
    private static void AddChangesAndEmptyFields(PdfDocument doc, FactSet facts)
    {
        if (!doc.IsEncrypted && doc.Data.Span.StartsWith("%PDF-"u8) && doc.Catalog is not null)
        {
            foreach (var field in PdfStructureReader.ReadSignatureFields(doc))
            {
                long end = field.ByteRange.Offset2 + field.ByteRange.Length2;
                AddChanges(facts, field.SigDictObjectNumber, () => PdfRevisionComparer.Compare(doc, end, field.SigDictObjectNumber));
            }
        }

        if (!doc.IsEncrypted)
        {
            foreach (var field in doc.View().Fields.Where(f => f.IsSignature && f.Value is null && f.PartialName is not null))
            {
                facts.Add($"empty-field/{field.FullName}", field.Id?.Number.ToString(CultureInfo.InvariantCulture) ?? "inline");
            }
        }
    }

    private static void AddChanges(FactSet facts, int signature, Func<PdfChangeFacts> compare)
    {
        string key = $"changes/{signature}/";
        PdfChangeFacts changes;
        try
        {
            changes = compare();
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException or FormatException)
        {
            facts.Add(key + "error", ex.GetType().Name);
            return;
        }

        facts.Add(key + "pages", $"{changes.SignedPageCount} -> {changes.FinalPageCount}");
        facts.Add(key + "overlap", changes.AnnotationsOverlap ? "true" : "false");
        facts.Add(key + "signatures", string.Join(" | ", changes.Signatures));
        facts.Add(key + "form-fills", string.Join(" | ", changes.FormFills));
        facts.Add(key + "annotations", string.Join(" | ", changes.Annotations));
        facts.Add(key + "undefined", string.Join(" | ", changes.Undefined));
        facts.Add(key + "changed-fields", string.Join(" | ", changes.ChangedFields));
        facts.Add(key + "docmdp", changes.DocMdpLevel.ToString(System.Globalization.CultureInfo.InvariantCulture));
        facts.Add(key + "fieldmdp", changes.FieldMdp is { } fieldMdp ? $"{fieldMdp.Action} [{string.Join(", ", fieldMdp.Fields)}]" : "-");
        facts.Add(key + "lock", changes.SigFieldLock is { } fieldLock ? $"{fieldLock.Action} [{string.Join(", ", fieldLock.Fields)}]" : "-");
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
            facts.Add($"page/{page.Index + 1}/box", FactWriter.Box(width, height, ((page.Rotate % 360) + 360) % 360));
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
            try
            {
                FactWriter.AddSignatures(facts, PdfStructureReader.ReadSignatureFields(doc));
            }
            catch (PdfStructureException ex)
            {
                facts.Add("signatures", "error: " + ex.Message);
            }
        }

        facts.Add("docmdp", view.DocMdpLevel.ToString(CultureInfo.InvariantCulture));

        var dss = DssExtractor.ParseExistingDss(doc.Data.ToArray());
        FactWriter.AddDss(facts, dss.CertObjRefs, dss.OcspObjRefs, dss.CrlObjRefs, dss.VriEntries.Select(e => (e.Key, e.Value)));
        FactWriter.AddDssData(facts, DssReader.Read(view));
        FactWriter.AddDssSummary(facts, DssReader.Summary(view));
        facts.Add("encrypted", doc.IsEncrypted ? "true" : "false");
        facts.Add("pdfa", PdfStructureReader.PdfALevelOf(view).ToString());

        FactWriter.AddEmbeddedFiles(facts, () => PdfEmbeddedFiles.Read(doc.Data));
        FactWriter.AddPageTexts(facts, () => PdfTextLocator.ReadPages(doc.Data.ToArray()));
    }

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
