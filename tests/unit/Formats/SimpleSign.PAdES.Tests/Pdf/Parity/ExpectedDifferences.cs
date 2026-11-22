using System.Globalization;
using System.Reflection;
using Shouldly;
using SimpleSign.PAdES.Pdf;
using SimpleSign.PAdES.Pdf.Enums;
using SimpleSign.PAdES.Pdf.Model;

namespace SimpleSign.PAdES.Tests.Pdf.Parity;

/// <summary>A difference between the readers that is intended, with why, and the test that recognizes it.</summary>
/// <param name="Name">A short name.</param>
/// <param name="Reason">Why the model reads it differently.</param>
/// <param name="Explains">Whether the rule explains a difference, given the document.</param>
internal sealed record ExpectedDifference(string Name, string Reason, Func<ParityContext, FactDifference, bool> Explains);

/// <summary>
/// The catalogue of intended differences between the legacy reader and the object model (ADR 0032). A rule must name
/// the precise condition it explains: a difference that matches none fails the parity harness.
/// </summary>
internal static class ExpectedDifferences
{
    public static IReadOnlyList<ExpectedDifference> All { get; } =
    [
        new(
            "RebuiltWhereLegacyFailed",
            "Without a readable startxref the legacy reader throws; the model rebuilds the cross-reference from the object headers.",
            (c, d) => c.Model.IsReconstructed && c.Legacy["error"] is not null),

        new(
            "HybridXRefStm",
            "The legacy reader ignores a hybrid file's /XRefStm (ISO 32000-1 §7.5.8.4): the objects only that stream lists "
            + "(compressed ones) are unknown to it.",
            (c, d) => d.ObjectNumber is int n && d.Legacy is null && Providing(c.Model, n) is { XrefStream: not null }),

        new(
            "LegacyMisreadsTable",
            "The legacy table reader is position-exact: it needs 'xref' at the very offset, LF line ends, 20-byte entries "
            + "and 'trailer' right after the last entry. A table with white-space before 'xref' or 'trailer', or lines "
            + "ending with a lone CR (all allowed by ISO 32000-1 §7.5.4), is lost to it, with the sections before it; "
            + "a subsection written '1 n' with object 0's entry first (a writer bug the model repairs, as pdf.js and "
            + "PDFBox do) is read one object too high.",
            (c, d) => d.ObjectNumber is int n && LegacyMisreadsUpTo(c.Data, c.Model, n)),

        new(
            "FreeEntryHonoured",
            "A free entry in a newer section deletes the object (§7.5.4); the legacy reader skips free entries and keeps an "
            + "older section's offset.",
            (c, d) => d.ObjectNumber is int n && d.Model is null or "missing" && c.Model.Lookup(n) is { Type: PdfXrefEntryType.Free }),

        new(
            "GenerationAboveZero",
            "The legacy reader looks for 'N 0 obj' only; the model finds an object with the generation its entry gives.",
            (c, d) => d.Key.StartsWith("object/", StringComparison.Ordinal) && d.Legacy == "missing"
                && c.Model.Lookup(d.ObjectNumber!.Value) is { Type: PdfXrefEntryType.InUse, Generation: > 0 }),

        new(
            "LookupByXref",
            "The legacy reader takes the last 'N 0 obj' text of the file; the model takes the object the cross-reference "
            + "points to. They differ when an object is written again where no cross-reference section lists it.",
            (c, d) => d.Key.StartsWith("object/", StringComparison.Ordinal)
                && c.Legacy.ObjectStarts.TryGetValue(d.ObjectNumber!.Value, out int legacyStart)
                && c.Model.GetObject(d.ObjectNumber.Value) is { } obj && obj.Source.Offset != legacyStart),

        new(
            "NestedPageTree",
            "The legacy reader takes the pages from the root's /Kids only; the model walks the whole page tree (§7.7.3.2).",
            (c, d) => (d.Key == "pages" || d.Key.StartsWith("page/", StringComparison.Ordinal))
                && c.Model.Resolve(c.Model.Catalog?.Get(PdfName.Pages)) is PdfDictionary root
                && c.Model.Resolve(root.Get(PdfName.Kids)) is PdfArray kids
                && kids.Any(kid => c.Model.Resolve(kid) is PdfDictionary node && PdfName.Pages.Equals(node.Get(PdfName.Type)))),

        new(
            "FieldInObjectStream",
            "The legacy reader finds a signature's field, an empty signature field and the AcroForm's /Fields by searching "
            + "the file's text; a field, or a catalog, inside an object stream is not in that text. The model reads the field tree.",
            (c, d) => (d.Key == "acroform/fields" && string.IsNullOrEmpty(d.Legacy) && c.Model.RootId is { } root && IsCompressed(c.Model, root))
                || (Signature(c, d) is { Signature.Field.Id: { } field } && d.Key.EndsWith("/name", StringComparison.Ordinal)
                    && d.Legacy == $"Signature_{Signature(c, d)!.Value.Number}" && IsCompressed(c.Model, field))
                || (d.Key.StartsWith("empty-field/", StringComparison.Ordinal) && d.Legacy == "not found"
                    && c.Model.View().Fields.FirstOrDefault(f => "empty-field/" + f.FullName == d.Key) is { Id: { } id } && IsCompressed(c.Model, id))),

        new(
            "LegacyKeyAnywhereInDictionary",
            "The legacy reader takes the first occurrence of a key anywhere in the signature dictionary's text, nested "
            + "dictionaries included (/Prop_Build /App /Name); the model reads the dictionary's own entry.",
            (c, d) => Signature(c, d) is { } s && d.Key[(d.Key.LastIndexOf('/') + 1)..] is var key
                && key is "Name" or "Reason" or "Location" or "ContactInfo" or "Filter" or "SubFilter"
                && NestedHas(c.Model, s.Signature.Dictionary, key, 0)),

        new(
            "LegacyDssArrayInlineWithSpace",
            "The legacy reader finds a DSS array by the text '/Certs [' (and '/OCSPs [', '/CRLs ['): an array written as a "
            + "reference, or without the space, is empty to it. The model reads the entry.",
            (c, d) => (d.Key is "dss/Certs" or "dss/OCSPs" or "dss/CRLs" && string.IsNullOrEmpty(d.Legacy)
                    || d.Key is "dss-data/Certs" or "dss-data/OCSPs" or "dss-data/CRLs" && d.Legacy?.StartsWith("0:", StringComparison.Ordinal) == true)
                && c.Model.View().Dss is { } dss && dss.Get(d.Key[(d.Key.IndexOf('/') + 1)..]) is { } entry
                && (entry is PdfReference || !RawText(c.Data, dss).Contains($"/{d.Key[(d.Key.IndexOf('/') + 1)..]} [", StringComparison.Ordinal))),

        new(
            "LegacyVriInlineOnly",
            "The legacy reader reads /VRI only when it is a dictionary written inside the DSS, and of it only the entries "
            + "that are references; the model follows a /VRI reference and reads inline entries too.",
            (c, d) => (d.Key == "dss/VRI" && string.IsNullOrEmpty(d.Legacy) || d.Key.StartsWith("dss-data/VRI/", StringComparison.Ordinal) && d.Legacy is null)
                && c.Model.View().Dss is { } dss
                && (dss.Get("VRI") is PdfReference
                    || (c.Model.Resolve(dss.Get("VRI")) as PdfDictionary)?.Get(d.Key[(d.Key.LastIndexOf('/') + 1)..]) is PdfDictionary)),

        new(
            "DssLookupByText",
            "The legacy reader finds the DSS through the catalog's text: a catalog or a DSS inside an object stream is not "
            + "in it. The model reads the catalog's /DSS.",
            (c, d) => d.Key.StartsWith("dss", StringComparison.Ordinal) && c.Legacy["dss-data/present"] == "false"
                && c.Model.RootId is { } root && c.Model.View().Catalog?.Get("DSS") is { } entry
                && (IsCompressed(c.Model, root) || entry is PdfReference reference && IsCompressed(c.Model, reference.Id))),

        new(
            "DssSummaryFromTheModel",
            "Inspection's DSS summary counts what the DSS holds; it differs where the legacy reader misread the DSS (an "
            + "explained difference of the DSS data), and the model does not report /VRI as malformed when it is a reference.",
            (c, d) => d.Key == "dss-summary"
                && (c.Model.View().Dss?.Get("VRI") is PdfReference
                    || c.Legacy.Facts.Keys.Union(c.ModelFacts.Facts.Keys).Where(k => k.StartsWith("dss-data/", StringComparison.Ordinal))
                        .Any(k => c.Legacy[k] != c.ModelFacts[k] && All!.Any(r => r.Name != "DssSummaryFromTheModel"
                            && r.Explains(c, new FactDifference(k, c.Legacy[k], c.ModelFacts[k])))))),

        new(
            "PdfAFromCatalogMetadata",
            "The PDF/A level is what the catalog's /Metadata stream declares (ISO 19005); the legacy reader took the first "
            + "pdfaid:part in any text of the file.",
            (c, d) => d.Key == "pdfa" && d.Model == nameof(PdfALevel.None) && d.Legacy != nameof(PdfALevel.None)),

        new(
            "EncryptFromTrailer",
            "A document is encrypted when its trailer has /Encrypt; the legacy reader took the text /Encrypt in the first or "
            + "last 4 KB of the file, wherever it was.",
            (c, d) => !c.Model.IsEncrypted && (d.Key == "encrypted" && d.Legacy == "true" || d.Key == "embedded-files" && d.Legacy == "encrypted"
                || d.Key.StartsWith("signature", StringComparison.Ordinal) && c.Legacy["signatures"] == "encrypted")),

        new(
            "ComparedSemantically",
            "The revision comparison compares objects (PdfObject.SemanticEquals): a page written again with other spacing, "
            + "numbers written otherwise (612.0 and 612) or its keys in another order is not a change, nor is an object number "
            + "the signed revision did not list; the legacy comparison compared normalized text.",
            OnlySemanticallyEqual),

        new(
            "FieldNameDecoding",
            "Field names in the comparison's messages are decoded text strings (§7.9.2: escapes, UTF-16 with its byte order "
            + "mark); the legacy comparison kept the escapes' digits and wrote a UTF-16 name byte by byte (þÿ S i g n …).",
            (c, d) => d.Key.StartsWith("changes/", StringComparison.Ordinal) && d.Legacy is not null && d.Model is not null
                && QuotedNames().Replace(d.Legacy, "''") == QuotedNames().Replace(d.Model, "''")
                && QuotedNames().Matches(d.Model).All(m => c.Model.View().Fields.Any(f => "'" + f.FullName + "'" == m.Value))),

        new(
            "SignatureDictionaryReportedOnce",
            "A signature dictionary written again in a later revision is one signature: the model reports the copy the "
            + "cross-reference gives; the legacy reader reported every copy it found in the file's text.",
            (c, d) => d.Key == "signatures/order" && d.Legacy is not null && d.Model is not null
                && d.Legacy.Split(' ').Distinct().SequenceEqual(d.Model.Split(' '))),

        new(
            "DocMdpFromStructure",
            "The DocMDP level is read from the certification signature's /Reference; the legacy reader needed the text "
            + "'/TransformMethod /DocMDP' with its space, and took the first /P within 2 KB of it.",
            (c, d) => (d.Key == "docmdp" || d.Key.StartsWith("changes/", StringComparison.Ordinal) && d.Key.EndsWith("/docmdp", StringComparison.Ordinal))
                && c.Model.View().CertificationSignature is not null
                && System.Text.Encoding.Latin1.GetString(c.Data).IndexOf("/TransformMethod /DocMDP", StringComparison.Ordinal) < 0),

        new(
            "LegacyInlineDescendantFont",
            "A Type 0 font whose /DescendantFonts holds the CIDFont dictionary inline: the legacy reader takes the first "
            + "reference inside that dictionary for the CIDFont, loses its /W and places every glyph 1000 units wide.",
            (c, d) => d.Key.StartsWith("text/", StringComparison.Ordinal) && d.Key.EndsWith("/origins", StringComparison.Ordinal)
                && int.TryParse(d.Key.Split('/')[1], out int page) && page <= c.Model.View().Pages.Count
                && c.Model.Resolve(c.Model.View().Pages[page - 1].Resources?.Get("Font")) is PdfDictionary fonts
                && fonts.Any(f => c.Model.Resolve(f.Value) is PdfDictionary font
                    && c.Model.Resolve(font.Get("DescendantFonts")) is PdfArray { Count: > 0 } descendants && descendants[0] is PdfDictionary)),

        new(
            "EncryptedContentUnreadable",
            "The content of an encrypted document is not decrypted: the model refuses its streams (not zlib), the legacy "
            + "reader inflated them as they were. Neither finds text.",
            (c, d) => c.Model.IsEncrypted && d.Key.StartsWith("text/", StringComparison.Ordinal) && d.Model is null or "unreadable"),

        new(
            "EmbeddedFileDecodeParms",
            "An embedded file with /DecodeParms (a predictor) was refused by the legacy reader; the model decodes it.",
            (c, d) => d.Key == "embedded-files" && d.Legacy?.Contains("/DecodeParms", StringComparison.Ordinal) == true
                && d.Model?.StartsWith("error", StringComparison.Ordinal) == false),

        new(
            "PdfDocEncodingText",
            "A text string without a byte order mark is PDFDocEncoding (ISO 32000-1 Annex D); the legacy attachment reader "
            + "read it as Latin-1, which differs in 0x18–0x1F and 0x80–0xA0.",
            (c, d) => d.Key == "embedded-files" && d.Legacy is not null && d.Model is not null
                && d.Legacy.Length == d.Model.Length
                && d.Legacy.Zip(d.Model).All(p => p.First == p.Second || p.First is (>= '\u0018' and <= '\u001F') or (>= '\u0080' and <= '\u00A0'))),

        new(
            "NameTreeNodeReadOnce",
            "A name tree whose /Kids point back to the root: the legacy reader read the root a second time, the model reads "
            + "each node once.",
            (c, d) => d.Key == "embedded-files" && d.Legacy is not null && d.Model is not null
                && d.Legacy.StartsWith(d.Model + " | ", StringComparison.Ordinal)),
    ];

    /// <summary>
    /// Whether the changes the legacy comparison reports and the model's does not are each one the model shows is not a
    /// change: a page whose dictionary is the same but for /Annots (written again with other spacing, number forms or key
    /// order), or an object the signed revision did not list (a number reused after a cross-reference stream that its own
    /// /Index left out). The model must report nothing the legacy comparison does not.
    /// </summary>
    private static bool OnlySemanticallyEqual(ParityContext c, FactDifference d)
    {
        if (!d.Key.StartsWith("changes/", StringComparison.Ordinal) || !d.Key.EndsWith("/undefined", StringComparison.Ordinal)
            || !int.TryParse(d.Key.Split('/')[1], out int signature))
        {
            return false;
        }

        var legacy = (d.Legacy ?? "").Split(" | ", StringSplitOptions.RemoveEmptyEntries);
        var model = (d.Model ?? "").Split(" | ", StringSplitOptions.RemoveEmptyEntries);
        if (model.Except(legacy).Any())
        {
            return false;
        }

        var field = PdfStructureReader.ReadSignatureFields(c.Model).First(f => f.SigDictObjectNumber == signature);
        var signed = PdfDocument.Open(c.Data.AsMemory(0, (int)(field.ByteRange.Offset2 + field.ByteRange.Length2)));
        var pages = c.Model.View().Pages;
        foreach (string extra in legacy.Except(model))
        {
            var page = System.Text.RegularExpressions.Regex.Match(extra, @"^Page (\d+) changed \(content or resources\)\.$");
            var obj = System.Text.RegularExpressions.Regex.Match(extra, @"^Object (\d+) changed\.$");
            if (page.Success && int.Parse(page.Groups[1].Value, CultureInfo.InvariantCulture) is int index && index <= pages.Count
                && pages[index - 1].Id is { } id
                && signed.GetObject(id.Number)?.Value is PdfDictionary before && c.Model.GetObject(id.Number)?.Value is PdfDictionary after
                && before.Keys.Union(after.Keys).Where(k => k.Value != "Annots").All(k => PdfObject.SemanticEquals(before.Get(k), after.Get(k))))
            {
                continue;
            }

            if (obj.Success && signed.Lookup(int.Parse(obj.Groups[1].Value, CultureInfo.InvariantCulture)) is null)
            {
                continue;
            }

            return false;
        }

        return true;
    }

    private static System.Text.RegularExpressions.Regex QuotedNames() => new("'[^']*'", System.Text.RegularExpressions.RegexOptions.None, TimeSpan.FromSeconds(1));

    private static (int Number, PdfSignatureInfo Signature)? Signature(ParityContext c, FactDifference d)
    {
        string[] parts = d.Key.Split('/');
        if (parts is not ["signature", var n, _] || !int.TryParse(n, out int number))
        {
            return null;
        }

        var signature = c.Model.View().Signatures.FirstOrDefault(s => (s.Id?.Number ?? s.Field?.Id?.Number ?? 0) == number);
        return signature is null ? null : (number, signature);
    }

    /// <summary>The bytes a dictionary was parsed from, as text; empty when it is not in the file's bytes.</summary>
    private static string RawText(byte[] data, PdfDictionary dictionary) =>
        dictionary.Source is { } source && source.End <= data.Length
            ? System.Text.Encoding.Latin1.GetString(data, (int)source.Offset, source.Length)
            : "";

    private static bool IsCompressed(PdfDocument doc, PdfObjectId id) => doc.Lookup(id.Number) is { Type: PdfXrefEntryType.Compressed };

    /// <summary>Whether a dictionary nested in this one (at any depth) has the key.</summary>
    private static bool NestedHas(PdfDocument doc, PdfDictionary dictionary, string key, int depth)
    {
        if (depth > 8)
        {
            return false;
        }

        foreach (var (_, value) in dictionary)
        {
            var nested = value is PdfReference ? doc.Resolve(value) : value;
            if (nested is PdfDictionary child && (child.ContainsKey(PdfName.Of(key)) || NestedHas(doc, child, key, depth + 1)))
            {
                return true;
            }

            if (nested is PdfArray array && array.OfType<PdfDictionary>().Any(item => item.ContainsKey(PdfName.Of(key)) || NestedHas(doc, item, key, depth + 1)))
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>The section the latest revision takes an object's entry from.</summary>
    private static PdfXrefSection? Providing(PdfDocument doc, int number)
    {
        for (var revision = doc.Latest; revision is not null; revision = revision.Previous)
        {
            foreach (var section in revision.Sections)
            {
                if (section.Entries.ContainsKey(number))
                {
                    return section;
                }
            }
        }

        return null;
    }

    private delegate long LegacyTable(ReadOnlySpan<byte> data, int start, List<PdfCrossRef> refs, HashSet<int> seen);

    private static readonly LegacyTable s_legacyTable = typeof(PdfStructureReader)
        .GetMethod("ParseClassicXrefRevision", BindingFlags.NonPublic | BindingFlags.Static)
        .ShouldNotBeNull()
        .CreateDelegate<LegacyTable>();

    /// <summary>
    /// Whether the legacy reader misreads a table section of the chain, from the newest down to the one the latest
    /// revision takes the object's entry from: it would lose that entry, or stop the chain before it.
    /// </summary>
    private static bool LegacyMisreadsUpTo(byte[] data, PdfDocument doc, int number)
    {
        var providing = Providing(doc, number);
        long? pointer = doc.StartXref;
        for (var revision = doc.Latest; revision is not null; revision = revision.Previous)
        {
            foreach (var section in revision.Sections)
            {
                if (section.Kind == PdfXrefSectionKind.Table && section.XrefStream is null
                    && !LegacyReadsTableAsModel(data, pointer ?? section.Offset, section))
                {
                    return true;
                }

                if (ReferenceEquals(section, providing))
                {
                    return false;
                }

                pointer = section.Prev;
            }
        }

        return providing is null;
    }

    /// <summary>Whether the legacy table reader gets the same in-use entries and /Prev as the model from a table.</summary>
    /// <param name="data">The file.</param>
    /// <param name="pointer">The offset the chain gives for the section (<c>startxref</c> or the newer section's /Prev).</param>
    /// <param name="section">The section as the model read it.</param>
    private static bool LegacyReadsTableAsModel(byte[] data, long pointer, PdfXrefSection section)
    {
        if (pointer < 0 || pointer >= data.Length || !data.AsSpan((int)pointer).StartsWith("xref"u8))
        {
            return false;
        }

        var refs = new List<PdfCrossRef>();
        long prev = s_legacyTable(data, (int)pointer, refs, []);
        var expected = section.Entries.Where(e => e.Value.Type == PdfXrefEntryType.InUse).Select(e => (e.Key, e.Value.Offset)).Order();
        long? legacyPrev = prev > 0 ? prev : null;
        return legacyPrev == section.Prev
            && refs.Select(r => (r.ObjectNumber, r.Offset)).Order().SequenceEqual(expected);
    }
}
