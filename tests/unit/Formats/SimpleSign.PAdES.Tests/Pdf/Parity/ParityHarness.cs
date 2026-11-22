using SimpleSign.Core.Validation.Policy;
using SimpleSign.PAdES.Pdf;
using SimpleSign.PAdES.Pdf.Model;

namespace SimpleSign.PAdES.Tests.Pdf.Parity;

/// <summary>A fact the two readers disagree on.</summary>
internal sealed record FactDifference(string Key, string? Legacy, string? Model)
{
    /// <summary>The object number of an <c>xref/N</c> or <c>object/N</c> fact; null for the others.</summary>
    public int? ObjectNumber => Key.IndexOf('/', StringComparison.Ordinal) is int slash and > 0
        && int.TryParse(Key.AsSpan(slash + 1), out int number) ? number : null;

    public override string ToString() => $"{Key}: legacy {Legacy ?? "(none)"} | model {Model ?? "(none)"}";
}

/// <summary>What the comparison of one PDF found.</summary>
internal sealed class ParityReport
{
    /// <summary>Differences no catalogued rule explains: each one fails the harness.</summary>
    public List<FactDifference> Unexplained { get; } = [];

    /// <summary>The differences explained, by rule name.</summary>
    public Dictionary<string, List<FactDifference>> Explained { get; } = [];

    /// <summary>How many facts were compared.</summary>
    public int Compared { get; set; }

    /// <summary>What each reader made of the document, for the message.</summary>
    public string Summary { get; set; } = "";

    public override string ToString() =>
        $"{Summary}{Environment.NewLine}{Compared} facts; explained: {string.Join(", ", Explained.Select(e => $"{e.Key} ×{e.Value.Count}"))}; "
        + $"unexplained ({Unexplained.Count}):{Environment.NewLine}  {string.Join(Environment.NewLine + "  ", Unexplained.Take(40))}";
}

/// <summary>Everything a rule may look at to decide whether it explains a difference.</summary>
internal sealed record ParityContext(byte[] Data, PdfDocument Model, FactSet Legacy, FactSet ModelFacts);

/// <summary>
/// Computes the facts of a PDF with the legacy reader and with the object model, and sorts each difference into
/// explained (by a rule of <see cref="ExpectedDifferences"/>) or unexplained (ADR 0032).
/// </summary>
internal static class ParityHarness
{
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

    public static ParityReport Compare(byte[] data)
    {
        var model = PdfDocument.Open(data);
        var legacy = LegacyFacts.Read(data, model);
        var modelFacts = ModelFacts.Read(model);

        // What changed after each signature, as each comparison sees it.
        if (!model.IsEncrypted && data.AsSpan().StartsWith("%PDF-"u8) && model.Catalog is not null)
        {
            var index = PdfObjectIndex.Build(data);
            foreach (var field in PdfStructureReader.ReadSignatureFields(model))
            {
                long end = field.ByteRange.Offset2 + field.ByteRange.Length2;
                AddChanges(legacy, field.SigDictObjectNumber, () => PdfRevisionComparerLegacy.Compare(index, data, end, field.SigDictObjectNumber));
                AddChanges(modelFacts, field.SigDictObjectNumber, () => PdfRevisionComparer.Compare(model, end, field.SigDictObjectNumber));
            }
        }

        // The empty signature fields a signer can fill, found by each reader by their partial name.
        if (!model.IsEncrypted)
        {
            foreach (var field in model.View().Fields.Where(f => f.IsSignature && f.Value is null && f.PartialName is not null))
            {
                string key = $"empty-field/{field.FullName}";
                legacy.Add(key, LegacyFacts.EmptyField(data, field.PartialName!));
                modelFacts.Add(key, field.Id?.Number.ToString(System.Globalization.CultureInfo.InvariantCulture) ?? "inline");
            }
        }
        var context = new ParityContext(data, model, legacy, modelFacts);

        var report = new ParityReport
        {
            Summary = $"legacy: {legacy.Facts.Count} facts{(legacy["error"] is { } error ? ", " + error : "")}; "
                + $"model: {modelFacts.Facts.Count} facts, {model.Revisions.Count} revision(s), "
                + $"sections {string.Join(",", model.Revisions.SelectMany(r => r.Sections).Select(s => s.Kind))}, "
                + $"repairs {string.Join(",", model.Diagnostics.Repairs.Select(r => r.Kind).Distinct())}",
        };
        foreach (string key in legacy.Facts.Keys.Union(modelFacts.Facts.Keys, StringComparer.Ordinal))
        {
            report.Compared++;
            string? left = legacy[key];
            string? right = modelFacts[key];
            if (string.Equals(left, right, StringComparison.Ordinal))
            {
                continue;
            }

            var difference = new FactDifference(key, left, right);
            var rule = ExpectedDifferences.All.FirstOrDefault(r => r.Explains(context, difference));
            if (rule is null)
            {
                report.Unexplained.Add(difference);
            }
            else
            {
                if (!report.Explained.TryGetValue(rule.Name, out var list))
                {
                    list = [];
                    report.Explained[rule.Name] = list;
                }

                list.Add(difference);
            }
        }

        return report;
    }
}
