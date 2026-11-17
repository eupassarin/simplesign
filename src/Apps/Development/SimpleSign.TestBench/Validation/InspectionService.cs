using SimpleSign.Core.Validation;
using SimpleSign.PAdES.Inspection;
using SimpleSign.PAdES.Validation;
using SimpleSign.TestBench.Documents;

namespace SimpleSign.TestBench.Validation;

public sealed record BulkItem(string FileId, string FileName, int Valid, int Total, string Overall, long Ms, string? Error);

public sealed record BulkRequest(IReadOnlyList<string> FileIds, ValidationSettings Settings, int MaxConcurrency = 4);

public sealed record BulkReport(IReadOnlyList<BulkItem> Items, int Processed, int Failed, double AverageMs, long TotalMs);

public sealed record DictEntryView(string Key, string Value, string? Explanation);

public sealed record ObjectView(int ObjectNumber, string Label, string Icon, IReadOnlyList<string> Badges, IReadOnlyList<DictEntryView> Entries,
    IReadOnlyList<int> References, string? StreamInfo, string? CmsContentType, string? CmsSigner);

public sealed record InspectionReport(string FileId, DocumentFacts Document, int Revisions, IReadOnlyList<ObjectView> Objects,
    IReadOnlyList<string> SignatureFields, string? Error);

/// <summary>Bulk validation (BulkValidator) and structural inspection (PdfStructureDumper, PadesExtractor).</summary>
internal sealed class InspectionService(ValidationService validation, DocumentStore documents)
{
    public async Task<BulkReport> BulkAsync(BulkRequest request, CancellationToken cancellationToken)
    {
        var validator = new BulkValidator(await validation.CreateValidatorAsync(request.Settings, cancellationToken), Math.Clamp(request.MaxConcurrency, 1, 16));
        var names = request.FileIds.ToDictionary(id => id, id => documents.Get(id).FileName, StringComparer.Ordinal);
        var watch = System.Diagnostics.Stopwatch.StartNew();
        var items = new List<BulkItem>();
        await foreach (var r in validator.ValidateAllAsync(Inputs(request.FileIds), cancellationToken))
        {
            string overall = r.Error is not null ? "Error"
                : r.TotalSignatureCount == 0 ? "NoSignatures"
                : r.ValidSignatureCount == r.TotalSignatureCount ? "Valid"
                : r.Results!.Any(s => s.Indication == SignatureIndication.Invalid) ? "Invalid"
                : "Indeterminate";
            items.Add(new BulkItem(r.Id, names[r.Id], r.ValidSignatureCount, r.TotalSignatureCount, overall, (long)r.Duration.TotalMilliseconds, r.Error?.Message));
        }

        items.Sort((a, b) => string.CompareOrdinal(names[a.FileId], names[b.FileId]));
        return new BulkReport(items, validator.SuccessCount, validator.FailureCount, validator.AverageElapsedMs, watch.ElapsedMilliseconds);

        async IAsyncEnumerable<(string Id, byte[] PdfBytes)> Inputs(IEnumerable<string> ids)
        {
            foreach (string id in ids)
            {
                await Task.Yield();
                yield return (id, documents.Get(id).Content);
            }
        }
    }

    public async Task<InspectionReport> InspectAsync(string fileId, CancellationToken cancellationToken)
    {
        var file = documents.Get(fileId);
        var facts = await documents.FactsAsync(fileId, cancellationToken);
        try
        {
            var objects = PdfStructureDumper.ExtractSignatureObjects(file.Content, includeExplanations: true);
            var fields = await PadesExtractor.ExtractAsync(file.Content, ct: cancellationToken);
            return new InspectionReport(fileId, facts, ValidationService.CountRevisions(file.Content),
                [.. objects.Select(o => new ObjectView(o.ObjectNumber, o.Label, o.Icon, o.Badges,
                    [.. o.Entries.Select(e => new DictEntryView(e.Key, e.RawValue, e.Explanation))],
                    o.References,
                    o.Stream is { } s ? $"{s.CompressedBytes} B{(s.DecompressedBytes is { } d ? $" → {d} B" : "")}{(s.IsFlateEncoded ? " (Flate)" : "")}" : null,
                    o.ContentsPreview?.ContentType, o.ContentsPreview?.SignerSubject))],
                [.. fields.Select(f => f.FieldName)], null);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return new InspectionReport(fileId, facts, 0, [], [], ex.Message);
        }
    }

    /// <summary>The CMS (PKCS#7) of one signature, as stored in /Contents (padding removed).</summary>
    public async Task<byte[]?> CmsAsync(string fileId, string field, CancellationToken cancellationToken)
    {
        var signatures = await PadesExtractor.ExtractAsync(documents.Get(fileId).Content, ct: cancellationToken);
        return signatures.FirstOrDefault(s => s.FieldName == field)?.CmsSignature;
    }
}
