using System.Collections.Concurrent;
using SimpleSign.PAdES.Inspection;
using SimpleSign.Pdf;
using SimpleSign.Pdf.Enums;

namespace SimpleSign.TestBench.Documents;

/// <summary>An existing signature in the document.</summary>
public sealed record ExistingSignature(string FieldName, string? SubFilter, string? Signer, bool IsDocumentTimestamp);

/// <summary>What the TestBench knows about a PDF; later steps only offer options these facts allow.</summary>
public sealed record DocumentFacts(
    string Id,
    string Title,
    string FileName,
    long Size,
    string PdfVersion,
    string PdfALevel,
    bool IsPdfA,
    bool IsPdfA1,
    bool IsEncrypted,
    int DocMdpLevel,
    IReadOnlyList<ExistingSignature> Signatures,
    IReadOnlyList<string> EmptyFields,
    string? Error);

/// <summary>A stored file: a PDF to sign, an image for the stamp, or a PFX.</summary>
internal sealed record StoredFile(string Id, string FileName, byte[] Content, DateTimeOffset Created);

/// <summary>In-memory store for samples, uploads and signed outputs (never written to disk).</summary>
internal sealed partial class DocumentStore
{
    private const int MaxUploads = 200;
    private readonly ConcurrentDictionary<string, StoredFile> _files = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, DocumentFacts> _facts = new(StringComparer.Ordinal);
    private readonly Dictionary<string, SampleDocument> _samples = new(StringComparer.Ordinal);

    public IReadOnlyCollection<SampleDocument> Samples => _samples.Values;

    public void AddSamples(IEnumerable<SampleDocument> samples)
    {
        foreach (var sample in samples)
        {
            _samples[sample.Id] = sample;
            _files[SampleKey(sample.Id)] = new StoredFile(SampleKey(sample.Id), sample.FileName, sample.Content, DateTimeOffset.UtcNow);
        }
    }

    public static string SampleKey(string sampleId) => "sample:" + sampleId;

    public StoredFile Add(string fileName, byte[] content)
    {
        if (_files.Count > MaxUploads)
        {
            foreach (var old in _files.Values.Where(f => !f.Id.StartsWith("sample:", StringComparison.Ordinal)).OrderBy(f => f.Created).Take(50))
            {
                _files.TryRemove(old.Id, out _);
                _facts.TryRemove(old.Id, out _);
            }
        }

        string id = Guid.NewGuid().ToString("N")[..12];
        var file = new StoredFile(id, Path.GetFileName(fileName), content, DateTimeOffset.UtcNow);
        _files[id] = file;
        return file;
    }

    public StoredFile Get(string id) =>
        _files.TryGetValue(id, out var file) ? file : throw new KeyNotFoundException($"No document or upload '{id}' (uploads are kept in memory only).");

    public bool TryGet(string id, out StoredFile? file) => _files.TryGetValue(id, out file);

    public async Task<DocumentFacts> FactsAsync(string id, CancellationToken cancellationToken = default)
    {
        if (_facts.TryGetValue(id, out var cached))
        {
            return cached;
        }

        var file = Get(id);
        string title = id.StartsWith("sample:", StringComparison.Ordinal) && _samples.TryGetValue(id[7..], out var sample) ? sample.Title : file.FileName;
        DocumentFacts facts;
        try
        {
            using var stream = new MemoryStream(file.Content, writable: false);
            var inspection = await PdfSignatureInspector.InspectAsync(stream, cancellationToken: cancellationToken);
            var doc = inspection.Document;
            facts = new DocumentFacts(
                id, title, file.FileName, file.Content.Length,
                VersionText(doc.PdfVersion), doc.PdfALevel.ToString(), doc.PdfALevel != PdfALevel.None,
                doc.PdfALevel is PdfALevel.A1a or PdfALevel.A1b,
                doc.IsEncrypted, doc.DocMdpPermissionLevel,
                [.. inspection.Signatures.Select(s => new ExistingSignature(s.FieldName, s.SubFilter, s.Signer?.Subject ?? s.DeclaredSignerName, s.IsDocumentTimestamp))],
                EmptySignatureFields(file.Content),
                null);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            facts = new DocumentFacts(id, title, file.FileName, file.Content.Length, "?", "None", false, false, false, 0, [], [], ex.Message);
        }

        _facts[id] = facts;
        return facts;
    }

    /// <summary>
    /// Names of unsigned signature fields (/FT /Sig without a /V value). The library only lists
    /// signed fields, so this scans the objects; fields inside compressed object streams are not
    /// found. The library checks the field again when signing (WithExistingField).
    /// </summary>
    internal static IReadOnlyList<string> EmptySignatureFields(byte[] pdf)
    {
        string text = System.Text.Encoding.Latin1.GetString(pdf);
        var names = new List<string>();
        foreach (System.Text.RegularExpressions.Match match in ObjectPattern().Matches(text))
        {
            string body = match.Groups[1].Value;
            if (!FieldTypeSig().IsMatch(body) || ValueEntry().Match(body) is { Success: true } v && v.Groups[1].Value != "null")
            {
                continue;
            }

            if (NameEntry().Match(body) is { Success: true } name && !names.Contains(name.Groups[1].Value))
            {
                names.Add(name.Groups[1].Value);
            }
        }

        return names;
    }

    [System.Text.RegularExpressions.GeneratedRegex(@"\d+\s+\d+\s+obj\b(.*?)\bendobj", System.Text.RegularExpressions.RegexOptions.Singleline)]
    private static partial System.Text.RegularExpressions.Regex ObjectPattern();

    [System.Text.RegularExpressions.GeneratedRegex(@"/FT\s*/Sig\b")]
    private static partial System.Text.RegularExpressions.Regex FieldTypeSig();

    [System.Text.RegularExpressions.GeneratedRegex(@"/V\s*(null|\d+\s+\d+\s+R|<<)")]
    private static partial System.Text.RegularExpressions.Regex ValueEntry();

    [System.Text.RegularExpressions.GeneratedRegex(@"/T\s*\(([^)]*)\)")]
    private static partial System.Text.RegularExpressions.Regex NameEntry();

    private static string VersionText(PdfVersion version) =>
        version == PdfVersion.Unknown ? "unknown" : $"{(int)version / 10}.{(int)version % 10}";
}
