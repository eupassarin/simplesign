using SimpleSign.PAdES.Inspection;
using SimpleSign.PAdES.Validation;

namespace SimpleSign.HostSigner.Services;

internal static class ValidationService
{
    private static readonly PdfSignatureValidator _validator = new();

    public static async Task<List<ValidateResultDto>> ValidateAsync(string path)
    {
        await using var stream = File.OpenRead(path);
        var results = await _validator.ValidateAsync(stream);

        // Get conformance levels via inspection
        Dictionary<string, PAdESConformanceLevel> levels = new();
        try
        {
            stream.Position = 0;
            var inspection = await PdfSignatureInspector.InspectAsync(stream);
            foreach (var (sig, level) in ConformanceDetector.DetectAll(inspection))
                levels[sig.FieldName] = level;
        }
        catch { /* best-effort */ }

        return results.Select(r => new ValidateResultDto
        {
            FieldName = r.FieldName,
            IsValid = r.IsValid,
            IsDocumentTimestamp = r.IsDocumentTimestamp,
            SignerName = r.SignerName,
            Level = levels.TryGetValue(r.FieldName, out var lv) ? FormatLevel(lv) : null,
            DigestAlgorithm = r.DigestAlgorithmName ?? r.DigestAlgorithmOid,
            SubFilter = r.SubFilter,
            IsIntegrityValid = r.IsIntegrityValid,
            IsSignatureValid = r.IsSignatureValid,
            IsCertificateChainValid = r.IsCertificateChainValid,
            IsNotRevoked = r.IsNotRevoked,
            IsChainTrustWarning = r.IsChainTrustWarning,
            HasValidTimestamp = r.HasValidTimestamp,
            SigningTime = r.SigningTime,
            Errors = r.Errors.ToList(),
            Warnings = r.Warnings.ToList()
        }).ToList();
    }

    private static string FormatLevel(PAdESConformanceLevel level) => level switch
    {
        PAdESConformanceLevel.Unknown => "Unknown",
        PAdESConformanceLevel.CmsOnly => "CMS (no PAdES)",
        PAdESConformanceLevel.BaselineB => "PAdES B-B",
        PAdESConformanceLevel.BaselineT => "PAdES B-T",
        PAdESConformanceLevel.BaselineLT => "PAdES B-LT",
        PAdESConformanceLevel.BaselineLTA => "PAdES B-LTA",
        _ => level.ToString()
    };
}
