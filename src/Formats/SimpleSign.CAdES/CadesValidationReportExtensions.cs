using SimpleSign.Core.Validation;

namespace SimpleSign.CAdES;

/// <summary>CAdES results as entries of <see cref="ValidationReports"/>.</summary>
public static class CadesValidationReportExtensions
{
    /// <summary>The signature as a report entry.</summary>
    /// <param name="result">The validation result.</param>
    /// <param name="id">The signature's identifier in the report. Default: <c>signer-1</c>.</param>
    /// <returns>The entry.</returns>
    public static SignatureReportEntry ToReportEntry(this CadesValidationResult result, string id = "signer-1")
    {
        ArgumentNullException.ThrowIfNull(result);
        return new SignatureReportEntry
        {
            Id = id,
            Format = "CAdES",
            Indication = result.Indication,
            SubIndication = result.SubIndication,
            Constraints = result.Constraints,
            SignerCertificate = result.SignerCertificate,
            ClaimedSigningTime = result.SigningTime,
            BestSignatureTime = result.BestSignatureTime,
            ValidationObjects = result.ValidationObjects,
            Policy = result.AppliedPolicy,
            Errors = result.Errors,
            Warnings = result.Warnings,
        };
    }

    /// <summary>Every signer and countersigner of the report as report entries (<c>signer-1</c>, <c>signer-1.1</c>…).</summary>
    /// <param name="report">The validation report.</param>
    /// <returns>The entries, in document order.</returns>
    public static IReadOnlyList<SignatureReportEntry> ToReportEntries(this CadesValidationReport report)
    {
        ArgumentNullException.ThrowIfNull(report);
        var entries = new List<SignatureReportEntry>();

        void Add(CadesSignerValidationResult signer, string id)
        {
            entries.Add(signer.Result.ToReportEntry(id));
            for (int i = 0; i < signer.CounterSignatures.Count; i++)
            {
                Add(signer.CounterSignatures[i], $"{id}.{i + 1}");
            }
        }

        foreach (var signer in report.Signers)
        {
            Add(signer, $"signer-{signer.Index + 1}");
        }

        return entries;
    }
}
