using System.Text.Json;
using SimpleSign.Core.Validation;
using SimpleSign.TestBench.Documents;
using SimpleSign.TestBench.Runs;
using SimpleSign.TestBench.Signing;

namespace SimpleSign.TestBench.Validation;

/// <summary>
/// Validates through the <c>simplesign</c> CLI: runs the validate command the Code tab shows (<c>validate</c>,
/// <c>cades validate</c>, <c>xades validate</c>) with <c>--json</c> and the ETSI and simple reports, and reads its verdicts.
/// </summary>
internal static class CliValidation
{
    private static readonly CliExecutor s_cli = new();

    private static readonly Dictionary<string, SignatureSubIndication> s_subIndications =
        Enum.GetValues<SignatureSubIndication>().ToDictionary(s => s.ToEtsiName(), StringComparer.Ordinal);

    /// <summary>
    /// Runs <paramref name="command"/> in a work folder holding <paramref name="inputs"/> (the file to validate, its data)
    /// and <paramref name="trust"/> (the roots, the LOTL signer, the policy: <see cref="ValidationService.CliFiles"/>).
    /// </summary>
    public static Task<CliOutcome> RunAsync(CliLine command, IReadOnlyDictionary<string, byte[]> inputs, IReadOnlyDictionary<string, byte[]> trust,
        CancellationToken cancellationToken)
    {
        var jobs = new CliJobs();
        foreach (var (name, content) in trust.Concat(inputs))
        {
            jobs.File(name, content);
        }

        return s_cli.RunAsync(jobs.Build([command]), cancellationToken);
    }

    /// <summary>
    /// Keeps the reports the CLI wrote next to the validated file: the simple report (shown as the run's report) and the
    /// ETSI TS 119 102-2 report (XML).
    /// </summary>
    public static CliReports Store(CliOutcome? outcome, DocumentStore documents, string? fileName)
    {
        if (outcome is null)
        {
            return new CliReports(null, null);
        }

        string stem = Path.GetFileNameWithoutExtension(fileName ?? "signature");
        string? simple = outcome.SimpleReport is { } json ? documents.Add(stem + "-simple-report.json", json).Id : null;
        string? etsi = outcome.EtsiReport is { } xml ? documents.Add(stem + "-etsi-report.xml", xml).Id : null;
        return new CliReports(simple, etsi);
    }

    /// <summary>The JSON a validate command printed, read as <typeparamref name="T"/>; null when there is none or it does not parse.</summary>
    public static T? Parse<T>(string? json)
        where T : class
    {
        if (json is null)
        {
            return null;
        }

        try
        {
            return JsonSerializer.Deserialize<T>(json, WorkbenchJson.Options);
        }
        catch (JsonException)
        {
            return null;
        }
    }

    /// <summary>The checks of a signature as the CLI printed them, back as the library's constraint results.</summary>
    public static IReadOnlyList<ValidationConstraintResult> Constraints(IReadOnlyList<CliConstraint>? constraints) =>
        [.. (constraints ?? []).Select(c => new ValidationConstraintResult(
            c.Id,
            Enum.TryParse<ConstraintStatus>(c.Status, out var status) ? status : ConstraintStatus.NotChecked,
            c.SubIndication is { } sub && s_subIndications.TryGetValue(sub, out var subIndication) ? subIndication : null,
            c.Message ?? ""))];

    /// <summary>The verdict on one PDF signature, from <c>validate --json</c>.</summary>
    public static PadesVerdict Verdict(CliPadesSignature s) => new(
        s.FieldName, s.Indication, s.SubIndication, s.IsDocumentTimestamp, s.Signer, s.SubFilter, s.Algorithm, s.SigningTime,
        s.Integrity, s.Signature, s.Chain, s.ChainTrustWarning, s.ChainRegion, s.NotRevoked, s.RevocationSource ?? "", s.HasValidTimestamp, s.IsTsaTrusted,
        Constraints(s.Constraints), s.Errors ?? [], s.Warnings ?? [], s.ChainMetadata);
}

/// <summary>The reports a validate command wrote, kept in the document store: the simple report (JSON) and the ETSI report (XML).</summary>
public sealed record CliReports(string? SimpleId, string? EtsiId);

/// <summary>One check of a signature in the CLI's JSON.</summary>
internal sealed record CliConstraint(string Id, string Status, string? SubIndication, string? Message);

/// <summary>The JSON of <c>simplesign validate --json</c>.</summary>
internal sealed record CliPadesOutput(IReadOnlyList<CliPadesSignature> Signatures);

/// <summary>One signature of a PDF in the JSON of <c>simplesign validate --json</c>.</summary>
internal sealed record CliPadesSignature(
    string FieldName,
    string Indication,
    bool IsDocumentTimestamp,
    string? Signer,
    string? Algorithm,
    bool Integrity,
    bool Signature,
    bool Chain,
    DateTimeOffset? SigningTime,
    string? SubIndication,
    IReadOnlyList<CliConstraint>? Constraints,
    IReadOnlyList<string>? Errors,
    IReadOnlyList<string>? Warnings,
    string? SubFilter,
    bool NotRevoked,
    string? RevocationSource,
    bool? HasValidTimestamp,
    bool? IsTsaTrusted,
    bool ChainTrustWarning,
    string? ChainRegion,
    IReadOnlyDictionary<string, string>? ChainMetadata);

/// <summary>The JSON of <c>simplesign cades validate --json</c>.</summary>
internal sealed record CliCadesOutput(IReadOnlyList<CliCadesSigner> Signatures, IReadOnlyList<string>? ReportErrors);

/// <summary>One signer (or countersignature) in the JSON of <c>simplesign cades validate --json</c>.</summary>
internal sealed record CliCadesSigner(
    string Id,
    int Index,
    string Indication,
    string? SubIndication,
    IReadOnlyList<CliConstraint>? Constraints,
    bool IsSignatureValid,
    bool IsIntegrityValid,
    bool IsCertificateChainValid,
    bool? HasValidTimestamp,
    bool? IsTsaTrusted,
    bool? HasValidContentTimestamp,
    DateTimeOffset? ContentTimestampTime,
    bool? IsLtvDataValid,
    bool? HasValidEscTimestamp,
    bool? HasValidArchiveTimestamp,
    bool? NotRevoked,
    string? RevocationSource,
    string? Signer,
    DateTimeOffset? SigningTime,
    IReadOnlyList<string>? Errors,
    IReadOnlyList<string>? Warnings,
    IReadOnlyList<CliCadesSigner>? CounterSignatures);

/// <summary>The JSON of <c>simplesign xades validate --json</c>.</summary>
internal sealed record CliXadesOutput(IReadOnlyList<CliXadesSignature> Signatures);

/// <summary>One signature (or countersignature) in the JSON of <c>simplesign xades validate --json</c>.</summary>
internal sealed record CliXadesSignature(
    string? Id,
    string Indication,
    string? SubIndication,
    IReadOnlyList<CliConstraint>? Constraints,
    bool IsSignatureValid,
    bool IsIntegrityValid,
    bool IsCertificateChainValid,
    bool? HasValidSignatureTimeStamp,
    bool? IsTsaTrusted,
    bool? HasValidDataObjectsTimeStamp,
    DateTimeOffset? DataObjectsTimeStampTime,
    bool? HasValidCompleteReferences,
    bool? HasValidSigAndRefsTimeStamp,
    bool? IsLtvDataValid,
    bool? HasValidArchiveTimeStamp,
    bool? NotRevoked,
    string? RevocationSource,
    string? DetectedLevel,
    string? Signer,
    DateTimeOffset? SigningTime,
    IReadOnlyList<string>? Errors,
    IReadOnlyList<string>? Warnings,
    IReadOnlyList<CliXadesSignature>? CounterSignatures);
