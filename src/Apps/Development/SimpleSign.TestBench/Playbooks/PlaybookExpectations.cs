using System.Text.Json;
using SimpleSign.TestBench.Runs;

namespace SimpleSign.TestBench.Playbooks;

/// <summary>Compares what a TestBench run showed with what a playbook step expects.</summary>
internal static class PlaybookExpectations
{
    /// <summary>The run of a step through one engine, with a row per field of <paramref name="expect"/>.</summary>
    /// <param name="engine">The engine the run used.</param>
    /// <param name="view">The run.</param>
    /// <param name="expect">What the step expects.</param>
    /// <param name="file">Reads a stored file by id (the ETSI report, for <see cref="PlaybookExpectation.EtsiReport"/>); null when not needed.</param>
    public static PlaybookEngineRun Evaluate(string engine, RunView view, PlaybookExpectation expect, Func<string, byte[]?>? file = null)
    {
        var verdict = view.Validation.FirstOrDefault(v => !v.IsTimestamp);
        string? indication = verdict?.EtsiIndication;
        string? subIndication = verdict?.SubIndication;
        string? reason = ReasonOf(view.ErrorType);
        var (dssAgrees, crossValidated, dssError) = Dss(view.CrossValidation);
        string? level = view.Kind == RunKinds.Validate ? verdict?.Level : view.AchievedLevel;
        var checks = new List<PlaybookCheckRow>();

        if (expect.Outcome is { } outcome)
        {
            string found = OutcomeOf(view, indication);
            checks.Add(new("outcome", outcome, found, Same(outcome, found)));
        }

        if (expect.Reason is { } expectedReason)
        {
            checks.Add(new("reason", expectedReason, reason ?? view.ErrorType ?? "—", Same(expectedReason, reason)));
        }

        if (expect.Indication is { } expectedIndication)
        {
            checks.Add(new("indication", expectedIndication, indication ?? "—", Same(expectedIndication, indication)));
        }

        if (expect.SubIndication is { } expectedSub)
        {
            checks.Add(new("subIndication", expectedSub, subIndication ?? "—", Same(expectedSub, subIndication)));
        }

        string? qualification = verdict?.Qualification;
        string? timestampQualification = verdict?.TimestampQualifications is [var first, ..] ? first : null;
        if (expect.Qualification is { } expectedQualification)
        {
            checks.Add(new("qualification", expectedQualification, qualification ?? "—", Same(expectedQualification, qualification)));
        }

        if (expect.TimestampQualification is { } expectedTimestamp)
        {
            checks.Add(new("timestampQualification", expectedTimestamp, timestampQualification ?? "—", Same(expectedTimestamp, timestampQualification)));
        }

        if (expect.Level is { } expectedLevel)
        {
            checks.Add(new("level", expectedLevel, level ?? "—", Same(expectedLevel, level)));
        }

        if (expect.DssAgrees is { } agrees)
        {
            string found = dssAgrees is { } a ? a ? "yes" : "no"
                : crossValidated ? $"DSS unavailable: {dssError ?? "no verdict"}"
                : "not cross-validated";
            checks.Add(new("dssAgrees", agrees ? "yes" : "no", found, dssAgrees == agrees));
        }

        if (expect.FailedConstraints.Count > 0)
        {
            var failed = view.Validation.Where(v => !v.IsTimestamp).SelectMany(v => v.Findings ?? [])
                .Where(f => f.Status == "fail").Select(f => f.Constraint).ToHashSet(StringComparer.Ordinal);
            foreach (string constraint in expect.FailedConstraints)
            {
                checks.Add(new("failedConstraint", constraint, failed.Contains(constraint) ? "failed" : "not failed", failed.Contains(constraint)));
            }
        }

        if (expect.EtsiReport is { } etsiReport)
        {
            string found = view.EtsiReportId is not { } reportId || file?.Invoke(reportId) is not { } xml ? "no report"
                : SimpleSign.Core.Validation.ValidationReports.ValidateEtsiXml(System.Text.Encoding.UTF8.GetString(xml)) is { Count: > 0 } errors
                    ? $"{errors.Count} schema error(s): {errors[0]}"
                    : "valid";
            checks.Add(new("etsiReport", etsiReport, found, found == etsiReport));
        }

        foreach (string text in expect.LogContains)
        {
            bool found = view.Logs.Any(l => l.Message.Contains(text, StringComparison.OrdinalIgnoreCase))
                || (view.Cli ?? []).Any(c => c.Output.Contains(text, StringComparison.OrdinalIgnoreCase));
            checks.Add(new("log", text, found ? "found" : "not found", found));
        }

        if (checks.Count == 0)
        {
            // Nothing named: the run must at least succeed.
            checks.Add(new("outcome", "success", view.Success ? "success" : view.Error ?? "failure", view.Success));
        }

        return new PlaybookEngineRun(engine, view.Id, view.Success, view.Error, view.ErrorType, view.OutputId, view.FileName, view.AchievedLevel,
            indication, subIndication, dssAgrees, view.ReportId, view.EtsiReportId, view.TotalMs, checks)
        {
            CrossValidated = crossValidated,
            DssError = dssAgrees is null && crossValidated ? dssError ?? "DSS gave no verdict." : null,
            Qualification = qualification,
            TimestampQualification = timestampQualification,
        };
    }

    /// <summary>
    /// Where the library and CLI runs of a step disagree: whether the run succeeded, the reason of a refusal, the
    /// indication, sub-indication and level of the first signature. Empty unless the step ran through both engines.
    /// </summary>
    public static IReadOnlyList<PlaybookEngineDifference> EngineDifferences(IReadOnlyList<PlaybookEngineRun> runs)
    {
        var library = runs.FirstOrDefault(r => r.Engine == RunEngines.Library);
        var cli = runs.FirstOrDefault(r => r.Engine == RunEngines.Cli);
        if (library is null || cli is null)
        {
            return [];
        }

        (string What, string? Library, string? Cli)[] fields =
        [
            ("success", library.Success ? "true" : "false", cli.Success ? "true" : "false"),
            ("reason", ReasonOf(library.ErrorType), ReasonOf(cli.ErrorType)),
            ("indication", library.Indication, cli.Indication),
            ("subIndication", library.SubIndication, cli.SubIndication),
            ("level", library.AchievedLevel, cli.AchievedLevel),
            ("qualification", library.Qualification, cli.Qualification),
            ("timestampQualification", library.TimestampQualification, cli.TimestampQualification),
        ];
        return [.. fields.Where(f => !string.Equals(f.Library, f.Cli, StringComparison.OrdinalIgnoreCase))
            .Select(f => new PlaybookEngineDifference(f.What, f.Library, f.Cli))];
    }

    /// <summary>signed, refused, error (a sign run) or valid, invalid, indeterminate (the first signature's verdict).</summary>
    internal static string OutcomeOf(RunView view, string? indication)
    {
        if (view.Kind is RunKinds.Sign or RunKinds.Augment && !view.Success)
        {
            return view.ErrorType?.StartsWith("SigningException", StringComparison.Ordinal) == true ? "refused" : "error";
        }

        if (view.Kind == RunKinds.Validate)
        {
            return indication switch
            {
                "TOTAL_PASSED" => "valid",
                "TOTAL_FAILED" => "invalid",
                null => "error",
                _ => "indeterminate",
            };
        }

        return view.Kind == RunKinds.Augment ? "augmented" : "signed";
    }

    /// <summary>The reason in <c>SigningException (Reason)</c>, or null.</summary>
    internal static string? ReasonOf(string? errorType)
    {
        if (errorType is null)
        {
            return null;
        }

        int open = errorType.IndexOf('(', StringComparison.Ordinal);
        int close = errorType.LastIndexOf(')');
        return open >= 0 && close > open ? errorType[(open + 1)..close].Trim() : null;
    }

    /// <summary>DSS's verdict on a run: whether it agrees (null: no verdict), whether DSS was asked, and why it gave none.</summary>
    private static (bool? Agrees, bool Asked, string? Error) Dss(object? crossValidation)
    {
        if (crossValidation is null)
        {
            return (null, false, null);
        }

        var element = JsonSerializer.SerializeToElement(crossValidation, crossValidation.GetType(), WorkbenchJson.Options);
        if (element.ValueKind != JsonValueKind.Object)
        {
            return (null, true, null);
        }

        string? error = element.TryGetProperty("error", out var e) && e.ValueKind == JsonValueKind.String ? e.GetString() : null;
        if (element.TryGetProperty("available", out var available) && available.ValueKind == JsonValueKind.False)
        {
            return (null, true, error ?? "DSS did not answer.");
        }

        return element.TryGetProperty("agree", out var agree) && agree.ValueKind is JsonValueKind.True or JsonValueKind.False
            ? (agree.GetBoolean(), true, null)
            : (null, true, error);
    }

    private static bool Same(string expected, string? found) => string.Equals(expected, found, StringComparison.OrdinalIgnoreCase);
}
