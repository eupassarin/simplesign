using System.Text.Json;
using SimpleSign.TestBench.Runs;

namespace SimpleSign.TestBench.Scripts;

/// <summary>Compares what a TestBench run showed with what a step expects.</summary>
internal static class ScriptExpectations
{
    /// <summary>The run of a step through one engine, with a row per field of <paramref name="expect"/>.</summary>
    public static ScriptEngineRun Evaluate(string engine, RunView view, ScriptExpectation expect)
    {
        var verdict = view.Validation.FirstOrDefault(v => !v.IsTimestamp);
        string? indication = verdict?.EtsiIndication;
        string? subIndication = verdict?.SubIndication;
        string? reason = ReasonOf(view.ErrorType);
        bool? dssAgrees = DssAgrees(view.CrossValidation);
        string? level = view.Kind == RunKinds.Validate ? verdict?.Level : view.AchievedLevel;
        var checks = new List<ScriptCheckRow>();

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

        if (expect.Level is { } expectedLevel)
        {
            checks.Add(new("level", expectedLevel, level ?? "—", Same(expectedLevel, level)));
        }

        if (expect.DssAgrees is { } agrees)
        {
            checks.Add(new("dssAgrees", agrees ? "yes" : "no", dssAgrees is null ? "not cross-validated" : dssAgrees.Value ? "yes" : "no", dssAgrees == agrees));
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

        return new ScriptEngineRun(engine, view.Id, view.Success, view.Error, view.ErrorType, view.OutputId, view.FileName, view.AchievedLevel,
            indication, subIndication, dssAgrees, view.ReportId, view.EtsiReportId, view.TotalMs, checks);
    }

    /// <summary>signed, refused, error (a sign run) or valid, invalid, indeterminate (the first signature's verdict).</summary>
    internal static string OutcomeOf(RunView view, string? indication)
    {
        if (view.Kind == RunKinds.Sign && !view.Success)
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

        return "signed";
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

    private static bool? DssAgrees(object? crossValidation)
    {
        if (crossValidation is null)
        {
            return null;
        }

        var element = JsonSerializer.SerializeToElement(crossValidation, crossValidation.GetType(), WorkbenchJson.Options);
        if (element.ValueKind != JsonValueKind.Object
            || (element.TryGetProperty("available", out var available) && available.ValueKind == JsonValueKind.False))
        {
            return null;
        }

        return element.TryGetProperty("agree", out var agree) && agree.ValueKind is JsonValueKind.True or JsonValueKind.False
            ? agree.GetBoolean()
            : null;
    }

    private static bool Same(string expected, string? found) => string.Equals(expected, found, StringComparison.OrdinalIgnoreCase);
}
