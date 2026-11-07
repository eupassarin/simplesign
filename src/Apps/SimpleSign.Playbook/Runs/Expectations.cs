using System.Globalization;
using System.Text.Json;
using System.Text.RegularExpressions;
using SimpleSign.Playbook.Model;

namespace SimpleSign.Playbook.Runs;

/// <summary>One check of a step: what was expected, whether it held, and what was found.</summary>
public sealed record CheckResult(string Name, bool Passed, string Expected, string Actual);

/// <summary>A request the Sandbox answered, as its /api/log gives it.</summary>
public sealed record SandboxRequestRecord(long Id, DateTimeOffset Time, string Method, string Path, int Status, string Service, string? Fault, long Ms);

/// <summary>What the command of a step gave.</summary>
public sealed record CommandOutcome(int? ExitCode, string Stdout, string Stderr, bool TimedOut);

/// <summary>Checks a step's outcome against its <see cref="Expectation"/>.</summary>
public static class Expectations
{
    /// <summary>The checks of <paramref name="expect"/> on <paramref name="outcome"/>. A command that timed out fails.</summary>
    /// <param name="expect">The expectation (null: only that the command finished).</param>
    /// <param name="outcome">The command's exit code and output.</param>
    /// <param name="requests">The Sandbox's requests during the step.</param>
    /// <param name="resolve">Resolves the variables of file paths.</param>
    public static IReadOnlyList<CheckResult> Evaluate(
        Expectation? expect, CommandOutcome outcome, IReadOnlyList<SandboxRequestRecord> requests, Func<string, string> resolve)
    {
        ArgumentNullException.ThrowIfNull(outcome);
        ArgumentNullException.ThrowIfNull(requests);
        ArgumentNullException.ThrowIfNull(resolve);
        var checks = new List<CheckResult>();
        if (outcome.TimedOut)
        {
            checks.Add(new CheckResult("finished", false, "the command finishes in time", "timed out"));
            return checks;
        }

        if (expect is null)
        {
            return checks;
        }

        if (expect.ExitCode is { } exitCode)
        {
            checks.Add(new CheckResult("exitCode", outcome.ExitCode == exitCode, exitCode.ToString(CultureInfo.InvariantCulture),
                outcome.ExitCode?.ToString(CultureInfo.InvariantCulture) ?? "—"));
        }

        if (expect.Json.Count > 0)
        {
            JsonDocument? document = null;
            try
            {
                document = JsonDocument.Parse(outcome.Stdout);
            }
            catch (JsonException)
            {
                // Every json check fails below.
            }

            using (document)
            {
                foreach (var (path, wanted) in expect.Json)
                {
                    string expected = wanted.GetRawText();
                    if (document is null)
                    {
                        checks.Add(new CheckResult($"json {path}", false, expected, "stdout is not JSON"));
                        continue;
                    }

                    var found = Find(document.RootElement, path);
                    checks.Add(found is { } element
                        ? new CheckResult($"json {path}", JsonEquals(element, wanted), expected, element.GetRawText())
                        : new CheckResult($"json {path}", false, expected, "missing"));
                }
            }
        }

        foreach (string text in expect.StdoutContains)
        {
            checks.Add(new CheckResult("stdout contains", outcome.Stdout.Contains(text, StringComparison.Ordinal), text, Excerpt(outcome.Stdout)));
        }

        foreach (string text in expect.StderrContains)
        {
            checks.Add(new CheckResult("stderr contains", outcome.Stderr.Contains(text, StringComparison.Ordinal), text, Excerpt(outcome.Stderr)));
        }

        foreach (string pattern in expect.StdoutMatches)
        {
            bool matched;
            try
            {
                matched = Regex.IsMatch(outcome.Stdout, pattern, RegexOptions.None, TimeSpan.FromSeconds(2));
            }
            catch (RegexMatchTimeoutException)
            {
                matched = false;
            }

            checks.Add(new CheckResult("stdout matches", matched, pattern, Excerpt(outcome.Stdout)));
        }

        foreach (string file in expect.Files)
        {
            string path = resolve(file);
            checks.Add(new CheckResult("file exists", File.Exists(path), path, File.Exists(path) ? "present" : "missing"));
        }

        foreach (var wanted in expect.SandboxRequests)
        {
            int count = requests.Count(r =>
                (wanted.Service is null || string.Equals(r.Service, wanted.Service, StringComparison.OrdinalIgnoreCase))
                && (wanted.PathContains is null || r.Path.Contains(wanted.PathContains, StringComparison.OrdinalIgnoreCase)));
            bool passed = count >= wanted.Min && (wanted.Max is null || count <= wanted.Max);
            string what = $"{wanted.Service ?? "any service"}{(wanted.PathContains is null ? "" : $" {wanted.PathContains}")}";
            string range = wanted.Max is { } max ? (wanted.Min == max ? $"{max}" : $"{wanted.Min}–{max}") : $"≥ {wanted.Min}";
            checks.Add(new CheckResult("sandbox requests", passed, $"{range} × {what}", $"{count}"));
        }

        return checks;
    }

    /// <summary>The element at a dotted path (<c>error.reason</c>, <c>signatures.0.indication</c>), or null.</summary>
    public static JsonElement? Find(JsonElement root, string path)
    {
        var current = root;
        foreach (string part in path.Split('.', StringSplitOptions.RemoveEmptyEntries))
        {
            if (current.ValueKind == JsonValueKind.Object && current.TryGetProperty(part, out var child))
            {
                current = child;
            }
            else if (current.ValueKind == JsonValueKind.Array && int.TryParse(part, NumberStyles.None, CultureInfo.InvariantCulture, out int index)
                && index < current.GetArrayLength())
            {
                current = current[index];
            }
            else
            {
                return null;
            }
        }

        return current;
    }

    /// <summary>Equal JSON values: strings compared exactly, numbers by value, the rest by their text.</summary>
    public static bool JsonEquals(JsonElement actual, JsonElement expected) =>
        (actual.ValueKind, expected.ValueKind) switch
        {
            (JsonValueKind.String, JsonValueKind.String) => actual.GetString() == expected.GetString(),
            (JsonValueKind.Number, JsonValueKind.Number) => actual.GetDecimal() == expected.GetDecimal(),
            (JsonValueKind.True or JsonValueKind.False, JsonValueKind.True or JsonValueKind.False) => actual.GetBoolean() == expected.GetBoolean(),
            (JsonValueKind.Null, JsonValueKind.Null) => true,
            _ => JsonElement.DeepEquals(actual, expected),
        };

    private static string Excerpt(string text) => text.Length <= 300 ? text.Trim() : text[..300].Trim() + "…";
}
