using System.Globalization;
using System.Text;
using System.Xml.Linq;
using SimpleSign.TestHelpers;
using Xunit;

namespace SimpleSign.VeraPdf.Tests;

/// <summary>A rule of the veraPDF validation profile that the document breaks.</summary>
/// <param name="Specification">The standard, e.g. <c>ISO 19005-2:2011</c>.</param>
/// <param name="Clause">The clause of the standard, e.g. <c>6.3.2</c>.</param>
/// <param name="TestNumber">The test of the clause.</param>
/// <param name="Description">What the rule requires.</param>
/// <param name="FailedChecks">How many objects of the document break it.</param>
public sealed record VeraPdfFailedRule(string Specification, string Clause, string TestNumber, string Description, int FailedChecks);

/// <summary>veraPDF's verdict on one document, read from its machine-readable report (<c>--format mrr</c>).</summary>
/// <param name="IsCompliant">Whether the document conforms to the flavour it was checked against.</param>
/// <param name="Profile">The validation profile veraPDF used.</param>
/// <param name="Error">Why veraPDF could not validate the document (it could not parse it, for one); null when it did.</param>
/// <param name="FailedRules">The rules the document breaks.</param>
/// <param name="Xml">The report as veraPDF wrote it.</param>
public sealed record VeraPdfReport(bool IsCompliant, string? Profile, string? Error, IReadOnlyList<VeraPdfFailedRule> FailedRules, string Xml)
{
    /// <summary>One line per broken rule, for an assertion message.</summary>
    public string Summary
    {
        get
        {
            if (Error is not null)
            {
                return $"veraPDF could not validate the document: {Error}";
            }

            if (IsCompliant)
            {
                return $"PASS ({Profile})";
            }

            var text = new StringBuilder($"FAIL ({Profile}), {FailedRules.Count} rule(s) broken:");
            foreach (var rule in FailedRules)
            {
                text.Append(CultureInfo.InvariantCulture, $"\n  {rule.Specification} {rule.Clause}-{rule.TestNumber} ({rule.FailedChecks} check(s)): {rule.Description}");
            }

            return text.ToString();
        }
    }
}

/// <summary>
/// Runs the veraPDF CLI on a document: the executable <c>SIMPLESIGN_VERAPDF</c> names when set, otherwise the
/// <see cref="Image"/> Docker image. Without either the calling test is skipped, or fails when
/// <c>SIMPLESIGN_REQUIRE_VERAPDF</c> is "true" (the CI job pulls the image, so a missing veraPDF is an error there).
/// </summary>
public static class VeraPdf
{
    /// <summary>
    /// The veraPDF CLI image (veraPDF 1.30.2), pinned by digest. To update it: <c>docker pull verapdf/cli:latest</c>,
    /// take the digest from <c>docker image inspect --format '{{index .RepoDigests 0}}' verapdf/cli:latest</c>,
    /// change it here and in .github/workflows/ci.yml, and run these tests.
    /// </summary>
    public const string Image = "verapdf/cli@sha256:d5ee329657cf9bc4b2400392dd54c7d0a0ce9980ff6fa2da5590eebeec007cdb";

    private static readonly Lazy<string?> Unavailable = new(FindProblem, LazyThreadSafetyMode.ExecutionAndPublication);

    private static string? LocalExecutable => Environment.GetEnvironmentVariable("SIMPLESIGN_VERAPDF") is { Length: > 0 } path ? path : null;

    /// <summary>
    /// Where the documents veraPDF rejects are written, with its report: <c>SIMPLESIGN_VERAPDF_FAILURES</c>, or
    /// <c>verapdf-failures</c> next to the test assembly.
    /// </summary>
    public static string FailuresDirectory =>
        Environment.GetEnvironmentVariable("SIMPLESIGN_VERAPDF_FAILURES") is { Length: > 0 } path
            ? path
            : Path.Combine(AppContext.BaseDirectory, "verapdf-failures");

    /// <summary>Skips the calling test when veraPDF cannot run here; fails it instead when <c>SIMPLESIGN_REQUIRE_VERAPDF</c> is "true".</summary>
    public static void Require()
    {
        if (Unavailable.Value is not { } problem)
        {
            return;
        }

        if (string.Equals(Environment.GetEnvironmentVariable("SIMPLESIGN_REQUIRE_VERAPDF"), "true", StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException(problem);
        }

        Skip.If(true, problem);
    }

    /// <summary>Validates <paramref name="pdf"/> against PDF/A <paramref name="flavour"/> (<c>1b</c>, <c>2b</c>, <c>3b</c>…).</summary>
    public static async Task<VeraPdfReport> ValidateAsync(byte[] pdf, string flavour, CancellationToken cancellationToken = default)
    {
        string directory = Path.Combine(Path.GetTempPath(), $"simplesign-verapdf-{Guid.NewGuid():N}");
        Directory.CreateDirectory(directory);
        try
        {
            string input = Path.Combine(directory, "input.pdf");
            await File.WriteAllBytesAsync(input, pdf, cancellationToken);

            string[] verapdfArgs = ["--format", "mrr", "--flavour", flavour];
            var run = LocalExecutable is { } executable
                ? await ExternalProcess.RunAsync(executable, [.. verapdfArgs, input], cancellationToken: cancellationToken)
                // The image's entry point is the veraPDF CLI. It is built for amd64 only (emulated on arm64).
                : await ExternalProcess.RunAsync("docker", ["run", "--rm", "--platform", "linux/amd64", "-v", $"{directory}:/data", Image, .. verapdfArgs, "/data/input.pdf"], cancellationToken: cancellationToken);

            return Parse(run.Stdout) ?? throw new InvalidOperationException($"veraPDF wrote no report ({run.Output}).");
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    /// <summary>Writes a document veraPDF rejected, and its report, to <see cref="FailuresDirectory"/>.</summary>
    /// <returns>The path of the document.</returns>
    public static string SaveFailure(string name, byte[] pdf, VeraPdfReport report)
    {
        Directory.CreateDirectory(FailuresDirectory);
        string path = Path.Combine(FailuresDirectory, name + ".pdf");
        File.WriteAllBytes(path, pdf);
        File.WriteAllText(Path.Combine(FailuresDirectory, name + ".verapdf.xml"), report.Xml);
        return path;
    }

    /// <summary>Reads veraPDF's machine-readable report; null when <paramref name="output"/> holds none.</summary>
    public static VeraPdfReport? Parse(string output)
    {
        int start = output.IndexOf("<?xml", StringComparison.Ordinal);
        if (start < 0)
        {
            return null;
        }

        string xml = output[start..];
        var job = XDocument.Parse(xml).Descendants("job").FirstOrDefault();
        if (job is null)
        {
            return null;
        }

        if (job.Element("validationReport") is not { } validation)
        {
            string error = job.Element("taskException")?.Element("exceptionMessage")?.Value ?? "no validation report";
            return new VeraPdfReport(false, null, error, [], xml);
        }

        var failed = validation.Descendants("rule")
            .Where(rule => (string?)rule.Attribute("status") == "failed")
            .Select(rule => new VeraPdfFailedRule(
                (string?)rule.Attribute("specification") ?? "",
                (string?)rule.Attribute("clause") ?? "",
                (string?)rule.Attribute("testNumber") ?? "",
                rule.Element("description")?.Value.Trim() ?? "",
                (int?)rule.Attribute("failedChecks") ?? 0))
            .ToList();

        return new VeraPdfReport(
            (bool?)validation.Attribute("isCompliant") ?? false,
            (string?)validation.Attribute("profileName"),
            null,
            failed,
            xml);
    }

    private static string? FindProblem()
    {
        if (LocalExecutable is { } executable)
        {
            return File.Exists(executable) ? null : $"SIMPLESIGN_VERAPDF names {executable}, which does not exist.";
        }

        if (!ExternalProcess.Succeeds("docker", "info"))
        {
            return "veraPDF is not available: no Docker here. Start Docker, or set SIMPLESIGN_VERAPDF to a local veraPDF CLI.";
        }

        return ExternalProcess.Succeeds("docker", "image", "inspect", Image)
            ? null
            : $"veraPDF is not available: the image is not pulled. Run: docker pull {Image}";
    }
}
