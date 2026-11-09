using System.Globalization;
using System.Text.Json;

namespace SimpleSign.Core.Policies;

/// <summary>A key or domain parameter of a <see cref="CryptographicSuiteEvaluation"/> (<c>moduluslength</c>, <c>plength</c>, <c>qlength</c>).</summary>
/// <param name="Name">The parameter name.</param>
/// <param name="Min">The smallest value, or null.</param>
/// <param name="Max">The largest value, or null.</param>
public sealed record CryptographicSuiteParameter(string Name, int? Min, int? Max);

/// <summary>One evaluation of an algorithm of a <see cref="CryptographicSuite"/>: for these parameters, suitable until <see cref="End"/>.</summary>
/// <param name="Start">The start of the suitability, or null.</param>
/// <param name="End">The end of the suitability, or null for no end.</param>
/// <param name="Parameters">The parameters the evaluation is about.</param>
/// <param name="Recommendation"><c>R</c> (recommended) or <c>L</c> (legacy), or null.</param>
public sealed record CryptographicSuiteEvaluation(
    DateTimeOffset? Start,
    DateTimeOffset? End,
    IReadOnlyList<CryptographicSuiteParameter> Parameters,
    string? Recommendation);

/// <summary>An algorithm of a <see cref="CryptographicSuite"/>.</summary>
/// <param name="Name">The name (<c>SHA256</c>, <c>sha256WithRSAEncryption</c>…).</param>
/// <param name="ObjectIdentifier">The OID, which identifies the algorithm.</param>
/// <param name="Uri">The XML URI, or null.</param>
/// <param name="Evaluations">Its evaluations.</param>
public sealed record CryptographicSuiteAlgorithm(
    string Name,
    string? ObjectIdentifier,
    string? Uri,
    IReadOnlyList<CryptographicSuiteEvaluation> Evaluations);

/// <summary>
/// A cryptographic suite in the JSON format of ETSI TS 119 322 (Annex B, <c>SecuritySuitabilityPolicy</c>): the
/// algorithms and key sizes and until when each is suitable. Given to a <see cref="ValidationPolicy"/> or a
/// <see cref="SigningPolicy"/>, it replaces their <c>Cryptographic</c> constraints, globally or for one context: an
/// algorithm that expired on or before <see cref="PolicyIssueDate"/> fails, one that expires after it gives a warning.
/// </summary>
public sealed class CryptographicSuite
{
    private CryptographicSuite(string name, string? oid, DateTimeOffset? issueDate, IReadOnlyList<CryptographicSuiteAlgorithm> algorithms, string json)
    {
        Name = name;
        ObjectIdentifier = oid;
        PolicyIssueDate = issueDate;
        Algorithms = algorithms;
        Json = json;
    }

    /// <summary>The suite's name (<c>PolicyName.Name</c>).</summary>
    public string Name { get; }

    /// <summary>The suite's OID (<c>PolicyName.ObjectIdentifier</c>), or null.</summary>
    public string? ObjectIdentifier { get; }

    /// <summary>The date the suite was issued (<c>PolicyIssueDate</c>), or null.</summary>
    public DateTimeOffset? PolicyIssueDate { get; }

    /// <summary>The algorithms.</summary>
    public IReadOnlyList<CryptographicSuiteAlgorithm> Algorithms { get; }

    /// <summary>The JSON the suite was read from.</summary>
    public string Json { get; }

    /// <summary>Reads a suite from its JSON (ETSI TS 119 322 Annex B).</summary>
    /// <param name="json">The JSON document.</param>
    /// <returns>The suite.</returns>
    /// <exception cref="InvalidDataException">The JSON is not a suite.</exception>
    public static CryptographicSuite FromJson(string json)
    {
        ArgumentNullException.ThrowIfNull(json);
        try
        {
            using var document = JsonDocument.Parse(json);
            if (!document.RootElement.TryGetProperty("SecuritySuitabilityPolicy", out var policy) || policy.ValueKind != JsonValueKind.Object)
            {
                throw new FormatException("$: the 'SecuritySuitabilityPolicy' object is missing.");
            }

            string name = policy.TryGetProperty("PolicyName", out var policyName) && policyName.TryGetProperty(nameof(Name), out var n)
                ? n.GetString() ?? "" : throw new FormatException("$.SecuritySuitabilityPolicy.PolicyName.Name is missing.");
            string? oid = policyName.TryGetProperty(nameof(ObjectIdentifier), out var o) ? o.GetString() : null;
            DateTimeOffset? issued = policy.TryGetProperty(nameof(PolicyIssueDate), out var date) ? ParseDate(date.GetString()) : null;
            if (!policy.TryGetProperty("Algorithm", out var algorithms) || algorithms.ValueKind != JsonValueKind.Array)
            {
                throw new FormatException("$.SecuritySuitabilityPolicy.Algorithm: expected an array.");
            }

            var list = new List<CryptographicSuiteAlgorithm>();
            foreach (var algorithm in algorithms.EnumerateArray())
            {
                var identifier = algorithm.GetProperty("AlgorithmIdentifier");
                var evaluations = new List<CryptographicSuiteEvaluation>();
                if (algorithm.TryGetProperty("Evaluation", out var evaluationArray))
                {
                    foreach (var evaluation in evaluationArray.EnumerateArray())
                    {
                        var validity = evaluation.TryGetProperty("Validity", out var v) ? v : default;
                        var parameters = new List<CryptographicSuiteParameter>();
                        if (evaluation.TryGetProperty("Parameter", out var parameterArray))
                        {
                            foreach (var parameter in parameterArray.EnumerateArray())
                            {
                                parameters.Add(new CryptographicSuiteParameter(
                                    parameter.GetProperty("name").GetString() ?? "",
                                    parameter.TryGetProperty("Min", out var min) ? min.GetInt32() : null,
                                    parameter.TryGetProperty("Max", out var max) ? max.GetInt32() : null));
                            }
                        }

                        evaluations.Add(new CryptographicSuiteEvaluation(
                            validity.ValueKind == JsonValueKind.Object && validity.TryGetProperty("Start", out var start) ? ParseDate(start.GetString()) : null,
                            validity.ValueKind == JsonValueKind.Object && validity.TryGetProperty("End", out var end) ? ParseDate(end.GetString()) : null,
                            parameters,
                            evaluation.TryGetProperty("Recommendation", out var recommendation) ? recommendation.GetString() : null));
                    }
                }

                list.Add(new CryptographicSuiteAlgorithm(
                    identifier.GetProperty(nameof(Name)).GetString() ?? "",
                    identifier.TryGetProperty(nameof(ObjectIdentifier), out var algorithmOid) ? algorithmOid.GetString() : null,
                    identifier.TryGetProperty("URI", out var uri) ? uri.GetString() : null,
                    evaluations));
            }

            return new CryptographicSuite(name, oid, issued, list, json);
        }
        catch (Exception ex) when (ex is JsonException or FormatException or InvalidOperationException or KeyNotFoundException)
        {
            throw new InvalidDataException($"The cryptographic suite is not valid: {ex.Message}", ex);
        }
    }

    /// <summary>Reads a suite from a JSON file.</summary>
    /// <param name="path">The file path.</param>
    /// <returns>The suite.</returns>
    public static CryptographicSuite Load(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        return FromJson(File.ReadAllText(path));
    }

    private static DateTimeOffset? ParseDate(string? text) =>
        string.IsNullOrWhiteSpace(text) ? null
        : DateTimeOffset.Parse(text, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal);
}
