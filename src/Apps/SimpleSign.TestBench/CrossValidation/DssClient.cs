using System.Diagnostics;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using SimpleSign.TestBench.Documents;
using SimpleSign.TestBench.Localization;
using SimpleSign.TestBench.Runs;

namespace SimpleSign.TestBench.CrossValidation;

/// <summary>Where the DSS validation service is and whether runs are sent to it.</summary>
public sealed record DssSettings(bool Enabled, string Url);

/// <summary>
/// Whether the DSS service answers at the configured URL, and how it is set up (<paramref name="Config"/>: what
/// tools/dss/entrypoint.sh wrote to <c>/simplesign/config.json</c>; null for a DSS started some other way).
/// </summary>
public sealed record DssStatus(bool Enabled, string Url, bool Reachable, string? Error, long Ms, DssServerConfig? Config = null);

/// <summary>
/// How the DSS of tools/dss was set up when it started: how it trusts the Sandbox, which roots and trusted lists it
/// loaded, how it fetches revocation data. Read from its <c>/simplesign/config.json</c>.
/// </summary>
public sealed record DssServerConfig(
    string? DssVersion,
    string? StartedAt,
    DssSandboxTrust? Sandbox,
    string? EuTrustedLists,
    bool TlLoaderOnline,
    int TlRefreshSeconds,
    bool AcceptInvalidTrustedLists,
    bool RevocationCache,
    bool IcpBrasil,
    bool GovBr,
    bool TsaRoots,
    DssPeruTrust? Peru,
    IReadOnlyList<DssTrustedCertificate>? Trusted,
    DssForwarding? Forwarding = null);

/// <summary>The Sandbox ports the container forwards from its own localhost to <paramref name="Host"/> (the certificates name localhost).</summary>
public sealed record DssForwarding(string? Host, string? Ports);

/// <summary>
/// The validation policy DSS is given with every request: SimpleSign's, as the DSS <c>constraint.xml</c>, without the
/// constraints the DSS of tools/dss does not know (<paramref name="NotInDss"/>), which DSS then does not evaluate.
/// </summary>
public sealed record DssPolicyView(string Name, string ConstraintXml, IReadOnlyList<string> NotInDss);

/// <summary>How DSS trusts the Sandbox: <c>list</c> (its trusted list), <c>anchor</c> (its root), <c>testbench</c> (the root through the TestBench) or <c>none</c>.</summary>
public sealed record DssSandboxTrust(string? Url, string? TestBenchUrl, string? Requested, string? Trust, string? LotlUrl, bool Tls);

/// <summary>The CAs of the Peruvian trusted list DSS trusts.</summary>
public sealed record DssPeruTrust(bool Enabled, int Trusted, string? Origin, string? Sequence, string? NextUpdate, string? Url = null);

/// <summary>A certificate in DSS's trust store: its group (icp-brasil, govbr, tsa, peru, sandbox, mounted), its name and subject.</summary>
public sealed record DssTrustedCertificate(string Group, string Name, string Subject);

/// <summary>One signature (or timestamp) of the DSS simple report.</summary>
public sealed record DssSignature(
    string? Id,
    string Indication,
    string? SubIndication,
    string? Format,
    string? SignedBy,
    string? SigningTime,
    IReadOnlyList<string> Errors,
    IReadOnlyList<string> Warnings);

/// <summary>
/// One line of the comparison: what SimpleSign says, what DSS says, and whether they agree. For a difference,
/// <paramref name="Reason"/> says in plain words what DSS concluded, <paramref name="Cause"/> whether it comes from
/// how DSS is set up (<c>setup</c>), from a real disagreement between the validators (<c>disagreement</c>) or is
/// unknown, and <paramref name="Action"/> what to do. <paramref name="Note"/> keeps DSS's own messages.
/// </summary>
public sealed record DssComparisonRow(
    string Label,
    string Topic,
    string? Library,
    string? Dss,
    bool Agree,
    string? Note,
    string? Reason = null,
    string? Cause = null,
    string? Action = null);

/// <summary>The DSS verdict for a run, next to SimpleSign's.</summary>
public sealed record DssComparison(
    bool Available,
    string? Error,
    string Url,
    long Ms,
    bool Agree,
    IReadOnlyList<DssSignature> Signatures,
    IReadOnlyList<DssComparisonRow> Rows,
    IReadOnlyList<string> Notes,
    string? ReportId,
    string? Summary = null);

/// <summary>
/// Validates signatures with the EU DSS (https://github.com/esig/dss) through the REST service of
/// its demo web application (<c>services/rest/validation/validateSignature</c>), so every run can
/// be checked against an independent ETSI EN 319 102-1 implementation. Off by default; start the
/// service with <c>tools/dss/docker-compose.yml</c> or point <see cref="DssSettings.Url"/> at one.
/// </summary>
internal sealed class DssClient(DocumentStore documents) : IDisposable
{
    public const string DefaultUrl = "http://localhost:8080";
    private const string ValidatePath = "services/rest/validation/validateSignature";
    private const string ConfigPath = "simplesign/config.json";
    private static readonly JsonSerializerOptions s_config = new(JsonSerializerDefaults.Web);

    private readonly HttpClient _http = new() { Timeout = TimeSpan.FromSeconds(120) };

    public DssSettings Settings { get; set; } = new(
        Enabled: false,
        Url: Environment.GetEnvironmentVariable("SIMPLESIGN_DSS_URL") is { Length: > 0 } url ? url : DefaultUrl);

    public void Dispose() => _http.Dispose();

    /// <summary>Checks that something answers at the configured URL.</summary>
    public async Task<DssStatus> StatusAsync(CancellationToken cancellationToken)
    {
        var settings = Settings;
        var watch = Stopwatch.StartNew();
        try
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(TimeSpan.FromSeconds(4));
            using var response = await _http.GetAsync(BaseUri(settings), HttpCompletionOption.ResponseHeadersRead, timeout.Token);
            long ms = watch.ElapsedMilliseconds;
            return new DssStatus(settings.Enabled, settings.Url, true, null, ms, await ConfigAsync(settings, timeout.Token));
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or UriFormatException or InvalidOperationException)
        {
            return new DssStatus(settings.Enabled, settings.Url, false, Unreachable(settings, ex), watch.ElapsedMilliseconds);
        }
    }

    /// <summary>What DSS is given as its policy for <paramref name="policy"/> (null: SimpleSign's default), exactly as a request sends it.</summary>
    internal static DssPolicyView Policy(SimpleSign.Core.Policies.ValidationPolicy? policy = null)
    {
        policy ??= SimpleSign.Core.Policies.ValidationPolicy.Default;
        return new DssPolicyView(policy.Name ?? "SimpleSign", DssPolicyConverter.ToConstraintXml(policy.ToJson(), DssPolicyConverter.NotInDss63),
            [.. DssPolicyConverter.NotInDss63.Order(StringComparer.Ordinal)]);
    }

    /// <summary>The setup tools/dss wrote when DSS started; null when the server has none (a DSS started another way) or it cannot be read.</summary>
    private async Task<DssServerConfig?> ConfigAsync(DssSettings settings, CancellationToken cancellationToken)
    {
        try
        {
            using var response = await _http.GetAsync(new Uri(BaseUri(settings), ConfigPath), cancellationToken);
            return response.IsSuccessStatusCode
                ? ReadConfig(await response.Content.ReadAsStringAsync(cancellationToken))
                : null;
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException)
        {
            return null;
        }
    }

    /// <summary>Reads <c>/simplesign/config.json</c>; null when it is not that file.</summary>
    internal static DssServerConfig? ReadConfig(string json)
    {
        try
        {
            return JsonSerializer.Deserialize<DssServerConfig>(json, s_config);
        }
        catch (JsonException)
        {
            return null;
        }
    }

    /// <summary>Sends a run's output to DSS and lines its verdict up with SimpleSign's.</summary>
    public async Task<DssComparison> CompareAsync(string format, RunView run, string? detachedDataId, string? detachedDataName, RunLogger logger, CancellationToken cancellationToken,
        SimpleSign.Core.Policies.ValidationPolicy? policy = null)
    {
        var report = await ValidateAsync(run.OutputId!, detachedDataId, logger, cancellationToken, detachedDataName, policy);
        return report.Available ? Compare(format, run, report) : report;
    }

    /// <summary>
    /// Validates a stored file with DSS (the original document goes along for detached signatures), under
    /// <paramref name="policy"/> written as the DSS constraint.xml (null: SimpleSign's default policy).
    /// </summary>
    public async Task<DssComparison> ValidateAsync(string fileId, string? detachedDataId, RunLogger? logger, CancellationToken cancellationToken, string? detachedDataName = null,
        SimpleSign.Core.Policies.ValidationPolicy? policy = null)
    {
        var sent = Policy(policy);
        var settings = Settings;
        var watch = Stopwatch.StartNew();
        var file = documents.Get(fileId);
        var body = new JsonObject
        {
            ["signedDocument"] = Document(file),
            ["originalDocuments"] = detachedDataId is not null && documents.TryGet(detachedDataId, out var original)
                ? new JsonArray(Document(original!, detachedDataName))
                : null,
            // The same policy on both sides: SimpleSign's, written as the DSS constraint.xml.
            ["policy"] = new JsonObject
            {
                ["bytes"] = Convert.ToBase64String(Encoding.UTF8.GetBytes(sent.ConstraintXml)),
                ["digestAlgorithm"] = null,
                ["name"] = "simplesign-policy.xml",
            },
            ["tokenExtractionStrategy"] = "NONE",
            ["signatureId"] = null,
        };

        try
        {
            var endpoint = new Uri(BaseUri(settings), ValidatePath);
            logger?.Note(RunStages.CrossValidation, $"DSS: POST {endpoint} ({file.FileName}, {file.Content.Length} bytes, policy \"{sent.Name}\")");
            using var content = new StringContent(body.ToJsonString(), Encoding.UTF8, "application/json");
            using var response = await _http.PostAsync(endpoint, content, cancellationToken);
            string text = await response.Content.ReadAsStringAsync(cancellationToken);
            if (!response.IsSuccessStatusCode)
            {
                string error = L.T("DSS answered HTTP {0}: {1}", (int)response.StatusCode, text.Length > 300 ? text[..300] : text);
                logger?.Note(RunStages.CrossValidation, error, warning: true);
                return Unavailable(settings, error, watch.ElapsedMilliseconds);
            }

            using var json = JsonDocument.Parse(text);
            var signatures = ReadSimpleReport(json.RootElement);
            string reportId = documents.Add(Path.GetFileNameWithoutExtension(file.FileName) + ".dss-report.json", Encoding.UTF8.GetBytes(text)).Id;
            logger?.Note(RunStages.CrossValidation,
                $"DSS: {signatures.Count} signature(s): {string.Join(", ", signatures.Select(s => s.SubIndication is null ? s.Indication : $"{s.Indication}/{s.SubIndication}"))}");
            return new DssComparison(true, null, settings.Url, watch.ElapsedMilliseconds, true, signatures, [], [], reportId);
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or JsonException or UriFormatException or InvalidOperationException)
        {
            string error = ex is JsonException
                ? L.T("DSS did not answer with JSON: {0}", ex.Message)
                : Unreachable(settings, ex);
            logger?.Note(RunStages.CrossValidation, error, warning: true);
            return Unavailable(settings, error, watch.ElapsedMilliseconds);
        }
    }

    /// <summary>
    /// Reads the signatures of the DSS simple report. The reader is tolerant on purpose: it finds the
    /// simple report whatever its property casing and takes every object that carries an Indication
    /// and a signature format or signer, so it keeps working across DSS versions.
    /// </summary>
    internal static IReadOnlyList<DssSignature> ReadSimpleReport(JsonElement root)
    {
        var simple = Find(root, "SimpleReport") ?? root;
        var found = new List<DssSignature>();
        Collect(simple, found);
        return found;
    }

    /// <summary>Lines the DSS signatures up with the run's verdicts, in order.</summary>
    internal static DssComparison Compare(string format, RunView run, DssComparison dss)
    {
        var rows = new List<DssComparisonRow>();
        var notes = new List<string>();
        // DSS reports document timestamps apart from signatures, so only signatures are lined up.
        var library = Flatten(run.Validation).Where(v => !v.IsTimestamp).ToList();
        var dssSignatures = dss.Signatures.Where(s => s.Format is not null || s.SignedBy is not null).ToList();
        int count = Math.Max(library.Count, dssSignatures.Count);
        for (int i = 0; i < count; i++)
        {
            var ours = i < library.Count ? library[i] : null;
            var theirs = i < dssSignatures.Count ? dssSignatures[i] : null;
            string label = ours?.Label ?? theirs?.Id ?? L.T("Signature {0}", i + 1);
            string? oursIndication = ours?.Indication;
            string? theirsIndication = theirs is null ? null : theirs.SubIndication is null ? theirs.Indication : $"{theirs.Indication} / {theirs.SubIndication}";
            bool indicationAgrees = ours is not null && theirs is not null && SameIndication(ours.Indication, theirs.Indication);
            var (reason, cause, action) = indicationAgrees ? (null, null, null) : Classify(theirs);
            rows.Add(new DssComparisonRow(label, "indication", oursIndication, theirsIndication, indicationAgrees,
                indicationAgrees ? null : Explain(theirs), reason, cause, action));
            if (theirs?.Format is not null)
            {
                // The run's achieved level is the level of the signature it just made: the last one.
                string? oursLevel = i == library.Count - 1 ? run.AchievedLevel : ours?.Level;
                bool levelAgrees = oursLevel is null || SameLevel(oursLevel, theirs.Format);
                rows.Add(new DssComparisonRow(label, "level", oursLevel, theirs.Format, levelAgrees, null,
                    levelAgrees ? null : L.T("DSS detects a different level than the one SimpleSign reports for this signature."),
                    levelAgrees ? null : Causes.Disagreement,
                    levelAgrees ? null : L.T("Check which attributes each validator found (timestamps, DSS dictionary, archive timestamp): one of them reads the file differently.")));
            }
        }

        _ = format;
        return dss with { Rows = rows, Notes = notes, Agree = rows.All(r => r.Agree), Summary = Summarize(rows) };
    }

    /// <summary>The causes of a difference.</summary>
    internal static class Causes
    {
        public const string Setup = "setup";
        public const string Disagreement = "disagreement";
        public const string Unknown = "unknown";
    }

    /// <summary>
    /// Why DSS's indication differs: what it concluded in plain words, whether that comes from how DSS is set up
    /// (it does not trust the Sandbox root, it cannot reach the Sandbox's CRL and OCSP) or is a real disagreement,
    /// and what to do.
    /// </summary>
    internal static (string? Reason, string Cause, string Action) Classify(DssSignature? theirs)
    {
        if (theirs is null)
        {
            return (L.T("DSS did not report this signature."), Causes.Unknown,
                L.T("Open the DSS report (JSON): DSS may have read the file as something else."));
        }

        string? reason = SubIndications.Explain(theirs.SubIndication) ?? theirs.Errors.FirstOrDefault();
        if (string.Equals(theirs.SubIndication, "NO_CERTIFICATE_CHAIN_FOUND", StringComparison.OrdinalIgnoreCase))
        {
            return (L.T("DSS does not trust the root of the signer's chain, so it cannot reach a conclusion."), Causes.Setup,
                L.T("This is how DSS is set up, not a problem of the signature: give DSS the Sandbox root (see tools/dss/README.md)."));
        }

        bool revocation = theirs.SubIndication is { } sub
                && (sub.Contains("REVOCATION", StringComparison.OrdinalIgnoreCase) || sub.Contains("TRY_LATER", StringComparison.OrdinalIgnoreCase))
            || theirs.Errors.Any(e => e.Contains("revocation", StringComparison.OrdinalIgnoreCase));
        if (theirs.Indication == "INDETERMINATE" && revocation)
        {
            return (L.T("DSS could not get revocation data for the chain."), Causes.Setup,
                L.T("The Sandbox's CRL and OCSP addresses are on this machine and DSS may not reach them: sign at B-LT or B-LTA so the data is embedded."));
        }

        return (reason, Causes.Disagreement,
            L.T("The validators disagree on this file: compare SimpleSign's checks with DSS's messages; one of them may be wrong."));
    }

    /// <summary>One sentence: whether they agree, and on what they differ.</summary>
    internal static string Summarize(IReadOnlyList<DssComparisonRow> rows)
    {
        if (rows.Count == 0)
        {
            return L.T("DSS reported no signature to compare.");
        }

        var differences = rows.Where(r => !r.Agree).ToList();
        if (differences.Count == 0)
        {
            return L.T("SimpleSign and DSS agree on every signature.");
        }

        string topics = string.Join(", ", differences.Select(r => r.Topic == "level"
            ? L.T("the level of {0}", r.Label)
            : L.T("the verdict on {0}", r.Label)).Distinct());
        bool allSetup = differences.All(r => r.Cause == Causes.Setup);
        return allSetup
            ? L.T("They differ on {0}, because of how DSS is set up, not because of the signature.", topics)
            : L.T("They differ on {0}.", topics);
    }

    private static IEnumerable<RunVerdict> Flatten(IEnumerable<RunVerdict> verdicts) =>
        verdicts.SelectMany(v => new[] { v }.Concat(Flatten(v.Children)));

    private static string? Explain(DssSignature? theirs) =>
        theirs is null ? L.T("DSS did not report this signature.")
            : theirs.Errors.Count > 0 ? string.Join(" ", theirs.Errors)
            : theirs.Warnings.Count > 0 ? string.Join(" ", theirs.Warnings)
            : null;

    /// <summary>Valid ↔ TOTAL_PASSED/PASSED, Invalid ↔ TOTAL_FAILED/FAILED, Indeterminate ↔ INDETERMINATE (EN 319 102-1 §5.1.3).</summary>
    internal static bool SameIndication(string library, string dss) => library switch
    {
        "Valid" => dss is "TOTAL_PASSED" or "PASSED",
        "Invalid" => dss is "TOTAL_FAILED" or "FAILED",
        _ => dss is "INDETERMINATE",
    };

    /// <summary>Compares "B-LT", "PAdES-B-LT" or "AD-RT" with DSS's "PAdES-BASELINE-LT" by the baseline suffix.</summary>
    internal static bool SameLevel(string library, string dss)
    {
        string? ours = Baseline(library);
        string? theirs = Baseline(dss);
        return ours is null || theirs is null || ours == theirs;
    }

    private static string? Baseline(string level)
    {
        string last = level.Split('-', ' ', '_')[^1].ToUpperInvariant();
        return last is "B" or "T" or "LT" or "LTA" ? last : null;
    }

    private static void Collect(JsonElement element, List<DssSignature> found)
    {
        if (element.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in element.EnumerateArray())
            {
                Collect(item, found);
            }

            return;
        }

        if (element.ValueKind != JsonValueKind.Object)
        {
            return;
        }

        if (Text(element, "Indication") is { } indication)
        {
            found.Add(new DssSignature(
                Text(element, "Id"),
                indication,
                Text(element, "SubIndication"),
                Text(element, "SignatureFormat"),
                Text(element, "SignedBy") ?? Text(element, "ProducedBy"),
                Text(element, "SigningTime") ?? Text(element, "ProductionTime"),
                Messages(element, "Error"),
                Messages(element, "Warning")));
            return;
        }

        foreach (var property in element.EnumerateObject())
        {
            Collect(property.Value, found);
        }
    }

    private static JsonElement? Find(JsonElement element, string name)
    {
        if (element.ValueKind == JsonValueKind.Object)
        {
            foreach (var property in element.EnumerateObject())
            {
                if (string.Equals(property.Name, name, StringComparison.OrdinalIgnoreCase))
                {
                    return property.Value;
                }
            }

            foreach (var property in element.EnumerateObject())
            {
                if (Find(property.Value, name) is { } nested)
                {
                    return nested;
                }
            }
        }

        return null;
    }

    private static string? Text(JsonElement element, string name)
    {
        foreach (var property in element.EnumerateObject())
        {
            if (string.Equals(property.Name, name, StringComparison.OrdinalIgnoreCase))
            {
                return property.Value.ValueKind switch
                {
                    JsonValueKind.String => property.Value.GetString(),
                    JsonValueKind.Null or JsonValueKind.Undefined => null,
                    JsonValueKind.Object => Text(property.Value, "value"),
                    _ => property.Value.ToString(),
                };
            }
        }

        return null;
    }

    /// <summary>Every message under properties called <paramref name="name"/> (Error or Warning), at any depth.</summary>
    private static List<string> Messages(JsonElement element, string name)
    {
        var messages = new List<string>();
        Walk(element);
        return [.. messages.Distinct()];

        void Walk(JsonElement current)
        {
            if (current.ValueKind == JsonValueKind.Array)
            {
                foreach (var item in current.EnumerateArray())
                {
                    Walk(item);
                }
            }
            else if (current.ValueKind == JsonValueKind.Object)
            {
                foreach (var property in current.EnumerateObject())
                {
                    if (string.Equals(property.Name, name, StringComparison.OrdinalIgnoreCase))
                    {
                        Add(property.Value);
                    }
                    else
                    {
                        Walk(property.Value);
                    }
                }
            }
        }

        void Add(JsonElement value)
        {
            if (value.ValueKind == JsonValueKind.Array)
            {
                foreach (var item in value.EnumerateArray())
                {
                    Add(item);
                }
            }
            else if (value.ValueKind == JsonValueKind.String)
            {
                messages.Add(value.GetString()!);
            }
            else if (value.ValueKind == JsonValueKind.Object && Text(value, "value") is { } text)
            {
                messages.Add(text);
            }
        }
    }

    private static JsonObject Document(StoredFile file, string? name = null) => new()
    {
        ["bytes"] = Convert.ToBase64String(file.Content),
        ["digestAlgorithm"] = null,
        ["name"] = string.IsNullOrWhiteSpace(name) ? file.FileName : name,
    };

    private static Uri BaseUri(DssSettings settings) =>
        new(settings.Url.EndsWith('/') ? settings.Url : settings.Url + "/", UriKind.Absolute);

    private static string Unreachable(DssSettings settings, Exception ex) =>
        L.T("DSS is not reachable at {0} ({1}). Start it with: docker compose -f tools/dss/docker-compose.yml up", settings.Url, ex.Message);

    private static DssComparison Unavailable(DssSettings settings, string error, long ms) =>
        new(false, error, settings.Url, ms, false, [], [], [], null);
}
