using System.Text.Json;
using System.Text.Json.Serialization;

namespace SimpleSign.Playbook.Model;

/// <summary>
/// A playbook: what to run with the SimpleSign CLI, in order, and what each step must give. It is a
/// JSON file (<c>playbook.json</c>) in a workspace folder, next to its assets.
/// </summary>
public sealed record PlaybookDefinition
{
    /// <summary>The current version of the format.</summary>
    public const int CurrentSchema = 1;

    /// <summary>The version of the format; must be <see cref="CurrentSchema"/>.</summary>
    public int Schema { get; set; } = CurrentSchema;

    public string Name { get; set; } = "";

    public string? Description { get; set; }

    /// <summary>The SimpleSign Sandbox the steps use, if any.</summary>
    public SandboxSettings? Sandbox { get; set; }

    /// <summary>Values the steps use as <c>${var.NAME}</c>; they may use other variables.</summary>
    public Dictionary<string, string> Variables { get; set; } = [];

    /// <summary>Files of the workspace the steps use as <c>${asset.ID}</c>.</summary>
    public List<AssetDefinition> Assets { get; set; } = [];

    public List<SectionDefinition> Sections { get; set; } = [];
}

/// <summary>The Sandbox of a playbook.</summary>
public sealed record SandboxSettings
{
    /// <summary>Its address, such as http://localhost:5300/.</summary>
    public string Url { get; set; } = "http://localhost:5300/";

    /// <summary>Put revocations and failures back before the run (POST /api/reset).</summary>
    public bool ResetBeforeRun { get; set; } = true;
}

/// <summary>A file of the workspace (a document, a certificate…).</summary>
public sealed record AssetDefinition
{
    /// <summary>The name the steps use: <c>${asset.ID}</c> is the file's full path.</summary>
    public string Id { get; set; } = "";

    /// <summary>The path in the workspace, such as assets/contract.pdf.</summary>
    public string File { get; set; } = "";

    /// <summary>The key of its password in the workspace's secrets.json: <c>${asset.ID.password}</c>.</summary>
    public string? Secret { get; set; }

    public string? Description { get; set; }
}

/// <summary>A group of steps.</summary>
public sealed record SectionDefinition
{
    public string Id { get; set; } = "";

    public string Title { get; set; } = "";

    public string? Description { get; set; }

    public List<StepDefinition> Steps { get; set; } = [];
}

/// <summary>
/// One step: Sandbox actions before (setup), a CLI command (run) and what it must give (expect),
/// Sandbox actions after (teardown). A manual step has no command: the operator records the result.
/// </summary>
public sealed record StepDefinition
{
    public string Id { get; set; } = "";

    public string Title { get; set; } = "";

    /// <summary>What the step does and what should happen.</summary>
    public string? Description { get; set; }

    /// <summary>The operator does the step and records the result, a note and attachments.</summary>
    public bool Manual { get; set; }

    public List<SandboxAction> Setup { get; set; } = [];

    public RunDefinition? Run { get; set; }

    public Expectation? Expect { get; set; }

    public List<SandboxAction> Teardown { get; set; } = [];
}

/// <summary>A change to the Sandbox. <see cref="Sandbox"/> says which one; the other fields are its arguments.</summary>
public sealed record SandboxAction
{
    /// <summary>faults, revoke, unrevoke, reset, certificate or shortLived.</summary>
    public string Sandbox { get; set; } = "";

    /// <summary>revoke, unrevoke: the certificate's id in the Sandbox.</summary>
    public string? Certificate { get; set; }

    /// <summary>revoke: the reason (KeyCompromise by default).</summary>
    public string? Reason { get; set; }

    /// <summary>revoke: Both, CrlOnly or OcspOnly.</summary>
    public string? Publication { get; set; }

    /// <summary>certificate: the certificate's id in the Sandbox.</summary>
    public string? Id { get; set; }

    /// <summary>certificate, shortLived: the variable that gets <c>.path</c> and <c>.password</c> (default "cert").</summary>
    public string? As { get; set; }

    /// <summary>shortLived: the lifetime in seconds.</summary>
    public int? Seconds { get; set; }

    /// <summary>faults: the CRL failure (None, Down, Slow, Expired, WrongKey, Stale).</summary>
    public string? Crl { get; set; }

    /// <summary>faults: the OCSP failure (None, Down, Slow, TryLater, Expired, Unauthorized, Unknown).</summary>
    public string? Ocsp { get; set; }

    /// <summary>faults: the TSA failure (None, Down, Slow, InvalidToken).</summary>
    public string? Tsa { get; set; }

    /// <summary>faults: the OCSP signer (Issuer, Delegated).</summary>
    public string? OcspSigner { get; set; }
}

/// <summary>The CLI command of a step.</summary>
public sealed record RunDefinition
{
    /// <summary>The arguments after the program (<c>sign</c>, the file, the options…), with variables.</summary>
    public List<string> Args { get; set; } = [];

    /// <summary>The longest the command may take. Default 120.</summary>
    public int TimeoutSeconds { get; set; } = 120;

    /// <summary>
    /// "sandbox" (default when the playbook has a Sandbox): adds --allow-origin for the Sandbox's
    /// origins, --allow-ldap and --tls-trust with its chain. "none": the arguments as written.
    /// </summary>
    public string? Network { get; set; }
}

/// <summary>What a step must give. Every check that is set must pass.</summary>
public sealed record Expectation
{
    public int? ExitCode { get; set; }

    /// <summary>Dotted paths in the JSON printed on stdout (such as error.reason) and the value each must have.</summary>
    public Dictionary<string, JsonElement> Json { get; set; } = [];

    public List<string> StdoutContains { get; set; } = [];

    public List<string> StderrContains { get; set; } = [];

    /// <summary>Regular expressions stdout must match.</summary>
    public List<string> StdoutMatches { get; set; } = [];

    /// <summary>Files that must exist after the command (with variables, such as ${out}/signed.pdf).</summary>
    public List<string> Files { get; set; } = [];

    /// <summary>Requests the Sandbox must (or must not) have answered during the step.</summary>
    public List<SandboxRequestExpectation> SandboxRequests { get; set; } = [];
}

/// <summary>A request to the Sandbox during the step: by service (CRL, OCSP, TSA, AIA, CSC) and part of the path.</summary>
public sealed record SandboxRequestExpectation
{
    public string? Service { get; set; }

    public string? PathContains { get; set; }

    /// <summary>The fewest such requests (default 1). Zero with <see cref="Max"/> 0 asserts there was none.</summary>
    public int Min { get; set; } = 1;

    public int? Max { get; set; }
}

/// <summary>Reads and writes playbooks (camelCase, source-generated: AOT-safe).</summary>
[JsonSourceGenerationOptions(
    WriteIndented = true,
    PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase,
    DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    ReadCommentHandling = JsonCommentHandling.Skip,
    AllowTrailingCommas = true)]
[JsonSerializable(typeof(PlaybookDefinition))]
[JsonSerializable(typeof(Dictionary<string, string>))]
internal sealed partial class PlaybookJson : JsonSerializerContext;
