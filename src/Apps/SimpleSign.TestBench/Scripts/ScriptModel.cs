using System.Text.Json;

namespace SimpleSign.TestBench.Scripts;

/// <summary>
/// A certification script: the requirements of an accreditation guide and the steps that show each one, written
/// beforehand (by hand or by an LLM from the guide) and run by the TestBench against the Sandbox. Schema:
/// <c>docs/schemas/certification-script.schema.json</c>.
/// </summary>
public sealed record CertificationScript
{
    /// <summary>The schema version: 1.</summary>
    public int Schema { get; init; } = 1;

    /// <summary>A short id (<c>indecopi-guia-v4</c>).</summary>
    public string Id { get; init; } = "";

    /// <summary>The title shown and written in the evidence.</summary>
    public string Title { get; init; } = "";

    /// <summary>The authority that accredits (INDECOPI, ITI…).</summary>
    public string? Authority { get; init; }

    /// <summary>The document the requirements come from, with its version.</summary>
    public string? Standard { get; init; }

    /// <summary>What the script covers.</summary>
    public string? Description { get; init; }

    /// <summary>The language of the texts and of the evidence: <c>en</c>, <c>pt</c> or <c>es</c>.</summary>
    public string Language { get; init; } = "en";

    /// <summary>What every step starts from.</summary>
    public ScriptDefaults Defaults { get; init; } = new();

    /// <summary>The requirements, in the guide's order.</summary>
    public IReadOnlyList<ScriptRequirement> Requirements { get; init; } = [];

    /// <summary>The steps, grouped in sections.</summary>
    public IReadOnlyList<ScriptSection> Sections { get; init; } = [];

    /// <summary>The steps in order, with their section.</summary>
    public IEnumerable<(ScriptSection Section, ScriptStep Step)> AllSteps() =>
        Sections.SelectMany(s => s.Steps.Select(step => (s, step)));
}

/// <summary>The values every step starts from.</summary>
public sealed record ScriptDefaults
{
    /// <summary>The engine: <c>library</c>, <c>cli</c> or <c>both</c>.</summary>
    public string Engine { get; init; } = ScriptEngines.Library;

    /// <summary>Whether each signature is also validated by EU DSS.</summary>
    public bool CrossValidate { get; init; }

    /// <summary>The format of steps that name none: <c>pades</c>, <c>cades</c> or <c>xades</c>.</summary>
    public string Format { get; init; } = "pades";

    /// <summary>
    /// Options merged under each step's options: <c>common</c> for every format, then <c>pades</c>, <c>cades</c> or
    /// <c>xades</c> for that format. Same shape as a step's options.
    /// </summary>
    public JsonElement? Options { get; init; }
}

/// <summary>A requirement of the guide.</summary>
public sealed record ScriptRequirement
{
    /// <summary>A unique id, as the guide numbers it (<c>F-5</c>, <c>Req-11</c>).</summary>
    public string Id { get; init; } = "";

    /// <summary>The group it belongs to (<c>Req. 11 — Revocation</c>).</summary>
    public string? Group { get; init; }

    /// <summary>What the guide asks, in its words.</summary>
    public string Text { get; init; } = "";

    /// <summary>Where it is in the guide (section, page).</summary>
    public string? Reference { get; init; }

    /// <summary>Whether it applies to the software; false needs a <see cref="Justification"/>.</summary>
    public bool Applies { get; init; } = true;

    /// <summary>Why it does not apply.</summary>
    public string? Justification { get; init; }
}

/// <summary>A group of steps.</summary>
public sealed record ScriptSection
{
    public string Id { get; init; } = "";

    public string Title { get; init; } = "";

    public string? Description { get; init; }

    public IReadOnlyList<ScriptStep> Steps { get; init; } = [];
}

/// <summary>One thing to run (or to do by hand) and what it must show.</summary>
public sealed record ScriptStep
{
    /// <summary>A unique id; <c>step:ID</c> in a later step's options names the file this one signed.</summary>
    public string Id { get; init; } = "";

    public string Title { get; init; } = "";

    public string? Description { get; init; }

    /// <summary><c>sign</c>, <c>validate</c> or <c>manual</c>.</summary>
    public string Kind { get; init; } = ScriptStepKinds.Sign;

    /// <summary>The requirements the step shows.</summary>
    public IReadOnlyList<string> Requirements { get; init; } = [];

    /// <summary>The format; the default's when null. Not used by a validation (the file says what it is).</summary>
    public string? Format { get; init; }

    /// <summary>The engine; the default's when null.</summary>
    public string? Engine { get; init; }

    /// <summary>Whether DSS also validates; the default's when null.</summary>
    public bool? CrossValidate { get; init; }

    /// <summary>The Sandbox state for the step, put back after it.</summary>
    public ScriptSandbox? Sandbox { get; init; }

    /// <summary>
    /// The TestBench options of the run (the Sign page's for a signature, <c>fileId</c>/<c>dataId</c>/<c>settings</c> for a
    /// validation), with symbolic values: <c>sandbox:SIGNER</c>, <c>sample:ID</c>, <c>preset:KIND:NAME</c>, <c>step:ID</c>.
    /// </summary>
    public JsonElement? Options { get; init; }

    /// <summary>What the run must show.</summary>
    public ScriptExpectation? Expect { get; init; }

    /// <summary>For a manual step: what to do and what to keep.</summary>
    public ScriptManual? Manual { get; init; }
}

/// <summary>The Sandbox failures and revocations a step needs.</summary>
public sealed record ScriptSandbox
{
    /// <summary>CRL failure: None, Down, Slow, Expired, WrongKey, Stale…</summary>
    public string? Crl { get; init; }

    /// <summary>OCSP failure: None, Down, Slow, TryLater, Expired, Unauthorized, Unknown.</summary>
    public string? Ocsp { get; init; }

    /// <summary>TSA failure: None, Down, Slow, InvalidToken, Untrusted.</summary>
    public string? Tsa { get; init; }

    /// <summary>Trusted list failure: None, Expired, WrongSigner, Tampered.</summary>
    public string? TrustedList { get; init; }

    /// <summary>Sandbox certificates to revoke for the step.</summary>
    public IReadOnlyList<string> Revoke { get; init; } = [];

    /// <summary>Whether anything is asked.</summary>
    public bool Any => Crl is not null || Ocsp is not null || Tsa is not null || TrustedList is not null || Revoke.Count > 0;
}

/// <summary>What a run must show; every field given is checked.</summary>
public sealed record ScriptExpectation
{
    /// <summary><c>signed</c>, <c>refused</c> (SigningException), <c>error</c>, <c>valid</c>, <c>invalid</c> or <c>indeterminate</c>.</summary>
    public string? Outcome { get; init; }

    /// <summary>The <c>SigningErrorReason</c> of a refusal (<c>CertificateRevoked</c>).</summary>
    public string? Reason { get; init; }

    /// <summary>The ETSI indication of the (first) signature: TOTAL_PASSED, TOTAL_FAILED or INDETERMINATE.</summary>
    public string? Indication { get; init; }

    /// <summary>The ETSI sub-indication (HASH_FAILURE, REVOKED_NO_POE…).</summary>
    public string? SubIndication { get; init; }

    /// <summary>The level achieved (B-B, B-T, B-LT, B-LTA).</summary>
    public string? Level { get; init; }

    /// <summary>Whether DSS must agree (cross-validation on).</summary>
    public bool? DssAgrees { get; init; }

    /// <summary>Texts the run's log must contain.</summary>
    public IReadOnlyList<string> LogContains { get; init; } = [];
}

/// <summary>A step done by hand.</summary>
public sealed record ScriptManual
{
    /// <summary>What to do and what to show the auditor.</summary>
    public string Instructions { get; init; } = "";

    /// <summary>Whether a file (screenshot, document) must be attached.</summary>
    public bool Attachment { get; init; }
}

/// <summary>The engines of a step.</summary>
public static class ScriptEngines
{
    public const string Library = "library";
    public const string Cli = "cli";
    public const string Both = "both";

    public static IReadOnlyList<string> All { get; } = [Library, Cli, Both];
}

/// <summary>The kinds of step.</summary>
public static class ScriptStepKinds
{
    public const string Sign = "sign";
    public const string Validate = "validate";
    public const string Manual = "manual";

    public static IReadOnlyList<string> All { get; } = [Sign, Validate, Manual];
}

/// <summary>The outcomes an expectation can name.</summary>
public static class ScriptOutcomes
{
    public static IReadOnlyList<string> All { get; } = ["signed", "refused", "error", "valid", "invalid", "indeterminate"];
}
