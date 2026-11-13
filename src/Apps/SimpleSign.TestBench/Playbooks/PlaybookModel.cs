using System.Text.Json;

namespace SimpleSign.TestBench.Playbooks;

/// <summary>
/// A playbook: sections of steps the TestBench runs against the Sandbox (signatures that must be made or refused,
/// files that must validate or not), through the library, the CLI or both. Written beforehand (by hand or by an LLM)
/// to help with the systemic part of a certification. Schema: <c>docs/schemas/playbook.schema.json</c>.
/// </summary>
public sealed record Playbook
{
    /// <summary>The schema version: 2.</summary>
    public int Schema { get; init; } = 2;

    /// <summary>A short id (<c>indecopi-guia-v4</c>).</summary>
    public string Id { get; init; } = "";

    /// <summary>The title shown and written in the evidence.</summary>
    public string Title { get; init; } = "";

    /// <summary>What the playbook covers.</summary>
    public string? Description { get; init; }

    /// <summary>What every step starts from.</summary>
    public PlaybookDefaults Defaults { get; init; } = new();

    /// <summary>
    /// Policies the playbook adjusts: a built-in one (or the default) with some constraints changed, referenced by its steps
    /// as <c>playbook:ID</c> (for example IOFE's signing policy that also requires nonRepudiation).
    /// </summary>
    public IReadOnlyList<PlaybookPolicy> Policies { get; init; } = [];

    /// <summary>
    /// Files the person running the playbook uploads (a PDF signed elsewhere, a document to sign), referenced by the steps
    /// as <c>input:ID</c>. A step whose input has no file yet is skipped.
    /// </summary>
    public IReadOnlyList<PlaybookInput> Inputs { get; init; } = [];

    /// <summary>The steps, grouped in sections.</summary>
    public IReadOnlyList<PlaybookSection> Sections { get; init; } = [];

    /// <summary>The steps in order, with their section.</summary>
    public IEnumerable<(PlaybookSection Section, PlaybookStep Step)> AllSteps() =>
        Sections.SelectMany(s => s.Steps.Select(step => (s, step)));

    /// <summary>A step by id, or null.</summary>
    public PlaybookStep? Step(string id) => AllSteps().Select(s => s.Step).FirstOrDefault(s => s.Id == id);
}

/// <summary>A policy the playbook adjusts, referenced as <c>playbook:ID</c> by <c>signingPolicyId</c> or <c>validation.policyId</c>.</summary>
public sealed record PlaybookPolicy
{
    /// <summary>The id, unique in the playbook.</summary>
    public string Id { get; init; } = "";

    /// <summary><c>signing</c> or <c>validation</c>.</summary>
    public string Kind { get; init; } = "";

    /// <summary>The policy it starts from: a built-in name (<c>iofe</c>, <c>strict</c>…) or <c>default</c>.</summary>
    public string Base { get; init; } = "default";

    /// <summary>The constraints changed, by path (<c>SigningCertificate/KeyUsage</c>), each as the policy file writes it.</summary>
    public JsonElement? Set { get; init; }
}

/// <summary>A file the person running the playbook uploads, referenced as <c>input:ID</c> (a file to validate, augment or sign).</summary>
public sealed record PlaybookInput
{
    /// <summary>The id, unique in the playbook.</summary>
    public string Id { get; init; } = "";

    /// <summary>What to upload, as the page asks for it.</summary>
    public string Title { get; init; } = "";

    /// <summary>Where the file comes from and what the steps do with it.</summary>
    public string? Description { get; init; }

    /// <summary>The file types the page offers, as an HTML <c>accept</c> value (<c>.pdf</c>); null for any.</summary>
    public string? Accept { get; init; }
}

/// <summary>The values every step starts from.</summary>
public sealed record PlaybookDefaults
{
    /// <summary>The engine: <c>library</c>, <c>cli</c> or <c>both</c>.</summary>
    public string Engine { get; init; } = PlaybookEngines.Library;

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

/// <summary>A group of steps.</summary>
public sealed record PlaybookSection
{
    public string Id { get; init; } = "";

    public string Title { get; init; } = "";

    public string? Description { get; init; }

    public IReadOnlyList<PlaybookStep> Steps { get; init; } = [];
}

/// <summary>One run and what it must show.</summary>
public sealed record PlaybookStep
{
    /// <summary>A unique id; <c>step:ID</c> in a later step's options names the file this one signed.</summary>
    public string Id { get; init; } = "";

    public string Title { get; init; } = "";

    public string? Description { get; init; }

    /// <summary>Free labels (a requirement id, a topic): the page filters by them and the evidence groups by them.</summary>
    public IReadOnlyList<string> Tags { get; init; } = [];

    /// <summary><c>sign</c>, <c>validate</c> or <c>augment</c> (raise the level of a signed file: options <c>fileId</c>, <c>dataId</c>, <c>level</c>, <c>timestamp</c>, <c>renew</c>).</summary>
    public string Kind { get; init; } = PlaybookStepKinds.Sign;

    /// <summary>The format; the default's when null. Not used by a validation (the file says what it is).</summary>
    public string? Format { get; init; }

    /// <summary>The engine; the default's when null.</summary>
    public string? Engine { get; init; }

    /// <summary>Whether DSS also validates; the default's when null.</summary>
    public bool? CrossValidate { get; init; }

    /// <summary>Seconds to wait before the step runs (a certificate that must expire first): 0 to 300.</summary>
    public int? Wait { get; init; }

    /// <summary>The Sandbox state for the step, put back after it.</summary>
    public PlaybookSandbox? Sandbox { get; init; }

    /// <summary>
    /// The TestBench options of the run (the Sign page's for a signature, <c>fileId</c>/<c>dataId</c>/<c>settings</c> for a
    /// validation), with symbolic values: <c>sandbox:SIGNER</c>, <c>sample:ID</c>, <c>cades-sample:ID</c>,
    /// <c>xades-sample:ID</c>, <c>preset:KIND:NAME</c>, <c>step:ID</c>, <c>input:ID</c>.
    /// </summary>
    public JsonElement? Options { get; init; }

    /// <summary>What the run must show.</summary>
    public PlaybookExpectation? Expect { get; init; }
}

/// <summary>The Sandbox failures and revocations a step needs.</summary>
public sealed record PlaybookSandbox
{
    /// <summary>CRL failure: None, Down, Slow, Expired, WrongKey, Stale, NoNextUpdate.</summary>
    public string? Crl { get; init; }

    /// <summary>OCSP failure: None, Down, Slow, TryLater, Expired, Unauthorized, Unknown.</summary>
    public string? Ocsp { get; init; }

    /// <summary>TSA failure: None, Down, Slow, InvalidToken, Untrusted.</summary>
    public string? Tsa { get; init; }

    /// <summary>Trusted list failure: None, Expired, WrongSigner, Tampered, WithdrawnAfterUse.</summary>
    public string? TrustedList { get; init; }

    /// <summary>Sandbox certificates to revoke for the step.</summary>
    public IReadOnlyList<string> Revoke { get; init; } = [];

    /// <summary>Whether anything is asked.</summary>
    public bool Any => Crl is not null || Ocsp is not null || Tsa is not null || TrustedList is not null || Revoke.Count > 0;

    /// <summary>The changes, one line each, as the page and the evidence show them.</summary>
    public IEnumerable<string> Describe()
    {
        if (Crl is not null)
        {
            yield return $"CRL: {Crl}";
        }

        if (Ocsp is not null)
        {
            yield return $"OCSP: {Ocsp}";
        }

        if (Tsa is not null)
        {
            yield return $"TSA: {Tsa}";
        }

        if (TrustedList is not null)
        {
            yield return $"Trusted list: {TrustedList}";
        }

        foreach (string id in Revoke)
        {
            yield return $"Revoke: {id}";
        }
    }
}

/// <summary>What a run must show; every field given is checked.</summary>
public sealed record PlaybookExpectation
{
    /// <summary><c>signed</c>, <c>refused</c> (SigningException), <c>error</c>, <c>valid</c>, <c>invalid</c>, <c>indeterminate</c> or <c>augmented</c>.</summary>
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

    /// <summary><c>valid</c>: the run's ETSI TS 119 102-2 report must be valid against its schema.</summary>
    public string? EtsiReport { get; init; }

    /// <summary>
    /// Constraints of the validation policy that must fail (their names, as the report shows them: <c>AccuracyPresent</c>),
    /// in the signature or in what it carries (a time-stamp, revocation data).
    /// </summary>
    public IReadOnlyList<string> FailedConstraints { get; init; } = [];

    /// <summary>Texts the run's log must contain.</summary>
    public IReadOnlyList<string> LogContains { get; init; } = [];

    /// <summary>The fields given, as label and value, for the page and the evidence.</summary>
    public IEnumerable<(string Name, string Value)> Fields()
    {
        if (Outcome is not null)
        {
            yield return ("outcome", Outcome);
        }

        if (Reason is not null)
        {
            yield return ("reason", Reason);
        }

        if (Indication is not null)
        {
            yield return ("indication", Indication);
        }

        if (SubIndication is not null)
        {
            yield return ("subIndication", SubIndication);
        }

        if (Level is not null)
        {
            yield return ("level", Level);
        }

        if (DssAgrees is { } agrees)
        {
            yield return ("dssAgrees", agrees ? "yes" : "no");
        }

        if (EtsiReport is not null)
        {
            yield return ("etsiReport", EtsiReport);
        }

        foreach (string constraint in FailedConstraints)
        {
            yield return ("failedConstraints", constraint);
        }

        foreach (string text in LogContains)
        {
            yield return ("logContains", text);
        }
    }
}

/// <summary>The engines of a step.</summary>
public static class PlaybookEngines
{
    public const string Library = "library";
    public const string Cli = "cli";
    public const string Both = "both";

    public static IReadOnlyList<string> All { get; } = [Library, Cli, Both];
}

/// <summary>The kinds of step.</summary>
public static class PlaybookStepKinds
{
    public const string Sign = "sign";
    public const string Validate = "validate";
    public const string Augment = "augment";

    public static IReadOnlyList<string> All { get; } = [Sign, Validate, Augment];
}

/// <summary>The outcomes an expectation can name.</summary>
public static class PlaybookOutcomes
{
    public static IReadOnlyList<string> All { get; } = ["signed", "refused", "error", "valid", "invalid", "indeterminate", "augmented"];
}
