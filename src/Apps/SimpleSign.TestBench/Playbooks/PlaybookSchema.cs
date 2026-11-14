using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using SimpleSign.Core.Signing;
using SimpleSign.TestBench.Policies;
using SimpleSign.TestBench.Runs;
using SimpleSign.TestBench.Sandbox;
using SimpleSign.TestBench.Schema;

namespace SimpleSign.TestBench.Playbooks;

/// <summary>
/// What a playbook author (a person or an LLM working offline) needs: the JSON Schema of the file
/// (<c>docs/schemas/playbook.schema.json</c>) and the catalogue of the run options a step can set
/// (<c>docs/playbooks/options.md</c>), both generated from the code so they never drift.
/// </summary>
internal static class PlaybookSchema
{
    /// <summary>Where the schema is published.</summary>
    public const string Id = "https://raw.githubusercontent.com/eupassarin/SimpleSign/main/docs/schemas/playbook.schema.json";

    private static readonly JsonSerializerOptions s_indented = new() { WriteIndented = true };

    /// <summary>The JSON Schema (draft 2020-12) of a playbook.</summary>
    public static string Json()
    {
        static JsonObject Str(string description, IEnumerable<string>? values = null)
        {
            var node = new JsonObject { ["type"] = "string", ["description"] = description };
            if (values is not null)
            {
                node["enum"] = new JsonArray([.. values.Select(v => (JsonNode)v)]);
            }

            return node;
        }

        static JsonObject Obj(string description, JsonObject properties, params string[] required)
        {
            var node = new JsonObject
            {
                ["type"] = "object",
                ["description"] = description,
                ["additionalProperties"] = false,
                ["properties"] = properties,
            };
            if (required.Length > 0)
            {
                node["required"] = new JsonArray([.. required.Select(r => (JsonNode)r)]);
            }

            return node;
        }

        static JsonObject Arr(JsonNode items, string description) =>
            new() { ["type"] = "array", ["description"] = description, ["items"] = items };

        static JsonObject Bool(string description) => new() { ["type"] = "boolean", ["description"] = description };

        static JsonObject Ref(string name) => new() { ["$ref"] = "#/$defs/" + name };

        var options = new JsonObject
        {
            ["type"] = "object",
            ["description"] = "TestBench run options (see docs/playbooks/options.md). Symbolic values: sandbox:SIGNER (a Sandbox signer), "
                + "sample:ID (a sample document), preset:KIND:NAME (a built-in policy), playbook:ID (a policy declared in policies), "
                + "step:ID (the file an earlier step signed), input:ID (the file uploaded for an input declared in inputs). "
                + "A validation takes { fileId, dataId?, settings? }.",
        };

        var defs = new JsonObject
        {
            ["section"] = Obj("A group of steps.", new JsonObject
            {
                ["id"] = Str("Unique id."),
                ["title"] = Str("Title."),
                ["description"] = Str("What the section shows."),
                ["steps"] = Arr(Ref("step"), "The steps, run in order."),
            }, "id", "title", "steps"),
            ["sandbox"] = Obj("The Sandbox state for the step; put back after it.", new JsonObject
            {
                ["crl"] = Str("CRL failure.", Enum.GetNames<CrlFault>()),
                ["ocsp"] = Str("OCSP failure.", Enum.GetNames<OcspFault>()),
                ["tsa"] = Str("TSA failure.", Enum.GetNames<TsaFault>()),
                ["trustedList"] = Str("Trusted list failure.", Enum.GetNames<TlFault>()),
                ["lotl"] = Str("List of trusted lists failure.", Enum.GetNames<LotlFault>()),
                ["revoke"] = Arr(Str("A Sandbox certificate id."), "Certificates to revoke for the step."),
            }),
            ["expect"] = Obj("What the run must show; every field given is checked, for each engine.", new JsonObject
            {
                ["outcome"] = Str("signed / refused (SigningException) / error, or the verdict valid / invalid / indeterminate.", PlaybookOutcomes.All),
                ["reason"] = Str("The SigningErrorReason of a refusal.", Enum.GetNames<SigningErrorReason>()),
                ["indication"] = Str("ETSI indication of the first signature.", ["TOTAL_PASSED", "TOTAL_FAILED", "INDETERMINATE"]),
                ["subIndication"] = Str("ETSI sub-indication (HASH_FAILURE, REVOKED_NO_POE…)."),
                ["level"] = Str("Level achieved (signature) or detected (validation).", ["B-B", "B-T", "B-LT", "B-LTA"]),
                ["failedConstraints"] = Arr(Str("A constraint name (AccuracyPresent)."),
                    "Constraints of the validation policy that must fail, by name, in the signature or what it carries (a time-stamp, revocation data)."),
                ["qualification"] = Str("The qualification of the first signature under the profile's framework (eIDAS: QESig, QESeal, AdESig-QC, AdESeal-QC, AdESig, AdESeal, Indeterminate …, Not AdES, N/A)."),
                ["timestampQualification"] = Str("The qualification of its first timestamp: QTSA (qualified electronic time-stamp), TSA or N/A."),
                ["etsiReport"] = Str("valid: the run's ETSI TS 119 102-2 validation report must be valid against its schema (embedded in SimpleSign).", ["valid"]),
                ["dssAgrees"] = Bool("Whether EU DSS must agree with SimpleSign. Needs crossValidate on the step or in the defaults, and a run that produces a file (a refusal is never sent to DSS); when DSS is unavailable this check fails."),
                ["logContains"] = Arr(Str("Text."), "Texts the run's log must contain."),
            }),
            ["step"] = Obj("One run and what it must show.", new JsonObject
            {
                ["id"] = Str("Unique id; step:ID names the file it signed."),
                ["title"] = Str("Title."),
                ["description"] = Str("What the step shows and why."),
                ["tags"] = Arr(Str("A tag."), "Free labels (a requirement id, a topic): the page filters by them, the evidence groups by them."),
                ["kind"] = Str("What the step does. Default: sign.", PlaybookStepKinds.All),
                ["format"] = Str("Format of a signature; the default's when absent.", RunFormats.All),
                ["engine"] = Str("Engine; the default's when absent.", PlaybookEngines.All),
                ["crossValidate"] = Bool("Whether EU DSS also validates the file this step produces; overrides defaults.crossValidate."),
                ["wait"] = new JsonObject { ["type"] = "integer", ["minimum"] = 0, ["maximum"] = 300, ["description"] = "Seconds to wait before the step runs, before its Sandbox changes (a short-lived certificate that must expire, a revocation that must come after a time-stamp)." },
                ["sandbox"] = Ref("sandbox"),
                ["options"] = options,
                ["expect"] = Ref("expect"),
            }, "id", "title", "expect"),
        };

        var schema = new JsonObject
        {
            ["$schema"] = "https://json-schema.org/draft/2020-12/schema",
            ["$id"] = Id,
            ["title"] = "SimpleSign playbook",
            ["description"] = "Sections of TestBench steps (signatures to make or refuse, files to validate) and what each must show. Load it in the TestBench (Playbook tab).",
            ["type"] = "object",
            ["additionalProperties"] = false,
            ["required"] = new JsonArray("schema", "id", "title", "sections"),
            ["properties"] = new JsonObject
            {
                ["$schema"] = Str("This schema's URL."),
                ["schema"] = new JsonObject { ["const"] = 2, ["description"] = "Schema version." },
                ["id"] = Str("Short id (indecopi-guia-v4)."),
                ["title"] = Str("Title of the playbook and of the evidence."),
                ["description"] = Str("What the playbook covers."),
                ["defaults"] = Obj("What every step starts from.", new JsonObject
                {
                    ["engine"] = Str("Engine.", PlaybookEngines.All),
                    ["format"] = Str("Format of steps that name none.", RunFormats.All),
                    ["crossValidate"] = Bool("Whether EU DSS also validates every file a step produces, next to SimpleSign (default false). When DSS is unavailable the step still runs and its result says so."),
                    ["options"] = new JsonObject
                    {
                        ["type"] = "object",
                        ["description"] = "Options under each step's: common (every format), then pades, cades or xades.",
                        ["properties"] = new JsonObject { ["common"] = options.DeepClone(), ["pades"] = options.DeepClone(), ["cades"] = options.DeepClone(), ["xades"] = options.DeepClone() },
                        ["additionalProperties"] = false,
                    },
                }),
                ["policies"] = Arr(Obj("A policy the playbook adjusts, named playbook:ID by signingPolicyId or validation.policyId.", new JsonObject
                {
                    ["id"] = Str("Unique id."),
                    ["kind"] = Str("Signing or validation policy.", [PolicyViewer.Signing, PolicyViewer.Validation]),
                    ["base"] = Str("The policy it starts from: default or a built-in name (iofe, strict…)."),
                    ["set"] = new JsonObject
                    {
                        ["type"] = "object",
                        ["description"] = "The constraints changed, by path (SigningCertificate/KeyUsage), each as the policy file writes it: { \"Level\": \"FAIL\", \"Id\": [\"nonRepudiation\"] }.",
                    },
                }, "id", "kind"), "Policies the steps adjust (a built-in one with some constraints changed)."),
                ["inputs"] = Arr(Obj("A file the person running the playbook uploads on the Playbook tab, named input:ID by a step's options (a fileId to validate or augment, a documentId or dataId to sign). A step whose input has no file is skipped.", new JsonObject
                {
                    ["id"] = Str("Unique id."),
                    ["title"] = Str("What to upload, as the page asks for it."),
                    ["description"] = Str("Where the file comes from and what the steps do with it."),
                    ["accept"] = Str("The file types the page offers, as an HTML accept value (.pdf, .xml, .p7s)."),
                }, "id", "title"), "Files uploaded by the person running the playbook (a PDF signed elsewhere, a document to sign)."),
                ["sections"] = Arr(Ref("section"), "The steps, grouped."),
            },
            ["$defs"] = defs,
        };
        return schema.ToJsonString(s_indented);
    }

    /// <summary>The catalogue of run options, symbolic values and Sandbox names, as Markdown.</summary>
    public static string OptionsMarkdown()
    {
        var schema = OptionSchema.All;
        var md = new StringBuilder();
        md.Append("# Playbook — run options\n\n")
            .Append("Generated from the TestBench (`PlaybookSchema.OptionsMarkdown`); do not edit. A step's `options` is a JSON object whose keys are the ")
            .Append("**paths** below (a dot is a nested object: `signingControls.trust` is `{ \"signingControls\": { \"trust\": [...] } }`).\n\n")
            .Append("## Symbolic values\n\n")
            .Append("| Value | Means |\n|---|---|\n")
            .Append("| `sandbox:SIGNER` | A Sandbox signer, as `credentialId` (see the Sandbox signers below). |\n")
            .Append("| `sample:ID` | A sample PDF as `documentId` (`contract`, …), or a PAdES validation sample as a validation's `fileId` (`valid`, `revoked`, `expired`, `tampered-content`, `untrusted-root`, `untrusted-tsa`…). |\n")
            .Append("| `cades-sample:ID` / `xades-sample:ID` | A CAdES or XAdES sample: data to sign as `dataId` (`text`, `json`, `pdf` / `order`), or a signed file as a validation's `fileId` (`v-valid`, `v-tampered`… / `v-xades`, `v-changed`…); `ID#data` is the data a detached sample signature is checked against, as a validation's `dataId`. |\n")
            .Append("| `preset:signing:NAME` / `preset:validation:NAME` | A built-in policy, as `signingPolicyId` or `validation.policyId`: ")
            .Append(string.Join(", ", PolicyPresets.All.Select(p => $"`{p.Id}`"))).Append(". |\n")
            .Append("| `step:ID` | The file an earlier step signed, as `fileId` of a validation or as the input of a later signature. |\n")
            .Append("| `input:ID` | The file uploaded on the Playbook tab for an input the playbook declares in `inputs` (a PDF signed elsewhere, a document to sign), wherever a file goes (`fileId`, `documentId`, `dataId`). A step whose input has no file is skipped. |\n")
            .Append("| `sandbox-short-lived:N` | A Sandbox signer issued when the step runs and valid for N seconds (1 to 3600), as `credentialId`: with a later step's `wait`, its certificate has expired by validation time. |\n")
            .Append("| `fixture:NAME` | A bundled file, as an upload option: ")
            .Append(string.Join(", ", Documents.Fixtures.All.Select(f => $"`{f.Id}` ({f.Title})"))).Append(". |\n\n")
            .Append("## Validation steps\n\n`kind: \"validate\"` takes `{ \"fileId\": \"step:ID\", \"dataId\": \"sample:ID\"?, \"settings\": { \"trust\": [...], \"policyId\": \"preset:validation:NAME\", \"level\": \"ArchivalData\" } }`.\n\n");
        foreach (var format in schema.Formats)
        {
            md.Append("## ").Append(format.Id).Append(" — signature options\n\n| Path | Kind | Values | What it is |\n|---|---|---|---|\n");
            foreach (var option in schema.Options.Where(o => o.Path is not null && o.Formats.Contains(format.Id)))
            {
                string values = option.Values.Count == 0 ? "" : string.Join(", ", option.Values.Select(v => v.Value.Length == 0 ? "`\"\"`" : $"`{v.Value}`"));
                md.Append("| `").Append(option.Path).Append("` | ").Append(option.Kind).Append(" | ").Append(values).Append(" | ")
                    .Append(Cell(option.Title)).Append(": ").Append(Cell(option.Summary)).Append(" |\n");
            }

            md.Append('\n');
        }

        md.Append("## Step fields\n\n`wait`: seconds (0 to 300) the step waits before it runs, before its Sandbox changes.\n\n");
        md.Append("## Sandbox\n\nSigner ids (`sandbox:ID`) and certificate ids (`sandbox.revoke`) are those of the connected Sandbox (`GET /api/pki` on it); ")
            .Append("the TestBench checks them when it loads a playbook. Failures: crl ").Append(string.Join("/", Enum.GetNames<CrlFault>()))
            .Append(", ocsp ").Append(string.Join("/", Enum.GetNames<OcspFault>()))
            .Append(", tsa ").Append(string.Join("/", Enum.GetNames<TsaFault>()))
            .Append(", trustedList ").Append(string.Join("/", Enum.GetNames<TlFault>()))
            .Append(", lotl ").Append(string.Join("/", Enum.GetNames<LotlFault>())).Append(".\n");
        return md.ToString();
    }

    /// <summary>
    /// What a step's <c>sandbox</c> block and <c>sandbox:ID</c> values can name: the failures of each service (from the
    /// enums, so they never drift) and, with a Sandbox connected, its signer and certificate ids.
    /// </summary>
    /// <param name="signers">The connected Sandbox's signers as id and title; null when none is connected.</param>
    /// <param name="certificates">The connected Sandbox's certificates (revocable by id); null when none is connected.</param>
    public static PlaybookSandboxReference SandboxReference(
        IEnumerable<(string Id, string Title)>? signers, IEnumerable<SandboxCertificateInfo>? certificates) =>
        new(
            signers is not null,
            signers?.Select(s => new PlaybookReferenceId(s.Id, s.Title)).ToList() ?? [],
            certificates?.Select(c => new PlaybookReferenceId(c.Id, c.Title)).ToList() ?? [],
            new Dictionary<string, IReadOnlyList<string>>(StringComparer.Ordinal)
            {
                ["crl"] = Enum.GetNames<CrlFault>(),
                ["ocsp"] = Enum.GetNames<OcspFault>(),
                ["tsa"] = Enum.GetNames<TsaFault>(),
                ["trustedList"] = Enum.GetNames<TlFault>(),
                ["lotl"] = Enum.GetNames<LotlFault>(),
            });

    private static string Cell(string text) => text.Replace("|", "\\|", StringComparison.Ordinal).Replace("\n", " ", StringComparison.Ordinal);
}

/// <summary>An id a playbook can name, with its title.</summary>
public sealed record PlaybookReferenceId(string Id, string Title);

/// <summary>What a playbook's <c>sandbox</c> blocks and <c>sandbox:ID</c> values can name.</summary>
/// <param name="Connected">Whether a Sandbox is connected (the ids come from it).</param>
/// <param name="Signers">The signer ids, for <c>sandbox:ID</c>.</param>
/// <param name="Certificates">The certificate ids, for <c>sandbox.revoke</c>.</param>
/// <param name="Faults">The failures of each service: crl, ocsp, tsa, trustedList.</param>
public sealed record PlaybookSandboxReference(
    bool Connected,
    IReadOnlyList<PlaybookReferenceId> Signers,
    IReadOnlyList<PlaybookReferenceId> Certificates,
    IReadOnlyDictionary<string, IReadOnlyList<string>> Faults);
