using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using SimpleSign.Core.Signing;
using SimpleSign.TestBench.Policies;
using SimpleSign.TestBench.Runs;
using SimpleSign.TestBench.Sandbox;
using SimpleSign.TestBench.Schema;

namespace SimpleSign.TestBench.Scripts;

/// <summary>
/// What a script author (a person or an LLM working offline) needs: the JSON Schema of the file
/// (<c>docs/schemas/certification-script.schema.json</c>) and the catalogue of the run options a step can set
/// (<c>docs/certification-scripts/options.md</c>), both generated from the code so they never drift.
/// </summary>
internal static class ScriptSchema
{
    /// <summary>Where the schema is published.</summary>
    public const string Id = "https://raw.githubusercontent.com/eupassarin/SimpleSign/main/docs/schemas/certification-script.schema.json";

    private static readonly JsonSerializerOptions s_indented = new() { WriteIndented = true };

    /// <summary>The JSON Schema (draft 2020-12) of a certification script.</summary>
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
            ["description"] = "TestBench run options (see docs/certification-scripts/options.md). Symbolic values: sandbox:SIGNER (a Sandbox signer), "
                + "sample:ID (a sample document), preset:KIND:NAME (a built-in policy), step:ID (the file an earlier step signed). "
                + "A validation takes { fileId, dataId?, settings? }.",
        };

        var defs = new JsonObject
        {
            ["requirement"] = Obj("A requirement of the guide.", new JsonObject
            {
                ["id"] = Str("Unique id, as the guide numbers it (F-5, Req-11)."),
                ["group"] = Str("The group it belongs to (Req. 11 — Revocation)."),
                ["text"] = Str("What the guide asks, in its words."),
                ["reference"] = Str("Where it is in the guide (section, page)."),
                ["applies"] = Bool("Whether it applies; false needs a justification. Default: true."),
                ["justification"] = Str("Why it does not apply."),
            }, "id", "text"),
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
                ["revoke"] = Arr(Str("A Sandbox certificate id."), "Certificates to revoke for the step."),
            }),
            ["expect"] = Obj("What the run must show; every field given is checked, for each engine.", new JsonObject
            {
                ["outcome"] = Str("signed / refused (SigningException) / error, or the verdict valid / invalid / indeterminate.", ScriptOutcomes.All),
                ["reason"] = Str("The SigningErrorReason of a refusal.", Enum.GetNames<SigningErrorReason>()),
                ["indication"] = Str("ETSI indication of the first signature.", ["TOTAL_PASSED", "TOTAL_FAILED", "INDETERMINATE"]),
                ["subIndication"] = Str("ETSI sub-indication (HASH_FAILURE, REVOKED_NO_POE…)."),
                ["level"] = Str("Level achieved (signature) or detected (validation).", ["B-B", "B-T", "B-LT", "B-LTA"]),
                ["dssAgrees"] = Bool("Whether EU DSS must agree (needs crossValidate)."),
                ["logContains"] = Arr(Str("Text."), "Texts the run's log must contain."),
            }),
            ["manual"] = Obj("A step done by hand: the operator follows the instructions, attaches evidence and decides.", new JsonObject
            {
                ["instructions"] = Str("What to do and what to show."),
                ["attachment"] = Bool("Whether a file must be attached."),
            }, "instructions"),
            ["step"] = Obj("One run (or manual check) and what it must show.", new JsonObject
            {
                ["id"] = Str("Unique id; step:ID names the file it signed."),
                ["title"] = Str("Title."),
                ["description"] = Str("What the step shows and why."),
                ["kind"] = Str("What the step does. Default: sign.", ScriptStepKinds.All),
                ["requirements"] = Arr(Str("A requirement id."), "The requirements the step shows."),
                ["format"] = Str("Format of a signature; the default's when absent.", RunFormats.All),
                ["engine"] = Str("Engine; the default's when absent.", ScriptEngines.All),
                ["crossValidate"] = Bool("Whether EU DSS also validates."),
                ["sandbox"] = Ref("sandbox"),
                ["options"] = options,
                ["expect"] = Ref("expect"),
                ["manual"] = Ref("manual"),
            }, "id", "title"),
        };

        var schema = new JsonObject
        {
            ["$schema"] = "https://json-schema.org/draft/2020-12/schema",
            ["$id"] = Id,
            ["title"] = "SimpleSign certification script",
            ["description"] = "The requirements of an accreditation guide and the TestBench steps that show each one. Load it in the TestBench (Certification).",
            ["type"] = "object",
            ["additionalProperties"] = false,
            ["required"] = new JsonArray("schema", "id", "title", "requirements", "sections"),
            ["properties"] = new JsonObject
            {
                ["$schema"] = Str("This schema's URL."),
                ["schema"] = new JsonObject { ["const"] = 1, ["description"] = "Schema version." },
                ["id"] = Str("Short id (indecopi-guia-v4)."),
                ["title"] = Str("Title of the script and of the evidence."),
                ["authority"] = Str("The authority that accredits."),
                ["standard"] = Str("The document the requirements come from, with its version."),
                ["description"] = Str("What the script covers."),
                ["language"] = Str("Language of the texts and of the evidence.", ["en", "pt", "es"]),
                ["defaults"] = Obj("What every step starts from.", new JsonObject
                {
                    ["engine"] = Str("Engine.", ScriptEngines.All),
                    ["format"] = Str("Format of steps that name none.", RunFormats.All),
                    ["crossValidate"] = Bool("Whether EU DSS also validates."),
                    ["options"] = new JsonObject
                    {
                        ["type"] = "object",
                        ["description"] = "Options under each step's: common (every format), then pades, cades or xades.",
                        ["properties"] = new JsonObject { ["common"] = options.DeepClone(), ["pades"] = options.DeepClone(), ["cades"] = options.DeepClone(), ["xades"] = options.DeepClone() },
                        ["additionalProperties"] = false,
                    },
                }),
                ["requirements"] = Arr(Ref("requirement"), "The requirements, in the guide's order."),
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
        md.Append("# Certification script — run options\n\n")
            .Append("Generated from the TestBench (`ScriptSchema.OptionsMarkdown`); do not edit. A step's `options` is a JSON object whose keys are the ")
            .Append("**paths** below (a dot is a nested object: `signingControls.trust` is `{ \"signingControls\": { \"trust\": [...] } }`).\n\n")
            .Append("## Symbolic values\n\n")
            .Append("| Value | Means |\n|---|---|\n")
            .Append("| `sandbox:SIGNER` | A Sandbox signer, as `credentialId` (see the Sandbox signers below). |\n")
            .Append("| `sample:ID` | A sample PDF as `documentId` (`contract`, …), or a PAdES validation sample as a validation's `fileId` (`valid`, `revoked`, `expired`, `tampered-content`, `untrusted-root`, `untrusted-tsa`…). |\n")
            .Append("| `cades-sample:ID` / `xades-sample:ID` | A CAdES or XAdES sample: data to sign as `dataId` (`text`, `json`, `pdf` / `order`), or a signed file as a validation's `fileId` (`v-valid`, `v-tampered`… / `v-xades`, `v-changed`…); `ID#data` is the data a detached sample signature is checked against, as a validation's `dataId`. |\n")
            .Append("| `preset:signing:NAME` / `preset:validation:NAME` | A built-in policy, as `signingPolicyId` or `validation.policyId`: ")
            .Append(string.Join(", ", PolicyPresets.All.Select(p => $"`{p.Id}`"))).Append(". |\n")
            .Append("| `step:ID` | The file an earlier step signed, as `fileId` of a validation or as the input of a later signature. |\n\n")
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

        md.Append("## Sandbox\n\nSigner ids (`sandbox:ID`) and certificate ids (`sandbox.revoke`) are those of the connected Sandbox (`GET /api/pki` on it); ")
            .Append("the TestBench checks them when it loads a script. Failures: crl ").Append(string.Join("/", Enum.GetNames<CrlFault>()))
            .Append(", ocsp ").Append(string.Join("/", Enum.GetNames<OcspFault>()))
            .Append(", tsa ").Append(string.Join("/", Enum.GetNames<TsaFault>()))
            .Append(", trustedList ").Append(string.Join("/", Enum.GetNames<TlFault>())).Append(".\n");
        return md.ToString();
    }

    private static string Cell(string text) => text.Replace("|", "\\|", StringComparison.Ordinal).Replace("\n", " ", StringComparison.Ordinal);
}
