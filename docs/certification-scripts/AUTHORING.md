# Writing a certification script (with an LLM)

A certification script is written once, offline, from the accreditation guide, and then only loaded and run by the
TestBench ([certification-script.md](../articles/certification-script.md)). An LLM does most of the work well if it
gets three things:

1. the guide (its requirement list and checklist — for INDECOPI, sections 4.2–4.4 and Annex B);
2. the JSON Schema: [`docs/schemas/certification-script.schema.json`](../schemas/certification-script.schema.json);
3. the catalogue of run options and Sandbox names: [`options.md`](options.md) (generated from the TestBench), and one
   finished script as an example ([`indecopi-guia-v4.json`](indecopi-guia-v4.json) or
   [`sandbox-basics.json`](sandbox-basics.json)).

Then load the file in the TestBench: it checks every reference against the connected Sandbox and lists what is wrong,
with its JSON path. Fix, reload, run.

## Prompt

Paste the three attachments above, then:

```text
Write a SimpleSign certification script (JSON, schema 1) for the attached accreditation guide.

Rules:
- requirements: one entry per item of the guide's audit checklist, in its order and numbering, with the guide's own
  words in "text" (in the guide's language) and "reference" (section/page). Items that cannot apply to a signature
  LIBRARY (a cryptographic module, key custody or a user interface that belongs to the solution) get
  "applies": false and a "justification".
- sections/steps: for every item that applies, at least one step that shows it. Prefer automated steps:
  - "sign" with "expect": { "outcome": "refused", "reason": "<SigningErrorReason>" } for each case the software must
    refuse, and a "signed" step for the accepted case next to it;
  - "validate" for the verification requirements, on "step:<id>" (a file an earlier step signed) or a sample;
  - "manual" only for what no run can show (manuals, code signing, real tokens), with instructions that say exactly
    what to show and to attach.
- Use only the option paths, values, Sandbox signer ids, failures, presets and symbolic values listed in options.md.
  Put what every step shares in "defaults.options.common" (policy preset, trust anchors, attemptRefused: true).
- Use "sandbox" on a step to switch a failure on (crl, ocsp, tsa, trustedList) or revoke a certificate for that step.
- Cover PAdES, CAdES and XAdES where the guide asks for formats or levels.
- Language of the texts and of the evidence: the guide's ("language": "es" | "pt" | "en").
Answer with the JSON file only.
```

## Checklist before running

- Every requirement that applies is shown by a step (the TestBench warns otherwise).
- Every refusal step names its `reason`: an auditor wants the refusal for *that* reason, not any failure.
- `attemptRefused: true` in the defaults, so the library (or the CLI) refuses, not the TestBench's pre-check.
- Steps that need DSS (`crossValidate`) only when a DSS service is connected.
- The Sandbox has what the script names (`GET /api/pki` on it): signers, certificates to revoke, TSAs.
