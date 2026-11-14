# Writing a playbook (with an LLM)

A playbook is written once, offline, from an accreditation guide or a test plan, and then only loaded and run by the
TestBench ([playbook.md](../articles/playbook.md)). An LLM does most of the work well if it gets three things:

1. the guide (its requirement list and checklist — for INDECOPI, sections 4.2–4.4 and Annex B);
2. the JSON Schema: [`docs/schemas/playbook.schema.json`](../schemas/playbook.schema.json);
3. the catalogue of run options and Sandbox names: [`options.md`](options.md) (generated from the TestBench), and one
   finished playbook as an example ([`indecopi-guia-v4.json`](indecopi-guia-v4.json) or
   [`sandbox-basics.json`](sandbox-basics.json)).

Then load the file in the TestBench (Playbook tab): it checks every reference against the connected Sandbox and lists
what is wrong, with its JSON path. Fix, reload, run.

## Prompt

Paste the three attachments above, then:

```text
Write a SimpleSign playbook (JSON, schema 2) for the attached accreditation guide.

Rules:
- Root: only "schema", "id", "title", "description", "defaults", "inputs" (when needed) and "sections". Titles and descriptions in English.
- Only what a run can show: no step for manuals, code signing, real tokens or anything a person must check.
- Only what this framework decides: a run that sandbox-basics or etsi-baseline already makes (revocation, validity, key
  usage, TSA checks, levels, algorithms, changed files) is not repeated; the checklist names that step instead
  (sandbox-basics:ID). Keep a step when the framework's profile, trusted list or policy is what the run shows, and
  one for every constraint where the framework's preset differs from the generic policy (PlaybookPoliciesTests lists
  them). The generic playbooks never name a framework's preset or profile.
- sections/steps: for every item of the guide a run can show, at least one step. Give each step "tags": the guide's
  item ids it helps with (as the guide numbers them) and a topic (crl, ocsp, tsa, levels…).
- Give every section a "description" (what it shows) and every step a "description" of one or two sentences: what the
  step runs (the certificate, the Sandbox failure, the file) and why (the case it stands for and what the expected
  result proves). Name the step whose file it uses when it is not obvious.
  - "sign" with "expect": { "outcome": "refused", "reason": "<SigningErrorReason>" } for each case the software must
    refuse, and a "signed" step for the accepted case next to it;
  - "validate" for the verification requirements, on "step:<id>" (a file an earlier step signed) or a sample.
- Use only the option paths, values, Sandbox signer ids, failures, presets and symbolic values listed in options.md.
  Put what every step shares in "defaults.options.common" (policy preset, trust anchors, attemptRefused: true).
- Use "sandbox" on a step to switch a failure on (crl, ocsp, tsa, trustedList) or revoke a certificate for that step.
- A file only the person running the playbook has (a PDF signed elsewhere, their own document): declare it in "inputs"
  ({ "id", "title", "description", "accept" }) and name it "input:ID" where a file goes. "accept" is checked when the
  file is uploaded (extension and content): list only the types the steps can use (.pdf; .xml; .p7s, .p7m).
- Cover PAdES, CAdES and XAdES where the guide asks for formats or levels.
Answer with the JSON file only.
```

## Checklist before running

- Every step has a `description` saying what it runs and why: the evidence shows it to the auditor.
- Every refusal step names its `reason`: an auditor wants the refusal for *that* reason, not any failure.
- Every input has `accept`: a wrong file is then refused at upload instead of failing each step that uses it.
- `attemptRefused: true` in the defaults, so the library (or the CLI) refuses, not the TestBench's pre-check.
- `crossValidate: true` (defaults or a step) has EU DSS validate what the step produces; it does not stop a run when DSS
  is down. Add `expect.dssAgrees` only where agreement with DSS is the point, and never on a refusal (nothing is sent).
- The Sandbox has what the playbook names (`GET /api/pki` on it): signers, certificates to revoke, TSAs.
