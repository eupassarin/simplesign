# Playbooks

A **playbook** is a list of TestBench steps, grouped in sections: a signature that must be made or refused for a
given reason, or a file that must validate or not, each with what its run must show. The TestBench runs it against a
[Sandbox](sandbox.md), through the library, the CLI or both, keeps the latest result of every step, and exports the
evidence. It helps with the *systemic* part of a certification (INDECOPI's *Guía de Acreditación de Software*, an
ICP-Brasil or eIDAS conformity scheme…): what can be shown by running the software. What needs a person (manuals,
code signing, a real token) is handled outside it.

The playbook is a JSON file written **beforehand**, by hand or by an LLM working from the guide
([how to write one](../playbooks/AUTHORING.md)). Nothing in the TestBench is specific to a guide: what is checked,
and why, is in the file. Each step has free **tags** (a requirement id of the guide, a topic): the page filters by
them and the evidence groups by them.

## Run one

1. Start a Sandbox and the TestBench, and connect them (`tools/stack/up.sh`, or the two `dotnet run` lines of
   [testbench.md](testbench.md)). Start DSS too for steps with `crossValidate`.
2. In the TestBench, open the **Playbook** tab (top bar, after Sign and Validate). Open a playbook file, or pick a
   sample (`docs/playbooks/*.json` are bundled: `sandbox-basics`, `indecopi-guia-v4`).
3. The playbook is checked when it loads: every Sandbox signer and certificate, failure, preset and step reference.
   Errors stop it; warnings do not.
4. The page has three columns:
   - **Steps**, by section, with their status and tags; click a tag to see only its steps. Run one step, a section
     or everything.
   - **What the step does**, before it runs: what is signed (or validated) and by whom (subject, issuer, key,
     validity), every setting the run uses, by group of the Sign page (the ones the playbook sets are highlighted),
     the Sandbox changes, the expectation, and the library (C#) and CLI commands.
   - **Its latest result**, per engine: expected and found, the error, the time, DSS's verdict, the report (opens in
     a dialog), the signed file, the ETSI and JSON reports, the CLI commands with their output, and the log.
5. A result stays until the step runs again: running another step, or the same playbook loaded again, keeps it.
   Loading another file starts with no result. Results live while the TestBench runs.
6. Choose the engine (as the playbook says, library, CLI, or both). A step that runs on both engines passes only
   when both show what it expects.
7. **Evidence**: the page has the steps by section, each with its tags and what was expected and found per engine,
   and a summary by tag; the zip adds the playbook, the results, and per step the signed file, the validation
   reports (SimpleSign JSON, ETSI TS 119 102-2 XML) and the run log (the CLI commands included).

## The file

```json
{
  "$schema": "https://raw.githubusercontent.com/eupassarin/SimpleSign/main/docs/schemas/playbook.schema.json",
  "schema": 2,
  "id": "demo",
  "title": "Demo",
  "description": "What it covers.",
  "defaults": { "engine": "both", "options": { "common": { "level": "BB", "attemptRefused": true } } },
  "sections": [
    { "id": "revocation", "title": "Revocation", "steps": [
      { "id": "revoked", "title": "Revoked by OCSP: refused", "tags": ["F-10", "ocsp"],
        "options": { "documentId": "sample:contract", "credentialId": "sandbox:revoked-ocsp" },
        "expect": { "outcome": "refused", "reason": "CertificateRevoked" } }
    ] }
  ]
}
```

| Kind | Runs | Expectation |
|---|---|---|
| `sign` | A TestBench signature (`options`: the Sign page's, see [options.md](../playbooks/options.md)) | `outcome` signed / refused / error, `reason` (the `SigningErrorReason` of a refusal), `level`, `indication`, `dssAgrees`, `etsiReport`, `logContains` |
| `validate` | A validation of `options.fileId` (`step:ID` for a file an earlier step signed, or a sample) | `outcome` valid / invalid / indeterminate, `indication`, `subIndication`, `etsiReport` |
| `augment` | Raises `options.fileId` to `options.level` (`BT`, `BLT`, `BLTA`) with the library's augmenter, through `options.timestamp` (`renew: true` renews a B-LTA), then validates the result; library engine only | `outcome` augmented / refused / error, `level`, `indication`, `subIndication` |

`etsiReport: "valid"` checks the run's ETSI TS 119 102-2 report against the schema embedded in SimpleSign.

The TestBench's **Options reference** (Playbook tab) lists, in the UI's language, every option path, symbolic value and
Sandbox id and failure a step can use; [options.md](../playbooks/options.md) is the same catalogue in Markdown.

**Clear result** (column 3) forgets one step's result; **Restart** (top bar) forgets them all, after a confirmation.
The files those runs produced stay in the TestBench's history.

A validation of `step:ID` run on its own uses the file of that step's latest result; if it never ran, the step says
to run it first.

`sandbox` puts the Sandbox in the state the step needs (CRL, OCSP, TSA or trusted-list failure, certificates to
revoke) and puts it back after the step. A run of several steps starts from a clean Sandbox.

`wait` (0 to 300 seconds) makes a step wait before it runs, before its Sandbox changes: a certificate issued with
`sandbox-short-lived:N` expires meanwhile, or a revocation comes clearly after an earlier step's time-stamp. Upload
options take bundled files as `fixture:NAME` (a signature-policy document, an attribute certificate, a SAML
assertion).

The options that matter most for a certification:

- `signingPolicyId: "preset:signing:iofe"` (or `strict`, or an upload) — the checks before signing;
- `signingControls` — the trust anchors the signer and each TSA must chain to (`SandboxRoot`, `SandboxTrustedList`),
  the TSA expected (`expectedTsa`), and the audit trail (`auditLog`);
- `attemptRefused: true` — run even when the TestBench foresees the policy will refuse the signer, so the evidence is
  the library's own refusal (`SigningException` and its reason), not the TestBench's warning.
- `profile` (on `signingControls`, `validation` and a validation's `settings`) — a trust profile, as the Profile menu
  and the CLI's `--profile` set it: `Iofe` (with `profileSource`: `Indecopi`, INDECOPI's real list, or `Sandbox`, the
  Sandbox's list read the same way), `IcpBrasil`, `GovBr` (validation only) or `Sandbox`; `trustProfiles` adds others'
  trust. A step with a profile and no policy takes the profile's; the preview and the evidence show it;
- `policies` (top level) — adjusted policies, `{ "id", "kind", "base", "set" }`, named `playbook:ID` in
  `signingPolicyId` / `policyId`; an explicit policy wins over the profile's (the INDECOPI playbook's
  `playbook:iofe-agent` asks for the nonRepudiation bit of an automated agent).

### Cross-validation with EU DSS

`"crossValidate": true` in `defaults` (every step) or on a step (that step only) has EU DSS validate, under the same
policy, every file the step produces, next to SimpleSign. The preview shows it (**Run** card, "DSS" in the step's
header) and column 3 shows DSS's verdict and report. Only a run that produces a file is sent: a refused signature never
reaches DSS. When DSS is unavailable the step still runs and its result says "DSS unavailable"; it fails for that only
with `"expect": { "dssAgrees": true }`, which makes the agreement a check. The TestBench reaches DSS at
`SIMPLESIGN_DSS_URL` (default `http://localhost:8080`).

## The samples

- `sandbox-basics` — a good chain, B-LT through the Sandbox's TSA, and the cases a signer must refuse.
- `indecopi-guia-v4` — the automated part of INDECOPI's guide v4.0, Annex B: signing (F-n) and verification (V-n) by
  automated agents and the time-stamp checks (S-n), with the IOFE policies and the Sandbox's list in INDECOPI's
  layout, through the library and the CLI. It covers the items [indecopi-checklist.md](../playbooks/indecopi-checklist.md)
  marks P; see [iofe.md](iofe.md). Written by `tools/playbooks/indecopi.py`.
- `etsi-baseline` — SimpleSign against the ETSI standards: PAdES, CAdES and XAdES baseline (EN 319 142-1, 319 122-1,
  319 132-1), the extended forms, time-stamps, EN 319 102-1 validation (indication and sub-indication) and trusted
  lists, cross-validated with EU DSS. It covers the items [etsi-checklist.md](../playbooks/etsi-checklist.md) marks P;
  each step is tagged with its item id and standard. Written by `tools/playbooks/etsi.py`.

Tests: `tests/unit/Apps/SimpleSign.TestBench.Tests/Playbooks` checks the format, the kept results and the preview, and
runs every sample against the Sandbox (and checks that the ETSI one covers every P item of its checklist). The schema is `docs/schemas/playbook.schema.json` (also
`GET /api/playbook/schema`).
