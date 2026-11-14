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
   sample (`docs/playbooks/*.json` are bundled: `sandbox-basics`, `indecopi-guia-v4`, `etsi-baseline`, `icp-brasil-pades`, `govbr-pades`).
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
        "description": "The OCSP responder reports the certificate revoked: the signer must refuse instead of signing.",
        "options": { "documentId": "sample:contract", "credentialId": "sandbox:revoked-ocsp" },
        "expect": { "outcome": "refused", "reason": "CertificateRevoked" } }
    ] }
  ]
}
```

| Kind | Runs | Expectation |
|---|---|---|
| `sign` | A TestBench signature (`options`: the Sign page's, see [options.md](../playbooks/options.md)) | `outcome` signed / refused / error, `reason` (the `SigningErrorReason` of a refusal), `level`, `indication`, `dssAgrees`, `etsiReport`, `logContains` |
| `validate` | A validation of `options.fileId` (`step:ID` for a file an earlier step signed, `input:ID` for a file you upload, or a sample) | `outcome` valid / invalid / indeterminate, `indication`, `subIndication`, `etsiReport` |
| `augment` | Raises `options.fileId` to `options.level` (`BT`, `BLT`, `BLTA`) with the library's augmenter, through `options.timestamp` (`renew: true` renews a B-LTA), then validates the result; library engine only | `outcome` augmented / refused / error, `level`, `indication`, `subIndication` |

`etsiReport: "valid"` checks the run's ETSI TS 119 102-2 report against the schema embedded in SimpleSign.

Give every step a `description`: what it runs and why (the case it stands for, what the expected result proves). The
page shows it next to the step and the evidence writes it under the step's title, so a reader of the evidence knows
what each result means without the playbook at hand. A step without one still runs; loading it gives a warning.

The TestBench's **Options reference** (Playbook tab) lists, in the UI's language, every option path, symbolic value and
Sandbox id and failure a step can use; [options.md](../playbooks/options.md) is the same catalogue in Markdown.

**Clear result** (column 3) forgets one step's result; **Restart** (top bar) forgets them all, after a confirmation.
The files those runs produced stay in the TestBench's history.

A validation of `step:ID` run on its own uses the file of that step's latest result; if it never ran, the step says
to run it first.

### Files you upload (`inputs`)

A playbook can ask for files that only the person running it has: a PDF signed on Gov.br's portal, a signature made
with a real ICP-Brasil certificate, a document of their own to sign. It declares them at the root, and steps name
them as `input:ID` wherever a file goes (`fileId`, `documentId`, `dataId`):

```json
"inputs": [
  { "id": "govbr-signed", "title": "A PDF signed on Gov.br's portal", "accept": ".pdf",
    "description": "Sign any PDF at Gov.br and upload what it hands back." }
],
…
{ "id": "v-portal", "kind": "validate", "title": "Validate the portal's signature", "tags": ["gov.br"],
  "options": { "fileId": "input:govbr-signed", "settings": { "profile": "GovBr" } },
  "expect": { "outcome": "valid" } }
```

`accept` is the upload's rule, not only a hint to the file picker: the TestBench refuses, when the file is uploaded, a
file whose extension (or MIME type: `application/pdf`, `text/xml`, `application/pkcs7-signature`…) is not listed, and a
`.pdf`, `.xml` or `.p7s`/`.p7m` whose content is not a PDF, an XML document or a CMS structure. An empty file is always
refused. An input without `accept` takes any file (loading the playbook warns).

The Playbook tab shows a **Files to upload** bar with each input: upload, replace or remove its file. A step whose
input has no file yet is **skipped** (not failed), with a note saying which file it needs; uploading another file
forgets the results of the steps that use it (and of the steps that use their files). The evidence lists each input
with its file name, size and SHA-256, and the zip carries the file under `inputs/`.

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

The samples complement each other. `sandbox-basics` and `etsi-baseline` are the generic ones: the checks every signer or
validator makes whatever the policy (revocation, validity and key usage, the TSA's certificate, levels, algorithms,
changed files) are shown there, once. A trust-framework playbook (`indecopi-guia-v4`, `eidas-baseline`,
`icp-brasil-pades`, `govbr-pades`) has only what its profile and policies decide; its checklist names the generic steps
it relies on (`sandbox-basics:crl-down`), and `PlaybookValidatorTests.SpecificSamples_DoNotRepeatAGenericStep` fails
when a framework playbook repeats a generic run. For an accreditation, run the framework playbook and the generic ones
and keep the evidence of each.

The generic playbooks use generic policies only (`sandbox-strict` and `strict-checks`: the strict preset with the checks
of the chain, CRLs and TSA set to FAIL; the default validation policy, or one with a single constraint changed), never a
framework's preset or profile. The framework presets set those checks the same way, which
`PlaybookPoliciesTests` checks constraint by constraint; where a preset differs (the icp-brasil signing policy accepts a
CRL without nextUpdate; the framework validation policies require a key usage for signing, IOFE's judges the trusted
list, Gov.br's accepts a signature without the signing-certificate attribute), the framework's playbook has the step
that shows it, and the test names it.

- `sandbox-basics` — a full tour of the Sandbox: every signer of its good chain in PAdES, CAdES and XAdES up to B-LTA;
  each of its TSAs; CRLs over HTTP, HTTPS and LDAP and its OCSP responder with every failure they can be switched to
  (and the fallback from one to the other); revocations made for a step; short-lived certificates; its trusted list
  and the IOFE profile read from it; the cases a signer must refuse and the samples a validator must not accept.
  Through the library only, with a signing policy it declares (`sandbox-strict`: the strict preset plus the chain to
  the Sandbox root, the TSA checks and CRLs with nextUpdate).
- `indecopi-guia-v4` — what INDECOPI's guide v4.0 (Annex B) asks that the IOFE profile and policies decide: the
  trusted list in INDECOPI's layout (signature, expiry, listed roots and the 'unspecified' TSA), nonRepudiation for an
  automated agent, the validation report and the audit trail, through the library and the CLI. The other items marked
  P in [indecopi-checklist.md](../playbooks/indecopi-checklist.md) name steps of `sandbox-basics` and `etsi-baseline`;
  see [iofe.md](iofe.md). Written by `tools/playbooks/indecopi.py`.
- `etsi-baseline` — SimpleSign against the ETSI standards: PAdES, CAdES and XAdES baseline (EN 319 142-1, 319 122-1,
  319 132-1), the extended forms, time-stamps, EN 319 102-1 validation (indication and sub-indication) and trusted
  lists, cross-validated with EU DSS. It covers the items [etsi-checklist.md](../playbooks/etsi-checklist.md) marks P;
  each step is tagged with its item id and standard. Written by `tools/playbooks/etsi.py`.
- `eidas-baseline` — the eIDAS profile on the Sandbox's list of trusted lists: the faults of the LOTL and the TL
  (`sandbox.lotl`, `sandbox.trustedList`), the qualification of each signature (`expect.qualification`: QESig, QESeal,
  AdESig-QC, AdESig) and of its time-stamps (`expect.timestampQualification`: QTSA, TSA), through the library and the
  CLI. It covers the items [eidas-checklist.md](../playbooks/eidas-checklist.md) marks P; see [eidas.md](eidas.md).
  Written by `tools/playbooks/eidas.py`.
- `icp-brasil-pades` — PAdES under the ICP-Brasil policies (AD-RB, AD-RT, AD-RC, AD-RA; DOC-ICP-15.03) with the
  `icp-brasil` profile and its policies, through the library and the CLI: the profile's trust, the policies, two-phase
  signing, PDF fields and a pt-BR stamp, validation under the ICP-Brasil policy and augmentation. The Sandbox's trust is added to the profile's; AD-RA downloads its artifacts from ITI's repository.
  Its inputs take a PDF signed with a real ICP-Brasil certificate (`icp-signed`, validated with the profile alone) and
  a PDF of yours to sign under AD-RB and AD-RT (`document`).
- `govbr-pades` — Gov.br signatures, which only Gov.br's portal makes (PAdES): validation with the `gov-br` profile and
  its policy (trust, the portal's forms, key usage) and the profile combined with ICP-Brasil's. The files are signed by the Sandbox, whose trust is added to the profile's.
  Its input `govbr-signed` takes a PDF signed on the portal: validated with the `gov-br` profile alone, raised to
  B-LTA, given a second signer.

Tests: `tests/unit/Apps/SimpleSign.TestBench.Tests/Playbooks` checks the format, the kept results and the preview, and
runs every sample against the Sandbox; it checks that the ETSI, INDECOPI and eIDAS samples cover every P item of their
checklists, that every step and section of a sample has a description, and that no framework sample repeats a generic
step. The schema is `docs/schemas/playbook.schema.json` (also
`GET /api/playbook/schema`).
