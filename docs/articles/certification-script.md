# Certification scripts

A **certification script** is the list of requirements of an accreditation guide (INDECOPI's *Guía de Acreditación
de Software*, an ICP-Brasil or eIDAS conformity scheme…) and, for each one, the TestBench steps that show it: a
signature that must be made or refused for a given reason, a file that must validate or not, or something an
operator does by hand. The TestBench runs it against a [Sandbox](sandbox.md), through the library, the CLI or both,
and writes the evidence an auditor asks for.

The script is a JSON file written **beforehand**, by hand or by an LLM working from the guide
([how to write one](../certification-scripts/AUTHORING.md)). Nothing in the TestBench is specific to a guide: what
is checked, and why, is in the file.

## Run one

1. Start a Sandbox and the TestBench, and connect them (`tools/stack/up.sh`, or the two `dotnet run` lines of
   [testbench.md](testbench.md)). Start DSS too for steps with `crossValidate`.
2. In the TestBench, open **Certification** (top bar). Open a script file, or pick a sample
   (`docs/certification-scripts/*.json` are bundled: `sandbox-basics`, `indecopi-guia-v4`).
3. The script is checked when it loads: every requirement, Sandbox signer and certificate, failure, preset and step
   reference. Errors stop it; warnings (a requirement no step shows) do not.
4. Choose the engine (as the script says, library, CLI, or both) and **Run all**, or run one section or step.
   A step that runs on both engines passes only when both show what it expects.
5. A **manual** step waits: follow its instructions, write what was shown, attach the evidence (screenshot, file)
   and mark it passed or failed.
6. **Evidence**: the page (in the script's language) has the matrix requirement → steps → result, each step with
   what was expected and what each engine found; the zip adds the script, the run, and per step the signed file,
   the validation reports (SimpleSign JSON, ETSI TS 119 102-2 XML), the run log (the CLI commands included) and the
   attachments.

Requirements marked `"applies": false` show as *not applicable* with their justification.

## What a step can do

| Kind | Runs | Expectation |
|---|---|---|
| `sign` | A TestBench signature (`options`: the Sign page's, see [options.md](../certification-scripts/options.md)) | `outcome` signed / refused / error, `reason` (the `SigningErrorReason` of a refusal), `level`, `indication`, `dssAgrees`, `logContains` |
| `validate` | A validation of `options.fileId` (`step:ID` for a file an earlier step signed, or a sample) | `outcome` valid / invalid / indeterminate, `indication`, `subIndication` |
| `manual` | Nothing: the operator decides | — |

`sandbox` puts the Sandbox in the state the step needs (CRL, OCSP, TSA or trusted-list failure, certificates to
revoke) and puts it back after the step.

The options that matter most for a certification:

- `signingPolicyId: "preset:signing:iofe"` (or `strict`, or an upload) — the checks before signing;
- `signingControls` — the trust anchors the signer and each TSA must chain to (`SandboxRoot`, `SandboxTrustedList`),
  the TSA expected (`expectedTsa`), and the audit trail (`auditLog`);
- `attemptRefused: true` — run even when the TestBench foresees the policy will refuse the signer, so the evidence is
  the library's own refusal (`SigningException` and its reason), not the TestBench's warning.

## The samples

- `sandbox-basics` — a good chain, B-LT through the Sandbox's TSA, and the cases a signer must refuse.
- `indecopi-guia-v4` — every item of Annex B of INDECOPI's guide v4.0 for signing (F-1…F-32) and verification
  (V-1…V-32) by automated agents and for the timestamp checks (S-1…S-4), in Spanish, with the IOFE policies, through
  the library and the CLI. The items about a cryptographic module or key that belongs to the solution do not apply to
  a library and say why.

Tests: `tests/unit/Apps/SimpleSign.TestBench.Tests/Scripts` checks the format and runs both samples against the
Sandbox. The schema is `docs/schemas/certification-script.schema.json` (also `GET /api/script/schema`).
