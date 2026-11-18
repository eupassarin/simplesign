# Accreditation audit walk-through (INDECOPI)

What to prepare, run and show the auditor to accredit `SimpleSign.Peru.Iofe.Accredited` and the `simplesign iofe`
commands under the *Guía de Acreditación de Aplicaciones de Software* v4.0, sections 4.2, 4.3 and 4.4. Everything
here was rehearsed on a development machine (macOS) against the test environment; what was not rehearsed says so.

Other languages: [Português](roteiro-de-auditoria.md) · [Español](guion-de-auditoria.md).

What the auditor is handed are the manuals ([`acreditacion/`](acreditacion/README.md) in Spanish,
[`acreditacion/en/`](acreditacion/en/README.md) in English) and the evidence this walk-through produces. This
document is for your team.

## 1. How the accreditation works

From chapter 6 of the guide ("Procedimientos de evaluación"):

1. Once chosen, the auditor hands over the list of requirements for the type of software.
2. The applicant **supports the scope** of the accreditation and **justifies what does not apply**.
3. The audit session is held with both present: the applicant shows **all the evidence of each item**. Annex B asks
   for **a screenshot per requirement** and, when a certificate is used in a test, an image of its profile.
4. The auditor gives the applicant and the commission a report, with findings and recommendations.
5. The auditor presents the evidence to the commission.
6. If approved, the applicant **presents the application's functions to the commissioners** before the resolution.
7. The commission issues the accreditation resolution.

Afterwards: **a yearly follow-up evaluation, in a real production environment** (trust, revocation and validity of
the certificate before signing), and an update evaluation when the scope changes. Fees, deadlines and forms are not
in the guide: confirm them with INDECOPI.

Who answers for what:

| The software (this walk-through shows it) | The operator (your own procedures and documents) |
|---|---|
| The checks of the certificate, the trusted list, the audit trail, transactions, the key only in a module or a remote service, the viewer, time-stamps, the manuals | The FIPS / Common Criteria certification of the HSM or the accreditation of the remote provider, key custody under two-person control, access control of the system, the code signing of your installer |

## 2. What shows it is the accredited library

| Tool | Uses `IofeSigningAgent` / `IofeVerificationAgent`? |
|---|---|
| `simplesign iofe sign \| verify \| view` | **Yes** |
| `auditoria.py` (this walk-through) | **Yes**: it runs only the commands above |
| `SimpleSign.Peru.Iofe.Accredited.Tests` | **Yes** |
| The TestBench (playbooks) and `simplesign sign --profile iofe` | No: the general signers. Complementary material, never evidence of the package |

## 3. Prerequisites

- .NET SDK 8 or 10, Python 3.9+, `curl`.
- For the PKCS#11 track of the rehearsal: SoftHSM2 and OpenSC (`brew install softhsm opensc openssl@3 jq`, or
  `apt-get install softhsm2 opensc openssl curl jq`).
- On the day, instead of the rehearsal's: the real HSM (or the real remote signing service), the real certificate,
  the real TSA.

## 4. Start the rehearsal environment

At the repository root, in two terminals:

```bash
dotnet run --project src/Apps/Development/SimpleSign.Sandbox -- --ephemeral
```

```bash
tools/stack/softhsm-provision.sh
```

```bash
export SOFTHSM2_CONF="$PWD/.softhsm/softhsm2.conf"
```

The first is the test PKI (http://localhost:5300): good and bad certificates, CRLs over HTTP/HTTPS/LDAP, OCSP, a TSA,
a trusted list laid out as INDECOPI's and a remote signing service. The second fills a SoftHSM token with the test
keys, the certificates of the issuing CAs and a key marked extractable (the one the agent must refuse).

With Docker instead, not rehearsed this time: `tools/stack/up.sh --no-dss`. On Windows there are the
`tools/stack/*.ps1` equivalents, not rehearsed either.

## 5. Install the CLI and the IOFE extension

In the rehearsal, from the source (on the day the published versions come from nuget.org):

```bash
dotnet pack src/Apps/SimpleSign.Cli -c Release -o ./nupkgs
```

```bash
dotnet pack src/Extensions/Peru/Iofe/SimpleSign.Peru.Iofe.Cli -c Release -o ./nupkgs
```

```bash
dotnet tool install --global SimpleSign.Cli --add-source ./nupkgs --version 0.13.0
```

```bash
simplesign extension install SimpleSign.Peru.Iofe.Cli --source ./nupkgs
```

```bash
simplesign extension list
```

```bash
simplesign version
```

Show the auditor: `simplesign version` (item "a" of the scope), `simplesign extension list` and
`simplesign iofe sign --help`, where there is **no** option for a policy, for skipping a check or for a PFX file.

Authenticity of the software (Req. 17, 27): `dotnet nuget verify <package>.nupkg` shows nuget.org's repository
signature on the published packages. A package built locally answers "The package is not signed". **The author's
code signing is open** (section 11).

## 6. Run the whole script

```bash
python3 src/Extensions/Peru/Iofe/tools/auditoria/auditoria.py --key both --lang en --out evidencias
```

There are 70 scenarios; with both key sources, 110 runs (about 5 minutes). Result of the rehearsal: **110 passed, 0
failed, 0 skipped**.

For each scenario the script prepares the Sandbox (switches a failure on, revokes, creates a credential), runs
`simplesign iofe …`, checks the signature or the refusal **and its reason**, and undoes the preparation. In
`evidencias/`:

| File | What it is |
|---|---|
| `informe.es.html`, `informe.en.html`, `informe.pt.html` (and `.md`) | The report by item of annex B: what the guide asks, the scenarios, the result, and each command with its output |
| `NN-scenario-key/comandos.txt` | The commands run and what each printed |
| `NN-…/auditoria.jsonl`, `verificacion.jsonl` | The scenario's audit trail |
| `NN-…/firmado-*.pdf`, `comunicado.txt`, `visor.html` | The signed document, the notice to the sender, the viewer's page |
| `NN-…/sandbox-log.json` | The requests the agent made to the CRL, OCSP, TSA and remote service |

Useful options: `--key remote` (the default; needs no token), `--key pkcs11`, `--list`, `-v` (shows everything),
`--cli "path/simplesign"`, `--sandbox URL`.

## 7. Live demonstration, item by item

The auditor picks an item; run it and it says what it does at each step:

```bash
python3 src/Extensions/Peru/Iofe/tools/auditoria/auditoria.py --item F-8 --key both --lang en
```

```bash
python3 src/Extensions/Peru/Iofe/tools/auditoria/auditoria.py --scenario contingencia --lang en
```

A suggested sequence (each name is a `--scenario`):

| What to show | Scenarios | Items |
|---|---|---|
| Trusted list: current; of another signer; changed; expired; root not listed | `tsl-vigente`, `tsl-otro-firmante`, `tsl-alterada`, `tsl-expirada`, `raiz-no-listada` | F-1 to F-3 |
| CRL over HTTP, HTTPS and LDAP; of another key; expired; without a next update | `crl-http`, `crl-https`, `crl-ldap`, `crl-clave-ajena`, `crl-expirada`, `crl-sin-proxima-actualizacion` | F-5 to F-7 |
| A revoked certificate does not sign; without CRL or OCSP nothing is signed; issuing CA revoked | `revocado`, `revocacion-no-disponible`, `cadena-revocada` | F-8, F-9 |
| OCSP: good, revoked, unauthorized response | `ocsp-vigente`, `ocsp-revocado`, `ocsp-no-autorizado` | F-10 |
| Expired, not yet valid, expired CA | `expirado`, `aun-no-valido`, `ec-expirada` | F-11 |
| Without nonRepudiation; without a signing key usage | `sin-no-repudio`, `sin-uso-de-firma` | F-12 |
| Nothing to switch off; a declared contingency; revoked under a contingency; contingency over | `sin-opcion-de-politica`, `contingencia`, `contingencia-revocado`, `contingencia-vencida` | F-14 |
| Audit: records, chain intact, chain changed; without an audit log nothing is signed | `auditoria`, `sin-registro-de-auditoria` | F-15 |
| A transaction not defined | `transaccion-no-definida` | F-16 |
| **PKCS#11 track**: key in the module; extractable key; module not declared | `clave-en-el-modulo`, `clave-extraible`, `modulo-no-declarado` | F-17 to F-19 |
| **Remote track**: key in the service; service not declared; credential a person authorizes | `clave-en-el-servicio-remoto`, `servicio-no-declarado`, `credencial-con-persona` | F-16 to F-19 |
| A PFX is not accepted; wrong PIN | `pfx-no-aceptado`, `pin-incorrecto` | F-17, F-18 |
| Algorithms: weak key, SHA-1 in the chain, current algorithms | `clave-debil`, `sha1-en-la-cadena`, `algoritmos-vigentes` | F-28 |
| Viewer; validation data (B-LT); XML and CMS | `visor`, `datos-de-validacion`, `formatos` | F-30, F-31 |
| Time-stamps: another authority, changed token, revoked TSA, expired TSA | `tsa-otra-autoridad`, `tsa-sello-alterado`, `tsa-revocada`, `tsa-expirada` | S-1 to S-4 |
| Verification: valid; revoked, with the notice; changed; without signatures; contingency; audit | `v-valido`, `v-revocado`, `v-documento-alterado`, `v-sin-firmas`, `v-contingencia`, `v-auditoria` | V-1 to V-15, V-30 |

For the screenshot annex B asks for, use the terminal with the scenario live or the scenario's section of
`informe.es.html`. The profile of the certificate used comes from `simplesign pkcs11 list --lib <driver>` (PKCS#11
track) or `simplesign csc list --csc-url … --csc-token …` (remote track), and from `simplesign iofe view`.

## 8. The report of the tests by item

```bash
dotnet test tests/unit/Extensions/Peru/Iofe/SimpleSign.Peru.Iofe.Accredited.Tests --framework net10.0 --filter "AnnexB~-" --logger "html;LogFileName=anexo-b.html" --results-directory evidencias/pruebas
```

```bash
dotnet test tests/unit/Extensions/Peru/Iofe/SimpleSign.Peru.Iofe.Accredited.Tests --filter "AnnexB=F-8"
```

In the rehearsal: 33 passed and 6 were skipped, because the token tests need SoftHSM; in Docker,
`scripts/tests/pkcs11.sh` runs them all with none skipped. `AnnexBCoverageTests` fails when an item that can be shown
is left without a test or a scenario.

## 9. On the day: what changes

| In the rehearsal | On the day |
|---|---|
| The Sandbox (a test PKI) | The real PKI: a certificate issued by an accredited CA |
| `--tsl http://localhost:5300/tl/tl.xml --tsl-signer …` | Nothing: by default the agent uses INDECOPI's list |
| The SoftHSM token, `--module-… "SoftHSM…"` | The real HSM: its maker's `--pkcs11-lib` and `--module-manufacturer/-model/-certification/-certificate` with the data of its FIPS 140-2 or Common Criteria certificate |
| The Sandbox's remote service | The provider's service: `--csc-url`, client credentials and `--service-…` with its accreditation |
| The Sandbox's TSA | The TSA under contract: `--tsa URL --tsa-cert file` |
| Local packages | `dotnet tool install --global SimpleSign.Cli` and `simplesign extension install SimpleSign.Peru.Iofe.Cli` from nuget.org |

In the real HSM, when the module holds the signing certificate alone, the agent completes the chain with the
issuing CAs' certificates given with `--chain file` or, without them, downloaded from the address the certificate
itself names (AIA). When an issuer is still missing, the refusal is `UntrustedRoot` and the message says which.
Rehearsed with a token without the CAs' certificates: refused without network, signed with `--chain` and signed
through AIA.

The failure scenarios (a CRL signed by another key, a revoked TSA) depend on the Sandbox: with the real PKI you show
the good path and the refusals that need no failure of a third party (transaction, module not declared, an option
that does not exist, PFX, contingency). The rest comes from the rehearsal's report. **Not rehearsed**: a real HSM, a
real remote service and INDECOPI's real list, this time.

## 10. Filling in annex B

Use `evidencias/informe.es.html`: the table "Por ítem del Anexo B" gives, for each item, the scenarios and the
result; each scenario has the command and its output. The full correspondence, with the tests, is in
[`playbooks/indecopi-checklist.md`](../playbooks/indecopi-checklist.md) (the table "Shown by the accredited package
itself"). The scope data (items a–k) is in [`acreditacion/en/scope.md`](acreditacion/en/scope.md).

Items to declare **not applicable or the operator's**, with the reason:

| Items | Reason |
|---|---|
| F-13, V-13 | Access control belongs to the product and to the system that hosts the library |
| F-20 to F-27, V-18 to V-27 | Key custody: the operation of the HSM. With the key in a remote service the module is the provider's |
| V-16, V-17, V-31 | The verification agent does not sign the documents it receives |
| F-4, V-4 | The periodic reload of the list: the library's (`IofeTrustedListSource`), shown by tests, not by a command |
| F-29, V-29 | **Open** (section 11) |
| Section 4.1 | Outside the scope of this package |

## 11. What is not covered, and what the rehearsal showed

- **Code signing (F-29 / V-29): open.** The packages have no author signature and the assemblies no Authenticode
  signature. It depends on the code-signing certificate.
- **A PFX / PKCS#12 file is not a key source** of the accredited package, because it contradicts Req. 15. No option
  enables it.
- **Section 4.1** (end-user software) is not covered.
- **Remote track**: the provider's accreditation and that the key cannot be extracted are a declaration of the
  operator; the protocol does not report them.
- The **verification agent** is created before there is a document: when it cannot read the trusted list, the
  command fails with the reason but there is no verification record (there is no document to record). A signing agent
  that does not open is recorded (`AgentNotOpened`).
- The agent signs at B-B (without a TSA) or B-LT (with one); there is no B-LTA in the accredited package.

## 12. Common problems

| Symptom | Cause and fix |
|---|---|
| `Error (RevocationStatusUnknown)` against the Sandbox | The CLI refuses local addresses: add `--allow-origin http://localhost:5300` (the script does) |
| `Error (UntrustedRoot)` on the PKCS#11 track | An issuing CA's certificate is missing and could not be downloaded (the message says which): `--chain file`, or `tools/stack/softhsm-provision.sh --force` in the rehearsal |
| `(pkcs11)` scenarios skipped | `SOFTHSM2_CONF` is not exported or the token was not provisioned |
| `Unknown option --…` in `simplesign iofe` | The command has no such option; unknown options are an error, on purpose |
| The Sandbox was restarted and the token "does not match" | Each `--ephemeral` Sandbox has a new PKI: provision again |

## 13. A suggested order for the presentation

1. Scope and what does not apply (`scope.md`, section 10) — 10 min.
2. Installation and version; `iofe sign --help` with no way around — 5 min.
3. The report of the whole script (`informe.es.html`) — 10 min.
4. Items live, as the auditor picks them (section 7) — 30 to 40 min.
5. The audit trail: `simplesign audit verify`, a changed record — 5 min.
6. The viewer and the notice to the sender — 5 min.
7. The report of the tests by item — 5 min.
8. The manuals and the security configuration; what is open (section 11) — 10 min.
