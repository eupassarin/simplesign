# SimpleSign TestBench

The TestBench is a local web app for signing **PAdES, CAdES and XAdES** with every option the
library has, on one screen, and for seeing what happened: the result, the verdict of two
validators, the log of every step and the code that does the same.

It covers the ETSI standards only (PAdES, CAdES and XAdES baseline signatures, EN 319 102-1
validation, RFC 3161 timestamps). National trust frameworks (ICP-Brasil, Gov.br, IOFE…) and the
visible signature stamp are library features that will get apps of their own.

```bash
dotnet run --project src/Apps/SimpleSign.TestBench          # http://127.0.0.1:5199, opens the browser
dotnet run --project src/Apps/SimpleSign.TestBench -- --port 5200 --no-browser
```

The UI is in **English (en-US) and Portuguese (pt-BR)**: it follows the browser's language, and
the selector in the top bar overrides it (saved in the browser). The explanations, the rule
messages and the sample descriptions come from the server in the same language
(`Accept-Language`). Library names, OIDs, standard terms and the generated code stay as they are.

The first run builds the UI (Node.js 20+ needed; `npm ci && npm run build` in
`src/Apps/SimpleSign.TestBench/web`). To work on the UI with hot reload, run the app and, in another
terminal, `npm run dev` in `web/` (Vite on :5173, proxying `/api` to :5199). The app listens on
127.0.0.1 only. Uploads, keys and token sessions stay in memory and are gone when it stops.

## Real network, plus a Sandbox

The TestBench always works on the real network: your PFX, the OS store, A3 tokens (PKCS#11), real
CSC accounts, the public TSAs (DigiCert, Sectigo, FreeTSA or any URL, with Basic/Bearer and mTLS)
and the certificates' real CRLs and OCSP responders. Validation trusts the OS roots.

For test certificates and services, connect a [SimpleSign Sandbox](sandbox.md), a separate app
with a test PKI and real CRL (HTTP, HTTPS, LDAP), OCSP, TSA and CSC endpoints:

```bash
dotnet run --project src/Apps/SimpleSign.Sandbox             # http://localhost:5300
```

Then, in the TestBench, open the **Sandbox** panel (flask icon) and connect to its address, or start
the TestBench with `--sandbox http://localhost:5300` (or `SIMPLESIGN_SANDBOX_URL`). The connection
is remembered for the next start. While connected:

| | |
|---|---|
| Certificates | The Sandbox's signers (every key type, revoked by CRL or OCSP, under a revoked or expired CA, expired, weak key…), picked from the signer list or with **Sign with** in the panel |
| Timestamp | Its TSAs: normal, HTTP Basic (credentials filled in), outside the chain, revoked, wrong TSA name |
| Cloud | Its CSC v2 service (PIN/OTP, SCAL 1/2, OAuth approved at once) |
| Revocation | Its CRLs and OCSP, reached through an `OutboundHttpPolicy` that lists its origins (`LoopbackOrigins`, LDAP allowed) |
| Validation | Its trusted list (read through its LOTL, `/tl/lotl.xml`) is trusted next to the OS roots, so the `TrustedLists` constraints are evaluated; "Sandbox root" trusts its root alone as a bare anchor. Its root is also trusted for its HTTPS endpoint |

The **Sandbox** button in the top bar is the one place for it. Not connected, it opens a popup with the
address, **Connect** and how to start one. Connected, it opens everything: an overview (its addresses, its
signers with **Sign with**, its root for Adobe), its environment, its PKI (revoke, take back, download PFX
and certificates), its failures and its request log. These go through the Sandbox's own admin API, passed
through by the TestBench (`/api/sandbox/admin/…`): the Sandbox keeps the state, so a failure switched on by
a playbook or `curl` shows here too. The button turns red while a failure is on.
Without a Sandbox, the Sandbox signers and TSAs are disabled and the validation samples that need
signed files are not built.

## One screen, two tasks

There is no menu. The top bar switches between the two tasks, **Sign** and **Validate**, which
share the same screen: the input on the left, the result on the right. Right after them, in the same bar:
the engine (**Library** or **CLI**); the panels **Policies**, **Reference** (what the library covers of each
standard) and **Environment** (what this machine has), which open over either task; and the outside
services, **Sandbox** and **DSS**. The DSS popup also shows how the DSS of `tools/dss` was set up: how it
trusts the Sandbox (its trusted list, its root, or not at all), the EU lists, the ICP-Brasil, Gov.br,
Peruvian and TSA roots, the revocation cache, and every trusted certificate. Each task keeps its own result, and both go to the same run history.

## The workbench (Sign)

The task bar picks the **format** (PAdES, CAdES, XAdES), has a shortcut for each **baseline
level** (B-B, B-T, B-LT, B-LTA) and the **Sign** button. The options are on the left, in sections
that open and close.

With a Sandbox connected, a signer and a sample document are chosen for you, so the first
signature is one click away.

### Every option names its standard

The form is drawn from one description of the options (`Schema/OptionSchema.cs`, served at
`/api/schema`). For each option it holds the explanation, the clause of the standard that defines
it and the library call it becomes. The UI shows the clause as a small badge next to the label;
hover it for every reference and the call.

| Section | What is there |
|---|---|
| What to sign | The PDF; the data and the operation (sign, co-sign, countersign) and content type of CAdES; the packaging (enveloped, enveloping, detached) of XAdES |
| Signer | Sandbox A1, PFX, OS store, A3 token (PKCS#11) or CSC v2 |
| Signature level | Baseline level, explicit signature policy, the CAdES and XAdES extended forms |
| Timestamps | The TSA of the signature timestamp and of the archive timestamp, with their credentials |
| Cryptography | Digest, RSA PKCS#1 v1.5 or PSS |
| Signed attributes | Claimed signing time, commitment type, signer metadata, signer roles, MIME type |
| PDF signature field | Sub-filter, field, certification (DocMDP), reason and location, PDF/A, document information |
| Run and validation | Sign now, deferred or batch (PDF), in two phases (CAdES, XAdES); whether and how the result is validated |

The rules that say which options combine stay in `Signing/Compatibility.cs`,
`Cades/CadesCompatibility.cs` and `Xml/XmlCompatibility.cs`: an option that cannot be chosen is
hidden or locked with the reason.

**Options the library does not have.** The schema also lists what the standards define and
SimpleSign does not implement (for example CAdES signer-location and content-time-stamp, XAdES
SignatureProductionPlace and countersignature, EdDSA). They appear at the end of each section,
disabled, with their clause. The *Reference* panel shows the whole list for each format.

### Signing and validation policies

Both policies are JSON files (ADR 0024), uploaded in the
options; without a file, the library's default applies. **Download the default** next to each
upload gives the file to start from (also at `GET /api/policies/signing` and
`GET /api/policies/validation`, or `simplesign policy export signing|validation`).

- **Signing policy (JSON)**, in every format: the checks the signer runs on the certificate, key and
  algorithm before signing (root `SigningConstraints`). The option check evaluates the chosen
  certificate against it (`SigningPolicy.Evaluate`): a constraint at FAIL is an error, at WARN a
  warning. To check the revocation of the chain, set `SigningCertificate/NotRevoked` and
  `CACertificate/NotRevoked` to FAIL; to try a certificate the default refuses, set the constraint to
  IGNORE.
- **Validation policy (JSON)**, with the **Validation level** and the **Revocation strategy**, in the
  validation options (after signing and in the Validate page): the constraints and levels of the
  validator (root `ValidationConstraints`). The ETSI sub-indication is shown next to the indication,
  with the policy's checks as rows. With DSS on, the same policy goes to DSS, translated to its format (see docs/policies/compatibility.md).

The Code tab loads the files as `signing-policy.json` and `validation-policy.json`
(`SigningPolicy.Load`, `ValidationPolicy.Load`, `--signing-policy`, `--policy`).

**Policies** in the top bar opens the policy viewer: the default signing or validation policy, or a
JSON file you open, as a tree. Each element shows what it checks, the clause that defines it
(EN 319 102-1, RFC 5280, EN 319 412-5…), its level and, for the validation policy, whether
SimpleSign evaluates it (the others are reported as not checked, while DSS evaluates them). A
summary counts the constraints per level. Click a level to change it; the JSON tab edits the file
directly. **Download JSON** saves it; **Use for signing** / **Use for validation** uploads it as the
policy of the next runs (and of DSS). The same view is at `POST /api/policies/view`.

### The result

| Tab | What it shows |
|---|---|
| Result | Requested and achieved level, size, times, the verdict of each signature, warnings, download |
| Inspection | What is inside the file: DSS, document timestamp, DocMDP and a page preview (PDF); the CMS structure (CAdES); the Signature element (XAdES) |
| Validation | SimpleSign's verdict with every check, and the DSS verdict next to it (see below) |
| Logs | Every library log event and network request of the run |
| Code | The exact C# builder calls and the equivalent `simplesign` command. Secrets are never printed |

**Logs.** The run passes its own logger to every builder and validator (`WithLogger`), so the tab
shows what the library did, live. Events are grouped by the stage of the signature they belong
to (prepare, digest, signed attributes, signature, signature timestamp, validation data, archive
timestamp, read-back check, validation), and each stage names the clause it implements. The
requests to the TSA, CRL and OCSP servers and to cloud signers are on the same timeline. There is
also a plain timeline view, a text filter, and a switch for the debug lines.

**History.** Every run of the session is kept; open one again, or start from its options.

### Many combinations quickly

- **Presets** set the baseline level in one click.
- **Combinations** signs once for every value of one option, or for the combinations of several,
  keeping the rest as it is. With several options choose *all combinations* or *pairwise* (a small
  set in which every pair of values still appears together at least once); *Everything, in
  pairs* takes every option of the format. Combinations the rules refuse are listed with the
  reason and not run.
- Each line is a normal run: achieved level, the verdicts of SimpleSign and DSS, the time, and
  the result, log and code on a click. There is a summary per value ("SHA-384 4/4") and filters
  for the failed ones, the ones where DSS differs, and the ones not run.

## Cross-validation with DSS

The [EU DSS](https://github.com/esig/dss) is an independent implementation of the validation
algorithm of ETSI EN 319 102-1. With **DSS** on in the top bar, every run is also sent to its REST
validation service, and the Validation tab lines the two verdicts up: indication and
sub-indication, detected level, and the DSS messages when they differ. The DSS report can be
downloaded.

**Reports.** Every validation also writes SimpleSign's JSON report: the library's simple report
(what `simplesign validate --simple-report` writes), plus each signature's certificate chain,
every constraint result of the policy, and what each timestamp, CRL and OCSP response says (TSA,
issuer, dates, the certificate it is about and its status). Next to each download, *View report*
opens either JSON (SimpleSign's or DSS's) in a viewer that explains it, in English or Portuguese:
the indication and sub-indication in plain words, the signer's chain, the timestamps, the
revocation data, and the checks grouped by outcome (failed, warnings, passed, not checked), with
the raw JSON folded below. `GET /api/reports/{id}` returns that reading.

**Samples.** *Validate all samples* (Validate task) runs every Sandbox sample and lines up what each
should get with what SimpleSign and DSS say: one entry per signature, the indication as a badge
and the ETSI sub-indication (or `TOTAL_PASSED`) under it, and both reports one click away.

It is off by default. To run DSS locally:

```bash
docker compose -f tools/dss/docker-compose.yml up --build
```

The first build takes about 15 minutes: the server that publishes the DSS bundle is slow.
`tools/dss/README.md` explains how the container trusts the Sandbox root (fetched from the
Sandbox when the container starts) and what to expect: with the default Sandbox environment, DSS
cannot reach its CRLs at B-B and B-T and answers INDETERMINATE (an environment created with
`--public-base-url http://host.docker.internal:5300` fixes that); at B-LT and B-LTA the data is
embedded and the verdicts can be compared. The
address can also point to a DSS you already run.

The same service backs an automated check: `DssCrossValidationTests` (in
`tests/unit/Apps/SimpleSign.TestBench.Tests`) signs with the optional CAdES attributes and XAdES
properties and asserts what DSS reads from each file: signatures and timestamps intact, every signed
reference found, the structure valid, the baseline level the one asked for. It runs with the rest of
the suite and is skipped when no DSS answers at `SIMPLESIGN_DSS_URL` (default `http://localhost:8080`).

## Validate

The Validate task checks a file that already exists. Drop a signed PDF, a CMS signature (.p7s,
.p7m) or a signed XML: **the format is read from the file**. A detached signature also takes the
original data.

A validation is a run like a signature, so the result is the same panel: the verdict of each
signature with every check, the DSS verdict next to it when cross-validation is on, what is
inside the file (per signature for PDF, with the dump of the signature objects and the CMS for
download; the CMS structure for CAdES; the Signature element for XML), the log and the code.
**Open in Validate**, on the result of a signature, brings the file here.

The trust settings are the same options the workbench uses (trusted roots and revocation).

**Samples** are built when a Sandbox is connected (and again with **Rebuild the samples**), valid
or broken in one specific way, each with the verdict it should get:

| Format | Samples |
|---|---|
| PDF | valid B-LT, content changed, signature value changed, bytes appended, revoked signer, expired signer, root outside the trust anchors, untrusted TSA |
| CAdES | detached, enveloped, two signers plus a countersignature, data changed, signature value changed, unknown root |
| XML | XAdES enveloped and detached, document changed, signature value changed, unknown root |

**Validate all samples** runs every one and shows a table: expected, SimpleSign, DSS. A row opens
that run. With DSS on, most of these samples are INDETERMINATE there unless the Sandbox environment
names an address DSS reaches: they are B-B signatures.

## Playbook

The **Playbook** tab (after Sign and Validate) runs a [playbook](playbook.md): sections of steps written beforehand,
each with free tags, against the Sandbox, through the library, the CLI or both. In three columns: the steps (filter by
tag, run one, a section or all), everything the selected step will do before it runs (what is signed and by whom,
every setting by group, the Sandbox changes, the expectation, the C# and CLI commands), and its latest result with
every detail (expected and found per engine, the report in a dialog, files, CLI commands, log). Results stay while the
TestBench runs (**Clear result** forgets one, **Restart** all of them); the evidence (an HTML page and a zip) is built
from them. Samples: `sandbox-basics` and INDECOPI's
guide v4.0. The **Options reference** button opens, in the UI's language, what a step can hold: the option paths of
each format, the symbolic values (`sandbox:`, `sample:`, `preset:`, `step:`…) and the Sandbox failures and ids; its
Markdown version ([options.md](../playbooks/options.md)) is the one to attach for an LLM.

The options it relies on are on the Sign page too: built-in signing and validation policies (`strict`, `minimal`,
`iofe`…) next to an uploaded file, the trust anchors and expected TSA of the checks made before signing, the audit
trail, and **Attempt refused signatures**, which runs even when the signing policy is foreseen to refuse the signer,
so the result shows the library's own refusal and its reason.

## Run matrix (CI)

`SimpleSign.TestBench.Tests` still runs the fixed matrix of `Matrix/*.cs` in CI: every value of
every dimension on its own plus pairwise combinations, for PAdES, CAdES and XML, each case signed
with the Sandbox's certificates, validated and checked. In the app, **Combinations** does the same from the option
schema, starting from the options on screen.

## Reference

The **Reference** panel lists what SimpleSign implements of each standard, from the same schema:
**by format** (every option with its clause and its library call) or **by standard** (each
clause and the options that implement it), with a filter for what is not implemented. The same
content is in [Standard coverage](coverage.md), which is generated from the schema; a test fails
when that page falls behind (`SIMPLESIGN_UPDATE_DOCS=1 dotnet test tests/unit/Apps/SimpleSign.TestBench.Tests`
writes it again).

## Environment

The **Environment** panel shows what really exists on this machine: the roots a validation can
trust (the operating system's), the public TSAs the library has a preset for, the PKCS#11 drivers
and tokens found, the certificates with a key in the OS store, what a real CSC service asks for,
and DSS.

## Cloud certificates: CSC

A cloud certificate keeps the key at a provider; the library sends only the hash and gets the
signature back. **CSC** (Cloud Signature Consortium API v2) is the international standard: the
service is authorized first; then each signature is authorized on the credential, with PIN and
OTP or OAuth. SCAL 2 binds the authorization to the exact hashes.

The Sandbox runs a CSC service. In the signer picker, the CSC tab explains the flow step by step
and, with a Sandbox connected, **Use the simulated provider** opens a credential in one click.
The run's log then shows the provider's calls and the signer's events (73xx).

## Limitations

- Empty signature fields inside compressed object streams are not listed.
- PKCS#11 needs a driver; with no token, try SoftHSM2.
- DSS cannot reach a Sandbox whose certificates name `localhost`: compare verdicts at B-LT or B-LTA,
  or create an environment with `--public-base-url` (see `tools/dss/README.md`).
- The tests (`SimpleSign.TestBench.Tests`) need a running Sandbox at `SIMPLESIGN_SANDBOX_URL`
  (default `http://localhost:5300`); without one they are skipped, and with
  `SIMPLESIGN_REQUIRE_SANDBOX=true` (CI) they fail.
- The clause numbers in the schema were written from the published standards; check them against
  the version of the standard you follow before quoting them.
