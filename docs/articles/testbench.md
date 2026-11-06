# SimpleSign TestBench

The TestBench is a local web app for signing **PAdES, CAdES and XAdES** with every option the
library has, on one screen, and for seeing what happened: the result, the verdict of two
validators, the log of every step and the code that does the same.

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

## Sandbox and Real

| | Sandbox | Real |
|---|---|---|
| Certificates | Test PKI (*AC Raiz Sandbox SimpleSign*): RSA 2048/3072/4096, ECDSA P-256/384/521, e-CNPJ, expired, not yet valid, revoked, no nonRepudiation | Your PFX, the OS store, A3 tokens (PKCS#11), real PSC/CSC accounts |
| Timestamp | Offline RFC 3161 TSA, plus one that requires HTTP Basic | DigiCert, Sectigo, FreeTSA or any URL (http, https, tcp), with Basic/Bearer and mTLS |
| Revocation | CRLs of both sandbox CAs | The certificates' real CRL/OCSP |
| Cloud | Simulated ICP-Brasil PSC (OAuth + PKCE, CPF + OTP) and CSC v2 service (PIN/OTP, SCAL 1/2, OAuth); login pages are approved automatically | Your provider; OAuth opens the system browser |
| Validation | Trusts the sandbox root | Trusts the OS roots and the ICP-Brasil roots |

Sandbox services answer on `*.sandbox.simplesign.test` through an in-process
`IHttpClientProvider`, so the library runs its normal code paths without the network. The
*Environment* panel lists the certificates, the services and every request they answered.

## One screen, two tasks

There is no menu. The top bar switches between the two tasks, **Sign** and **Validate**, which
share the same screen: the input on the left, the result on the right. Two panels open over
either task: **Reference** (what the library covers of each standard) and **Environment** (the
sandbox, with failures you can switch on). Each task keeps its own result, and both go to the same run history.

## The workbench (Sign)

The task bar picks the **format** (PAdES, CAdES, XAdES), has a shortcut for each **baseline
level** (B-B, B-T, B-LT, B-LTA) and the **Sign** button. The options are on the left, in sections
that open and close.

In the sandbox a signer and a sample document are chosen for you, so the first signature is one
click away.

### Every option names its standard

The form is drawn from one description of the options (`Schema/OptionSchema.cs`, served at
`/api/schema`). For each option it holds the explanation, the clause of the standard that defines
it and the library call it becomes. The UI shows the clause as a small badge next to the label;
hover it for every reference and the call.

| Section | What is there |
|---|---|
| What to sign | The PDF; the data and the operation (sign, co-sign, countersign) and content type of CAdES; the packaging (enveloped, enveloping, detached) of XAdES |
| Signer | Sandbox A1, PFX, OS store, A3 token (PKCS#11), PSC or CSC v2 |
| Signature level | Baseline level, explicit signature policy, the CAdES and XAdES extended forms |
| Timestamps | The TSA of the signature timestamp and of the archive timestamp, with their credentials |
| Cryptography | Digest, RSA PKCS#1 v1.5 or PSS |
| Signed attributes | Claimed signing time, commitment type, signer metadata, signer roles, MIME type |
| PDF signature field | Sub-filter, field, certification (DocMDP), reason and location, PDF/A, document information |
| Visible stamp | Position, text, colors, font, image and QR code, with a preview you can click to place the stamp |
| Run and validation | Sign now, deferred or batch; whether and how the result is validated |

The rules that say which options combine stay in `Signing/Compatibility.cs`,
`Cades/CadesCompatibility.cs` and `Xml/XmlCompatibility.cs`: an option that cannot be chosen is
hidden or locked with the reason.

**Options the library does not have.** The schema also lists what the standards define and
SimpleSign does not implement (for example CAdES signer-location and content-time-stamp, XAdES
SignatureProductionPlace and countersignature, EdDSA). They appear at the end of each section,
disabled, with their clause. The *Reference* panel shows the whole list for each format.

### Trust frameworks

The workbench opens with the generic ETSI options only. The chips in the top bar switch a
national framework on:

- **Brazil (ICP-Brasil · Gov.br)** adds the ICP-Brasil policies (AD-RB…AD-RA and their versions),
  the PBAD.PAdES sub-filter, the advanced electronic signature of Lei 14.063, health documents,
  the fiscal XML-DSig layouts, the ICP-Brasil roots and the Brazilian validation rules. These
  options are in the same sections as the others, in green and tagged **BR**.
- eIDAS and IOFE are listed as planned.

With every framework off, validation uses no `ICountryExtension`.

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

It is off by default. To run DSS locally:

```bash
docker compose -f tools/dss/docker-compose.yml up --build
```

The first build takes about 15 minutes: the server that publishes the DSS bundle is slow.
`tools/dss/README.md` explains how the container trusts the sandbox root (the TestBench keeps
that root between runs so the trust survives a restart; `--ephemeral-sandbox` makes a new one each
time) and what to expect: at B-B and B-T, DSS cannot reach the sandbox CRLs and answers
INDETERMINATE; at B-LT and B-LTA the data is embedded and the verdicts can be compared. The
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

The trust settings are the same options the workbench uses (trusted roots, revocation, and the
Brazilian rules when that framework is on).

**Samples** are built at startup in the sandbox, valid or broken in one specific way, each with
the verdict it should get:

| Format | Samples |
|---|---|
| PDF | valid B-LT, content changed, signature value changed, bytes appended, revoked signer, expired signer, root outside the trust anchors, untrusted TSA |
| CAdES | detached, enveloped, two signers plus a countersignature, data changed, signature value changed, unknown root |
| XML | XAdES enveloped and detached, signed NF-e, NF-e changed, signature value changed, unknown root |

**Validate all samples** runs every one and shows a table: expected, SimpleSign, DSS. A row opens
that run. With DSS on, most of these samples are INDETERMINATE there: they are B-B signatures and
DSS cannot fetch the sandbox CRLs.

## Run matrix (CI)

`SimpleSign.TestBench.Tests` still runs the fixed matrix of `Matrix/*.cs` in CI: every value of
every dimension on its own plus pairwise combinations, for PAdES, CAdES and XML, each case signed
in the sandbox, validated and checked. In the app, **Combinations** does the same from the option
schema, starting from the options on screen.

## Reference

The **Reference** panel lists what SimpleSign implements of each standard, from the same schema:
**by format** (every option with its clause and its library call) or **by standard** (each
clause and the options that implement it), with a filter for what is not implemented. The same
content is in [Standard coverage](coverage.md), which is generated from the schema; a test fails
when that page falls behind (`SIMPLESIGN_UPDATE_DOCS=1 dotnet test tests/unit/Apps/SimpleSign.TestBench.Tests`
writes it again).

## Environment

The **Environment** panel follows the Sandbox | Real switch.

**In Real** nothing is simulated, so it shows what really exists: the roots a validation can
trust (the operating system's, and the ICP-Brasil and Gov.br roots bundled with the library),
the public TSAs the library has a preset for, the PKCS#11 drivers and tokens found, the
certificates with a key in the OS store, what a real PSC or CSC asks for, and DSS.

**In Sandbox** it is a lab: it shows the sandbox and lets you break it on purpose. Failures only
act in Sandbox; the top bar says when one is on.

- **Test PKI** as a tree (root, intermediate CA, TSA, signers), with the download of each
  certificate, of `root.pem` and of the CRLs as they are now. *Sign with this* makes a signer the
  one used by the three formats; *Revoke now* adds it to the CRL.
- **Failures** to switch on, then sign or validate again:

  | Service | Failure | What it shows |
  |---|---|---|
  | TSA | Down (HTTP 503) | B-T and above fail, or fall back to B-B when lower levels are allowed |
  | TSA | Slow | Where the time of a signature goes |
  | TSA | Invalid token | The library refuses a token that does not verify |
  | TSA | Outside the chain | The signature validates with a TSA warning |
  | CRL server | Down | B-LT and B-LTA cannot be built |
  | CRL server | Expired CRLs | A CA that stopped publishing |

  While a failure is on, the top bar says so. *Back to normal* clears failures and revocations.
- **Services** (TSA, PSC, CSC, DSS) and the **requests** they answered, live, with a filter by
  service: sign with a cloud certificate and see the authorization and `signHash` calls.

### Cloud certificates: PSC and CSC

Both keep the key at a provider; the library sends only the hash and gets the signature back.

- **PSC** (DOC-ICP-17.01) is the ICP-Brasil cloud certificate (BirdID, VIDaaS, NeoID, SafeID…).
  You authorize on the provider's page (OAuth with PKCE) or with CPF and OTP; the token's scope
  says how many signatures it allows.
- **CSC** (Cloud Signature Consortium API v2) is the international standard, used by European
  providers. The service is authorized first; then each signature is authorized on the
  credential, with PIN and OTP or OAuth. SCAL 2 binds the authorization to the exact hashes.

The sandbox simulates one of each, in-process. In the signer picker, the PSC and CSC tabs explain
the flow step by step and, in Sandbox, **Use the simulated provider** opens a credential in one
click. The run's log then shows the provider's calls and the signer's events (73xx).

## Limitations

- Sandbox certificates do not chain to a real ICP-Brasil root: the policy version is not picked
  by root, and AD-RA embeds simulated policy artifacts.
- Empty signature fields inside compressed object streams are not listed.
- PKCS#11 needs a driver; with no token, try SoftHSM2.
- DSS cannot fetch the sandbox CRLs or reach the sandbox TSA: compare verdicts at B-LT or B-LTA.
- The clause numbers in the schema were written from the published standards; check them against
  the version of the standard you follow before quoting them.
