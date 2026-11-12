# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added — Traces and metrics (`SimpleSignTelemetry`)

- An `ActivitySource` and a `Meter` named `SimpleSign` (constants in `SimpleSign.Core.Diagnostics.SimpleSignTelemetry`):
  activities, counters and duration histograms for signing (format, requested/achieved level, outcome, reason — every
  signer, deferred included), TSA requests, OCSP requests, CRL fetches (cache hit), trusted-list loading and
  validation (format, indication). Tags hold no payload, certificate data, full URL or personal data. Nothing is
  measured when nobody listens. See `docs/articles/observability.md`.

### Added — Sandbox: signers with a chosen subject

- `POST /api/certificates/custom` issues a signing certificate under the intermediate CA with a subject given as a DN
  string or a list of attributes (`CN`, `serialNumber`, `C`, `O`, `OU`, `L`, `ST`, `T`, `G`, `SN`,
  `organizationIdentifier`; checked for length and characters), an optional key type, key usage and validity. It is
  listed with the other certificates (`custom-…`): revocable, downloadable as PFX/CER, answered by OCSP and the CRLs;
  `POST /api/reset` removes it.
- `--signing-country XX` (or `none`) sets the country of the seeded signers' subject when an environment is created;
  `BR` stays the default and existing environments keep theirs.

### Added — `DataToSignInspector`: what is about to be signed; the Agent signs only signature data

- `DataToSignInspector.Inspect(data, certificate)` recognizes the two `ExternalSigningPayloadKind`s: DER CMS signed
  attributes (one `contentType`, one `messageDigest`, and a `signingCertificateV2`/`signingCertificate` that must name
  the given certificate) and a canonical XML-DSig `SignedInfo` (no declaration or DTD, its methods, at least one
  reference with a digest). It returns the kind, the digests with their algorithm (`DataToSignDigest.ToShortString()`
  for a consent dialog) or the reason for refusing (`DataToSignRefusal`).
- **Behavior change — SimpleSign.Agent:** `POST /api/sign` now refuses, with 400 and before asking the user, any item
  that is not signed attributes or a `SignedInfo` (a raw hash, a document, bytes of another protocol), and the
  confirmation dialog shows the digest being signed. Token signatures carry the detected payload kind. The self-test
  signs real signed attributes.

### Added — `SigningCertificateCheck`: will this certificate be accepted?

- `SigningCertificateCheck.EvaluateAsync(certificate, SigningCertificateCheckOptions)` runs the checks the signers
  make before signing — validity of the certificate and its chain, key usage, key and algorithms, chain to the trust
  anchors (`SigningCertificate/ProspectiveCertificateChain`) and revocation of the chain (`IChainRevocationChecker`) —
  without signing, and returns every finding with the `SigningErrorReason` a signer would refuse with. It never throws
  for a refused certificate. Same code path as the signers (`SignerAcceptance`), not a copy.

### Added — PKCS#11: PIN warning flags of a token

- `Pkcs11TokenInfo.IsPinCountLow`, `IsPinFinalTry`, `IsPinToBeChanged` and `IsUserPinInitialized`, read from
  `CK_TOKEN_INFO.flags` by `Pkcs11Signer.ListTokens` with `IsPinLocked`: warn the user before a wrong PIN locks the
  token. Init-only properties; the positional constructor is unchanged.

### Added — `AuditChain`: the audit hash chain for any store

- `AuditChain.Canonicalize(SignatureAuditEvent)`, `AuditChain.Link(previousHash, content)`, `AuditChain.Append`,
  `AuditChain.Genesis`, `AuditChain.Follows` and `AuditChain.Verify(IEnumerable<AuditChainRecord>)`: the content and
  SHA-256 chaining of `JsonLinesAuditSink`, public so that a database-backed `ISignatureAuditSink` produces the same
  chain and can be checked the same way. `JsonLinesAuditSink` uses them; its file format is unchanged and existing logs
  keep verifying.

### Fixed — IOFE: timestamping authorities that INDECOPI's list types as `unspecified`

- INDECOPI's trusted list publishes some accredited TSAs as `Svctype/unspecified` (Llama.pe's
  "Timestamping CA", BPO Advisors' and Girasol's TSUs), which `TrustedList` dropped by default. A Llama.pe
  timestamp whose token carries the TSU certificate only then failed to chain to Llama.pe's root and was refused
  under `IofePolicies.Signing` (`TimestampUntrusted`). `IofeExtension` now reads the list with
  `IofeExtension.DefaultListOptions`: the usual CA/TSA types plus `unspecified`, leaving out code-signing
  certificates (the same type holds the accredited signature software). `Load(byte[], …)` uses them too.
- `TrustedListOptions.ExcludedExtendedKeyUsages`: extended key usages that keep a certificate of a kept service from
  becoming a trust anchor.

### Added — Playbooks in the TestBench (the Playbook app is gone)

- **TestBench → Playbook tab** (after Sign and Validate; it was the Certification page): loads a playbook (JSON,
  schema 2, `docs/schemas/playbook.schema.json`) written beforehand — sections of steps, each with free tags — checks
  it against the connected Sandbox and runs one step, a section or all, through the library, the CLI or both. Three
  columns: the steps (filter by tag), everything the selected step will do before it runs (what is signed and by
  whom, every setting by group, Sandbox changes, expectation, C# and CLI commands), and its latest result with every
  detail (report in a dialog, files, CLI commands, log). The latest result of each step is kept while the TestBench
  runs. Evidence: an HTML page (steps by section, summary by tag) and a zip with the playbook, the results, and per
  step the signed file, reports and log. API under `/api/playbook`.
- **Playbook tab details:** a two-row toolbar; a tag filter with autocomplete (several tags at once); C# and CLI in
  their own tabs with syntax colors; before a step runs, column 3 shows its JSON as written (and the defaults,
  collapsed); **Clear result** for one step and **Restart** for all; the loaded playbook can be viewed (colored JSON) or
  downloaded; **Options reference**, a dialog in the UI's language with every option path per format, the symbolic
  values and the Sandbox's failures and ids (`/api/playbook/sandbox`; the Markdown stays for LLMs).
- **EU DSS cross-validation in a playbook:** `crossValidate` in `defaults` or on a step; the preview shows it (Run card),
  results and evidence say "DSS unavailable" when DSS does not answer (the step still runs; it fails only with
  `expect.dssAgrees`), and the validator warns about `dssAgrees` without `crossValidate` or on a refusal. The INDECOPI
  playbook turns it on.
- **Samples:** `docs/playbooks/sandbox-basics.json` (the old Playbook app's sample) and `indecopi-guia-v4.json` (the
  automated part of INDECOPI's guide v4.0, Annex B, in English, tagged with the guide's item ids; written by
  `tools/playbooks/indecopi.py`). `AUTHORING.md` is the kit to have an LLM write one; `options.md` is generated from
  the TestBench.
- **Built-in policies:** `strict`, `minimal`, `iofe` (signing) and `iofe`, `iofe-nonrepudiation` (validation), in the
  TestBench's policy fields and as names for the CLI's `--signing-policy` / `--policy` and `policy export --preset`.
- **IOFE:** `IofePolicies.Signing` turns on the trust anchor, CRL nextUpdate, chain cryptography and TSA checks;
  `IofePolicies.Validation` refuses an expired or badly signed trusted list; new `ValidationNonRepudiation` (Req. 23).
  Written out in `docs/policies/iofe-*.json`.
- **CLI sign commands:** `--trust`, `--trust-dir`, `--tsl/--tsl-signer` (trust anchors before signing),
  `--expected-tsa`, `--audit-log`; `--signing-policy` on `sign-dir` and `deferred`; `simplesign audit verify`.
- **TestBench options:** trust anchors before signing, expected TSA, audit trail (shown in the log), and *Attempt
  refused signatures*. CLI runs against the Sandbox now pass `--allow-ldap`, its HTTPS origin and `--tls-trust` with
  its root, so CRLs over HTTPS and LDAP work through the CLI too.
- **TestBench and the new Sandbox cases:** the TSA choice *Sandbox, expired TSA* (`SandboxExpired`) and the CRL failure
  `NoNextUpdate`; the INDECOPI playbook uses them, the SHA-1 CA and the signer without KeyUsage, so the expired TSA, the
  SHA-1 chain and the CRL without nextUpdate are automated steps.

### Added — ETSI conformance playbook

- `docs/playbooks/etsi-checklist.md`: what a run must show for each ETSI standard (PAdES, CAdES, XAdES baseline and
  extended, RFC 3161 / EN 319 422, EN 319 102-1 validation, TS 119 612, EN 319 412 / TS 119 312), each item marked as
  shown by a playbook, by unit tests, needing something new, or out of scope.
- `docs/playbooks/etsi-baseline.json` (bundled sample, written by `tools/playbooks/etsi.py`): 115 steps covering every
  item a run can show, tagged with the item ids and standards, cross-validated with EU DSS.
- Playbooks: `sandbox-short-lived:N` (a Sandbox signer valid for N seconds, issued when the step runs), `fixture:NAME`
  (bundled signature-policy document, attribute certificate and SAML assertion) and a step's `wait`. New CAdES samples
  `v-ts-order` (content time-stamp later than the signature time-stamp) and `v-wrong-cert-ref`; built-in validation
  policy `strict` (TestBench and CLI `--policy strict`). Sandbox: `/tsa/shifted?seconds=N`, a TSA whose clock is off;
  short-lived signers are valid from two hours back, so their CRL and OCSP data is not older than them.

### Fixed

- Validation: a time-stamp whose TSA could not be judged still counts for the order of the time-stamps
  (TIMESTAMP_ORDER_FAILURE), and a signing-certificate reference that is missing, repeated or does not match is
  INDETERMINATE / NO_SIGNING_CERTIFICATE_FOUND (EN 319 102-1 §5.2.3), as in EU DSS, instead of SIG_CONSTRAINTS_FAILURE.
- CAdES validation: the signature time-stamp is evaluated in the policy's Timestamp context also when no trust
  anchors are passed to the call (its TSA is judged against the configured roots, as the content and archive
  time-stamps already were).
- Validation: a detached CAdES or XAdES signature validated without its data is INDETERMINATE / SIGNED_DATA_NOT_FOUND
  (it was INVALID, or for CAdES a result with no evaluation); the data's integrity is not judged without it.
- Validation: a signature that names a signature policy whose document it does not carry now has `PolicyAvailable`
  false, so a validation policy that requires it (`PolicyAvailable` FAIL, as the `strict` preset) gives
  INDETERMINATE / SIGNATURE_POLICY_NOT_AVAILABLE. New `ValidationOptions.SignaturePolicyDocuments`
  (`ISignaturePolicyDocumentProvider`) supplies policy documents from elsewhere. The default policy only informs.

### Added — Augmenting existing signatures (ADR 0025)

- `PadesAugmenter`, `CadesAugmenter` and `XadesAugmenter` raise a signed file to B-T, B-LT or B-LTA without touching
  what is signed, and `RenewArchive` adds a new archive (or document) time-stamp to a B-LTA. A level that cannot be
  reached throws `SigningException` (`LevelNotAchievable`).
- CLI: `simplesign augment <file> --level BT|BLT|BLTA --tsa URL [--data] [--signature-id] [--renew] [--json]`.
- TestBench: run kind `augment`; playbook steps of kind `augment` (options `fileId`, `dataId`, `level`, `timestamp`,
  `renew`; outcome `augmented`). The ETSI playbook raises a B-B of each format to B-LTA and renews a PAdES B-LTA.
- The PAdES conformance detector counts a document time-stamp after a signature as its B-T time-stamp (EN 319 142-1).

### Added — Past signature validation with archive time-stamps (ADR 0027)

- When the signature time-stamp is intact but its TSA is no longer trusted (its certificate expired), a later trusted
  time-stamp over it gives it back its trust: the archive-time-stamp of CAdES, the ArchiveTimeStamp of XAdES, a later
  document time-stamp of PAdES. The earlier TSA's chain is built at the later token's time (EN 319 102-1 §5.6). A B-LTA
  whose signer and signature TSA both expired stays TOTAL_PASSED.
- Sandbox: `/tsa/short-lived?seconds=N`, a TSA whose certificate is issued per request and valid N more seconds.
  TestBench: TSA provider `SandboxShortLived` (30 s). The ETSI playbook covers VA-9 with the signature TSA expired too,
  for PAdES and CAdES; the checklist has no open items left.

### Added — Trust anchors at a time: trusted-list service history (ADR 0026)

- `TrustedList` reads each service's `StatusStartingTime` and `ServiceHistory` (`TrustedListService.StatusAt`) and
  gives `GetTrustAnchors(DateTimeOffset at)`. New `ITimedTrustAnchorProvider`, implemented by `TrustedList` and
  `TrustedListSet`.
- `ValidationOptions.TimedTrustAnchors`: when today's anchors do not trust a certificate, the PAdES, CAdES and XAdES
  validators use the anchors of the time-stamp's genTime (for its TSA) and of the signature's proof of existence (for
  the signer). A signature time-stamped before its CA's service was withdrawn stays valid. The CLI passes `--tsl` and
  `--lotl` lists this way.
- Fixed: the CAdES and XAdES validators now judge the signature time-stamp's TSA with `ValidationOptions.TrustedRoots`
  too (it gave no proof of existence without anchors passed to the call), and the XAdES time-stamp keeps its genTime.
- Sandbox: trusted-list failure `WithdrawnAfterUse` (the root CA's service withdrawn now, granted before in its
  history). TestBench: built-in signing policy `anchored` (the chain must reach the signer's trust anchors). The ETSI
  playbook covers TL-5.

### Added — ETSI report schema and EN 319 422 time-stamp profile

- `ValidationReports.ValidateEtsiXml`: checks a TS 119 102-2 report against its schema (v1.2.1), embedded with the
  schemas it imports; nothing is fetched (the schema test is offline now).
- Validation policy constraints `Timestamp/AccuracyPresent`, `Timestamp/OrderingFalse` and
  `Timestamp/AcceptablePolicies` (the EN 319 422 profile of a time-stamp: accuracy given, no ordering, an accepted
  TSA policy). Not in the default policy, so nothing changes until a policy sets them.
- TestBench: library runs also produce the ETSI report (`etsi-report.xml`); playbooks can expect `etsiReport: valid`.
  Sandbox TSAs give their accuracy (one second); `/tsa/no-accuracy` does not.
- TestBench: the files of a playbook's kept results (signed output, reports) are no longer forgotten when more than
  200 files are produced, so a long playbook's validation steps and evidence keep finding them.

### Removed — The Playbook app

- `src/Apps/SimpleSign.Playbook` and its tests: its sample is now a playbook, run by the TestBench's Playbook tab.

### Added — Signing controls you can turn on in the signing policy, an audit trail and a readable report

Every new check is off in `SigningPolicy.Default`, so signing is unchanged until a policy turns it on.

- **Trust anchor before signing:** `SigningCertificate/ProspectiveCertificateChain` refuses a signing certificate
  that does not chain to a given anchor (`SigningErrorReason.UntrustedRoot`). The anchors come from
  `WithTrustAnchors(...)` on the PAdES, CAdES, XAdES, deferred and batch builders, and on PAdES also from
  `WithCountryExtension` (stored before but never read). Anchors also complete a chain given without its root for
  the revocation check.
- **TSA checked while signing (B-T, B-LT, B-LTA):** a new `Timestamp` section of the signing policy
  (`ProspectiveCertificateChain`, `NotExpired` at genTime, `NotRevoked`, `RevocationDataAvailable`), and
  `TimestampOptions.ExpectedTsaCertificate` / `ArchiveTimestampOptions.ExpectedTsaCertificate` to pin the TSA.
  A refusal (`TimestampUntrusted`, `TimestampCertificateNotValid`, `TimestampCertificateRevoked`,
  `TimestampRevocationStatusUnknown`) is never downgraded by `SigningLevelFailureBehavior.ReturnLowerLevel`.
- **CRL without nextUpdate:** `SigningCertificate/CRLNextUpdatePresent` and `CACertificate/CRLNextUpdatePresent`.
  `ChainRevocationChecker.CheckCurrentAsync` now returns the CRLs and OCSP responses it used.
- **Audit trail:** `ISignatureAuditSink` gets a `SignatureAuditEvent` for every signature made or refused
  (certificate, policy, input and output SHA-256, level, reason). Set it with `WithAuditSink(...)`.
  `JsonLinesAuditSink` writes a hash-chained JSON-lines file, and `JsonLinesAuditSink.Verify` finds a changed,
  removed or inserted line. The signing start log events (1000, 7000, 7100) now include the certificate serial.
- **Readable report:** `ValidationReports.ToHtml(entries, language)` returns one HTML page in `en`, `pt` or `es`.
  The CLI's validate commands take `--html-report <file>` and `--report-language <code>`. `ToSimpleJson` adds
  `signerPublicKey` (SPKI, base64) and `signerCertificateSha256`.

### Changed — PFX private keys are loaded as non-exportable

- `CertificateLoader` (and so the CLI's `--cert`) no longer sets `X509KeyStorageFlags.Exportable`. Keys are
  ephemeral except on macOS, whose key store has no ephemeral keys. Nothing in SimpleSign exported them. On Linux,
  .NET does not enforce non-exportable keys.

### Fixed — CAdES/XAdES synchronous validation says it did not check revocation

- `Validate` / `ValidateAll` never checked revocation, neither of the signer chain nor of the TSA chain, yet a TSA
  could show as trusted. With `ValidationOptions.CheckRevocation` on, the result now carries a warning saying so;
  `ValidateAsync` replaces it with the checks' outcome.

### Added — Sandbox: an expired TSA, a SHA-1 CA, a signer without KeyUsage, CRLs without nextUpdate

- **`tsa-expired`** (Timestamping, expired yesterday), served at `POST /tsa/expired`; `GET /api/info` gives its
  address in `tsa.expiredUrl`.
- **`intermediate-sha1`**, an intermediate CA whose certificate the root signs with sha1WithRSAEncryption, and
  **`under-sha1-ca`**, a signer under it. An environment created before this CA existed gets it the next time it
  opens. Its root and the certificates it already issued stay the same.
- **`no-key-usage-extension`**: a signer with no KeyUsage extension at all. `no-signing-key-usage` has one, with
  keyEncipherment only.
- **`CrlFault.NoNextUpdate`**: while it is on, the CRLs (HTTP, HTTPS, LDAP) have no nextUpdate field. They are still
  signed by their CA. The TestBench's Sandbox control lists it with the other CRL failures.

### Fixed — PAdES: the B-LT/B-LTA DSS update no longer overwrites the stamp's font object

- **`LtvEmbedder`:** to add `/DSS` to the catalog it searched backwards for `"N 0 obj"` as plain text, so catalog
  `1 0 obj` matched `21 0 obj`. A visible stamp appends its font as objects 20–21 after the catalog, so the DSS
  revision wrote the font descriptor as the new catalog. The AcroForm and the signature field were lost, and
  validation reported "Form field removed" (a DocMDP violation when certified). It now uses
  `PdfStructureParser.FindObjectBytes`, which rejects suffix matches.
- **TestBench matrix:** the `appearance` dimension is back (invisible, visible, styled+QR, auto+image).

### Changed — TestBench: Sandbox and DSS on/off, the DSS drawer, a faster Sandbox connection

- **Sandbox and DSS on or off:** each control in the top bar opens a popup to turn it on when it is off (the address
  and how to start it) and a drawer with everything once it is on, with a switch to turn it off. The controls are
  back on the right of the top bar, after Sign and Validate.
- **The DSS drawer**, in three tabs:
  - **Overview:** one table of every server setting (how the Sandbox is trusted, EU lists, refresh, lists with a bad
    signature, trust anchors, revocation cache, policy), with what each means next to SimpleSign's verdicts and the
    variable that changes it.
  - **Trust:** how DSS trusts the Sandbox and the lists, then every trusted certificate by group, in a searchable
    table (name, organization and country read from the subject, UTF-8 escapes decoded).
  - **Policy:** the validation policy DSS receives, in the same explained tree as the Policies panel. The constraints
    left out of its `constraint.xml` (DSS 6.3 does not know them) are marked, and the XML can be read or downloaded
    (`GET /api/dss/policy`, `/api/dss/constraint.xml`).
- **`tools/dss` `config.json`:** also the forwarded Sandbox ports and the Peruvian list's address.
- **Connecting to the Sandbox takes about 2 s instead of 15 s:**
  - the signed samples are built in the background, each list readable as soon as it is done (the "expired" sample
    waits ~10 s for a certificate to expire);
  - connecting or disconnecting stops a build still running first, which also fixes "m_safeCertContext is an invalid
    handle" on a quick reconnect;
  - the signers' keys are loaded in parallel.
- **Edit the stamp** no longer opens the first explanation's hover card: drawers do not move the focus when they open.
- **`.env.example`** in `tools/stack` and `tools/dss`: every variable with its default and what it does. A local
  `.env` (git-ignored) keeps a machine's choices, such as `DSS_LOAD_EU_TRUSTED_LISTS=cached`.

### Changed — The Sandbox is API only; its UI is the TestBench's Sandbox control

- **Sandbox:** no page of its own (`web/` removed, no Node.js in its build or its Docker image). `/` says it is
  API only, where `/api/info` is and how to open the TestBench; unknown `/api/…` routes still answer JSON 404.
  The services and the admin API are unchanged: the CLI, playbooks, DSS and `curl` use it without a TestBench.
  `--no-browser` is still accepted (and ignored).
- **TestBench, one Sandbox control:** the **Sandbox** button opens a popup to connect (and how to start one) when
  none is connected, and everything when one is: overview and signers, environment, PKI (revoke, take back,
  downloads), failures and request log. It turns red while a failure is on. The admin API is passed through at
  `/api/sandbox/admin/{**path}`; the Sandbox keeps the state.
- **TestBench top bar:** the engine (Library/CLI), Policies, Reference, Environment, Sandbox and DSS sit right after
  Sign/Validate; language and theme stay on the right.
- **DSS setup in the DSS popup:** `tools/dss` writes `/simplesign/config.json` (how the Sandbox is trusted, EU lists,
  ICP-Brasil, Gov.br, Peru, TSA roots, revocation cache, every trusted certificate) and the popup shows it.
- **Playbook:** the Sandbox link opens its `/api/info`.

### Added — TestBench: the Stamp page (visible signature with a live preview)

- **Stamp page:** a drawer opened from the Sign page ("Edit the stamp"). The stamp's options are on the left. On the right is the PDF,
  signed with the stamp by the library itself (a throwaway B-B signature, `POST /api/stamp/preview`) a moment after
  each change.
- **Placing it:** drag the rectangle to move it, drag its corner to resize it, or click the page to place it. With
  automatic placement the rectangle shows where the library put the stamp.
- **Signing with it:** the stamp is part of the PAdES options, so the Sign page signs with it, through the library or
  the CLI, and the C# and CLI snippets include it.
- The appearance options, their rules and their code generation come back from before `b4f12709`.

### Added — CLI: more stamp options

- `--vertical-align`, `--no-shrink-to-fit`, `--max-text-length`, `--date-culture`, `--signer-display-name`,
  `--extra-line` (repeatable), `--hide-reason` and `--hide-location`.
- `--background-image` reads PNG or JPEG by its content, not its extension.
- The AEA lines (`--brasil`) are added after the `--extra-line` ones instead of replacing them.

### Changed — `cades validate` and `xades validate` check every signature

- **Every signature:** both commands validate every signer, co-signer and countersignature (`ValidateAllAsync`), not
  only the first. `--json` adds `signatures`, one entry per signature with its `counterSignatures` and every check
  (timestamps, LTV data, revocation source…). The top-level fields stay those of the first signature. The exit code
  is 0 only when all are valid.
- **System roots:** with `--trust`, the operating system's roots stay trusted, as in `validate`; `--no-system-roots`
  turns them off. Before, `--trust` replaced them.
- **Attached CAdES:** `cades validate` no longer requires `--data`; the signed content is read from the signature.
- **Trusted lists on the CLI's network:** `--lotl` and `--tsl` are downloaded through the CLI's HTTP client, so
  `--allow-origin` and the proxy apply to them. Before, a list on `localhost` (the Sandbox's) was refused.
- **`validate --json`:** each signature also has `warnings`, `subFilter`, `notRevoked`, `revocationSource`,
  `hasValidTimestamp`, `isTsaTrusted`, `chainTrustWarning`, `chainRegion` and `chainMetadata`.

### Added — TestBench: validate through the CLI

- **The engine for the whole app:** the Library / CLI selector moved to the top bar and applies to signing and
  validating, in PAdES, CAdES and XAdES.
- **Validation through the CLI:** with CLI selected, a validation runs `simplesign validate`, `cades validate` or
  `xades validate` with `--json`, and the verdicts shown are the CLI's.
- **Reports:** the ETSI and simple reports are the ones the CLI wrote.
- **Signing through the CLI:** the signed file is validated through the CLI too.

### Added — the public TSAs' roots are trusted (TestBench and `tools/dss`)

- **TestBench:** new trust choice "Public TSA roots" (`TrustChoice.PublicTsas`), on by default. It trusts the roots of
  the public TSAs offered (DigiCert Trusted Root G4, Sectigo Public Time Stamping Root R46, FreeTSA Root CA), kept in
  `src/Apps/SimpleSign.TestBench/TsaRoots`. A FreeTSA timestamp no longer fails with "[signature timestamp] The
  certificate chain could not be validated to a trust anchor".
- **`tools/dss`:** DSS trusts the same roots at start (`DSS_TRUST_TSA_ROOTS`, default `true`; the folder is mounted),
  so it no longer reports "The certificate chain for time-stamp is not trusted" for these TSAs.

### Added — Windows versions of the TestBench scripts

- `tools/stack/up.ps1`, `down.ps1`, `testbench.ps1`, `softhsm-provision.ps1` and `scripts/tests/pkcs11.ps1`
  (PowerShell 7.2+): the same options, environment variables and `.softhsm/` files as the bash scripts.
- `softhsm-provision.ps1` reads the PFX files with .NET, so it needs neither OpenSSL nor jq. It finds SoftHSM2 for
  Windows (`C:\SoftHSM2`) and OpenSC.
- On Windows the token is optional: without SoftHSM2 and OpenSC, `up.ps1` starts the Sandbox and DSS and warns.
- New CI job `windows-scripts`: lints every script and fills a token on `windows-latest`.

### Added — `tools/stack/down.sh`

- Stops the stack `up.sh` started, with the same project name: `down.sh` keeps the Sandbox's PKI and the DSS download
  cache, `--drop-pki` drops the PKI only, `--volumes` drops every volume.

### Fixed — CRLs served as PEM

- A CRL downloaded over HTTP that comes PEM-encoded (`-----BEGIN X509 CRL-----`) instead of DER (RFC 5280 §4.2.1.13)
  is now read: it is turned into DER as it is downloaded (`CrlClient`, `ChainRevocationChecker`, LTV collection in
  `LtvEvidenceCollector` and `LtvEmbedder`), so what is cached and embedded stays DER. FreeTSA serves its CRL this
  way; its timestamps were reported as "the revocation status of the TSA certificate chain could not be established".

### Added — the Sandbox as a trust scheme (trusted list + LOTL)

- **Sandbox endpoints:**
  - `/tl/lotl.xml` and `/tl/tl.xml` publish a list of trusted lists and a trusted list (ETSI TS 119 612 v5, territory
    `ZZ`), each signed by its own scheme operator. The trusted list's services are the root CA (CA/QC, granted), the TSA
    (TSA/QTST, granted) and the revoked TSA (withdrawn). The operators' certificates are `/tl/lotl-signer.pem` and
    `/tl/tl-signer.pem`; `/api/info` lists the URLs (`trustedLists`).
  - The signatures follow TS 119 612 §5.7.1: enveloped, whose only transforms are the enveloped one and exclusive
    canonicalization.
- **New Sandbox failure `TlFault`:** an expired list, a list signed by a certificate the LOTL does not name, or a list
  changed after signing. It is in the Sandbox UI and the Playbook (`faults.trustedList`).
- **TestBench:** new trust choice "Sandbox trusted list", now the default. The validators trust the Sandbox through its
  LOTL (`TrustedListSet`), so the `TrustedLists` constraints are evaluated. "Sandbox root" (a bare anchor) is still
  there.
- **`tools/dss`:** DSS trusts the Sandbox through its LOTL by default (`DSS_SANDBOX_TRUST=list`, or `anchor` for the
  root alone). With the EU lists off it uses the EU slot; with them on, the second slot. The lists are downloaded again
  every `DSS_TL_REFRESH_SECONDS` (10 s with the Sandbox's list alone). A list whose signature fails is not used
  (TS 119 615, as in SimpleSign): a Spring component compiled into the image sets the TL job's
  `ExpirationAndSignatureCheckStrategy`; `DSS_ACCEPT_INVALID_TRUSTED_LISTS=true` restores the demo's default.
- **`DssScenarioCrossValidationTests`:** the trusted-list failures are compared too, and the test waits for DSS to load
  the Sandbox's list.

### Changed — TestBench: a readable Validation tab

- The tab opens with a summary per signature: SimpleSign's verdict and DSS's side by side. Each difference says:
  - what DSS concluded, in plain words (the ETSI sub-indications, in English and Portuguese);
  - whether the cause is DSS's setup (it does not trust the Sandbox root, it cannot reach the Sandbox's CRL/OCSP)
    or a real disagreement;
  - what to do.
- The points where they agree fit on one line, and DSS's raw messages are folded away.
- SimpleSign's warnings are grouped by constraint of the validation policy, with its name in plain words and a
  count. A check repeated for each certificate or token shows once.

### Fixed — validation against DSS 6.3 (every Sandbox scenario cross-validated)

- **PAdES no longer accepts a signature under a revoked CA.** The validator checked online revocation for the
  signing certificate only, and the failed chain status was waived because the chain reaches its anchor. It now checks
  the CA certificates of the chain too (`ChainRevocationChecker`, as CAdES and XAdES do), with the data it used going to
  the policy.
- PAdES validation reads CRLs published only over LDAP when the outbound policy allows LDAP (`AllowLdap`), like CAdES and
  XAdES: the signing certificate's own check falls back to the chain checker when it cannot decide.
- **Revocation sub-indications follow EN 319 102-1 §5.2.6:** a revoked signing certificate gives INDETERMINATE /
  `RevokedNoPoe` (no longer TOTAL_FAILED / `Revoked`) and PASSES when a proof of existence predates the revocation; a
  revoked CA gives INDETERMINATE / `RevokedCaNoPoe` (`CACertificate/NotRevoked` is now evaluated). No revocation data, or
  none acceptable, gives `CertificateChainGeneralFailure`; `TryLater` is kept for data that is not fresh and for
  certificates on hold. New `SignatureSubIndication` values: `CertificateChainGeneralFailure`, `RevokedCaNoPoe`.
- XAdES: a changed `ds:SignatureValue` gives `SigCryptoFailure` (was `HashFailure`); a changed reference still gives
  `HashFailure`.
- CAdES and XAdES B-LT can be made when the OCSP responses come from a delegated responder: its certificate
  (id-pkix-ocsp-nocheck) needs no revocation data of its own (RFC 6960 §4.2.2.2.1).
- CAdES and XAdES B-LTA send the TSA's credentials (Basic/bearer, client certificate) with the archive timestamp request
  too, as PAdES does (`ArchiveTimestampOptions.Resolve`).
- TestBench: past its limit, the in-memory store forgets the least recently used files, not the oldest, so an uploaded
  policy or PFX that runs keep reading is not lost after about a hundred runs.
- `tools/dss`: DSS reaches a default Sandbox (`localhost` ports forwarded inside the container), trusts its root for TLS
  (CRLs over HTTPS), keeps no revocation cache (`DSS_REVOCATION_CACHE`), waits for the Sandbox at start, and the image is
  rebuilt on every `up`. New test `DssScenarioCrossValidationTests` requires the same indication and sub-indication from
  SimpleSign and DSS for every Sandbox scenario (222 of 226 agree; the other cases are documented in the test).

### Changed — configurable signing and validation policies (ADR 0023, ADR 0024)

- **Migration of validation policy files:** rename the root `ConstraintsParameters` to `ValidationConstraints` and
  `eIDAS` to `TrustedLists`, and drop the elements SimpleSign's format no longer has (ASiC containers, PDF/A,
  evidence records, attestations and key binding signatures, JSON-signature headers, EU qualification and PSD2
  statements, `OCSPCertHash*`, lists of trusted entities, `SunsetDate`, `ManifestEntry*`, `PdfVisualDifference`). The
  reader names each one; `docs/policies/compatibility.md` lists them with the reason.
- **Stricter default validation policy:** the certificate checks now follow the policy's levels, and some are FAIL by
  default. Notably, a chain whose CA certificate has no Subject Key Identifier
  (`CACertificate/SubjectKeyIdentifierPresent`, FAIL in every context: signature, timestamp, revocation,
  countersignature) now makes the signature INDETERMINATE; a missing Authority Key Identifier is only a warning.
  Signatures from test or private PKIs that validated before may not validate now. A policy can lower these checks
  to WARN.
- `ValidationPolicy` (now `SimpleSign.Core.Policies`) reads and writes JSON in SimpleSign's own format (root
  `ValidationConstraints`; contexts `SignatureConstraints`, `CounterSignatureConstraints`, `Timestamp`, `Revocation`,
  `Cryptographic`, `Model`, `TrustedLists`), one FAIL/WARN/INFORM/IGNORE level per constraint. Names outside the
  format are refused, with a pointer to `docs/policies/compatibility.md` (how the names correspond to other
  validators' policies). Constraints SimpleSign does not evaluate yet are reported as `NotChecked`; INFORM gives
  `ConstraintStatus.Information`. Constraint ids are paths
  (`SignatureConstraints/BasicSignatureConstraints/SigningCertificate/KeyUsage`).
- Validation policy, signature context: the levels of the policy now apply to the RFC 5280 certificate checks
  (`IssuerName`, `MaxPathLength`, `NameConstraints`, `PolicyTree`, `SupportedCriticalExtensions`,
  `ForbiddenExtensions`, AIA, CRL/OCSP locations, AKI, SKI, `SerialNumberPresent`, `NoRevAvail`,
  `RevocationDataSkip`), the subject attributes (`CommonName`, `Country`…), the PDF ByteRange checks, the CMS
  SignerInfo count, the signature Id (XAdES), the signed attributes (signing-certificate references, content type,
  hints and identifier, commitment, location, roles), the unsigned attributes (timestamps, countersignatures, valid
  T/LTA timestamp) and `AcceptableFormats`, `FullScope`, `PolicyAvailable`, `SignaturePolicyStorePresent`. A check
  that does not apply to the format is not reported. `PolicyCoverage` says what SimpleSign evaluates, by path;
  `SignatureSubIndication` gains `SignedDataNotFound` and `SignaturePolicyNotAvailable`.
- Validation policy, timestamp and revocation contexts: each signature timestamp is evaluated in the `Timestamp`
  context (the token, the TSA certificate at the timestamp's time and its chain, the signed attributes,
  `TimestampValid`, `TSAGeneralName*`); one that fails there is not a proof of existence. Each CRL and OCSP response
  the signature carries is evaluated in the `Revocation` context (`UnknownStatus`, `ThisUpdatePresent`, issuer known
  and valid when it produced it, `OCSPResponderIdMatch`, `SelfIssuedOCSP`, the issuer certificate); one that fails
  there is not acceptable revocation data. The certificates gain `AcceptableRevocationDataFound`,
  `CRL/OCSPNextUpdatePresent`, `RevocationFreshnessNextUpdate`, `RevocationIssuerNotExpired` and `NotOnHold`, and the
  signature `BestSignatureTimeBeforeExpirationDateOfSigningCertificate` and `RevocationTimeAgainstBestSignatureTime`.
  Messages of a token name it (`[OCSP of 'Leaf'] …`).
- Validation policy: each countersignature (CAdES, XAdES) is evaluated in the `CounterSignatureConstraints`
  context, with its own result. `ValidationOptions.TrustedLists` gives the CAdES and XAdES validators the trusted lists
  the anchors come from, for the `TrustedLists` constraints (the CLI passes those of `--tsl` and `--lotl`).
- Validation policy: archive timestamps are evaluated as tokens too (`Coherence`, `AtsHashIndex`); the CRLs and OCSP
  responses fetched online are kept and evaluated like the ones the signature carries (CAdES, XAdES; PAdES: OCSP
  responses); `TrustServiceTypeIdentifier`/`TrustServiceStatus` read the service of the anchor in its trusted list
  (`TrustedListInfo.Services`); `PdfSignatureDictionary` checks that later PDF revisions keep the signature dictionary's
  ByteRange and Contents. `ChainRevocationResult` gains `Crls`/`Ocsps` (the data the statuses came from).
- Validation results (`SignatureValidationResult`, `CadesValidationResult`, `XadesValidationResult`) gain
  `ValidationObjects`: the timestamps and revocation data used, each with the outcome of its own evaluation; the ETSI
  TS 119 102-2 report lists them as validation objects (with the POE of each timestamp), the simple report as
  `timestamps` and `revocationData` with their own indication. `BestSignatureTime` is the earliest accepted
  signature timestamp.
- Validation policy: `RevocationHasInformationAboutCertificate` (revocation data issued after the certificate expired
  counts only with expiredCertsOnCRL or archiveCutoff from before the expiry); `ContentTimeStamp` and
  `ContentTimeStampMessageImprint` (CAdES content-time-stamp, XAdES data objects timestamps), the content timestamp
  being judged in the Timestamp context and ordered before the signature timestamps (`Coherence`).
- Validation policy, PAdES: the revision a signature (or document timestamp) covers is compared with the final one.
  `PdfPageDifference`, `PdfAnnotationOverlap`, `DocMDP` (the changes the certification's P forbids), `FieldMDP` and
  `SigFieldLock` (locked fields whose value changed), `FormFillChanges`, `AnnotationChanges` and `UndefinedChanges`
  (page content, resources, the catalog, fields added or removed) are evaluated; the messages name the changes.
  Validation data (DSS) and document timestamps added later are not changes (ETSI EN 319 142-1).
- Validation policy: `StructuralValidation` (XAdES: the signature against the XML Signature and XAdES schemas;
  CAdES/PAdES: the CMS decoded) and `TLStructure` (`TrustedList.StructureErrors`, `TrustedListInfo.IsStructureValid`:
  the list against the ETSI TS 119 612 schema). The schemas are embedded in SimpleSign.XAdES; nothing is fetched.
  Every constraint of the validation policy format is now evaluated.
- `SigningPolicy` (now `SimpleSign.Core.Policies`) reads JSON (`SigningConstraints`) with the names of the validation
  policy for the signing and CA certificates and the cryptography; WARN constraints give `SigningWarningCode.PolicyConstraint`.
  `SigningPolicy.Strict` and `SigningPolicy.Minimal` are removed: set `NotRevoked`/`RevocationDataAvailable` to FAIL,
  or the constraints to IGNORE. `SigningPolicy.Evaluate` gives the local checks of a certificate.
- `CryptographicSuite`: ETSI TS 119 322 cryptographic suites (JSON), globally or per context
  (`WithCryptographicSuite`).
- JSON Schemas of the policy files (`docs/schemas/`, `GetJsonSchema()`, `simplesign policy schema`); `ToJson` writes
  `$schema`.
- `IPolicyProvider`/`StaticPolicyProvider`: the validation policy chosen by the signature policy OID;
  `ValidationOptions.PolicyProvider`, DI (`SimpleSignOptions.SigningPolicy`), `AppliedPolicy` on the results.
- `ChainRevocationResult.IssuedAt`, `CrlEvaluator.ReadThisUpdate`, `OcspClient.ReadProducedAt`: the freshness of
  revocation data (`RevocationFreshness`).
- TestBench: a policy viewer (**Policies** in the top bar) shows the signing and validation policies as an explained
  tree — what each constraint checks, its clause, its level, and whether SimpleSign evaluates it — lets the levels be
  changed, and downloads the result or uses it in the next runs (`POST /api/policies/view`).
- TestBench: the signing and validation policies are uploaded as JSON files (the Default/Strict/Minimal choice is
  gone), with a download of each default; the validation options gain the validation level and the revocation
  strategy. The option check evaluates the signer against the chosen signing policy, and DSS validates with the
  chosen validation policy, translated to its format. The generated CLI passes the policy files
  (`--signing-policy signing-policy.json`, `--policy validation-policy.json`) instead of `--signing-policy strict`,
  which the CLI no longer reads.
- `ValidationOptions.Verifier` (`VerifierOptions`: revocation strategy, now OCSP first everywhere, fallback, AIA,
  revocation of untrusted chains — off) and `ValidationOptions.Level` (`ValidationLevel`); CLI `--level`, `--revocation-strategy`, `--revocation-for-untrusted`.
- `ValidationReports`: the ETSI TS 119 102-2 validation report (XML) and a simple report (JSON);
  `ToReportEntry()` on the PAdES, CAdES and XAdES results, `BestSignatureTime` on them; CLI `--etsi-report`,
  `--simple-report`.
- `TrustedListSet`: trusted lists loaded from a LOTL (EU or other), with per-list problems and a disk cache;
  `TrustedList.Version`/`Pointers`; `TrustedListInfo`/`ITrustedListInfoProvider` and the `TrustedLists` constraints
  (`TLFreshness`, `TLNotExpired`, `TLWellSigned`, `TLVersion`); CLI `--lotl`, `--lotl-signer`, `--lotl-territory`.
- CAdES and XAdES revocation uses the CRLs and OCSP responses the signature carries.
- `DeferredSigningPrepareResult.Warnings`. CLI: `--signing-policy` takes a JSON file; `policy export validation|signing` writes the defaults. `IofePolicies` derive from the
  defaults. The Agent's `policyIssue` comes from `SigningPolicy.Default`.

### Added — SimpleSign Sandbox and loopback origins

- `src/Apps/SimpleSign.Sandbox`: a test PKI and its services on real HTTP endpoints (AIA, CRLs, RFC 3161 TSA,
  CSC v2), with failures to switch on, revocation, a request log, an admin API and a UI. Environments are kept by
  name; the URL written into the certificates is fixed when an environment is created.
- `OutboundHttpPolicy.LoopbackOrigins`: services on this machine listed by exact origin (scheme, host, port) pass
  the SSRF guard, for local test environments; empty by default. HTTP, LDAP and the TSA TCP transport honor it.
- `TimestampClient` no longer refuses a loopback TSA URL in its constructor: it is refused when the request is
  sent, unless its origin is listed (private and link-local URLs are still refused at once).

### Added — SimpleSign Playbook

- `src/Apps/SimpleSign.Playbook`: a web app (127.0.0.1:5400, en/pt-BR) that runs a playbook — a JSON file of
  SimpleSign CLI commands in sections — in a workspace folder (playbook.json, assets/, secrets.json, runs/). Before a
  step it can change a SimpleSign Sandbox (failures, revocations, certificates as PKCS#12); after it, it checks the exit
  code, paths in the JSON on stdout, text, files and the requests the Sandbox answered. Manual steps wait for the
  operator's result, note and attachments. Each run is recorded (machine, CLI version, Sandbox and root, playbook
  SHA-256, each step's command, output, checks, requests and files) with report.md, report.html and a zip; runs can be
  compared. The playbook is edited as a form or as JSON, checked by the server as you type. A neutral sample
  (`Sandbox basics`) signs and validates with a Sandbox's certificates.
- `docs/articles/playbook.md`; tests in `tests/unit/Apps/SimpleSign.Playbook.Tests`, including the sample run with the
  real CLI against a running Sandbox.

### Added — CLI: the signing options the library has
- `sign` (PAdES) gains the options it lacked:
  - `--signing-time`;
  - `--doc-info KEY=VALUE` (repeatable);
  - `--contents-size`;
  - `--archive-tsa`, a separate archive TSA;
  - `--return-lower-level`;
  - `--policy-hash` (and `--policy-hash-algorithm`), for an explicit signature policy;
  - structured signer metadata without `--brasil`: `--signer-id`, `--signer-id-type`, `--ip-address`,
    `--institution-id`, `--institution-id-type`, `--legal-basis`, plus `--signer-email`, `--institution`,
    `--auth-method` and `--commitment` (origin, receipt, delivery, sender, approval, creation).
- `sign`, `cades sign` and `xades sign` reach a TSA that asks for credentials, through `--tsa-user`/`--tsa-password`
  (HTTP Basic), `--tsa-token` (bearer) or `--tsa-cert`/`--tsa-cert-password` (TLS client certificate). Secrets
  accept `env:NAME`.
- `validate`, `validate-dir`, `cades validate` and `xades validate --no-system-roots`: trust only `--trust`,
  `--trust-dir` and the trusted lists.
- `sign-dir`: signs every PDF of a directory with one certificate (`BatchSigner`). It takes `--max-concurrency`,
  `--recursive`, the level, TSA and field options, a PFX or an external credential.
- `deferred prepare` / `deferred complete`: deferred signing (`DeferredSigner`).
  - `prepare` writes the session and the data to sign; the session is protected by `--session-key`.
  - `complete` embeds the signature made elsewhere.
- `cades sign --cosign [--data]` and `--countersign [--signer-index]` add a signer to an existing signature, or
  countersign one of its signers.
- `cades sign` and `xades sign` take `--signing-time`, `--signature-algorithm rsassa-pss` and
  `--extended-form complete-references|extended-long|archive`.
- `xades sign` gains:
  - `--signing-certificate-v1` and `--data-mime-type` (DataObjectFormat);
  - the external credentials of `sign` and `cades sign`: PKCS#11, PSC and CSC.
- `sign`, `cades sign` and `xades sign` take `--operation-id`.
- `cades sign` and `xades sign` with `--cert` now embed the other certificates of the PFX as the chain, as `sign`
  already did. Before, the chain came only from `--chain`, and without it a signature that is valid with the library
  validated as INDETERMINATE.
- TestBench: the CLI line in the Code tab now covers every option the CLI has:
  - the new flags;
  - the Sandbox's `--allow-origin`;
  - `deferred prepare`/`complete` and `sign-dir` for the deferred and batch modes;
  - `--check-revocation` for CAdES and XAdES validation.

  It also fixes `--sub-filter`, `--signature-algorithm`, `--certify` and `--thumbprint`, which the CLI did not accept
  as written. `CliEquivalenceTests` runs the generated lines through the CLI against the Sandbox and checks that their
  signatures validate like the library's (25 PAdES, CAdES and XAdES cases).

### Added — CLI: network options and JSON result for signing

- Every command accepts `--allow-origin <URL>` (repeatable), `--allow-ldap` and `--tls-trust <PEM>` (also
  `SIMPLESIGN_ALLOW_ORIGINS`, `SIMPLESIGN_ALLOW_LDAP`, `SIMPLESIGN_TLS_TRUST`): the HTTP provider lets the listed
  loopback origins through the SSRF guard, reads CRLs over LDAP and accepts the given root (and intermediates) for
  HTTPS. `sign`, `cades sign` and `xades sign` now use that provider for the TSA, LTV and the Strict revocation check.
- `sign`, `cades sign` and `xades sign --json`: `{ success, format, output, signer, requestedLevel, achievedLevel,
  warnings, error: { type, reason, message } }`; a refusal carries its `SigningErrorReason`.

### Changed — CI, DSS and docs use the Sandbox

- CI starts an ephemeral SimpleSign Sandbox on each OS before the tests (`--ephemeral`, waits for `/api/info`,
  keeps `sandbox.log` with the test results) and sets `SIMPLESIGN_REQUIRE_SANDBOX=true`, so a missing Sandbox fails
  the TestBench tests instead of skipping them.
- `tools/dss`: the container trusts the Sandbox's root (`SANDBOX_URL`, default `http://host.docker.internal:5300`);
  `TESTBENCH_URL` is optional. The README explains `--public-base-url` for DSS to reach the CRLs and OCSP.
- Docs: new `docs/articles/sandbox.md`; the TestBench article (real network plus a connected Sandbox).
- Sandbox: OCSP responses start an hour back (`thisUpdate`). They started five minutes back, the same instant the
  TestBench's "time" option claims as signing time, and embedded OCSP evidence is checked with no clock-skew
  tolerance against it, so CAdES/XAdES matrix cases failed "incomplete LTV" whenever a second boundary fell between.

### Changed — opening the OAuth page on Windows

- `LoopbackAuthorizationHandler.OpenInSystemBrowser` starts `explorer.exe` with the URL as its argument on Windows,
  like `open`/`xdg-open` elsewhere, instead of shell-executing the URL itself (CodeQL `cs/command-line-injection`).

### Fixed — Strict signing no longer trusts a CRL cached before a revocation

- `SigningPolicy.Strict` asked a shared `ChainRevocationChecker` (DI, `WithChainRevocationChecker`) for the status
  "now", and the checker answered from a CRL cached up to its nextUpdate: a certificate revoked after that CRL was
  cached could still sign. New `IChainRevocationChecker.CheckCurrentAsync`
  (a default interface method, so existing implementations still compile): `ChainRevocationChecker` asks each OCSP
  responder first and then downloads the CRL again, refreshing the cache. Signing uses it; validation is unchanged.
- CAdES/XAdES: "does not contain complete LTV" now says why (the certificates without revocation data and the
  reason, or that the embedded data did not validate when the signature was read back).
- TestBench: the "expired" validation sample no longer fails on a busy machine (its certificate lived 3 seconds).
- TestBench: `SandboxScenarioTests` sign with Strict against a running SimpleSign Sandbox for each case
  (CRLs over HTTP, HTTPS and LDAP, OCSP only, revoked CA, expired and wrongly signed CRLs, unusable OCSP answers,
  a stale CRL after a revocation, expired and not-yet-valid certificates, expired CA).

### Added — apps, DI and packaging follow the new checks

- `SimpleSign.Peru.Iofe` is packed and released (pack lists, `PACKAGE.md`); RELEASING lists it and the signer packages.
- DI: `AddSimpleSignRevocation()` registers `IRevocationCache` and `IChainRevocationChecker` on the registered
  `IHttpClientProvider`; `AddSimpleSignCades`/`AddSimpleSignXades` build their validators with it (they used the
  default HTTP client); `SimpleSignOptions.ValidationPolicy`.
- `CadesSignatureValidator.ValidateAllAsync`, `XadesSignatureValidator.ValidateAllAsync` and
  `XadesSignatureValidator.ValidateAsync(…, externalData)`: revocation for every signer and countersignature.
  `CadesSignerValidationResult.IsValid` follows the signer's indication.
- `SignatureSubIndication.ToEtsiName()`.
- CLI: `--signing-policy` on the sign commands, refusal reasons with a hint, `validate-dir` with the policy/trust
  options and sub-indications, three-state CAdES/XAdES output, `explain` for the ETSI terms.
- TestBench: signing policy option, sub-indications and policy checks in the reports, real revocation for
  CAdES/XAdES, weak-key and no-key-usage sandbox signers.
- Agent: `/api/certificates` reports `policyIssue` (keyUsage, weakKey), shown in the Overview; `/api/sign` refuses an
  unsupported `hashAlgorithm` with 400 instead of signing SHA-256.
- Docs: README, conformance, PAdES/CAdES/XAdES, validation, getting started, deferred, PKCS#11, cloud and TestBench
  articles; ADRs 0009, 0011, 0013, 0018 and 0020 point to ADRs 0021/0022; CLAUDE.md, CONTRIBUTING, SECURITY.

### Removed (TestBench) — ETSI only

The TestBench now covers the ETSI standards only; trust frameworks and the visible stamp will get apps of their own.
The libraries are unchanged (the Brazil and Peru packages, `PadesSignerBuilder.WithAppearance`).

- Visible signature stamp: the appearance options, the stamp preview (`/api/preview`) and the matrix dimension.
- Trust frameworks: the frameworks bar and the `framework` tags of the option schema; the ICP-Brasil policies
  (AD-RB…AD-RA, versions, `/api/icp/versions`), the PBAD.PAdES sub-filter, the AEA of Lei 14.063, health documents,
  the fiscal XML-DSig layouts and their samples, the ICP-Brasil/Gov.br roots and rules in validation, the Lei 14.063
  classification and the IOFE validation policy choice.
- The simulated ICP-Brasil PSC and the PSC signer (CSC v2 stays).
- The sandbox PKI is generic: no CPF/CNPJ (SAN otherName 2.16.76.*), no e-CNPJ signer, neutral subjects.

### Added — signing policy: checks before signing

- `SigningPolicy` (`Default`, `Strict`, `Minimal`) with `WithSigningPolicy(...)` on the PAdES, CAdES, XAdES,
  deferred and batch builders. Before anything is signed it checks the validity of every certificate of the
  chain, the key usage of the signing certificate (digitalSignature or nonRepudiation), the RSA key size
  (2048 bits or more), the elliptic curve and the hash algorithm (SHA-2 and SHA-3 only).
  `SigningPolicy.Strict` also checks the revocation of the whole chain (CRL and OCSP) and refuses a revoked
  certificate or one whose status cannot be established.
- `IChainRevocationChecker` and `ChainRevocationChecker` are now public in `SimpleSign.Core.Revocation`
  (moved from the Brazil package), with `WithChainRevocationChecker(...)` on the builders.
- New `SigningErrorReason` values: `CertificateRevoked`, `RevocationStatusUnknown`, `ChainCertificateNotValid`,
  `KeyUsageNotPermitted`, `AlgorithmNotPermitted`, `KeyTooWeak`.

### Added — revocation: LDAP CRLs, cache, verified online CRLs

- CRLs from `ldap://` and `ldaps://` distribution points (read-only LDAPv3 on the BCL), used when a certificate
  has no HTTP distribution point and `OutboundHttpPolicy.AllowLdap` is set. LDAP hosts get the same address checks
  as HTTP.
- `IRevocationCache` and `InMemoryRevocationCache`: CRLs are kept until their nextUpdate.
  `ChainRevocationChecker.Cache` (15 minutes by default) and `CrlClient.Cache`.
- `CrlClient.CheckCrlAsync(cert, issuer, url, ct)` and `ICrlClient` default member: the CRL is checked against the
  issuer (signature, issuer name, validity). `RevocationChecker` uses it whenever the issuer is in the chain.
- ADR 0021.

### Added — timestamp authority checks

- `TimestampTsaChecks.TsaNameMatches`: the `tsa` name of TSTInfo must name the TSA certificate (RFC 3161 §2.4.2);
  `TimestampValidator.ValidateWithTrust` makes a mismatching TSA untrusted.
- `TimestampTsaChecks.CheckTsaRevocationAsync`: the revocation of the TSA chain at genTime, with the embedded
  evidence and online CRL/OCSP. A revoked or unknown status makes the TSA untrusted. PAdES validation runs it when
  `ValidationOptions.CheckRevocation` is on.
- At signing time a token received from the TSA (or from an injected client) must be validly signed by a
  certificate with the critical, exclusive timeStamping EKU; otherwise `TimestampException`.

### Added — policy enforcement tests

- `PolicyEnforcementContractTests`: refusals at signing time (revoked chain, CRL with a bad
  signature, expired CRL, expired intermediate, missing key usage, SHA-1, MD5, RSA-1024, tampered TSA token), an
  altered document is INVALID, signatures by PFX and by a remote signer are VALID, a revoked TSA is untrusted.
- `Pkcs11RealDeviceTests`: the three formats on a real token or HSM, set with `SIMPLESIGN_PKCS11_MODULE`.
- Test helpers: `SyntheticPki.IssueTimestampingCertificate`, `BuildCrlRevoking`, `BuildLeafCrl(thisUpdate, nextUpdate)`,
  `ConstraintTestCertificates`, `TimestampTokenOptions` (TSA certificate, tsa name, genTime, tampered signature).
- Article: `remote-signing.md`.

### Added — CLI verification report

- `validate`, `cades validate` and `xades validate`: `--policy`, `--policy-signer`, `--trust-dir`,
  `--trust-dir-signer`, `--tsl`, `--tsl-signer`, `--lang es`; `cades validate --check-revocation`.
- A verification report per signature: indication, ETSI sub-indication, public key (algorithm, size, SPKI SHA-256,
  PEM) and every check; in JSON as `subIndication`, `publicKey` and `constraints`.
- `timestamp verify` shows whether the TSA name in the token matches its certificate
  (`TimestampTsaChecks.TsaNameMatches(byte[])`).

### Added — trust store, trusted lists and the Peru extension

- `DirectoryTrustAnchorProvider` (Core): trust anchors from a folder of certificates, changeable without a rebuild,
  optionally protected by a signed manifest (`manifest.json` + `manifest.json.p7s`) with the SHA-256 of every file.
- `TrustedList` (XAdES, `SimpleSign.XAdES.TrustedLists`): ETSI TS 119 612 and TS 102 231 v3 trusted lists, read
  after their XML signature is checked against the scheme operator's certificate; active CA and TSA services become
  trust anchors; an expired list is refused; `DownloadAsync` keeps the last good copy.
- New package `SimpleSign.Peru.Iofe`: `IofeExtension` (anchors from INDECOPI's trusted list), `IofePolicies.Signing`
  and `IofePolicies.Validation`, `AddSimpleSignIofe`.

### Added — validation policy and ETSI sub-indications

- `ValidationPolicy` on `ValidationOptions.Policy`: accepted digest algorithms with dates, minimum RSA size,
  accepted curves, key usage of the signing certificate, each with a `fail`/`warn`/`ignore` level. Loaded from JSON
  at run time (`ValidationPolicy.Load`, `FromJson`, `ToJson`); `ValidationPolicy.LoadSigned` checks a detached CMS
  signature over the file first.
- `SignatureSubIndication` (ETSI EN 319 102-1 names), `ValidationConstraintResult` and `ConstraintStatus`.
  `SignatureValidationResult`, `CadesValidationResult` and `XadesValidationResult` expose `Indication`,
  `SubIndication` and `Constraints`.
- `CadesSignatureValidator.ValidateAsync` and `XadesSignatureValidator.ValidateAsync`: revocation of the signer chain
  and of the TSA chain through `IChainRevocationChecker`; results expose `IsNotRevoked` and `RevocationSource`
  (new value `CertificateChain`). `CadesValidationResult` and `XadesValidationResult` are now records.
- ADR 0022.

### Changed

- **Breaking:** with the default policy a SHA-1 or MD5 signature without a timestamp proving it existed before the
  algorithm's limit, or a signing key under 2048 bits, is INDETERMINATE (`CryptoConstraintsFailureNoPoe`) instead of
  VALID with a warning. `IsValid` of CAdES and XAdES results follows the indication.
- **Breaking:** `CrlClient.CheckCrlAsync(cert, url, ct)` without the issuer no longer reports "not revoked" from a
  CRL whose signature it cannot check; it throws `RevocationCheckException`. A revocation is still reported.
- OCSP and caIssuers locations other than HTTP(S) are skipped instead of failing the request.
- **Breaking:** signing now refuses, by default, a certificate without the key usage extension or without
  digitalSignature/nonRepudiation, an RSA key under 2048 bits and a chain with an expired certificate.
  Use `WithSigningPolicy(SigningPolicy.Minimal)` to keep the previous behaviour.

### Added — B-LT behind corporate proxies (#215)

- `LongTermValidationOptions.ClockSkewTolerance` (default 5 minutes, `OcspClient.DefaultClockSkewTolerance`):
  OCSP responses fetched during LTV collection are accepted when `thisUpdate` is up to this much ahead
  of the local clock, or `nextUpdate` up to this much behind it. Previously a responder a fraction of a
  second ahead had its fresh response rejected. Also settable on `OcspClient` and `LtvEmbedder`.
  Embedded evidence checked against a signing time keeps no tolerance.
- `OutboundHttpPolicy.PrivateNetworkHosts`: hosts allowed to resolve to private (RFC 1918) addresses,
  for split-DNS networks. Exposed by `IHttpClientProvider.OutboundPolicy` (default member) and settable on
  `SingleClientProvider`, `HttpClientFactoryProvider`, `OcspClient`, `CrlClient` and `TimestampClient`.
  Loopback, link-local and literal IP addresses stay blocked. New overloads:
  `ResilientHttp.GetBytesAsync(HttpClient, Uri, OutboundHttpPolicy, …)`,
  `ICertificateChainService.DownloadAiaCertsAsync(…, OutboundHttpPolicy, …)`,
  `LtvDataCollector.CollectAsync(IHttpClientProvider, …, LongTermValidationOptions, …)`.

### Added — more of the ETSI standards in CAdES and XAdES

CAdES (ETSI EN 319 122-1), on `CadesSignerBuilder`:

- `WithSignerLocation(CadesSignerLocation)` (§5.2.5), `WithContentHints(CadesContentHints)` and
  `WithMimeType(string)` (§5.2.4). A countersignature refuses the last two.
- `WithSignerRoles` / `WithSignerRole`, `WithAttributeCertificates` and `WithSignedAssertions`
  (§5.2.6.1, signer-attributes-v2). Attribute certificates and signed assertions are embedded as given
  and read back, not verified. `CadesSignedAttributes.Read` reads all of these from a signature.
- `WithContentTimestamp(TimestampOptions)` (§5.2.8): a timestamp over the content, taken before
  signing. `CadesValidationResult.HasValidContentTimestamp` and `ContentTimestampTime` report it.
- `WithSignaturePolicyStore(SignaturePolicyStore)` (§5.2.10), read with `CadesSignaturePolicyStore.Read`.
  Signing fails unless the policy is declared with its hash.

XAdES (ETSI EN 319 132-1), on `XadesSignerBuilder`:

- `WithSignatureProductionPlace(SignatureProductionPlace)` (§5.2.5). With
  `XadesSigningCertificateForm.V1` it is written as the XAdES 1.3.2 `SignatureProductionPlace`, which
  has no street address: signing fails when one is set.
- `WithAttributeCertificates` and `WithSignedAssertions` (§5.2.6, CertifiedRolesV2 and SignedAssertions),
  embedded as given and read back, not verified.
- `WithDataObjectsTimestamp(TimestampOptions)` (§5.2.8.1, AllDataObjectsTimeStamp).
- `WithSignaturePolicyStore(SignaturePolicyStore)` (§5.2.10).
- `WithCanonicalization(XadesCanonicalization)`: Exclusive C14N 1.0 (default) or Canonical XML 1.0 for
  SignedInfo and the references.
- `WithAdditionalDataObject(XadesDataObject)`: more files signed with the document, carried inside the
  signature (`XadesDataObject.Embedded`) or kept outside it (`XadesDataObject.External`), each with
  its DataObjectFormat.
- `XadesSigner.CounterSign(signedXml, signatureId)` (§5.2.7.2): an enveloped countersignature, at B-B or B-T.
- `XadesValidationResult` gains `CounterSignatures`, `HasValidDataObjectsTimeStamp`,
  `DataObjectsTimeStampTime`, `SignaturePolicyStore`, `ClaimedRoles`, `AttributeCertificates` and
  `SignedAssertions`. `XadesSignatureValidator.Validate` and `ValidateAll` have overloads that take the
  content of each external reference by URI (`IReadOnlyDictionary<string, byte[]>`).

All formats:

- `LongTermValidationOptions.RevocationPreference` (`RevocationPreference.OcspFirst`, the default, or
  `CrlFirst`): which revocation source is tried first when collecting B-LT data. Also on `LtvEmbedder`
  and `LtvDataCollector.CollectAsync`; a deferred PAdES session carries it.
- `ILtvEmbedder.EmbedLtvDataAsync(…, LongTermValidationOptions, …)`: the PAdES signer now calls this
  overload, so an injected embedder receives the signature's options. It is a default interface member
  that forwards to the overload without options; `LtvEmbedder` overrides it, and the signature's
  revocation preference and clock skew replace the ones the embedder was created with (before, an
  embedder injected into `PadesSignerBuilder`, such as the one `AddSimpleSign()` registers, ignored
  them).
- `SignaturePolicyStore` (`SimpleSign.Core.Crypto`): the policy document, or the URI of a local copy,
  with `MatchesHash(SignaturePolicyReference)`.

CLI:

- `simplesign cades sign`: `--signer-country`, `--signer-locality`, `--signer-postal-address`,
  `--signer-role`, `--attribute-certificate`, `--signed-assertion`, `--mime-type`,
  `--content-description`, `--content-timestamp`, `--policy-document` with `--policy-specification`.
- `simplesign xades sign`: `--place-city`, `--place-street`, `--place-state`, `--place-postal-code`,
  `--place-country`, `--canonicalization`, `--data-objects-timestamp`, `--attribute-certificate`,
  `--signed-assertion`, `--embed-object`, `--external-object`, `--policy-document` with
  `--policy-specification`, and `--countersign` with `--countersign-id`.
- `simplesign xades validate --external-object URI=PATH` for signatures with external data objects.
- `--revocation-preference ocsp|crl` on `sign`, `cades sign` and `xades sign`.

Tests: `DssCrossValidationTests` sends signatures that use these options to a local EU DSS
(`tools/dss`) and asserts what it reads from them; it is skipped when no DSS is running. The TestBench
combination matrices for CAdES and XAdES include the new options.

### Changed — XAdES output and validation

- Every signature now has a `DataObjectFormat` for the document (`text/xml`, pointing to an `Id` on the
  document's `ds:Reference`), as ETSI EN 319 132-1 §6.3 requires for each signed data object. Not
  written for a countersignature or with `XadesSigningCertificateForm.V1`, unless a format or an
  additional data object is asked for. A `DataObjectFormat` given without an `ObjectReference` now
  points to the document reference; it had no `ObjectReference` attribute before.
- Claimed signer roles are written in `SignerRoleV2`, as ETSI EN 319 132-1 requires. The `SignerRole` it
  obsoletes is written only with `XadesSigningCertificateForm.V1`.
- Every new signature has an `Id` on `ds:SignatureValue`, which is what a countersignature references.
- The validator reports a countersignature under `XadesValidationResult.CounterSignatures` of the
  signature it signs. `ValidateAll` no longer lists it as one more signature of the document, and
  `Validate` accepts a document with one signature and its countersignatures.
- The validator canonicalizes SignedInfo with the algorithm it declares (it used Exclusive C14N for every
  signature), and canonicalizes Canonical XML 1.0 subsets with the namespace context of their ancestors.
- `validator.Validate(xml, anchors, null)` is now ambiguous between the two overloads: drop the
  argument, name it (`originalData: null`) or cast the `null`.

### Fixed

- `TimestampClient.EmbedTimestampInCms` wrapped the values of every unsigned attribute already in the
  SignerInfo in a second SET. It affected a CMS that had an unsigned attribute before the signature
  timestamp was embedded; such attributes are now kept octet for octet.
- `TimestampToken.Verify` and `VerifyHash` did not recognize SHA-3 message imprints and reported a
  valid token as not covering the data.

### Changed (Breaking) — SimpleSign.Brasil split into SimpleSign.Brazil, .IcpBrasil and .GovBr

`SimpleSign.Brasil` is discontinued. Each Brazilian hierarchy is now its own package, under
`src/TrustFrameworks/Brazil/`. `SimpleSign.Brazil.IcpBrasil` and `SimpleSign.Brazil.GovBr` depend on
the shared `SimpleSign.Brazil`, never on each other. Install the one you need, or both.

| Before | After |
|---|---|
| package `SimpleSign.Brasil` | `SimpleSign.Brazil.IcpBrasil` and/or `SimpleSign.Brazil.GovBr` (both pull in `SimpleSign.Brazil`) |
| package `SimpleSign.Brasil.Xades` | `SimpleSign.Brazil.IcpBrasil.Xades` |
| package `SimpleSign.Brasil.Fiscal` | `SimpleSign.Brazil.Fiscal` |
| `SimpleSign.Brasil` (`Cpf`, `Cnpj`, `Lei14063`) | `SimpleSign.Brazil` |
| `SimpleSign.Brasil.Signing` (manifest, `WithAdvancedSignature`) | `SimpleSign.Brazil.Signing` (`SignerBuilderBrasilExtensions` → `SignerBuilderBrazilExtensions`) |
| `SimpleSign.Brasil.Signing` (`IcpBrasilPadesOptions`, `WithIcpBrasilPolicy`, health documents) | `SimpleSign.Brazil.IcpBrasil` |
| `SimpleSign.Brasil.IcpBrasil` | `SimpleSign.Brazil.IcpBrasil` |
| `SimpleSign.Brasil.GovBr` | `SimpleSign.Brazil.GovBr` |
| `SimpleSign.Brasil.ValidarIti` | `SimpleSign.Brazil.ValidarIti` |
| `SimpleSign.Brasil.Xades` / `.Fiscal` | `SimpleSign.Brazil.IcpBrasil.Xades` / `SimpleSign.Brazil.Fiscal` |
| `new BrasilExtension(...)` | `new IcpBrasilExtension(...)` and `new GovBrExtension(...)`: pass both to accept both |
| `BrasilExtension.CreateValidator()` | `IcpBrasilExtension.CreateValidator()` / `GovBrExtension.CreateValidator()` |
| `BrasilExtensionOptions` (`AdditionalIcpRoots`) | `IcpBrasilExtensionOptions` (`AdditionalRoots`) and `GovBrExtensionOptions` |
| `services.AddSimpleSignBrasil()` | `services.AddSimpleSignIcpBrasil()` and/or `services.AddSimpleSignGovBr()` |

Behavior is unchanged: the same roots, chain rules, metadata (`BR.*`, `BR.Lei14063`) and log event
IDs. To validate both hierarchies:

```csharp
var validator = new PdfSignatureValidator(options, httpClient,
    countryExtensions: [new IcpBrasilExtension(), new GovBrExtension()]);
```

`src/TrustFrameworks/Europe/Eidas/` and `src/TrustFrameworks/Peru/Iofe/` are placeholders for
planned eIDAS and IOFE extensions.

### Changed (Breaking) — SimpleSign.Pdf merged into SimpleSign.PAdES

The PDF structure parser is now part of `SimpleSign.PAdES`; the `SimpleSign.Pdf` package is
discontinued and no longer published.

- Remove any `SimpleSign.Pdf` package reference; `SimpleSign.PAdES` contains the same types.
- **Namespaces renamed:** `SimpleSign.Pdf` → `SimpleSign.PAdES.Pdf`, and likewise
  `.Constants`, `.Enums` and `.Exceptions` (e.g. `using SimpleSign.PAdES.Pdf.Exceptions;`).
- Type names are unchanged (`PdfStructureReader`, `PdfSignatureField`, `PdfByteRange`,
  `PdfVersion`, `PdfALevel`, `PdfStructureException`, `EncryptedPdfException`, …).

### Changed (Breaking) — SimpleSign.Brasil no longer uses Core internals

`SimpleSign.Brasil`, `.Fiscal` and `.Xades` now build against the public API of Core, PAdES,
CAdES and XAdES only (no `InternalsVisibleTo`).

- **Removed:** `Oids.IcpBrasilSanHolderData` and `Oids.IcpBrasilSanCnpj` from `SimpleSign.Core`
  (use the literal OIDs `2.16.76.1.3.1` and `2.16.76.1.3.3`; `IcpBrasilChainValidator` reads them for you).
- **Now public**, for country extensions:
  - `CrlEvaluator.Evaluate` / `ReadNextUpdate` and `CrlStatus`
  - `CrlClient.GetCrlUri` and `OcspClient.GetOcspUri`
  - `ResilientHttp.GetBytesAsync(HttpClient, Uri, …)` and `ResilientHttp.DefaultChainRetrievalTimeout`
  - `SignerCertificate` / `SignerChain` on `PadesSignerBuilder`, `CadesSignerBuilder` and `XadesSignerBuilder`
- The ICP-Brasil and Gov.br log events (3110, 3113, 3210) moved from Core to `SimpleSign.Brasil`
  with the same event IDs.

### Removed (repository)

- `samples/`, `bench/`, `interop/` and the interop tests, the fuzz harness, Stryker, the docfx site,
  migration guides, `llms*.txt`, `AGENTS.md` and `.github/copilot-instructions.md`. The README now
  links to `docs/articles/`.
- `tests/unit/` now mirrors `src/` (`Core/`, `Formats/`, `TrustFrameworks/Brazil/…`, `Signers/`,
  `Extras/`, `Apps/`), the CLI tests moved there and into `SimpleSign.sln` (so CI runs them on every
  PR), every test class has a `Category` trait, and `dss-1443.pdf` (a byte-identical copy of
  `pades-lta.pdf`) is gone. New tests cover `ResilientHttp` (SSRF refusal, retries) and the
  ICP-Brasil and Gov.br extensions registered together.
- The `simplesign-<rid>.zip` CLI archives on GitHub Releases and `scripts/install/install-cli.sh` /
  `.ps1`. They were framework-dependent, so they needed .NET anyway: install the CLI with
  `dotnet tool install -g SimpleSign.Cli`. The release workflow now runs the CLI tests before
  pushing to NuGet.

### Changed — SimpleSign.XAdES no longer depends on SimpleSign.CAdES

The LTV collection and revocation-evidence helpers that XAdES borrowed from CAdES (internals)
moved into `SimpleSign.Core`. `LtvDataCollector` and `LtvCollectionResult` stay public in CAdES,
with the same behavior. Installing `SimpleSign.XAdES` no longer pulls in `SimpleSign.CAdES`.

### Fixed

- **XAdES B-LTA was not recognized as LTA by other validators.** The `EncapsulatedTimeStamp` of
  `xades141:ArchiveTimeStamp` was written in the XAdES v1.4.1 namespace; its type is
  `xades:XAdESTimeStampType`, so the child belongs to v1.3.2. EU DSS did not find the token and
  reported XAdES-BASELINE-LT. It is now written in the v1.3.2 namespace, and DSS reports
  XAdES-BASELINE-LTA (and XAdES-A for the extended form). Signatures made by earlier versions are
  still read and validated by SimpleSign. Found with the TestBench's DSS cross-validation.

- Log EventId 2401 was used by two different events (Core "certificate revoked in embedded CRL"
  and PAdES "revocation check failed"); the PAdES event is now 2032. The never-emitted event 2712
  was removed, and 1023 ("LTV embedded, no archival timestamp") is now emitted for B-LT.

- `AddSimpleSignIcpBrasil()` / `AddSimpleSignGovBr()` (before: `AddSimpleSignBrasil()`) registered
  `IcpBrasilChainValidator` and `GovBrChainValidator` so that the container could not build them
  (two ambiguous constructors): resolving either one threw. They are now created from the registered
  `IHttpClientProvider` and `ILoggerFactory`, and the extensions use them too.

- HtmlToPdf: deeply nested HTML crashed the process with a stack overflow. Layout recurses once
  or more per nesting level, and the 256 levels the parser allows overflowed small thread stacks
  (512 KiB for .NET 8 secondary threads on macOS; flex, inline-block, float and list nesting
  already at about 128 levels). Layout now checks the remaining stack and, when it runs low,
  continues on a fresh thread-pool stack, so the document renders in full on any thread.
- CAdES validation: on SHA-3 signatures the escTimeStamp (CAdES-X) and archive-time-stamp v2
  (CAdES-A) were checked against a SHA-256 imprint, so they were reported as not covering the
  signature, and signing with `WithExtendedValidationData(CadesExtendedForm.Archive)` on B-LTA
  failed its own archive check. The imprint now uses the signer's SHA-3 digest.
- CAdES: `WithExtendedValidationData` combined with B-LT or B-LTA. The extended form was applied
  before the B-LT certificate and revocation values, so with `CadesExtendedForm.Archive` the
  archive-time-stamp v2 did not cover them (B-LT: the signature failed validation; B-LTA: signing
  threw because the archive-time-stamp-v3 did not validate). The extended form now goes after the
  LT values and before the archive-time-stamp-v3; every form works on B-T, B-LT and B-LTA.

- `CadesSignatureValidator` now builds the signer's chain with the certificates embedded in the
  CMS, as it already did for the TSA. Before, a signer under an intermediate CA was reported with
  `PartialChain` (chain not valid) unless the intermediate was itself passed as a trust anchor or
  was in the OS store.
- `XadesSignatureValidator` builds the signer's chain with the certificates in `KeyInfo/X509Data`
  (it already did for the TSA) and honours `ValidationOptions.TrustedRoots` and
  `TrustSystemRoots = false`, like the CAdES validator (including its tolerance of unknown
  revocation status under custom roots). Before, a signer under an intermediate CA
  failed with `PartialChain`, and `TrustedRoots` was ignored (only the `trustAnchors` argument
  counted).

### Security

- `LoopbackAuthorizationHandler.OpenInSystemBrowser` only opens absolute http(s) URLs; other
  schemes (e.g. `file:`), which the OS shell would hand to other programs, throw `ArgumentException`.

### Added (diagnostic logging)

- **XAdES** signing now logs every step (events 7000–7028): start and completion, resolved
  algorithm, SignedProperties, reference digests, SignedInfo canonicalization, SignatureValue,
  external signer, timestamps, validation data, extended forms and the read-back check. The logger
  given to `WithLogger` was accepted but ignored before.
- `XadesSignatureValidator` accepts an `ILogger` (new optional constructor parameter) and logs the
  verdict of each signature (7050, 7051).
- **CAdES** signing logs its own steps (events 7100–7131): start and completion, algorithm, signed
  attributes, timestamps, validation data, extended forms, archive-time-stamp-v3, co-signatures and
  countersignatures.
- **PAdES** logs the resolved algorithm, the PDF/A level, the field configuration, the read-back
  check (1002–1005) and the DocTimeStamp writer steps (5010, 5011).
- **Signers:** `Pkcs11SignerOptions.Logger`, `CscClientOptions.Logger` and `PscClientOptions.Logger`
  receive diagnostics of token, CSC and PSC signatures (events 72xx, 73xx). PINs, OTPs, tokens and
  client secrets are never logged.

### Changed (SimpleSign TestBench) — one workbench for PAdES, CAdES and XAdES

- The PDF wizard and the separate CAdES and XML pages are replaced by a single **workbench**: pick
  the format, set any option, sign, and read the result, the verdicts, the log and the code on the
  same screen. Baseline presets (B-B…B-LTA) and **Vary** (sign once per value of one option) make
  many combinations quick; every run is kept in a history.
- **Every option names its standard.** The form is drawn from one option schema
  (`/api/schema`): each option carries its explanation, the clause that defines it (ETSI EN 319
  142-1, 122-1, 132-1, 102-1, RFC 5652/3161/6960/5280, ISO 32000-1, XMLDSig) and the library call it
  becomes. Options the standards define and SimpleSign does not implement are listed too, disabled;
  the new **Coverage** page shows them for each format.
- **Logs.** Each run passes a logger to every builder and validator and shows the library events
  and the network requests live, grouped by signing stage; each stage names its clause.
- **Cross-validation with the EU DSS** (off by default): each run is also sent to the DSS REST
  validation service and the two verdicts are shown side by side. `tools/dss/` runs DSS in Docker
  and makes it trust the sandbox root, which the TestBench now keeps between runs
  (`--ephemeral-sandbox` for a new root every start).
- **Trust frameworks are off by default.** The Brazil chip shows the ICP-Brasil, Gov.br, health
  and fiscal options in their own color and turns the Brazilian validation rules on.
- The run matrix reports cases as they finish and can be stopped.
- **No side menu: two tasks, Sign and Validate**, on the same screen. Reference (coverage) and
  Environment (sandbox) open as panels; the run matrix opens from Vary.
- **Combinations** replaces the run matrix page: one or several options, all combinations or
  pairwise, each line a normal run with its log; summary per value and filters. The fixed matrix
  stays in the CI tests only, and its endpoints are removed.
- **Environment is a sandbox lab:** the PKI as a tree with downloads, run-time revocation of a
  signer, and failures to switch on (TSA down, slow, invalid token or outside the chain; CRL
  server down or serving expired CRLs), to see how signing and validation react.
- **Reference by standard**, and a generated [coverage page](docs/articles/coverage.md) that a test
  keeps in step with the option schema.
- **Environment follows the mode.** In Real it shows the trusted roots, the public TSAs, the
  tokens and the OS store of this machine instead of the sandbox; sandbox failures only show and
  act in Sandbox.
- **PSC and CSC are explained** in the signer picker, step by step, and in Sandbox one click opens
  a credential of the simulated provider. Cloud and token signers now log into the run (they were
  opened without a logger, so events 72xx and 73xx never reached the Logs tab).
- **Values are no longer cut:** URLs, names, OIDs and hex wrap, with a copy button; the signer
  tabs no longer overlap their content.
- **Validate is one screen for the three formats.** The format is read from the file; a validation
  is a run like a signature, with the same result panel, log, DSS comparison and history.
  "Validate all samples" checks every sample against its expected verdict. The separate PDF, CAdES
  and XML validation pages and `/api/validation`, `/api/cades/validate` and `/api/xml/validate`
  are replaced by `/api/runs` with `kind: "validate"`.
- The UI and the server texts are in English and Portuguese; Spanish was removed.
- API: `/api/options`, `/api/sign`, `/api/cades/options|sign` and `/api/xml/options|sign` are
  replaced by `/api/workbench/options` and `/api/runs` (with a server-sent events stream).

### Added (SimpleSign TestBench)

- TestBench **XML** page: XAdES (enveloped, detached, enveloping; B-B…B-LTA, ICP-Brasil XML
  policies, custom policy, extended forms, roles, DataObjectFormat, SigningCertificate V1) and the
  fiscal XML-DSig layouts (NF-e, events, voiding, CT-e, MDF-e, NFS-e DPS, eSocial, EFD-Reinf; sign
  one or all), with validation, the Signature element, generated C# and CLI, broken samples and an
  XML run matrix.

- TestBench **CAdES** page: sign, co-sign and countersign any file (detached .p7s or enveloped
  .p7m) at every CAdES baseline level, ICP-Brasil CAdES policy (AD-RB…AD-RA) or custom policy,
  with RFC 5126 extended forms; validation tree with countersignatures, CMS structure, generated
  C# and CLI, broken samples, and a CAdES run matrix. The signer picker is shared with PDF signing.
- Validation samples are no longer evicted from the in-memory store after 200 uploads.

- TestBench **Validation** page: full report per signature (checks, PAdES and Lei 14.063 levels,
  certificates, timestamp, ByteRange coverage, DSS) with configurable trust, bulk validation
  (`BulkValidator`), structural inspection (`PdfStructureDumper`, CMS download), and sample PDFs
  broken in specific ways (tampered content or CMS, appended bytes, revoked or expired signer,
  unknown root, untrusted TSA). The signing result links to it.

- The TestBench is available in English (en-US), Portuguese (pt-BR) and Spanish (es): browser
  language by default, with a selector in the top bar. Server texts (explanations, compatibility
  messages, samples) follow `Accept-Language`; a test checks every text has its translations.

- New `src/SimpleSign.TestBench`: a local web app (ASP.NET Core minimal API + React, Vite,
  Tailwind and shadcn/ui) to try every PDF signing option, explained, in a step-by-step flow that
  only offers compatible options. Signers: sandbox A1, PFX, OS store, A3 tokens (PKCS#11), ICP-Brasil
  PSC and CSC v2. Signature types: PAdES B-B…B-LTA, every ICP-Brasil PAdES policy and version, or a
  custom policy. Live stamp preview (pdf.js), validation report, and the matching C# and CLI code.
- **Sandbox** mode: offline test PKI (every key type and the edge cases), RFC 3161 TSA (plain and
  with Basic auth), CRLs, and simulated PSC and CSC v2 services, served through an in-process
  `IHttpClientProvider`. **Real** mode uses your certificates and real services.
- **Run matrix**: cases generated from the compatibility rules (every value, plus pairwise
  combinations), signed and validated in the sandbox; part of the CI (`testbench` job). See
  `docs/articles/testbench.md`.

### Added (ICP-Brasil PAdES AD-RC and AD-RA)

- `WithIcpBrasilPolicy(policy, IcpBrasilPadesOptions)` signs PAdES under AD-RB, AD-RT, **AD-RC**
  (signature timestamp, DSS with VRI, document timestamp) and **AD-RA** (AD-RC plus the PA, LPA and
  LPA signature in the DSS), with an optional specific policy `Version`, archive TSA and revocation
  settings. `ResolveIcpBrasilPolicy` returns the version that would be used.
- `IcpBrasilPolicyArtifacts.DownloadAsync` downloads and verifies the AD-RA artifacts from the ITI.
- `IcpBrasilPolicyValidator.Validate(cms, time, root, PdfSignatureFacts)` checks the PDF structures
  the PAdES PAs mandate (`2.16.76.1.8.1`–`.3`); the ICP-Brasil provider runs it for PDF signatures.
- PAdES: `PdfSignatureSubFilter.PbadPades`, `PadesSignerBuilder.WithDssArtifacts` and
  `PdfDssArtifact` (custom DSS arrays and VRI entries, kept when a later signature rewrites the
  DSS); `ChainValidationContext.Pdf` (`PdfSignatureFacts`) and `PdfSignatureField.Filter`.
- `ArchiveTimestampOptions.Authorization`, `ClientCertificate` and `Resolve`; without its own
  endpoint the archive timestamp now uses the signature TSA's credentials and client certificate.
- `DeferredSignerBuilder.WithTimestampOptions` supplies the TSA credentials a resumed session
  cannot store.
- CLI: `--icp-policy ad-rc|ad-ra`; the version follows the signer's root.

### Changed

- ICP-Brasil PAdES signatures use `/Filter /PBAD_PAdES /SubFilter /PBAD.PAdES`, as the PAs mandate
  (previously `ETSI.CAdES.detached`). Same CMS; PDF/A-1 preservation refuses it like ETSI.
- DocMDP: only P=1 blocks further signatures; P=2 and P=3 documents can be signed again
  (ISO 32000-1 §12.8.2.2.2). Certifying a document that is already signed is refused.
- `WithExistingField` draws the configured appearance in the field's rectangle (it was ignored);
  an appearance on a field without a visible rectangle is refused.
- CLI: `--archival` requires `--tsa` (it silently produced B-B); `--icp-policy` rejects
  `--sub-filter`, `--ltv` and `--archival` (the policy sets them).

### Added (SimpleSign Agent — replaces SimpleSign.HostSigner)

- New cross-platform tray / menu-bar app (Avalonia; macOS, Windows, Linux), `src/SimpleSign.Agent`:
  the **local signing agent** web pages call to sign with the OS store or an A3 token. The menu
  pauses the agent, lists and revokes authorized sites, and starts it at login. See
  `docs/articles/agent.md`.
- **Local signing agent** (127.0.0.1:21590), compatible with the HostSigner
  `/api/health`, `/api/certificates` and `/api/sign` contract, now with A3 tokens, per-site
  authorization, a consent dialog for every signature, the PIN asked by the app, Chrome Private
  Network Access, rate and size limits.

### Removed

- `SimpleSign.HostSigner` (Windows-only tray app), its web UI and install scripts. Its
  `/api/sign-file`, `/api/inspect` and `/api/validate` endpoints, which took local file paths,
  are not in the new agent.

### Added (SimpleSign.Signers.Pkcs11 — driver detection)

- `Pkcs11Drivers`: catalog of the token middlewares used in Brazil with their install paths per OS
  (`Known`), `DetectInstalled()`, `FindTokensAsync()` and `FindLibraryAsync(tokenLabel)`; extra paths
  through `SIMPLESIGN_PKCS11_LIBRARY`.
- CLI: `pkcs11 list` without `--lib` lists the tokens of every installed driver; `pkcs11 drivers`;
  `--pkcs11-lib auto` when signing.

### Added (new package SimpleSign.Brasil.Xades)

- `XadesSignerBuilder.WithIcpBrasilPolicy(policy, tsa)`: XAdES AD-RB, AD-RT, AD-RV, AD-RC and AD-RA
  under the XML PAs, root-aware, with SigningCertificate (XAdES 1.3.2) and every mandated property.
- `IcpBrasilXadesPolicyValidator.Validate(signedXml, result)`: hash, period, roots, mandated
  properties, algorithm and key size.
- `IcpBrasilXadesPolicies.RefreshAsync`: downloads `LPA_XAdES.xml` and verifies its ITI XML signature
  with a strict verifier (the ITI's KeyInfo reference cannot be verified by `SignedXml`).

### Added (XAdES)

- `WithSigningCertificateForm(XadesSigningCertificateForm.V1)`: XAdES 1.3.2 SigningCertificate; the
  validator now resolves the signer from SigningCertificate as well as SigningCertificateV2 (it
  failed on signatures from other ICP-Brasil signers).
- `WithExtendedValidationData(XadesExtendedForm)`: CompleteCertificateRefs, CompleteRevocationRefs,
  SigAndRefsTimeStamp, CertificateValues/RevocationValues and ArchiveTimeStamp (XAdES-C/X/X-L/A);
  `XadesValidationResult.HasValidSigAndRefsTimeStamp` and `HasValidCompleteReferences`.

### Added (SimpleSign.Brasil — XML policies, timestamps)

- Rules of the 45 XML PAs in the catalog; `IcpBrasilPolicyRules.ParseXml`,
  `IcpBrasilSignaturePolicies.FromXmlPolicyDocument`, `IcpBrasilLpa.ParseXml`.
- `IcpBrasilTimestamp.Verify` / `VerifyHash`: standalone timestamps from ICP-Brasil ACTs.

### Added (Core — standalone timestamps)

- `TimestampToken.CreateAsync` / `CreateForHashAsync` / `Verify` / `VerifyHash` (`.tst` files,
  RFC 3161) and `TimestampClient.GetTimestampForHashAsync`. CLI: `simplesign timestamp create|verify`.

### Added (SimpleSign.Brasil — complete signature policies)

- **PA rules:** `IcpBrasilPolicyRules` (accepted roots, mandatory signed/unsigned attributes,
  signature algorithms and key sizes) for the 55 CAdES/PAdES PAs, via
  `IcpBrasilSignaturePolicies.TryGetRules`; `IcpBrasilPolicyRules.Parse`; `RefreshAsync` parses the
  rules of new PAs.
- **Root-aware policy selection:** `Current(policy, format, signerRoot)` and `WithIcpBrasilPolicy`
  pick the newest PA that accepts the signer's AC Raiz (v12 signers get CAdES ≥ 2.4 / PAdES ≥ 1.2)
  and throw `IcpBrasilPolicyException` when none does. `IcpBrasilChainValidator.FindBundledRoot`.
- **Policy validation:** `IcpBrasilPolicyValidator.Validate(cms, time, format, signerRoot)` checks
  roots, attributes and algorithms; the ICP-Brasil provider passes the chain root.
  `Validate(SignaturePolicyReference, time, hasTimestamp, format)` validates XAdES (and other) references.
- **CAdES AD-RV, AD-RC and AD-RA:** `CadesSignerBuilder.WithIcpBrasilPolicy(policy, tsa)`.
- **XAdES:** the 45 XML policies of `LPA_XAdES.xml` in the catalog (no refresh, no rules).

### Added (CAdES / XAdES)

- `CadesSignerBuilder.WithExtendedValidationData(CadesExtendedForm)`: complete certificate and
  revocation references, escTimeStamp, certificate and revocation values, archive-time-stamp v2
  (RFC 5126). `CadesSignatureValidator` verifies escTimeStamp and archive v2 imprints.
- `XadesSignerBuilder.WithSignaturePolicy(SignaturePolicyReference)` writes the policy's hash in
  `SigPolicyHash` and the OID as `urn:oid:` (`Qualifier="OIDAsURN"`);
  `XadesValidationResult.SignaturePolicy` exposes the declared policy.

### Changed

- CAdES signatures now always include the signing-certificate-v2 signed attribute (it was
  PAdES-only); every ICP-Brasil PA mandates it.

### Added (CAdES — several signers)

- `CadesSigner.CoSign(existing, data?)` (parallel signers, .p7s or .p7m) and
  `CadesSigner.CounterSign(existing, signerIndex)` (RFC 5652 §11.4, no content-type).
- `CadesSignatureValidator.ValidateAll` → `CadesValidationReport` with every signer and
  countersigner; `ValidateWithHash(cms, hash, oid)`; `Validate(cms, null)` validates an attached
  signature's encapsulated content (passing null used to throw).
- `CadesSigner.ExtractContent(p7m)`; Core: `CmsParser.ParseAll` / `CmsSignedDataSet`,
  `CmsSignedData.EncapsulatedContent` and `CounterSignatures`, `Oids.CounterSignature`.

### Added (new package SimpleSign.Brasil.Fiscal)

- `FiscalXmlSigner` / `FiscalXmlValidator`: XMLDSig of NF-e/NFC-e, CT-e, MDF-e, events and
  inutilização, NFS-e Nacional (DPS), eSocial and EFD-Reinf (`FiscalDocumentProfile`), local key or
  `IExternalSigner`; validation of digest, signature value and ICP-Brasil chain, rejecting
  duplicate Ids. CLI: `simplesign fiscal sign|validate`.

### Added (SimpleSign.Brasil — ICP-Brasil infrastructure)

- **Bundled intermediate ACs:** the ~176 ICP-Brasil intermediates from the ITI's `ACcompactado.zip`
  (`IcpBrasilChainValidator.LoadBundledIntermediateCerts()`), used for offline chain building by the
  ICP-Brasil validator and trust anchor provider. Regenerate with `scripts/update-icp-intermediates.sh`.
- **LPA refresh:** `IcpBrasilSignaturePolicies.RefreshAsync(httpClient, format)` downloads the
  PAdES/CAdES LPA, verifies its ITI signature (`LPA_*.p7s`) and chain, applies new revocation dates
  and adds new PAs checked against the LPA digest. `IcpBrasilLpa.Parse` reads an LPA.
- **LCR disk cache:** `CrlCacheDirectory` on `IcpBrasilChainValidator`, `GovBrChainValidator` and the
  new `BrasilExtensionOptions`; LCRs are reused until their nextUpdate.
- **ACT authentication and TCP (Core):** `TimestampOptions.Authorization` (Basic/bearer, per request),
  `TimestampOptions.ClientCertificate` (mutual TLS) and `tcp://host:port` endpoints (RFC 3161 §3.3
  socket transport); `TimestampClient.Create(options, provider)`.

### Fixed (SimpleSign.Brasil — see the [v0.10 → v0.11 migration guide](docs/articles/icp-brasil.md#upgrading-from-v010-to-v011))

- **Professional registrations:** CRM/CRO were read from `2.16.76.1.3.4`/`3.5`/`3.6`, which hold
  the e-CNPJ responsible person's data, the voter registration and the CEI. Registrations are now
  read from `2.16.76.1.4.2.{council}` (registration, UF, specialty) for all 16 councils:
  `ExtractProfessionalRegistrations` and `ProfessionalRegistration` replace `ExtractHealthProfessional`.
- **Signature manifest OID:** the Lei 14.063 manifest used `2.16.76.1.12.1.1`, the ITI's OID for the
  "prescrição de medicamento" document type. It now uses a SimpleSign UUID OID; old signatures are
  still read.
- **Certificate types:** S1–S4 are policy types 101–104 (were 11–14); T3, T4, A CF-e-SAT and OM-BR
  added. Policy OIDs are decoded instead of matched by bytes.
- **Signature policies:** `DetectPolicy(certificate)` is obsolete (policies are signature
  attributes); new `IcpBrasilPolicyInfo.TryParse` maps CAdES, XAdES and PAdES policy OIDs. The false
  "policy OID not found" warning on every ICP-Brasil certificate is gone.
- **CNPJ:** alphanumeric CNPJs (IN RFB 2.229/2024) are accepted.
- **VALIDAR:** `ValidarItiUrlBuilder.ForDocument` is obsolete (`?document=` is not a VALIDAR
  parameter). New `ValidarItiQrEndpoint` implements the documented QR protocol
  (`_format`, `_secretCode`, JSON with the signed files, 401/404).
- **Chain validation time and revocation:** the ICP-Brasil and Gov.br providers validate at the
  trusted signature timestamp time and check LCRs/OCSP (embedded in the DSS first, then online) for
  the certificate and every AC, instead of the OS check at the current time that treated unknown
  revocation as success. B-LT/B-LTA signatures stay valid after the certificate expires. Results
  report `RevocationStatus` and `ValidationTime`; the Certisign/ITI "verify manually" links are gone.
- **Gov.br anchors:** only the AC Raiz is a trust anchor; the intermediate ACs are chain-building help.
- **Duplicate policy attribute:** `WithAdvancedSignature` with a `PolicyOid` wrote the
  signature-policy-identifier twice; signed attributes are now unique per type.

### Added (SimpleSign.Brasil)

- **ICP-Brasil signature policies with hash:** `IcpBrasilSignaturePolicies` embeds the ITI's
  LPA_PAdES and LPA_CAdES (55 policies: OID, PA URI, signPolicyHash, signing period, revocation);
  `Current(policy, format)` picks the version in force (PAdES AD-RB/AD-RT v1.3, CAdES v2.4).
  `PadesSignerBuilder.WithIcpBrasilPolicy(AdRb | AdRt, tsa?)` signs under them; previously the
  signature-policy-identifier carried an empty hash.
- `IcpBrasilPolicyValidator`: checks sigPolicyHash, signing period/revocation and the timestamp
  AD-RT requires; the ICP-Brasil provider reports `BR.SignaturePolicy`/`BR.SignaturePolicyStatus`.
- `WithHealthDocument(type, registrations…)`: VALIDAR health-document OIDs (document type, CFM/CFF/CFO
  registration and UF) in the PDF document information dictionary.
- `Cpf` / `Cnpj`: public `IsValid`, `Format`, `Normalize` (and `Cpf.Mask`), alphanumeric CNPJ included.
- `IcpBrasilRoots`: bundled roots, `ExpiringWithin`, `DownloadAsync`/`FromPinnedBytes` (SHA-256
  pinned) for new AC Raiz versions; `IcpBrasilChainValidator.AdditionalTrustAnchors` and
  `new BrasilExtension(httpClient, logger, additionalIcpRoots)`.
- CLI: `sign --icp-policy ad-rb|ad-rt`, `--health-document`, `--registration COUNCIL:NUMBER/UF`;
  `validate`/`validate-dir` run the ICP-Brasil and Gov.br providers and print the Lei 14.063 level,
  certificate data, policy status and revocation status (`--json`: `lei14063`, `brasil`).
- Core/PAdES/CAdES: `SignaturePolicyReference`, `CmsAttribute.SignaturePolicyIdentifier(reference)`,
  `CmsAttribute.ReadSignaturePolicy`, `PadesSignerBuilder.WithSignaturePolicy(reference)`,
  `CadesSignerBuilder.WithSignaturePolicy(reference)`, `PadesSignerBuilder.WithDocumentInfo(key, value)`.

- `IChainValidationProvider.ValidateAsync(ChainValidationContext, CancellationToken)`: providers
  receive the validation time, the embedded CRLs/OCSP responses and the parsed signature. Default
  implementation delegates to the existing overloads. `ChainValidationResult.RevocationStatus`,
  `TimestampTokenValidationResult.GenTime`, `TimestampValidator.ReadGenTime`,
  `ITrustAnchorProvider.GetIntermediateCertificates()`.
- `Lei14063.Classify(result, manifestJson?)`: simples / avançada / qualificada (art. 4); the providers
  also fill `ChainValidationMetadata["BR.Lei14063"]`.
- `IcpBrasilCertificateData`: all DOC-ICP-04 SubjectAltName fields (PF birth date, CPF, NIS, RG,
  voter registration, CEI; PJ responsible name and CPF, CNPJ, company name). Gov.br CPF extraction
  shares the same parser.

### Added

- **One-call signing:** `PadesSigner.SignFileAsync(input, output, pfxPath, password, level?)`
  signs a PDF file with a PKCS#12 file and writes the result. The first certificate with a
  private key signs; the other certificates in the file are embedded as its chain.
- `PadesSignerBuilder.WithCertificateFile(pfxPath, password)` loads the signer and its chain from
  a PKCS#12 file, for the fluent API.
- **Well-known TSAs:** `TimestampOptions.DigiCert`, `TimestampOptions.Sectigo` and
  `TimestampOptions.FreeTsa`, e.g. `AdesBaselineProfile.Timestamped(TimestampOptions.DigiCert)`.
- **New package `SimpleSign.Signers.Pkcs11`:** sign with A3 tokens, smartcards and HSMs through
  their PKCS#11 driver (`Pkcs11Signer.Open(...)`, an `IExternalSigner` for PAdES, CAdES and XAdES;
  `Pkcs11Signer.ListTokens(...)`). Own minimal interop: no third-party dependencies, no `unsafe`,
  Native AOT compatible. Tested against SoftHSM2 (`scripts/tests/pkcs11.sh` runs it in Docker).
- **New package `SimpleSign.Signers.Cloud`:** sign with cloud certificates. `PscSigner`/`PscClient`
  implement the ICP-Brasil PSC API ("API v0", DOC-ICP-17.01: OAuth 2.0 with PKCE or CPF + OTP,
  certificate discovery, RAW signatures) for BirdID, VIDaaS, NeoID, SafeID, RemoteID and similar;
  field names are configurable through `PscWireFormat`. `CscSigner`/`CscClient` implement the
  Cloud Signature Consortium API v2 (service OAuth, credentials list/info/authorize, signHash;
  SCAL 1/2, PIN/OTP or OAuth credential authorization; RSA, RSASSA-PSS and ECDSA).
  `LoopbackAuthorizationHandler` completes OAuth logins in the browser for desktop and CLI apps.
  Validated against in-process simulators; real-provider tests run when sandbox credentials are set.
- CLI: `sign` and `cades sign` accept `--psc-*` and `--csc-*` options (secrets accept `env:NAME`);
  `psc certificates` and `csc list` show the available certificates.
- CLI: `sign` and `cades sign` accept `--pkcs11-lib`, `--pkcs11-token`, `--pkcs11-key` and `--pin`;
  `pkcs11 list --lib <path>` lists tokens and certificates.
- **Brasil:** `BrasilExtension.CreateValidator(options?, httpClient?, logger?)` returns a PAdES
  validator that trusts the ICP-Brasil and Gov.br roots, without positional `null` arguments.

## [0.10.1] - 2026-11-04

### Fixed

- **PDF reader: quadratic scan on hostile files.** Finding the signature dictionary for each
  `/ByteRange` marker searched backwards and rescanned the rest of the file for every `<<` it met.
  Thousands of unclosed dictionaries or markers made a 168 KB file take over 30 s (a denial of
  service on any service that validates uploads). Signature fields are now found in one linear
  pass, and the backward search used elsewhere stops at object and stream boundaries.
- **HtmlToPdf: quadratic hyphenation.** With `hyphens: auto`, choosing where to break a long word
  measured every candidate prefix on every line (13 s for a 17 KB page); it is now a binary search.
- **XAdES:** signing malformed XML threw a raw `XmlException`; it now throws `ArgumentException`
  (parameter `xmlData`, the parse error as inner exception), like a document without a root element.
- **Signature stamp:** the appearance content stream used the platform newline, so Windows and
  Unix produced different bytes for the same stamp; it now always uses LF.
- CAdES, XAdES and PAdES no longer create a new `HttpClient` for each embedded-revocation check.

### Added

- CLI: `validate --trust` and `validate-dir --trust` add your own root CA (PEM or DER) to the
  default roots, and `xades validate --data` validates detached XAdES signatures (documented
  before but missing).
- Fuzz harness: a built-in mutation fuzzer (`--mutate SECONDS`) that needs no AFL/libFuzzer, and
  `--input FILE` to reproduce a finding. `NullReferenceException`, `IndexOutOfRangeException`,
  `DivideByZeroException` and `OutOfMemoryException` are now reported as findings instead of
  being ignored. The weekly fuzz workflow had failed since it was added (it installed a
  non-existent `SharpFuzz.CommandTool` package); it now runs the mutation fuzzer on 11 targets.

### Tests

- 21 end-to-end CLI tests (validate with JSON, `--trust` and a tampered file; `validate-dir`;
  `inspect --json` and `--structure`; `html-to-pdf` with PDF/A; `explain`; CAdES and detached
  XAdES sign/validate). CLI tests that replace the global console now run serially.
- Regression tests for the fuzz findings; time bounds of the hostile-input tests relaxed so they
  do not flake under coverage instrumentation.

### Documentation

- README keeps only the v0.10.0 release notes. Fixed examples that did not compile against
  0.10.0 (`SignatureValidationResult.IsValid` → `Indication`, `DeclaredSignerName`), CLI examples
  with options that do not exist (`--timestamp`, `extract --output`, `explain --cert`), the
  ICP-Brasil validator example, missing `using` in the PAdES package readme, and test counts.

## [0.10.0] - 2026-11-04

### Changed (Breaking) — Signature Validation

See the [v0.9 → v0.10 migration guide](https://github.com/eupassarin/SimpleSign/blob/pre-cleanup/docs/migration/v0.9-to-v0.10.md).

- Made the three-state signature indication (`Valid`, `Invalid`, `Indeterminate`) the single
  overall result in the validation API, CLI, JSON output, HostSigner, and WebInspectSample.
  Removed the ambiguous `IsValid`/`valid` boolean for PAdES validation results.

### Improved

- NuGet polish: every package ships its own concise README (rendered on
  nuget.org), the shared package icon, and SourceLink-enabled portable PDBs,
  with symbol packages (.snupkg) published to NuGet.org alongside the main
  packages. Release builds are deterministic.

### Added — SimpleSign.HtmlToPdf

- **Fonts**: caller-supplied TrueType/OpenType fonts (`WithFont`/`WithFontFile`, with
  `FontVariant` for bold/italic faces, or CSS `@font-face`) embedded as Type0/CID fonts with
  ToUnicode maps, **subset** to the glyphs used and written once per document; `font-family`
  fallback lists; per-glyph fallback to other registered fonts; synthesized bold/italic.
- **CSS engine**: complex selectors (`>`, `+`, `~`, attribute operators, structural
  pseudo-classes, `:not()`), correct cascade (specificity, source order, `!important`),
  custom properties (`var()`), `currentColor`, `inherit`, `@media print`, `@page` (size and
  margins), `::before`/`::after` with `content` (strings, `attr()`), `font` and `list-style`
  shorthands, extended colors (all CSS named colors, alpha), presentational HTML attributes
  (`align`, `valign`, `bgcolor`, `width`, `border`, `cellpadding`, `cellspacing`, `<font>`).
- **Layout**: floats and `clear`, `position: relative/absolute/fixed` (fixed repeats on every
  page), `inline-block`, inline images, flexbox (wrap, grow/shrink with min-content, all
  `justify-content` modes), CSS grid (`fr`, `repeat()`, spans), `text-align: justify`,
  `text-indent`, baseline alignment of mixed font sizes, inline backgrounds, `margin: auto`
  centering, `box-sizing`, min/max sizes, percentage paddings, list markers for every common
  `list-style-type` (graphical bullets, `start`/`reversed`/`value`), `orphans`/`widows`,
  `break-*`/`page-break-inside: avoid`, headings kept with the next content, backgrounds and
  borders of boxes split across pages.
- **Tables**: any content inside cells (paragraphs, lists, images, nested tables), content-based
  column sizing (min/max-content, fixed and percentage widths, `<col>`), `border-collapse`,
  `border-spacing`, rowspan heights, captions, and **pagination** that never splits rows and
  repeats `<thead>` on each page (`<tfoot>` after the last row).
- **Rendering**: dashed/dotted/double borders, `border-radius`, borders drawn inside the box,
  linked images, `visibility: hidden`.
- **Images & resources**: full PNG decoding (palette, 1–16-bit, interlaced, alpha as soft
  masks), progressive and Adobe CMYK JPEGs; `WithBaseDirectory` (sandboxed to that folder) and
  `WithResourceLoader` for images, `<link rel="stylesheet">`, and fonts.
- **PDF/A-2b** via `WithPdfA()` (sRGB output intent, XMP metadata, embedded fonts only), document
  `/Lang` from `<html lang>` or `WithLanguage`, `<title>` as the default title, trailer `/ID`.
- CLI `html-to-pdf`: `--font`, `--base-dir` (defaults to the input folder), `--pdfa`,
  `--header`, `--footer`, `--landscape`; page size defaults to CSS `@page`.
- Fuzz targets `html` and `css` in `SimpleSign.Fuzz`.
- **Paint**: `background-image` (PNG, JPEG, SVG), linear/radial/repeating gradients as PDF shadings
  (translucent stops through soft masks), `background-size/position/repeat/origin/clip`, multiple
  layers, page-wide root background; `opacity`, alpha colors with real transparency, `box-shadow`
  (blur, spread, inset), `text-shadow`, `transform` + `transform-origin`, `mix-blend-mode`,
  `overflow: hidden` clipping.
- **CSS**: `calc()`, `min()`, `max()`, `clamp()`; CSS counters (`counter-reset/increment/set`,
  `counter()`, `counters()`); `@page` margin boxes with `counter(page)`/`counter(pages)` and
  `:first/:left/:right`; multi-column layout (`column-count/width/gap/rule/span`).
- **SVG**: inline `<svg>`, SVG images and backgrounds drawn as vectors (shapes, paths, text,
  gradients, clip paths, `use`/`symbol`).
- **International text**: OpenType shaping for embedded fonts (kerning, ligatures, marks, Arabic
  joining, Devanagari conjuncts; verified against HarfBuzz), bidirectional text (`dir`,
  `direction`, `text-align: start/end`), hyphenation (`&shy;`, `hyphens: auto` for pt/es),
  all HTML 4 named entities.

### Fixed — SimpleSign.HtmlToPdf

- `<style>` elements inside the document were ignored and their CSS was rendered as text.
- Tables were not paginated: rows past the bottom of the page were cut off and lost.
- Mixed inline formatting inside table cells (`Total <b>x</b>`) was split onto separate lines.
- Embedded fonts were written once per page instead of once per document.
- Characters outside WinAnsi in standard fonts were measured with the wrong width (overlapping text).
- `body { ... }` rules did not apply to HTML fragments (an implied `<body>` is now created).
- Negative lengths (`margin-left: -10px`, `text-indent: -1em`) were read as percentages.
- A forced page break after the last element added a blank page.
- Named entities other than `&amp; &lt; &gt; &quot; &apos; &nbsp;` were left undecoded.

### Changed — SimpleSign.HtmlToPdf (behavior)

- Words of the same style on a line are emitted as one text run (smaller PDFs, better text
  extraction/copy-paste).
- Auto-width tables shrink to their content like browsers; use `width: 100%` for full width.
- Unknown elements are inline (browser behavior); `<td>`/`<th>` default to `vertical-align: middle`;
  `<a>` without `href` is no longer styled as a link.
- Colors with alpha are drawn with PDF transparency (`PdfColor.Alpha`) instead of being ignored.
- Hostile input is bounded: conditional at-rules nest at most 16 levels, `:not()` 8,
  `calc()` 32, SVG documents 128, and an SVG embedding itself through `<image>` stops after 4 levels.
- `CssParser.ParseLength` encodes percentages as values ≤ −100000 (−100000 − p) so negative
  lengths stay representable.
- Text with embedded fonts is shaped (kerning/ligatures change widths slightly); hard hyphens are
  line-break opportunities; elements with `overflow: hidden` and a fixed height keep that height.
- Every PDF now contains at least one page (empty documents produce a blank page).

### Added — Signature Appearance

- Customizable stamp text: `SignedByLabel` (replaces "Signed by"; an empty string hides the
  line), `ReasonLabel`, `LocationLabel`, `DateLabel` and `SignerDisplayName`, plus the
  `WithLabels(...)` clone method.
- Date display options: `DateFormat`, `TimeZone` and `DateCulture`, plus `WithDateFormat(...)`.
  With a time zone other than UTC the default format shows the offset (`11:30 UTC-03:00`).
- `BackgroundColor`, fixed `Width`/`Height`, `MaxTextLength`, and `BackgroundImageFit`
  (`Stretch`, `Contain`, `Cover`).
- PNG backgrounds with transparency (RGBA, gray+alpha and palette images with `tRNS`) are embedded
  with a soft mask, so a scanned handwritten signature can sit over the stamp. Palette PNGs
  (1/2/4/8-bit) are now accepted.
- `TextAlignment` (`Left`, `Center`, `Right`), `VerticalAlignment` (`Top`, `Middle`, `Bottom`) and
  `ShrinkToFit` (default on): with a fixed `Width`/`Height`, text that does not fit is scaled down
  instead of being clipped.
- CLI: `--signed-by-label`, `--reason-label`, `--location-label`, `--date-label`, `--date-format`,
  `--time-zone`, `--background-color`, `--image-fit`, `--stamp-width`, `--stamp-height` and
  `--text-align`.
- HostSigner: `POST /api/sign-file` accepts an optional `stamp` object (labels, date format, time
  zone, position, size, alignment), and the Sign page has fields for them. The visible stamp now
  shows the reason and location when they are given, and is placed automatically when no
  position is set.

### Fixed — Signature Appearance

- The stamp size now uses the font's real character widths and the configured font sizes. Large
  font sizes no longer overflow the stamp, and line spacing grows with the font size. Stamps with the
  default fonts are narrower than before, because the old estimate was too wide.
- The border is drawn over the background image instead of under it.
- Grayscale and CMYK JPEG backgrounds use the right color space. JPEG dimensions are read by
  walking the marker segments, so bytes inside metadata are no longer taken for the frame header.
- Characters the stamp font cannot show are replaced with readable text (for example `–` → `-`,
  `Ł` → `L`), instead of all becoming `?`.
- Reason, location and extra lines always use the label font size; before, they used the name size
  when the date was hidden.
- The PDF/A-1 check only reports PNG backgrounds that actually have transparency.
- Helvetica-Bold, Times-Roman and Times-Bold stamps are measured with their own character widths
  instead of an approximation, so the stamp fits the text.

### Fixed — Signature Dictionary

- `/Name`, `/Reason`, `/Location`, `/ContactInfo` and the field name (`/T`) are written as UTF-16
  when they contain characters outside PDFDocEncoding (for example `Ł`, `€`, Greek or Cyrillic).
  Before, those characters became `?` in the signature panel of PDF readers.

## Older releases

Versions 0.2.0 to 0.9.3 are recorded in the
[changelog at tag `pre-cleanup`](https://github.com/eupassarin/SimpleSign/blob/pre-cleanup/CHANGELOG.md).
