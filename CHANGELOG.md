# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.11.0] - 2026-11-13

The first release since 0.10.1 (2026-11-04), and a large one. **It contains breaking changes**: the
Brazilian packages were split and renamed, `SimpleSign.Pdf` was merged into `SimpleSign.PAdES`, and
`SimpleSign.HostSigner` was replaced by the SimpleSign Agent. See
[Changed (Breaking)](#changed-breaking) and the
[v0.10 → v0.11 migration guide](docs/articles/icp-brasil.md#upgrading-from-v010-to-v011).

### Highlights

- **Two-phase (deferred) signing in all three formats.** `CadesDeferredSigner` and
  `XadesDeferredSigner` join `DeferredSigner`, with co-signatures, countersignatures,
  `From(builder)` and content that can stay outside the session (ADR 0028).
- **Augmenting existing signatures.** `PadesAugmenter`, `CadesAugmenter` and `XadesAugmenter` raise
  a signed file to B-T, B-LT or B-LTA, and renew an archive time-stamp, without touching what is
  signed (ADR 0025).
- **ETSI EN 319 102-1 validation.** Trusted-list service history gives the trust anchors *at a time*
  (ADR 0026), and past signature validation gives a signature back its trust from a later archive
  time-stamp when its own TSA is no longer trusted (ADR 0027).
- **Configurable signing and validation policies** in SimpleSign's own JSON format, with a level per
  constraint, the ETSI TS 119 102-2 validation report and a readable HTML report (ADR 0023, 0024).
- **IOFE (Peru) is complete.** `SimpleSign.Peru.Iofe` takes its anchors from INDECOPI's signed
  trusted list and keeps it current (`IofeTrustedListSource`), with the policies of INDECOPI's
  accreditation guide v4.0, its checklist, a playbook and an article.
- **Before you sign, and what you sign.** `SigningCertificateCheck` answers "will this certificate
  be accepted?" before asking for a PIN; `DataToSignInspector` says what a payload actually is;
  `AuditChain` exposes the audit hash chain for any store.
- **Observability.** An `ActivitySource` and a `Meter` named `SimpleSign` publish traces and metrics
  for signing, TSA, OCSP, CRL, trusted lists and validation (`SimpleSignTelemetry`).
- **Tooling.** The **Sandbox** is a test PKI on real HTTP/HTTPS/LDAP endpoints with failures you can
  switch on; the **TestBench** gained a Playbook tab that runs scripted steps against it and exports
  the evidence; the **Agent** replaces HostSigner. See [the apps](docs/articles/apps.md).

### Changed (Breaking)

#### `SimpleSign.Brasil` split into `SimpleSign.Brazil`, `.IcpBrasil` and `.GovBr`

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

`HealthProfessionalInfo` and `HealthProfessionalCouncil` are gone; health documents moved into
`SimpleSign.Brazil.IcpBrasil`, and professional registrations are read with
`ExtractProfessionalRegistrations` / `ProfessionalRegistration` (see Fixed).

#### `SimpleSign.Pdf` merged into `SimpleSign.PAdES`

The PDF structure parser is now part of `SimpleSign.PAdES`; the `SimpleSign.Pdf` package is
discontinued and no longer published.

- Remove any `SimpleSign.Pdf` package reference; `SimpleSign.PAdES` contains the same types.
- **Namespaces renamed:** `SimpleSign.Pdf` → `SimpleSign.PAdES.Pdf`, and likewise
  `.Constants`, `.Enums` and `.Exceptions` (e.g. `using SimpleSign.PAdES.Pdf.Exceptions;`).
- Type names are unchanged (`PdfStructureReader`, `PdfSignatureField`, `PdfByteRange`,
  `PdfVersion`, `PdfALevel`, `PdfStructureException`, `EncryptedPdfException`, …).

#### `SimpleSign.Core.Constants.Oids`: one constant changed value, two were removed

- **`Oids.SignatureManifest` has a new value.** The Lei 14.063 manifest used `2.16.76.1.12.1.1`, the
  ITI's OID for the "prescrição de medicamento" document type; it now uses a SimpleSign UUID OID
  (`2.25.203506691189164941140958961231912791013`). The old value stays as
  `Oids.SignatureManifestLegacy`, and signatures made with it are still read. Because this is a
  `const`, code compiled against 0.10.1 keeps the old literal inlined until it is recompiled.
- **Removed:** `Oids.IcpBrasilSanHolderData` and `Oids.IcpBrasilSanCnpj`. Use the literal OIDs
  `2.16.76.1.3.1` and `2.16.76.1.3.3`, or let `IcpBrasilChainValidator` read them for you.

#### `SimpleSign.Brasil` no longer uses Core internals

`SimpleSign.Brazil`, `.Fiscal` and `.Xades` now build against the public API of Core, PAdES, CAdES
and XAdES only (no `InternalsVisibleTo`).

- **Now public**, for country extensions: `CrlEvaluator.Evaluate` / `ReadNextUpdate` and `CrlStatus`;
  `CrlClient.GetCrlUri` and `OcspClient.GetOcspUri`;
  `ResilientHttp.GetBytesAsync(HttpClient, Uri, …)` and `ResilientHttp.DefaultChainRetrievalTimeout`;
  `SignerCertificate` / `SignerChain` on `PadesSignerBuilder`, `CadesSignerBuilder` and
  `XadesSignerBuilder`.
- The ICP-Brasil and Gov.br log events (3110, 3113, 3210) moved from Core to `SimpleSign.Brazil`
  with the same event IDs.

#### `SimpleSign.HostSigner` removed

Replaced by **SimpleSign Agent** (`src/Apps/SimpleSign.Agent`), a cross-platform tray / menu-bar app.
The agent keeps the `/api/health`, `/api/certificates` and `/api/sign` contract. Its
`/api/sign-file`, `/api/inspect` and `/api/validate` endpoints, which took local file paths, are
**not** in the new agent.

#### `CadesValidationResult` and `XadesValidationResult` are now records

Both were `sealed class` and are now `sealed record`. Every member survives and both only gained
properties, but reference equality, `Equals` and `ToString` behave differently.

#### Validation and signing are stricter by default

- With the default validation policy, a SHA-1 or MD5 signature without a time-stamp proving it
  existed before the algorithm's limit, or a signing key under 2048 bits, is INDETERMINATE
  (`CryptoConstraintsFailureNoPoe`) instead of VALID with a warning.
- A chain whose CA certificate has no Subject Key Identifier
  (`CACertificate/SubjectKeyIdentifierPresent`, FAIL in every context) now makes the signature
  INDETERMINATE. Signatures from test or private PKIs that validated before may not validate now; a
  policy can lower the check to WARN.
- Signing refuses, by default, a certificate without the key usage extension or without
  digitalSignature/nonRepudiation, an RSA key under 2048 bits, and a chain with an expired
  certificate. `WithSigningPolicy(SigningPolicy.Minimal)` keeps the previous behaviour.
- `CrlClient.CheckCrlAsync(cert, url, ct)` without the issuer no longer reports "not revoked" from a
  CRL whose signature it cannot check; it throws `RevocationCheckException`. A revocation is still
  reported.
- `SigningPolicy.Strict` and `SigningPolicy.Minimal` are removed as presets: set `NotRevoked` /
  `RevocationDataAvailable` to FAIL, or the constraints to IGNORE.
- Validation policy files migrate by renaming the root `ConstraintsParameters` to
  `ValidationConstraints` and `eIDAS` to `TrustedLists`, and dropping the elements SimpleSign's
  format no longer has. The reader names each one; `docs/policies/compatibility.md` lists them.
- `XadesSignatureValidator.Validate(xml, anchors, null)` is now ambiguous between two overloads:
  drop the argument, name it (`originalData: null`) or cast the `null`.
- PFX private keys are loaded as non-exportable (`CertificateLoader`, and so the CLI's `--cert`).

### Added

#### Two-phase (deferred) signing, in all three formats (ADR 0028)

- `CadesDeferredSigner` and `XadesDeferredSigner`, with the shape of the PAdES `DeferredSigner`:
  `Document(...).WithCertificate(cert).WithSessionIntegrityKey(key)…PrepareAsync()` runs the signing
  policy and returns the bytes to sign (`DataToSign`: the DER signed attributes, or the canonical
  `ds:SignedInfo`) with a session; `Resume(sessionData, key)…CompleteAsync(rawSignature)` verifies
  the raw signature against the certificate, assembles the signature and finishes B-B to B-LTA, in
  the same process or another one.
- Every form: CAdES detached and attached; XAdES enveloped, enveloping and detached, with additional
  data objects. The deferred builders take every option of their one-call builder except
  `WithExternalSigner`; a contract test keeps them from falling behind.
- `CadesDeferredSigner.CoSign` / `CounterSign` and `XadesDeferredSigner.CounterSign` prepare a
  co-signature or countersignature for a key that is elsewhere.
- `DeferredSigner.From(PadesSignerBuilder)`, `CadesDeferredSigner.From(...)` and
  `XadesDeferredSigner.From(...)`: configure once, choose one call or two phases at the end.
- Content can stay out of the session, which then carries its SHA-256 instead:
  `WithContentOutsideSession()` → `WithContent(data)` (CAdES); `WithDetachedDataOutsideSession()` →
  `WithDetachedData` / `WithExternalData(uri, content)` (XAdES). Content that is not what phase one
  signed is refused.
- On the resumed builder: `WithTimestampOptions` (TSA credentials, mutual-TLS certificate, expected
  TSA certificate), `WithHttpClientProvider`, `WithSigningPolicy`, `WithTrustAnchors`,
  `WithChainRevocationChecker`, `WithAuditSink`, `WithLogger`, `WithOperationId`.
  `CompleteWithDetailsAsync` returns the achieved level and the warnings, in all three formats.
- The session is authenticated with HMAC-SHA256 over its stored bytes, so a session prepared by one
  version completes in another. New PAdES session fields (`OperationId`, `DssArtifacts`,
  `LongTermClockSkewSeconds`) are written only when used, so older sessions still complete.
- `DeferredSignerBuilder` (PAdES) gained the options of `PadesSignerBuilder`: `WithOperationId`,
  `WithPdfAPreservation`, `WithSignaturePolicy`, `WithCountryExtension`, `WithSigningTime`,
  `WithMetadata`, `WithDocumentInfo`, `WithDssArtifacts`, `WithFieldName`, `WithAppearance`,
  `AsCertification`, `WithExistingField`, `WithSubFilter`. Preparing now reads the document's PDF/A
  level and shapes the field for it. A country extension is code, not data: register it again on the
  resumed builder.
- `ToSigningRequest()` on the prepare results of the three formats returns the
  `ExternalSigningRequest` an `IExternalSigner` receives.
- The Brazilian builder extensions work on the two-phase builders (`WithAdvancedSignature`,
  `WithIcpBrasilPolicy` ×3 formats, `ResolveIcpBrasilPolicy`, `WithHealthDocument`).
- CLI: `--prepare` on `sign`, `cades sign` and `xades sign` (with `--session-key`, `--session`,
  `--to-sign`, `--content-outside-session`, `--detached-data-outside-session`); `deferred complete`
  finishes a session of any of the three formats.

#### Augmenting existing signatures (ADR 0025)

- `PadesAugmenter.Document(signedPdf)`, `CadesAugmenter.Signature(cms, detachedContent?)` and
  `XadesAugmenter.Document(signedXml, detachedData?)` raise a signed file to B-T, B-LT or B-LTA
  without touching what is signed; `RenewArchive()` adds a new archive (or document) time-stamp to a
  B-LTA. A level that cannot be reached throws `SigningException` (`LevelNotAchievable`).
  `CadesAugmenter.LevelOf` and `XadesAugmenter.LevelOf` report a signature's current level.
- CLI: `simplesign augment <file> --level BT|BLT|BLTA --tsa URL [--data] [--signature-id] [--renew] [--json]`.
- TestBench run kind `augment`, and playbook steps of kind `augment`.

#### ETSI EN 319 102-1: anchors at a time, and past signature validation (ADR 0026, ADR 0027)

- `TrustedList` reads each service's `StatusStartingTime` and `ServiceHistory`
  (`TrustedListService.StatusAt`) and gives `GetTrustAnchors(DateTimeOffset at)`. New
  `ITimedTrustAnchorProvider`, implemented by `TrustedList` and `TrustedListSet`.
- `ValidationOptions.TimedTrustAnchors`: when today's anchors do not trust a certificate, the PAdES,
  CAdES and XAdES validators use the anchors of the time-stamp's genTime (for its TSA) and of the
  signature's proof of existence (for the signer). A signature time-stamped before its CA's service
  was withdrawn stays valid. The CLI passes `--tsl` and `--lotl` lists this way.
- When the signature time-stamp is intact but its TSA is no longer trusted, a later trusted
  time-stamp over it gives it back its trust: the archive-time-stamp of CAdES, the ArchiveTimeStamp
  of XAdES, a later document time-stamp of PAdES. The earlier TSA's chain is built at the later
  token's time (EN 319 102-1 §5.6). A B-LTA whose signer and signature TSA both expired stays
  TOTAL_PASSED.

#### Signing and validation policies (ADR 0023, ADR 0024)

- `ValidationPolicy` and `SigningPolicy` (now in `SimpleSign.Core.Policies`) read and write JSON in
  SimpleSign's own format, one FAIL/WARN/INFORM/IGNORE level per constraint, with constraint ids as
  paths (`SignatureConstraints/BasicSignatureConstraints/SigningCertificate/KeyUsage`). Names outside
  the format are refused, pointing at `docs/policies/compatibility.md`. `PolicyCoverage` says what
  SimpleSign evaluates. **Every constraint of the format is now evaluated**, across the signature,
  countersignature, timestamp, revocation, cryptographic, model and trusted-list contexts, including
  the RFC 5280 certificate checks, the PDF revision checks (`DocMDP`, `FieldMDP`, `SigFieldLock`,
  `FormFillChanges`, `AnnotationChanges`, `UndefinedChanges`), `StructuralValidation` and
  `TLStructure`.
- Built-in presets: `default`, `strict`, `minimal`, `anchored`, `iofe` (signing) and `default`,
  `strict`, `iofe`, `iofe-nonrepudiation` (validation).
- `ValidationOptions` gained `Policy`, `Level` (`ValidationLevel`), `Verifier` (`VerifierOptions`:
  revocation strategy, now OCSP first everywhere, fallback, AIA, revocation of untrusted chains),
  `TrustedLists`, `PolicyProvider` (`IPolicyProvider`, the policy chosen by the signature policy OID)
  and `SignaturePolicyDocuments` (`ISignaturePolicyDocumentProvider`).
- Validation results gained `ValidationObjects` (the time-stamps and revocation data used, each with
  its own outcome) and `BestSignatureTime`.
- `ValidationReports`: the ETSI TS 119 102-2 validation report (XML), a simple report (JSON), and
  `ToHtml(entries, language)` — one readable HTML page in `en`, `pt` or `es`.
  `ValidationReports.ValidateEtsiXml` checks a report against its embedded schema (v1.2.1).
- `CryptographicSuite`: ETSI TS 119 322 cryptographic suites (JSON), globally or per context.
- JSON Schemas of the policy files (`docs/schemas/`, `GetJsonSchema()`, `simplesign policy schema`).
- Validation policy constraints for the EN 319 422 time-stamp profile: `Timestamp/AccuracyPresent`,
  `Timestamp/OrderingFalse` and `Timestamp/AcceptablePolicies`. Not in the default policy.
- CLI: `--policy`, `--policy-signer`, `--level`, `--revocation-strategy`, `--revocation-for-untrusted`,
  `--etsi-report`, `--simple-report`, `--html-report`, `--report-language`;
  `simplesign policy export|schema`.

#### Signing controls, an audit trail and the certificate pre-check

Every new signing check is off in `SigningPolicy.Default`, so signing is unchanged until a policy
turns it on.

- **Trust anchor before signing:** `SigningCertificate/ProspectiveCertificateChain` refuses a signing
  certificate that does not chain to a given anchor (`SigningErrorReason.UntrustedRoot`). Anchors
  come from `WithTrustAnchors(...)` on every builder, and on PAdES also from `WithCountryExtension`.
- **TSA checked while signing:** a `Timestamp` section of the signing policy, and
  `TimestampOptions.ExpectedTsaCertificate` / `ArchiveTimestampOptions.ExpectedTsaCertificate` to pin
  the TSA. A refusal is never downgraded by `SigningLevelFailureBehavior.ReturnLowerLevel`.
- **CRL without nextUpdate:** `SigningCertificate/CRLNextUpdatePresent` and
  `CACertificate/CRLNextUpdatePresent`.
- **`SigningCertificateCheck.EvaluateAsync(certificate, SigningCertificateCheckOptions)`** runs the
  checks the signers make — validity of the certificate and its chain, key usage, key and algorithms,
  chain to the trust anchors, revocation of the chain — *without signing*, and returns every finding
  with the `SigningErrorReason` a signer would refuse with. It never throws for a refused
  certificate, and uses the same code path as the signers. Call it before asking for a PIN.
- **Audit trail:** `ISignatureAuditSink` gets a `SignatureAuditEvent` for every signature made or
  refused. `JsonLinesAuditSink` writes a hash-chained JSON-lines file. **`AuditChain`**
  (`Canonicalize`, `Link`, `Append`, `Genesis`, `Follows`, `Verify`) exposes that content and
  SHA-256 chaining, so a database-backed sink produces the same chain and can be checked the same
  way. CLI: `--audit-log` and `simplesign audit verify`.

#### `DataToSignInspector`: what is about to be signed

- `DataToSignInspector.Inspect(data, certificate)` recognizes the two `ExternalSigningPayloadKind`s:
  DER CMS signed attributes (one `contentType`, one `messageDigest`, and a
  `signingCertificateV2`/`signingCertificate` that must name the given certificate) and a canonical
  XML-DSig `SignedInfo`. It returns the kind, the digests with their algorithm
  (`DataToSignDigest.ToShortString()` for a consent dialog) or the reason for refusing
  (`DataToSignRefusal`).

#### Traces and metrics (`SimpleSignTelemetry`)

- An `ActivitySource` and a `Meter` named `SimpleSign` (constants in
  `SimpleSign.Core.Diagnostics.SimpleSignTelemetry`): activities, counters and duration histograms
  for signing (format, requested/achieved level, outcome, reason — every signer, deferred included),
  TSA requests, OCSP requests, CRL fetches, trusted-list loading and validation. Tags hold no
  payload, certificate data, full URL or personal data, and nothing is measured when nobody listens.
  See [observability.md](docs/articles/observability.md).

#### Trusted lists

- `TrustedList` (`SimpleSign.XAdES.TrustedLists`): ETSI TS 119 612 and TS 102 231 v3 trusted lists,
  read after their XML signature is checked against the scheme operator's certificate; active CA and
  TSA services become trust anchors. `TrustedListSet` loads the lists of a LOTL, with per-list
  problems and a disk cache. `TrustedListInfo` / `ITrustedListInfoProvider` and the `TrustedLists`
  constraints (`TLFreshness`, `TLNotExpired`, `TLWellSigned`, `TLVersion`, `TLStructure`).
- `TrustedListOptions`: `SignerCertificates`, `ServiceTypes`, `ActiveStatuses`, `RejectExpired` and
  `ExcludedExtendedKeyUsages` (extended key usages that keep a certificate of a kept service from
  becoming a trust anchor; applied to end-entity certificates only).
- CLI: `--tsl`, `--tsl-signer`, `--tsl-profile`, `--lotl`, `--lotl-signer`, `--lotl-territory`.
- `DirectoryTrustAnchorProvider` (Core): trust anchors from a folder of certificates, optionally
  protected by a signed manifest.

#### IOFE (Peru) — `SimpleSign.Peru.Iofe`

- `IofeExtension` takes its anchors from INDECOPI's signed trusted list, and `IofePolicies`
  (`Signing`, `SigningNonRepudiation`, `Validation`, `ValidationNonRepudiation`) implement the
  *Guía de Acreditación de Aplicaciones de Software* v4.0.
- **`IofeTrustedListSource`** (`IofeExtension.LoadRefreshableAsync`, `new IofeExtension(source)`)
  reads the list again on demand (`RefreshAsync`) or on a schedule (`StartAutoRefresh`). Each copy is
  verified like the first and swapped in one step, so concurrent signers and validators see the old
  list or the new one. A copy that cannot be downloaded or verified, or with a lower sequence
  number, is refused (`RefreshFailed`) and the last good copy is served — from `CacheFile` after a
  restart, written atomically — until its NextUpdate passes, then no anchors. `Current` gives the
  sequence number, issue time, NextUpdate and SHA-256; `Changed` gives the services added and
  removed. It is an `ITimedTrustAnchorProvider` and `ITrustedListInfoProvider`.
- `services.AddSimpleSignIofe(options, refreshInterval)` registers it with a hosted service that
  reads the list when the host starts and every 6 hours by default.
- Tested against a copy of INDECOPI's real list (sequence 25) offline, and against the live list in
  an integration test: the list verifies, the five time-stamping services are anchors, and no
  end-entity code-signing certificate is.
- `docs/playbooks/indecopi-checklist.md` maps every item of annex B of the guide (sections 4.1–4.4)
  to the playbook step, test, or product responsibility that shows it; a test checks that every P
  item has a step and every step it names exists.
- [`docs/articles/iofe.md`](docs/articles/iofe.md) covers all of it; IOFE is ✅ in
  [conformance.md](docs/conformance.md).

#### More of the ETSI standards in CAdES and XAdES

CAdES (EN 319 122-1), on `CadesSignerBuilder`: `WithSignerLocation` (§5.2.5), `WithContentHints` and
`WithMimeType` (§5.2.4), `WithSignerRoles` / `WithSignerRole`, `WithAttributeCertificates` and
`WithSignedAssertions` (§5.2.6.1), `WithContentTimestamp` (§5.2.8), `WithSignaturePolicyStore`
(§5.2.10), `WithExtendedValidationData(CadesExtendedForm)` (RFC 5126: complete references,
escTimeStamp, values, archive-time-stamp v2), `CoSign` and `CounterSign`.

XAdES (EN 319 132-1), on `XadesSignerBuilder`: `WithSignatureProductionPlace` (§5.2.5),
`WithAttributeCertificates` and `WithSignedAssertions` (§5.2.6), `WithDataObjectsTimestamp`
(§5.2.8.1), `WithSignaturePolicyStore` (§5.2.10), `WithCanonicalization(XadesCanonicalization)`,
`WithAdditionalDataObject(XadesDataObject)` (embedded or external), `WithSigningCertificateForm`,
`WithExtendedValidationData(XadesExtendedForm)`, and `XadesSigner.CounterSign` (§5.2.7.2).

All formats: `LongTermValidationOptions.RevocationPreference` (`OcspFirst`, the default, or
`CrlFirst`) and `ClockSkewTolerance`; `ILtvEmbedder.EmbedLtvDataAsync(…, LongTermValidationOptions, …)`
so an injected embedder receives the signature's options; `SignaturePolicyStore`
(`SimpleSign.Core.Crypto`); `TimestampToken.CreateAsync` / `Verify` for standalone `.tst` files.

XAdES output follows the standard more closely: every signature has a `DataObjectFormat` for the
document (§6.3) and an `Id` on `ds:SignatureValue`; claimed roles are written in `SignerRoleV2`; a
countersignature is reported under `XadesValidationResult.CounterSignatures` rather than as another
signature of the document; and SignedInfo is canonicalized with the algorithm it declares.

#### Revocation, timestamps and outbound HTTP

- CRLs from `ldap://` and `ldaps://` distribution points (read-only LDAPv3 on the BCL), used when a
  certificate has no HTTP distribution point and `OutboundHttpPolicy.AllowLdap` is set (ADR 0021).
- `IRevocationCache` / `InMemoryRevocationCache`: CRLs kept until their nextUpdate.
  `IChainRevocationChecker` and `ChainRevocationChecker` are public in `SimpleSign.Core.Revocation`,
  with `WithChainRevocationChecker(...)` on the builders, and gained `CheckCurrentAsync`.
- `TimestampTsaChecks.TsaNameMatches` (RFC 3161 §2.4.2) and `CheckTsaRevocationAsync`. At signing
  time a token must be validly signed by a certificate with the critical, exclusive timeStamping EKU.
- `TimestampOptions.Authorization` (Basic/bearer), `ClientCertificate` (mutual TLS) and
  `tcp://host:port` endpoints (RFC 3161 §3.3); `TimestampOptions.DigiCert`, `Sectigo` and `FreeTsa`.
- `OutboundHttpPolicy.LoopbackOrigins` (services on this machine, by exact origin) and
  `PrivateNetworkHosts` (hosts allowed to resolve to RFC 1918 addresses, for split-DNS networks).
- New `SigningErrorReason` values: `CertificateRevoked`, `RevocationStatusUnknown`,
  `ChainCertificateNotValid`, `KeyUsageNotPermitted`, `AlgorithmNotPermitted`, `KeyTooWeak`.

#### Signers

- **`SimpleSign.Signers.Pkcs11`**: sign with A3 tokens, smartcards and HSMs through their PKCS#11
  driver (`Pkcs11Signer.Open`, `ListTokens`). Own minimal interop: no third-party dependencies, no
  `unsafe`, Native AOT compatible. `Pkcs11Drivers` catalogs the middlewares used in Brazil with their
  install paths per OS (`Known`, `DetectInstalled`, `FindTokensAsync`, `FindLibraryAsync`).
  **PIN warning flags** on `Pkcs11TokenInfo`: `IsPinCountLow`, `IsPinFinalTry`, `IsPinToBeChanged`
  and `IsUserPinInitialized`, read from `CK_TOKEN_INFO.flags` alongside `IsPinLocked`, so a user can
  be warned before a wrong PIN locks the token.
- **`SimpleSign.Signers.Cloud`**: `PscSigner`/`PscClient` for the ICP-Brasil PSC API (DOC-ICP-17.01)
  and `CscSigner`/`CscClient` for the Cloud Signature Consortium API v2 (SCAL 1/2, RSA, RSASSA-PSS,
  ECDSA). `LoopbackAuthorizationHandler` completes OAuth logins in the browser.

#### ICP-Brasil

- PAdES **AD-RC** and **AD-RA** (`WithIcpBrasilPolicy(policy, IcpBrasilPadesOptions)`), CAdES AD-RV,
  AD-RC and AD-RA, and the 45 XAdES XML policies. `ResolveIcpBrasilPolicy` returns the version that
  would be used; policy selection is root-aware.
- `IcpBrasilSignaturePolicies` embeds the ITI's LPA_PAdES and LPA_CAdES with `signPolicyHash`;
  `RefreshAsync` downloads and verifies a new LPA. `IcpBrasilPolicyRules` holds the rules of the 55
  CAdES/PAdES PAs. `IcpBrasilPolicyArtifacts.DownloadAsync` fetches the AD-RA artifacts.
- The ~176 bundled intermediate ACs for offline chain building, LCR disk cache, ACT timestamps, and
  `IcpBrasilCertificateData` with every DOC-ICP-04 SubjectAltName field.
- `SimpleSign.Brazil.Fiscal`: XMLDSig of NF-e/NFC-e, CT-e, MDF-e, events, NFS-e Nacional (DPS),
  eSocial and EFD-Reinf. CLI: `simplesign fiscal sign|validate`.
- `PdfSignatureSubFilter.PbadPades`, `PadesSignerBuilder.WithDssArtifacts` and `PdfDssArtifact`.

#### The apps

Four apps now ship beside the library. [apps.md](docs/articles/apps.md) says what each is for and
when to use which; each has its own article.

- **SimpleSign Sandbox** — a test PKI and its services on real endpoints: AIA, CRLs over HTTP,
  HTTPS and LDAP, an RFC 3161 TSA, OCSP and CSC v2, with failures to switch on, revocation, a
  request log and an admin API. It publishes trusted lists in both the TS 119 612 and INDECOPI
  TS 102 231 v3 layouts, and offers TSAs that are expired, revoked, short-lived, clock-shifted,
  wrongly named or without accuracy, a SHA-1 intermediate CA, signers without KeyUsage and CRLs
  without nextUpdate. `POST /api/certificates/custom` issues a signer with a subject you choose.
  It is **API only**; its UI is the TestBench's Sandbox control.
- **SimpleSign TestBench** — one local web app for the three formats, where every option names the
  clause that defines it. Sign, Validate and **Playbook** tasks; an engine switch that runs
  everything through the library *or* the CLI; panels for the policies, the standards reference, the
  environment, the Sandbox and EU DSS cross-validation; a Stamp drawer with a live preview.
- **The Playbook tab** loads a playbook (JSON, schema 2) written beforehand — sections of tagged
  steps — checks it against the connected Sandbox, and runs one step, a section or all of them,
  through the library, the CLI or both. It shows everything a step will do before it runs, keeps each
  step's latest result, and exports the evidence as an HTML page and a zip. It reports where the
  library and the CLI disagree ("Lib ≠ CLI") and where EU DSS disagrees. Bundled samples:
  `sandbox-basics`, `indecopi-guia-v4` (70 steps) and `etsi-baseline` (115 steps).
- **SimpleSign Agent** — a cross-platform tray / menu-bar app (Avalonia) that web pages call to sign
  with the OS store or an A3 token, on `127.0.0.1:21590`, with per-site authorization, a consent
  dialog for every signature and the PIN asked by the app.
  `GET /api/certificates?country=XX` (or `?trust=icp-brasil|govbr`, `?signingOnly=true`) lists the
  certificates that chain to that country's registered `ICountryExtension`s, checked with
  `SigningCertificateCheck`.
- **CLI** — `augment`, `sign-dir`, `deferred prepare|complete`, `cades sign|validate`,
  `xades sign|validate`, `timestamp create|verify`, `policy export|schema`, `audit verify`,
  `pkcs11 list|drivers`, `psc certificates`, `csc list`, `fiscal sign|validate` and `explain`, plus
  the signing options the library has, `--allow-origin` / `--allow-ldap` / `--tls-trust`, and
  `--json` on the signing commands.

### Changed

- **CLI: an expired trusted list is judged by the policy.** `simplesign validate --tsl/--lotl` (and
  `validate-dir`, `cades validate`, `xades validate`) keep a trusted list whose NextUpdate has
  passed, with or without `--tsl-profile`: the policy's `TLNotExpired` judges it, as the library in
  the TestBench and EU DSS do.
  - *Before:* such a list gave `NO_CERTIFICATE_CHAIN_FOUND`.
  - *After:* with the default policy (`TLNotExpired` WARN) it gives TOTAL-PASSED with a warning; the
    `iofe` policy (FAIL) gives INDETERMINATE / TRY_LATER.
  - Signing is unchanged: an expired list gives no anchors.
- **`cades validate` and `xades validate` check every signature** (`ValidateAllAsync`), not only the
  first. `--json` adds `signatures`, one entry per signature with its `counterSignatures`; the exit
  code is 0 only when all are valid. With `--trust`, the operating system's roots stay trusted
  (`--no-system-roots` turns them off); before, `--trust` replaced them. `cades validate` no longer
  requires `--data` for an attached signature.
- ICP-Brasil PAdES signatures use `/Filter /PBAD_PAdES /SubFilter /PBAD.PAdES`, as the PAs mandate.
- DocMDP: only P=1 blocks further signatures; P=2 and P=3 documents can be signed again
  (ISO 32000-1 §12.8.2.2.2). Certifying a document that is already signed is refused.
- CAdES signatures always include the signing-certificate-v2 signed attribute (it was PAdES-only).
- `SimpleSign.XAdES` no longer depends on `SimpleSign.CAdES`; the shared LTV internals moved to Core.
- CLI: `--archival` requires `--tsa` (it silently produced B-B); `--icp-policy` rejects
  `--sub-filter`, `--ltv` and `--archival` (the policy sets them).
- `LoopbackAuthorizationHandler.OpenInSystemBrowser` starts `explorer.exe` with the URL as an
  argument on Windows instead of shell-executing the URL (CodeQL `cs/command-line-injection`), and
  only opens absolute http(s) URLs.
- The repository was reorganized into `src/Core`, `src/Formats`, `src/Signers`,
  `src/TrustFrameworks` and `src/Apps`, with `tests/unit/` mirroring it (ADR 0018). `samples/`,
  `bench/`, `interop/`, the fuzz harness, Stryker, the docfx site and the `simplesign-<rid>.zip` CLI
  archives are gone; install the CLI with `dotnet tool install -g SimpleSign.Cli`.

### Fixed

- **PAdES accepted a signature under a revoked CA.** The validator checked online revocation for the
  signing certificate only, and the failed chain status was waived because the chain reaches its
  anchor. It now checks the CA certificates of the chain too, as CAdES and XAdES do.
- **Revocation sub-indications follow EN 319 102-1 §5.2.6:** a revoked signing certificate gives
  INDETERMINATE / `RevokedNoPoe` (no longer TOTAL_FAILED / `Revoked`) and PASSES when a proof of
  existence predates the revocation; a revoked CA gives INDETERMINATE / `RevokedCaNoPoe`. No
  revocation data, or none acceptable, gives `CertificateChainGeneralFailure`.
- **The B-LT/B-LTA DSS update overwrote the stamp's font object.** `LtvEmbedder` searched backwards
  for `"N 0 obj"` as plain text, so catalog `1 0 obj` matched `21 0 obj`: with a visible stamp the
  DSS revision wrote the font descriptor as the new catalog, losing the AcroForm and the signature
  field. It now uses `PdfStructureParser.FindObjectBytes`, which rejects suffix matches.
- **XAdES B-LTA was not recognized as LTA by other validators.** The `EncapsulatedTimeStamp` of
  `xades141:ArchiveTimeStamp` was written in the XAdES v1.4.1 namespace instead of v1.3.2, so EU DSS
  did not find the token. Signatures made by earlier versions are still read.
- **XAdES with an external ECDSA key never worked.** `WithExternalSigner` (and `CounterSign` with
  one) wrote the DER `SEQUENCE { r, s }` the external signer returns into `ds:SignatureValue`, which
  takes `r || s` (XMLDSig Core 1.1 §6.4.3), so signing failed its own read-back verification.
- **INDECOPI's real trusted list could not be loaded.** `TrustedList` now verifies lists whose
  `ds:Signature` element declares a namespace (INDECOPI's declares `xmlns:etsi` there): `SignedXml`
  left those declarations out of the canonical SignedInfo, so the list was always refused as "not
  signed by the scheme operator's certificate".
- **IOFE: timestamping authorities typed `unspecified`.** INDECOPI publishes some accredited TSAs as
  `Svctype/unspecified`, which `TrustedList` dropped by default, so their timestamps were refused
  under `IofePolicies.Signing`. `IofeExtension` now reads the list with
  `IofeExtension.DefaultListOptions`. `IofePolicies.Validation` also accepts a trusted list of
  version 3, which is what INDECOPI publishes.
- `PdfSignatureValidator` evaluates the TrustedLists constraints for the lists of
  `ValidationOptions.TrustedLists` too, not only for those of its trust anchor providers: an expired
  list passed to `simplesign validate --tsl/--lotl` validated as TOTAL-PASSED.
- A detached CAdES or XAdES signature validated without its data is INDETERMINATE /
  `SIGNED_DATA_NOT_FOUND`; the data's integrity is not judged without it.
- A time-stamp whose TSA could not be judged still counts for the order of the time-stamps, and a
  signing-certificate reference that is missing, repeated or mismatched is INDETERMINATE /
  `NO_SIGNING_CERTIFICATE_FOUND` (EN 319 102-1 §5.2.3), as in EU DSS.
- CAdES/XAdES synchronous `Validate` / `ValidateAll` never checked revocation, yet a TSA could show
  as trusted; with `CheckRevocation` on, the result now carries a warning saying so.
- `CadesSignatureValidator` and `XadesSignatureValidator` build the signer's chain with the
  certificates embedded in the signature, as they already did for the TSA; before, a signer under an
  intermediate CA was reported with `PartialChain`.
- CRLs served as PEM over HTTP are read (FreeTSA serves its CRL this way); CAdES/XAdES B-LT can be
  built when OCSP responses come from a delegated responder (RFC 6960 §4.2.2.2.1); CAdES/XAdES
  B-LTA send the TSA's credentials with the archive timestamp request too.
- CAdES: `WithExtendedValidationData` combined with B-LT or B-LTA, and SHA-3 imprints in the
  escTimeStamp and archive-time-stamp v2.
- `TimestampClient.EmbedTimestampInCms` wrapped the values of unsigned attributes already in the
  SignerInfo in a second SET; `TimestampToken.Verify` did not recognize SHA-3 message imprints.
- Strict signing no longer trusts a CRL cached before a revocation
  (`IChainRevocationChecker.CheckCurrentAsync`).
- HtmlToPdf: deeply nested HTML overflowed small thread stacks; layout now continues on a fresh
  thread-pool stack when it runs low.
- `AddSimpleSignIcpBrasil()` / `AddSimpleSignGovBr()` registered chain validators the container could
  not build (two ambiguous constructors), so resolving either one threw.
- **ICP-Brasil** (see the [migration guide](docs/articles/icp-brasil.md#upgrading-from-v010-to-v011)):
  professional registrations are read from `2.16.76.1.4.2.{council}` for all 16 councils instead of
  the e-CNPJ responsible person's fields; certificate types S1–S4 are policy types 101–104 (were
  11–14), with T3, T4, A CF-e-SAT and OM-BR added; `DetectPolicy(certificate)` is obsolete in favour
  of `IcpBrasilPolicyInfo.TryParse`; alphanumeric CNPJs (IN RFB 2.229/2024) are accepted; chains are
  validated at the trusted signature timestamp time with real revocation checks instead of an OS
  check at the current time that treated unknown revocation as success; only the Gov.br AC Raiz is a
  trust anchor; and `WithAdvancedSignature` no longer writes the signature-policy attribute twice.
- Log EventId 2401 was used by two different events; the PAdES one is now 2032.
- **CLI:** `simplesign validate --help` (and nine other help screens) crashed on unescaped
  Spectre.Console markup — a literal `[--preset NAME]` in the `--policy` and `--signing-policy`
  descriptions was parsed as a style tag.
- **CLI:** `validate --json` reported `"lei14063": "Simples"` for any valid signature outside the
  Brazilian framework, including Peruvian (IOFE) ones, and the human-readable tree printed a
  `Brasil: Lei 14.063` node for them. The level is now reported only for a signature validated under
  the Brazilian framework or carrying an AEA manifest.

### Documentation

- New [apps.md](docs/articles/apps.md) (the CLI, Agent, TestBench and Sandbox, with screenshots),
  [iofe.md](docs/articles/iofe.md), [sandbox.md](docs/articles/sandbox.md),
  [playbook.md](docs/articles/playbook.md), [observability.md](docs/articles/observability.md) and
  [remote-signing.md](docs/articles/remote-signing.md).
- Augmentation and past signature validation are documented in
  [pades.md](docs/articles/pades.md), [cades-xades.md](docs/articles/cades-xades.md) and
  [inspection-validation.md](docs/articles/inspection-validation.md).
- ADRs 0021–0028; `docs/playbooks/etsi-checklist.md` and `indecopi-checklist.md`;
  `docs/policies/compatibility.md`; `docs/schemas/`.
- `RELEASING.md` now states that while SimpleSign is on 0.x, breaking changes ship in a MINOR bump
  and `x.0.0` is reserved for 1.0.

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
