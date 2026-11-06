# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
- The `simplesign-<rid>.zip` CLI archives on GitHub Releases and `scripts/install/install-cli.sh` /
  `.ps1`. They were framework-dependent, so they needed .NET anyway: install the CLI with
  `dotnet tool install -g SimpleSign.Cli`. The release workflow now runs the CLI tests before
  pushing to NuGet.

### Changed — SimpleSign.XAdES no longer depends on SimpleSign.CAdES

The LTV collection and revocation-evidence helpers that XAdES borrowed from CAdES (internals)
moved into `SimpleSign.Core`. `LtvDataCollector` and `LtvCollectionResult` stay public in CAdES,
with the same behavior. Installing `SimpleSign.XAdES` no longer pulls in `SimpleSign.CAdES`.

### Fixed

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
