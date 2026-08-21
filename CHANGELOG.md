# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.8.0] - UNRELEASED

### Added

- **Cross-format signing contract** — shared `AdesBaselineProfile` (factories `Basic`, `Timestamped`, `LongTerm`, `Archive`) with cumulative level dependencies encoded in types; `AdesBaselineLevel`, `TimestampOptions`, `LongTermValidationOptions`, `ArchiveTimestampOptions`, `SigningLevelFailureBehavior`, `ISigningResult`, `SigningWarning`/`SigningWarningCode`, `SigningErrorReason`, `IExternalSigner`/`ExternalSigningRequest`/`ExternalSigningPayloadKind` in `SimpleSign.Core`.
- **`PadesSigner` / `PadesSignerBuilder`** — format-qualified PAdES entry point and builder (`Document`, `DocumentAsync`, `WithLogger`, `WithLevel`, `WithSigningTime`, `WithHttpClientProvider`, chain-capable external signers).
- **Strict level fulfillment** — the requested baseline level is a postcondition; B-LT/B-LTA without collectible material throw `SigningException` unless the profile opts into `SigningLevelFailureBehavior.ReturnLowerLevel` (requires `SignWithDetailsAsync`).
- **Truthful results across formats** — `RequestedLevel`, `AchievedLevel`, `HasSignatureTimestamp`, `HasLongTermValidationMaterial`, `HasArchiveTimestamp`, and structured `SigningWarning` warnings on `PadesSigningResult`, `CadesSigningResult`, and `XadesSigningResult`.
- **Explicit external-signing request** — `IExternalSigner.SignAsync(ExternalSigningRequest, …)` carries payload kind, resolved algorithms, and operation ID; `FuncExternalSigner` adapts legacy delegates; algorithm resolution moved to terminal execution (order-independent).
- **Provider-based HTTP configuration for all formats** — `WithHttpClientProvider`, scoped providers in `TimestampOptions`/`LongTermValidationOptions`/`ArchiveTimestampOptions`, `SingleClientProvider` adapter; deterministic scoped-over-builder-wide precedence.
- **Cross-format contract test suite** — `tests/unit/SimpleSign.Contracts.Tests` (43 tests) covering profile factories, strict/downgrade semantics, atomic profile replacement, credential replacement, defensive copying, lazy provider resolution, and external-signer request contents.
- **CAdES-Enveloped (.p7m)** — `CadesContentType` enum (`Detached`, `Enveloped`) with `WithContentType()` on the builder. CLISupport via `--content-type detached|enveloped`. When Enveloped, the original data is embedded as `eContent` in the CMS SignedData.
- **JSON output for CAdES/XAdES validation** — `--json` flag on `cades validate` and `xades validate` commands, using source-generated JSON serialization (AOT-safe).
- **CAdES signing fuzz target** — new `cades-sign` fuzz target in the SharpFuzz harness (10 total targets).
- **CAdES validator tests** — 10 new tests in `CadesSignatureValidatorTests.cs` covering detached, enveloped, tampered, chain validation, and level detection.
- **XAdES validator tests** — 10 new tests in `XadesSignatureValidatorTests.cs` covering enveloped, detached, enveloping forms with chain, integrity, and level validation.
- **CAdES benchmarks** — 6 new benchmarks in `CadesBenchmarks.cs` (signing detached/enveloped at 1KB/100KB + validation).
- **XAdES benchmarks** — 6 new benchmarks in `XadesBenchmarks.cs` (signing all 3 forms + validation).
- **CLI stdin/pipe support** — all sign and validate commands accept `-` as input path to read from stdin.

### Breaking changes

- **Removed legacy signing surface** (migration guide: `docs/migration/v0.7-to-v0.8.md`):
  - `SimpleSigner` / `SignerBuilder` → `PadesSigner` / `PadesSignerBuilder`.
  - `WithTimestamp`, `WithLtv`, `WithArchivalTimestamp`, `WithHttpClient`, `WithRevocationHttpClient` → `WithLevel(AdesBaselineProfile)` + provider-based options.
  - CAdES/XAdES enum-based `WithLevel` and `WithTimestamp`; `CadesSigningOptions`/`XadesSigningOptions` and the static `SignAsync` shortcuts → builder + profile.
  - `PdfSigningResult.Pdf`/`DssEmbedded`, `CadesSigningResult.Cms`/`TimestampApplied`/`LtvDataEmbedded`/`ArchiveTimestampApplied`, `XadesSigningResult.SignedXml`/… → `SignedArtifact` + `ISigningResult` members.
  - `Func<byte[], Task<byte[]>>` external signers → `IExternalSigner` (use `FuncExternalSigner` to adapt).
  - Error behavior: signing configuration failures throw `SigningException` with `SigningErrorReason` across formats.
- **Strict level postcondition** — B-LT/B-LTA requests that cannot be fulfilled now throw by default instead of silently producing a lower-level artifact.
- **Truthful feature flags** — PAdES basic signatures report `HasLongTermValidationMaterial == false`; CAdES/XAdES flags derive from the produced artifact, not the requested enum.

### Changed

- **Builders use record-based immutable state** — injected collaborators (TSA factory, LTV embedder, CMS parser) survive every fluent call; credentials are mutually exclusive states; collections are defensively copied; byte-array inputs are snapshotted.
- **ADRs** — new ADR 0015 (cross-format signing contract); ADRs 0006, 0008, 0010, and 0012 updated to the profile/provider/external-signer model.
- **README** — updated CAdES section to mention enveloped mode (.p7m); added enveloped example and CLI `--content-type` example.

### Improved

- **XML documentation** — added `/// <summary>` docs to all CLI command classes and settings properties (128 members), PdfKeys constants (16), and Brasil extension providers (14). XML doc coverage: 76% → 95%.
- **Error resilience** — added `ex.Message` to silent catch blocks in XAdES validator; added S2221 justification comments to all `catch(Exception)` in CAdES and XAdES validators.
- **Performance** — replaced `Convert.ToHexString` + `Encoding.Latin1.GetBytes` double allocation in `PdfSignatureWriter.FinalizeAsync` with span-based hex output using `ArrayPool<byte>` (~64 KB saved per signature).
- **WebHtmlToPdf sample** — restored missing Program.cs and .csproj; now a functional minimal web API.
- **CLI archive timestamp bug** — fixed `HasValue` typo in XAdES validate output (was checking `.HasValue` twice instead of `.Value`).
- **CLI pipeline tests** — fixed DI integration after SOLID refactoring; all 154 CLI tests pass.

## [0.7.0] - 2026-06-30

### Added

- **`UnsignedSignatureProperties` wrapper** — XAdES unsigned properties now wrapped in `<UnsignedSignatureProperties>` per ETSI EN 319 132-1 §5.3. Backward-compatible: validator searches both nested and flat structures.
- **`CommitmentType` values** — added `ProofOfReceipt`, `ProofOfDelivery`, `ProofOfSender`, `ProofOfCreation` to the `CommitmentType` enum with corresponding OID mappings in CAdES and XAdES.
- **`SignerRole` + `DataObjectFormat` support** — `XadesSignerBuilder.WithSignerRoles()` / `WithDataObjectFormat()` for XAdES signed data object properties.
- **XAdES CLI tests** — 17 CLI execution tests covering signing with self-signed cert, all error cases (invalid level/form/hash/missing input), sign-then-validate round trip, signer role, commitment type, and all level aliases (basic/timestamped/longterm/archive).
- **XAdES EU DSS interop tests** — 4 tests (B-B, B-T, B-LT, double-signed) validating SimpleSign XAdES output against the official EU DSS validator.
- **Expanded XAdES unit test suite (56 total)** — 20 error-path tests (null/empty/invalid arguments, unsupported forms), 6 algorithm-variant tests (ECDSA SHA-384/512, RSA-PSS SHA-384/512, all 6 CommitmentType OIDs, extra certs in KeyInfo), and 8 validation edge-case tests (digest mismatch, missing SignatureValue, missing SignatureMethod, wrong trust anchor, QualifyingProperties Target mismatch, missing SignedProperties Type, plain XMLDSig without XAdES properties).
- **Validator reference integrity checks** — validates QualifyingProperties Target matches Signature Id and that a Reference with `SignedProperties` Type exists.

### Fixed

- **Detached/Enveloping forms rejected** — `BuildSignature` and `BuildSignedInfoToHash` now throw `NotSupportedException` with a clear message (only Enveloped is implemented for now).
- **NuGet CI now packs XAdES and CAdES** — added `SimpleSign.XAdES` and `SimpleSign.CAdES` to the `dotnet pack` build list in CI.

### Infrastructure

- **`SimpleSign.Core/Crypto/CmsAttribute.cs`** — new CommitmentType OIDs added.
- **Fuzz harness for XAdES** — added `xades-sign` and `xades-validate` targets to the SharpFuzz-based fuzzer in `tests/fuzz/`.

### Changed

- **SOLID service interfaces** — 15 interfaces extracted across all projects for DI and testability:
  - Core: `IOcspClient`, `ICrlClient`, `IRevocationChecker`, `ITimestampClient`, `ITimestampClientFactory`, `ICertificateChainService`, `ICryptoVerifier`, `ICmsParser`, `ITimestampValidator`
  - PAdES: `IPdfSignatureValidator`, `IIntegrityVerifier`, `ILtvEmbedder`, `IConformanceDetector`, `IPdfSignatureInspector`, `IPadesExtractor`
  - Pdf: `IPdfStructureReader` with `PdfStructureReaderService`
  - CAdES: `ICadesSignatureValidator`
  - XAdES: `IXadesSignatureValidator`
- **DI registration** — `AddSimpleSign()` wires all services via `IServiceCollection`. New extension methods: `AddSimpleSignCades()`, `AddSimpleSignXades()`. All factories and implementations registered as transient or singleton via `TryAdd*`.
- **CLI DI integration** — `SimpleSignTypeRegistrar` bridges Spectre.Console to `IServiceCollection`. All CLI commands (`sign`, `validate`, `validate-dir`, `inspect`, `extract`, `cades sign`, `cades validate`, `xades sign`, `xades validate`) use constructor injection instead of manual `new`.
- **Brasil validators** — `GovBrChainValidator` and `IcpBrasilChainValidator` now accept `ICertificateChainService` via constructor injection.
- **`InternalsVisibleTo` removed** — the `simplesign` CLI no longer accesses internal APIs from Core, Pdf, or PAdES assemblies. `SignatureAppearance.WithBackgroundImagePng`/`WithBackgroundImageJpeg`/`WithExtraLines` made `public`.
- **`ICertificateChainService` extended** — added `LoadPkcs12FromFile` and `LoadPkcs12CollectionFromFile` methods for certificate loading.

## [0.6.0] - 2026-06-19

### Added

- **`SimpleSign.XAdES`** — new project for XML digital signatures with XAdES (ETSI EN 319 132). Fluent `XadesSigner.Document().WithCertificate().SignAsync()` builder. Supports XAdES-B-B, B-T, B-LT, B-LTA conformance levels. Enveloped, detached, and enveloping forms. RSA/*, ECDSA, and RSA-PSS signing. Synthetic timestamp and LTV data embedding. `XadesSignatureValidator` for round-trip validation.
- **`xades sign` / `xades validate` CLI commands** — `simplesign xades sign <xml>` and `simplesign xades validate <signed.xml>` for terminal workflows.
- **XAdES unit tests (18 total)** — signing, validation, B-T/B-LT/B-LTA round-trips, timestamp validation (valid/hash mismatch/malformed/null), LTV detection, archive timestamp validation, `SignWithDetailsAsync` level flags.
- **`XmlDSigUrls` constants for RSA-PSS** — `RsaPssSha256`, `RsaPssSha384`, `RsaPssSha512` URIs for XMLDSig signature methods.

- **`CadesSignerBuilder`** — new fluent immutable builder for CAdES signatures, matching the `SignerBuilder` pattern with `Document()`, `WithCertificate()`, `WithTimestamp()`, `WithHashAlgorithm()`, `WithSignatureAlgorithm()`, `WithOperationId()`, and `WithExternalSigner()` methods. `CadesSigner.SignAsync()` static methods now delegate to the builder for backward compatibility.
- **`CadesSigningResult`** — sign-with-details result type exposing `TimestampApplied`, `LtvDataEmbedded`, `ArchiveTimestampApplied`, and `Warnings` for diagnostic and logging integration.
- **CancellationToken in chain validation** — `IChainValidationProvider.ValidateAsync` now accepts `CancellationToken`, plumbed through `PdfSignatureValidator`, `CadesSignatureValidator`, `CountryExtension`, and `BrasilExtension`. Enables timeout-aware validation pipelines.

### Fixed

- **VRI `/SHA256` key removed from DSS dictionary** — the non-standard `/SHA256` key inserted into every VRI entry is not defined in ISO 32000-2 §12.8.4.4 Table 250 and caused ETSI Signature Conformance Checker schema validation failures (`Children order and number DO NOT MATCH specification`). VRI dictionaries now only contain `/Type`, `/Cert`, `/CRL`, `/OCSP`, `/TS`, and the SHA-1 key per the standard.
- **`WithSignatureAlgorithm` OID preserved in auto-detect `WithExternalSigner`** — both CAdES and PAdES external-signer paths now respect an explicit `.WithSignatureAlgorithm(oid)` call when auto-detecting the signature OID. Previously the user-specified OID was silently discarded, causing the library to fall back to auto-detection from the certificate.

### Changed (Breaking)

- **`DeferredSignerBuilder.WithSignatureAlgorithmOid()` renamed to `WithSignatureAlgorithm()`** — consistent naming with `SignerBuilder.WithSignatureAlgorithm()` and `CadesSignerBuilder.WithSignatureAlgorithm()`. Call sites using the old method name will fail to compile.

### Improved

- **`DetectSignatureAlgorithmOid` consolidated into `CryptoUtility`** — removed 3 duplicate copies from `SignerBuilder`, `DeferredSigner`, and `CadesSigner`. Single shared implementation with SHA3-256/384/512, Ed25519/Ed448, and ECDSA hash-from-curve-size mappings.
- **CAdES/PAdES fluent APIs unified** — shared code patterns across `SignerBuilder`, `CadesSignerBuilder`, and `DeferredSignerBuilder` for hash resolution, signature OID detection, PSS params extraction.
- **`X509Chain` helper extracted** — `CertificateChainUtility.BuildX509Chain()` centralises chain construction with revocation mode, URL retrieval, and verification flags, replacing 3 inline copies.
- **LTV embedder simplifications** — VRI parameter simplified from `List<(string Sha1, string Sha256)>` to `List<string>` (SHA-1 only). Trailing-EOL logic deduplicated.

## [0.5.0] - 2026-06-16



### Added

- **`SignerBuilder.WithHttpClient(HttpClient)`** — new fluent API for setting the default HTTP client for revocation (OCSP/CRL/AIA) and TSA fallback when no TSA-specific client is configured.
- **`HttpClientFactoryProvider`** — built-in `IHttpClientFactory` adapter that implements `IHttpClientProvider`. Ships in `SimpleSign.Core.Http`. Each call to `GetClient()` delegates to `IHttpClientFactory.CreateClient(name)`.
- **Auto-detection of `IHttpClientFactory` in DI** — `AddSimpleSign()` now checks for `IHttpClientFactory` in the DI container. When present, it wires `HttpClientFactoryProvider` automatically using `SimpleSignOptions.HttpClientName` as the named-client key. No manual adapter implementation needed.
- **`SimpleSignOptions.HttpClientName` is now consumed** — previously documented but silently ignored. Now used by the `IHttpClientFactory`-backed provider fallback in `AddSimpleSign()`.
- **Per-operation HTTP client slots in `SignerBuilder`** — TSA (signature timestamp + archival DocTimeStamp) and revocation (OCSP/CRL/AIA) now use independent `HttpClient` instances, enabling per-operation authentication (e.g., bearer token for TSA, anonymous for revocation).
- **`SignerBuilder.WithCountryExtension<T>()` / `.WithCountryExtension(extension)`** — fluent API to register country-specific trust anchors and chain validation providers (e.g., ICP-Brasil, eIDAS). Extensions enrich `SignatureValidationResult` with policy level, signer national ID, and region metadata. Both generic (`new T()`) and instance overloads supported.
- **`IChainValidationProvider` integration into `PdfSignatureValidator`** — after standard `X509Chain.Build()`, the first matching provider runs its `ValidateAsync`. If it trusts the chain (but the standard PKI path failed), chain errors are demoted to warnings (`IsChainTrustWarning = true`). `SignatureValidationResult` gains 5 new properties: `ChainValidationRegion`, `PolicyLevel`, `SignerId`, `SignerIdType`, `ChainValidationMetadata`.
- **LTV loop parallelisation** — `LtvEmbedder.EmbedLtvDataAsync` now uses `Parallel.ForEachAsync` with `ConcurrentDictionary` for thumbprint deduplication and `ConcurrentBag` for result collection. Snapshot isolation (`allCerts.ToList()`) prevents concurrent modification. `MaxDegreeOfParallelism = CPU × 2`.
- **PDF/A-aware annotation flags** — `/F 4` (Print) for PDF/A-1 signatures, `/F 132` (Print + Locked) for PDF/A-2+ and non-PDF/A. Detected from XMP metadata in `SignerBuilder.SignCoreAsync`, passed via `pdfALevel` to `PdfSignatureWriter.PrepareAsync` and `DocTimeStampWriter.AppendDocTimeStampAsync`.
- **SHA-256 VRI hash alongside SHA-1** — `ExtractSignatureContentHashPairs` now returns tuples; `/SHA256 {hex}` is added to each VRI object alongside the existing SHA-1 key (PAdES Part 4 requirement). Collision-resilient cross-reference without breaking existing verifiers.
- **AIA issuer-subject validation** — `DownloadAiaForCertAsync` compares downloaded cert's `SubjectName` with expected `IssuerName`. Warning logged on mismatch, but cert is still added to result for chain engine fallback.
- **PDF/A detection for compressed XMP** — `ScanCompressedObjStmsForPdfAIdTags` decompresses ObjStm streams and searches for `pdfaid:part`/`pdfaid:conformance` tags when raw byte scan returns `None`. Two-pass detection: fast raw scan (~99% of PDFs) → decompression fallback (PDF 1.5+).
- **`BatchSignerBuilder` immutable** — converted from mutable (`return this`) to immutable (copy constructor with 15 fields, `With()` carry-forward pattern), consistent with `SignerBuilder`.
- **SHA-3/EdDSA OID mappings** — end-to-end CMS compliance tests for SHA3-256/384/512 and Ed25519/Ed448 (RFC 8702, 8933, 8032, 8410). Wire-level attribute validation.
- **`SignatureValidationResult` moved to `SimpleSign.Core.Validation`** — extracted from `SimpleSign.PAdES.Validation` for cross-format reuse (PAdES, CAdES, XAdES). All 675 unit tests updated.
- **Competitor benchmarks (iText 9 + BouncyCastle)** — new `CompetitorBenchmarks` suite at `bench/SimpleSign.Benchmarks/`. MediumRun results: SimpleSign 13.700 ms (498 KB) vs iText 9 4.940 ms (766 KB) — SimpleSign 2.8× slower but 35% less memory.
- **6 ADRs (0009–0014)** — documenting: Country Extension plug-in, Fluent Builder pattern, Validation Pipeline, LTV Architecture, Certificate Chain Validation, PDF/A Conformance Strategy.
- **`BrasilManifestProvider` and `ISignatureManifestProvider` removed** — dead code elimination. Manifest construction uses `SignatureMetadata` directly without interface indirection.

### Fixed

- **`SignerBuilder.WithHttpClientProvider` now resolves lazily** — `IHttpClientProvider.GetClient()` is called at signing time, not at builder-configuration time. Previously the provider was eagerly resolved and discarded, making factory-style providers impossible.
- **`IHttpClientProvider` preserved through all builder methods** — `WithLtv()`, `WithMetadata()`, `WithOperationId()`, `WithPdfAPreservation()`, `WithLegacyCms()`, `WithSubFilter()`, and `WithArchivalTimestamp()` no longer silently replace the custom provider with the static default. The provider now survives every builder clone.
- **`SimpleSignOptions.HttpClientName` is now consumed** — previously documented but silently ignored. Now used by the `IHttpClientFactory`-backed provider fallback.
- **LTV loop `&&` → `||` logic fix** — responder certs already processed were incorrectly double-checked with `&&` instead of `||`.
- **`PdfSignatureValidator` field count** — `PdfStructureReader` exception handlers narrowed from `catch(Exception)` to specific exception types in 4 locations.

### Changed (Breaking)

- **`SignerBuilder.WithTimestamp(url, httpClient)` scope narrowed** — the injected `HttpClient` now applies only to TSA calls (signature timestamp + archival DocTimeStamp), not to revocation (OCSP/CRL/AIA). Use the new `WithHttpClient(HttpClient)` for the default/revocation client. This only affects callers relying on the undocumented side-effect of the TSA client leaking to revocation.
- **`SignerBuilder.WithTimestamp(url, httpClient)` corrects archival timestamp client** — archival DocTimeStamp (B-LTA) now uses the TSA client instead of the revocation client, fixing an inconsistency where the step 7 timestamp reused the step 6 revocation `HttpClient`.
- **`BatchSignerBuilder` immutable** — `With*` methods now return new instances instead of `this`. Code relying on reference identity after `With*` calls will break.
- **`SignatureValidationResult` namespace** — changed from `SimpleSign.PAdES.Validation` to `SimpleSign.Core.Validation`. Add `using SimpleSign.Core.Validation;` to existing code.
- **`ISignatureManifestProvider` removed** — implementors of this interface will no longer compile. Use `SignatureMetadata` directly.

### Improved

- **21 new unit tests** — LTV parallelism (3), chain validation integration (6), `SignatureValidationResult` new properties (5), `WithCountryExtension` (7).
- **`IChainValidationProvider` async** — `Validate` changed to `ValidateAsync`, fixing sync-over-async deadlock.
- **`BuildXrefTableAndTrailer` extracted as `internal static`** — removed duplicate `BuildDssXrefAndTrailer` from `LtvEmbedder`.
- **`PdfKeys` constants class** — 12 PDF dictionary key constants, 17+ substitutions removing magic strings.
- **`LtvEmbedder` HashSet O(1) dedup** — replaces linear scan for certificate deduplication.
- **`BuildFieldAnnotation` reduced 11→2 params** — `FieldAnnotationParams` record encapsulates remaining options.
- **`TestPdfFactory` shared** — `CreateMinimalPdf()` in `SimpleSign.TestHelpers`, migrated 15+ test files.
- **`MockHttpHandler` consolidated** — single shared `HttpMessageHandler` mock replaces 4 copies.
- **`[Trait("Category", "Unit")]`** — added to 93 test classes for CI filtering.
- **Benchmarks.md** — updated to 15 suites / 69 benchmarks with CompetitorBenchmarks (MediumRun) results.

## [0.4.0] - 2026-06-11

### Added

- **CI infrastructure** — three new GitHub Actions workflows: weekly fuzz testing (7 targets via SharpFuzz), Stryker mutation testing (Advanced level), and stress tests (1,000 sequential / 500 concurrent / 100 incremental). NU1903 suppression removed — no vulnerable packages remain.
- **PDF/A-4 (ISO 19005-4:2020)** — new `A4a`, `A4b`, `A4u`, `A4e` enum values, detection via XMP metadata (`pdfaid:part=4`), CLI/HostSigner formatting, and preservation validation (PNG/transparency allowed as per ISO 19005-4).
- **EdDSA verification** — `CryptoVerifier.VerifySignature` no longer throws `NotSupportedException` for Ed25519/Ed448; verification falls through to the ECDSA path. Direct signing remains via external signer pipeline only.
- **CAdES-XL validation references** — new OIDs and `CmsAttribute` factory methods for CAdES-X/L/A: `CertificateRefs`, `RevocationRefs`, `CertValues`, `RevocationValues`. Enables ICP-Brasil AD-RV/AD-RC/AD-RA profile use via attribute injection.
- **SHA-3 hash support** — `HashAlgorithmName.SHA3_256/384/512` on .NET 9+ across hashing, CMS digest OID mapping, timestamping, verification, and XMLDSig URIs (guarded with `#if NET9_0_OR_GREATER`).
- **Architecture Decision Records** — 4 ADRs: use of `System.Security.Cryptography` (no BouncyCastle), incremental PDF save, result-object validation, AOT compatibility.
- **Migration guides** — `docs/migration/v0.2-to-v0.3.md` and `docs/migration/v0.3-to-v0.4.md` with breaking changes and upgrade steps.
- **Issue templates** — `bug_report.md`, `feature_request.md`, `standards_request.md` for structured issue triage.
- **`SignerBuilder.WithSignatureAlgorithm(oid)`** — new public API to force a specific signature algorithm OID on the local signing path. Primary use case: producing RSASSA-PSS signatures with certificates whose public key OID is `rsaEncryption` (`1.2.840.113549.1.1.1`). Compatibility with the certificate's key type is validated at signing time.
- **`CmsSignatureBuilder.ValidateSignatureAlgorithmCompatibility`** — shared validator that throws `ArgumentException` when the requested signature OID is incompatible with the certificate's public key family (e.g., ECDSA OID on an RSA cert).
- **`DeferredSigningOptions.HashAlgorithmExplicitlySet`** — new `bool` property that distinguishes "user chose SHA-256" from "library defaulted to SHA-256", enabling algorithm inference on the deferred signing path.
- **`AlgorithmInference.ExtractPssParamsFromSpki`** — reads PSS parameters from SubjectPublicKeyInfo when the public key OID is `id-RSASSA-PSS` (RFC 4055 §4), enabling PSS detection on certificates that encode the constraint at the SPKI level rather than the signature algorithm level.
- **`TestCertificateFactory.CreatePssSelfSignedCert`** — new test helper that creates PSS-issued self-signed certificates with embedded `RSASSA-PSS-params`.
- **`TestCertificateFactory.TryCreateEdDsaCert`** — new test helper that creates Ed25519 self-signed certificates on .NET 9+; returns `null` on unsupported platforms. Enables end-to-end EdDSA signing and compatibility validation tests.

### Fixed

- **Directory.Build.props XML comment** — `--vulnerable` contained `--` which broke XML parsing (`MSB4024`). Fixed to use `-vulnerable` instead.
- **PSS cert's `RSASSA-PSS-params` ignored at the SPKI level** — certificates that encode the PSS constraint at the SubjectPublicKeyInfo level (`PublicKey.Oid.Value == Oids.RsaPss`, RFC 4055 §4) were not detected as PSS certs, causing `DetectRsaPadding` to return PKCS#1 and `DetectSignatureAlgorithmOid` to produce `rsaEncryption` instead of `id-RSASSA-PSS`. The new `AlgorithmInference.ExtractPssParamsFromSpki` reads the SPKI parameters field, and all four PSS detection points (`AlgorithmInference`, `SignerBuilder.DetectSignatureAlgorithmOid`, `DeferredSigner.DetectSignatureAlgorithmOid`, `CmsSignatureBuilder.GetSignatureAlgorithmOid`) now check both `PublicKey.Oid.Value` and `SignatureAlgorithm.Value`.
- **PSS cert's `RSASSA-PSS-params` ignored when inferring hash** — certificates issued with `id-RSASSA-PSS` and declaring SHA-384 or SHA-512 in their PSS params were always signed with SHA-256 unless the caller explicitly called `.WithHashAlgorithm()`. The new `AlgorithmInference.ResolveEffectiveHashAlgorithm` helper reads the hash from the cert's DER-encoded PSS params (via `CryptoUtility.ParsePssHashAlgorithm`) and uses it when the user has not overridden the default. Applied to `SignerBuilder`, `DeferredSigner`, and `DeferredSignerBuilder`.
- **Default hash for RSA PKCS#1 always SHA-256 regardless of key size** — RSA keys >= 3072 bits now default to SHA-384 per NIST SP 800-57 Part 1 Rev. 5, Table 2. Smaller keys remain at SHA-256. Applied to all three signing paths.
- **`DeferredSigner.CompleteAsync` timestamp hash used wrong algorithm** — when the deferred signer chose PKCS#1 SHA-512, the timestamp request was still sent with SHA-256. `CompleteAsync` now derives the timestamp hash from the CMS digest OID via `HashAlgorithmFromDigestOid`, which correctly handles SHA-384 and SHA-512.
- **`WithExternalSigner` bypassed algorithm inference** — both overloads of `SignerBuilder.WithExternalSigner` (with and without chain) now resolve the effective hash via `AlgorithmInference` before calling `DetectSignatureAlgorithmOid`, ensuring PSS params and key-size defaults are honoured on the external-signer path.
- **`SelectHashForRsaKeySize` too-broad catch** — narrowed to `CryptographicException` so `NotSupportedException` from other sources propagates correctly.
- **`CmsSignatureBuilder.BuildSignedData` mis-logged PSS detection** — the debug log now checks `signatureOid == Oids.RsaPss` instead of comparing the original OID to `Oids.RsaPss`.
- **`ExtractCmsFromPdf` hex stripping off by one** — the `/Contents` hex string trimmer was stripping individual `'0'` characters instead of `"00"` byte pairs, corrupting hex values containing embedded `0` digits.
- **No compatibility validation on signature algorithm OID** — previously, setting an incompatible OID (e.g., ECDSA OID on an RSA cert) produced a structurally invalid CMS with no error at signing time. Now validated at `CmsSignatureBuilder.Build`, `BuildAsync`, and `DeferredSigner.PrepareAsync`.
- **`_signatureAlgorithmOid` ignored on local signing path** — `SignerBuilder.SignCoreAsync` only passed the OID to the external-signer branch. Now threaded through both branches via the new `signatureAlgorithmOid` parameter on `CmsSignatureBuilder.Build`.
- **PDF/A-3b `spacingCompliesPDFA` on signed PDFs** — residual ISO 19005-3 §6.1.9 Test 1 failures on objects 99, 75, and 114 (the three objects appended by the LTV + DocTimeStamp signing chain) when the source PDF is bare-`%%EOF` (no EOL after `%%EOF`). The new `IncrementalUpdateUtility.EnsureTrailingEol` helper is called by all three writers (`PdfSignatureWriter`, `LtvEmbedder`, `DocTimeStampWriter`) after they copy the source PDF into the result stream, guaranteeing the first new object written is preceded by an EOL marker.
- **LTV catalog write missing trailing EOL** — `LtvEmbedder.BuildUpdatedCatalogDss` now also normalises CRLF→LF and falls back to a depth-aware `PdfStructureParser.FindOutermostDictClose` when the `>>\nendobj` sentinel is not found, and appends a `\n` to the rewritten catalog if it does not end with an EOL marker. This is the root cause of the 3 object-level failures (the xref stream written immediately after the catalog rewrite would otherwise be the first object not preceded by an EOL).
- **LTV early-return path with bare-`%%EOF` source** — when no CRL/OCSP data can be collected, the embedder now still passes the source through `EnsureTrailingEol` so a follow-up incremental update is always LF-preceded. The 4 corresponding tests were updated to assert the new trailing-EOL behavior.
- **`DocxToPdf`, `Europa`, `App` stub projects** — removed (empty projects with no source code).

### Improved

- **Test coverage for algorithm inference** — 26 new tests across 4 new test files:
  - `AlgorithmInferenceTests.cs` (10 tests) — PSS params extraction, key-size hash, default hash, SPKI-level PSS detection on `SimpleSigner`.
  - `DeferredAlgorithmInferenceTests.cs` (6 tests) — PSS params, key-size hash, default hash, end-to-end PSS deferred signing.
  - `DeferredSignerBuilderAlgorithmInferenceTests.cs` (3 tests) — PSS params, key-size hash, explicit hash passthrough.
  - `CmsSignatureBuilderCompatibilityTests.cs` (7 tests) — RSA, ECDSA, EdDSA compatible/incompatible OID pairs; PSS OID build.
- **EdDSA support** — `TestCertificateFactory.TryCreateEdDsaCert` on .NET 9+ with `#if`-wrapped platform guards. EdDSA compatibility tests auto-skip on unsupported platforms.
- **New test helpers** — `TestCertificateFactory.CreatePssSelfSignedCert` for PSS-issued certs with arbitrary hash.
- **Documentation** — ADRs (4), migration guides (2), issue templates (3), updated conformance matrix.
- **`PdfALevel` enum** — fully classified with `A1a`–`A4e` values (previously missing `A2u`, `A3u`, all `A4` variants).

## [0.3.2] - 2026-06-08

### Added

- **RFC 4055 §3.1 RSASSA-PSS-params** — `CmsSignatureBuilder` now emits the full `RSASSA-PSS-params` structure (hashAlgorithm + maskGenAlgorithm with id-mgf1 + same hash + saltLength) when signing with `id-RSASSA-PSS`, instead of leaving the parameters field empty. Required for acceptance by Adobe Acrobat, EU DSS, iText, and eIDAS validators (PS256 / PS384 / PS512).
- **`Oids.Mgf1`** — new `1.2.840.113549.1.1.8` constant for the id-mgf1 mask-generation function used inside the PSS params.
- **`CryptoUtility.ParsePssHashAlgorithm`** — parses the hash OID from a DER-encoded `RSASSA-PSS-params` structure (RFC 4055 §3.1); returns SHA-256 as the RFC default when the params are absent or the hash OID is unrecognised.
- **External signer chain overloads** — two new `SignerBuilder.WithExternalSigner(..., chain)` overloads (one with explicit OID, one with auto-detection) let HSM / cloud-KMS callers supply the pre-fetched intermediate certificate chain, avoiding redundant AIA HTTP requests during LTV embedding.
- **PSS-params-aware revocation verification** — `OcspClient.VerifyOcspSignature`, `CrlClient.VerifyCrlSignature`, and `TimestampValidator.VerifyTsaSignature` now accept and honour the `RSASSA-PSS-params` from the response / token; PS384 and PS512 responses are no longer silently verified with SHA-256.
- **PDF/A-2/3 conformance tests** — new `PdfAConformanceTests` covering the `/F 132` Print flag, `LF` after `obj` in incremental updates, CRLF-aware `AppendAnnots` / `InsertIntoDict`, and end-to-end signing of a PDF/A-3b-labelled document.
- **PS256/PS384/PS512 test coverage** — round-trip signing and validation for all three PSS hash variants, plus parser/params assertions in `Phase3ProductionTests`.

### Fixed

- **PDF/A-2/3 conformance after signing** — `BuildFieldAnnotation` previously emitted `/F 0` for invisible signature widgets, failing ISO 19005-3 §6.3.2 Test 2 (the Print flag must be set even when the widget is invisible). The widget now always carries `/F 132` (Print + Locked). `DocTimeStampWriter` had the same bug; also fixed.
- **Indirect-object EOL after `obj`** — `BuildUpdatedPageObject` previously wrote `"N 0 obj <<"` with a single space, failing ISO 19005-3 §6.1.9 Test 1 (`spacingCompliesPDFA`). Now writes `"N 0 obj\n<<"`.
- **CRLF source PDF corruption** — `AppendAnnots` and `InsertIntoDict` used `LastIndexOf(">>\nendobj")` which never matched on Windows / iText / Adobe source PDFs (CRLF line endings), falling back to a depth-blind `LastIndexOf(">>")` that could insert new keys inside a nested dictionary. Both now normalise CRLF → LF and fall back to a depth-aware `FindOutermostDictClose` that finds the closing `>>` of the top-level dictionary.
- **PS384/PS512 OCSP, CRL, and TSA verification** — previously all PSS signatures were verified with SHA-256 regardless of the actual hash, causing silent acceptance / rejection mismatches in revocation validation.

### Improved

- **`Iso32000ComplianceTests.Widget_InvisibleHasF0AndZeroRect`** — renamed and updated to assert `/F 132` (reflecting the corrected behaviour); the previous test enshrined the bug.
- **PSS signing is now interoperable with all major validators** — Adobe Acrobat Reader, EU DSS, iText, and eIDAS-compliant validators now accept the produced signatures for PS256, PS384, and PS512 (previously rejected as malformed due to the missing params).

## [0.3.1] - 2026-06-01

### Added

- **DSS merge for multi-signature PDFs** — `LtvEmbedder` now reads existing DSS dictionaries and merges prior VRI entries, CRL/OCSP/Cert object references with new data instead of replacing them. Counter-signatures and multi-party signing workflows now preserve all revocation data.
- **VRI-aware validation path** — `PdfSignatureValidator` computes SHA-1 of each signature's `/Contents` and looks up per-signature VRI entries from the DSS, falling back to global arrays. Enables correct per-signature revocation validation in multi-signer documents.
- **Full DSS extraction** — `DssExtractor.TryReadFullDssDataAsync` returns structured `DssValidationData` with global CRLs/OCSPs/Certs and per-VRI entries (new `DssValidationData` and `VriData` record types).
- **Embedded OCSP validation** — `RevocationChecker` and `OcspClient` now support validating embedded OCSP responses from DSS/VRI without network access (priority: embedded OCSP → embedded CRL → online OCSP → online CRL).
- **CRL issuer certificate chase** — LTV stabilisation loop now detects indirect CRL issuers (issuer DN ≠ cert issuer DN) and fetches their certificates via AIA `caIssuers`, making the loop fully general for all PKI topologies.
- **`CrlClient.ExtractCrlIssuerDn`** — new static method to parse CRL issuer Distinguished Name from DER-encoded CRL bytes.
- **`OcspClient.CheckEmbeddedOcspResponse`** — new instance method for offline OCSP response validation against a target certificate.

### Fixed

- **DSS replacement in multi-signature scenarios** — prior VRI entries and revocation data are no longer lost when adding a second signature with LTV enabled.

## [0.3.0] - 2026-05-25

### Added

- **AI-first documentation** — `llms.txt`, `llms-full.txt` (llmstxt.org standard), `CLAUDE.md`, `AGENTS.md`, `.github/copilot-instructions.md` for AI agent discoverability
- **`samples/README.md`** — scenario-to-code index for AI agents and developers
- **ETSI conformance: OcspNoCheck** — OID `1.3.6.1.5.5.7.48.1.5` now prevents infinite recursion in revocation checking (RFC 6960 §4.2.2.2.1)
- **ETSI conformance: OCSP responder certs in DSS** — `OcspClient` returns all responder certificates from OCSP responses for DSS `/Certs` inclusion (Annex A §A.2.2)
- **`TsaCertificateExtractor`** — new utility to extract certificates from RFC 3161 timestamp tokens for DSS inclusion
- **VRI `/TS` stream** — VRI dictionaries now include signature timestamp tokens and `/Type /VRI` (required by ETSI EN 319 142-1)
- **LTV iterative stabilisation** — revocation loop replaced with queue-based stabilisation that chases OCSP responder certs and respects OcspNoCheck
- **Fluent API guards** — `WithLtv()` throws immediately without timestamp; `WithArchivalTimestamp()` throws without LTV

### Fixed

- **VRI key computation** — parses DER length to exclude trailing zero padding, producing correct SHA-1 hashes
- **Certificate deduplication in DSS** — uses thumbprint-keyed map to avoid duplicate embeddings
- **Certificate leak in LtvEmbedder** — duplicate certs now properly disposed in stabilisation loop
- **Double-read in TsaCertificateExtractor** — AsnReader consumption fixed in catch block
- **Double-read in OcspClient** — same fix applied
- **OCSP responder cert disposal** — `ParseOcspResponseWithCerts` wraps in try/catch to dispose on parse failure

### Changed (Breaking)

- **`WithLtv()` now requires `WithTimestamp()`** — calling `.WithLtv()` without a preceding `.WithTimestamp()` throws `InvalidOperationException`
- **`WithArchivalTimestamp()` requires LTV** — calling `.WithArchivalTimestamp()` without `.WithLtv()` throws `InvalidOperationException`
- **`BatchSigner.WithArchivalTimestamp()`** — no longer implicitly enables LTV
- **PDF/A-1 PNG severity** — changed from Warning to Error (absolute prohibition per ISO 19005-1)

### Improved

- **NuGet package metadata** — enhanced `PackageTags` and `Description` for better discoverability by AI agents and package search
- **XML documentation** — added `<example>` tags to `PdfSignatureValidator` and `PdfSignatureInspector`

## [0.2.3] - 2026-05-21

### Fixed (Security)

- **Shadow Attack mitigation** — trailing unsigned content after the last signature's ByteRange is now validated structurally (requires `xref`/cross-reference stream + `startxref` + `%%EOF`); previously only checked for the `%%EOF` string, allowing arbitrary content injection disguised as a valid update
- **Unknown hash OID in signingCertificateV2** — throws `NotSupportedException` instead of silently falling back to SHA-256; prevents an attacker from using a fake algorithm OID to bind a signature to a substitute certificate
- **RSA-PSS NULL parameter** — `SignatureAlgorithmUsesNullParameter` now correctly returns `false` for RSA-PSS (`1.2.840.113549.1.1.10`); RFC 4055 requires `RSASSA-PSS-params`, not NULL; fixes rejection by strict validators (eIDAS, ICP-Brasil Verificador)
- **OCSP CertID verification** — `ParseOcspResponse` now verifies the `CertID` in the response matches the certificate requested (issuerNameHash + serialNumber), as required by RFC 6960 §3.2; single-response fallback preserved for compatibility
- **SSRF DNS rebinding bypass** — `UrlValidator.IsSafeUrl` now resolves hostnames to IP addresses before applying private-range checks, blocking rebinding attacks via domains that resolve to `127.0.0.1` or `169.254.169.254`; IPv4-mapped IPv6 addresses (`::ffff:x.x.x.x`) are also checked
- **`HttpResponseMessage` leak on retry** — `ResilientHttp.Pipeline` now disposes the previous `HttpResponseMessage` in the `OnRetry` callback; previously each 5xx retry leaked a response and its underlying network stream
- **TimestampValidator double-read** — TSA certificate bytes are now read before the `try` block in the ASN.1 loop; a `CryptographicException` on `LoadCertificate` no longer silently consumes the next certificate in the set
- **`PdfByteRange.IsValid` overflow** — added guard for `Offset2 + Length2` overflow; a malformed PDF with near-max values could previously cause `CoversEntireFile` to incorrectly return `true`

### Added

- **`ValidarItiUrlBuilder`** — static helper to generate `https://validar.iti.gov.br/?document=<url>` links for QR code embedding in signed documents
- **CPF/CNPJ on `IcpBrasilValidationResult`** — new properties `Cpf`, `Cnpj`, `CpfFormatted` (`XXX.XXX.XXX-XX`), and `CnpjFormatted` (`XX.XXX.XXX/XXXX-XX`) extracted from the certificate SAN
- **Health professional data** — `IcpBrasilValidationResult.HealthProfessional` exposes CRM/CRO registration number and state code for e-prescriptions (DOC-ICP-04 OIDs `2.16.76.1.3.4`/`.3.5`/`.3.6`)
- **Complete DOC-ICP-15.03 policy OIDs** — `PolicyOids` expanded from 2 to 6 variants per policy level, covering all combinations of version (v1/v2/v3) × certificate type (PF/PJ); previously AD-RB–AD-RA only recognised v3 certs
- **Sponsor button** — `.github/FUNDING.yml` added (GitHub Sponsors via `eupassarin`)

## [0.2.2] - 2026-05-20

### Fixed

- **CAdES signingTime** — `signingTime` signed attribute is no longer included; the attribute is not allowed by ETSI EN 319 122 and was causing conformance errors (CheckAllowedAttributes violation)
- **Null guard in ValidateChainStep** — `PdfSignatureValidator.ValidateChainStep` no longer throws `NullReferenceException` when the signer certificate is absent; returns a clean validation error instead
- **Async AIA chain fetching** — `PdfSignatureValidator.ValidateChainStep` is now async and pre-fetches AIA certificates before `X509Chain.Build()`, fixing silent chain failures on macOS/Linux where auto-fetch is unreliable
- **BFS AIA chasing** — `CertificateChainUtility` now performs breadth-first multi-tier AIA chasing, enabling full ICP-Brasil intermediate chain resolution
- **P7B certificate bags** — `CertificateLoader` and `CertificateChainUtility.LoadCertsFromBytes` now handle PKCS#7 certificate bags (`.p7b`)
- **ICP-Brasil trust anchors** — `HostSigner` and `ValidationService` now inject `BrasilExtension` trust anchor providers so ICP-Brasil chains validate correctly

## [0.2.1] - 2026-05-19

### Fixed

- **OCSP `certs[0]` SEQUENCE OF wrapper** — correctly unwrap the inner `SEQUENCE OF Certificate` inside the OCSP BasicOCSPResponse `certs [0] EXPLICIT` wrapper (was failing to load OCSP responder certs)
- **CRL v2 bare version INTEGER** — handle the bare `INTEGER` version field in TBSCertList (v2 CRLs use `02 01 01` directly, not wrapped in a context tag like X.509 certs)
- **CMS serial comparison** — use `ReadIntegerBytes` for serial number comparison to preserve DER leading zeros (e.g. serial `00BB3F...` was being truncated by `BigInteger.ToString("X")`)
- **BER tolerance in extension parsers** — `CrlClient.GetCrlUrl`, `OcspClient.ParseAiaUri`, and `CertificateChainUtility.ExtractAiaUrls` now use `AsnEncodingRules.BER` (extensions can be BER-encoded; DER was silently losing revocation URLs)
- **Issuer cert lookup** — compare by `SubjectName.RawData` bytes first in OCSP and revocation checker (string comparison failed for re-encoded DNs with different ASN.1 string types)
- **TimestampClient BER tolerance** — `ExtractSignatureValue` and `ParseTimeStampResponse` now use BER instead of DER (tolerates Brazilian CAs and TSA servers with BER-encoded responses)
- **TSA signer cert identification** — `TimestampValidator` now identifies the correct signer certificate via `issuerAndSerialNumber` instead of blindly using `Certificates[0]` (fixes multi-cert TSA tokens like PostSignum)
- **DSS endstream detection** — `DssExtractor` now handles both `\r\n` and `\n` before the `endstream` keyword (PDF spec allows both; was silently losing embedded CRLs)
- **CRL issuer DN matching** — tolerate UTF8String vs PrintableString encoding differences when matching CRL issuer to certificate issuer
- **signingCertificate hash algorithm** — correctly use SHA-1 for V1 (`signingCertificate`) and SHA-256 for V2 (`signingCertificateV2`) attributes
- **Inspector CMS parse failure** — `PdfSignatureInspector` now logs a warning when CMS parsing fails (was silently returning minimal info)
- **CI formatting (IDE0055)** — enforce LF line endings via `.gitattributes` to prevent spurious formatting errors on Windows CI runners

### Added

- **Diagnostic logging** — 13 new structured log messages across revocation, OCSP, CMS parser, timestamp validator, inspector, and LTV embedder for improved troubleshooting in verbose mode
- **CmsParser normalized issuer fallback** — 3-step signer cert lookup: exact bytes → normalized issuer → issuer-only (resilient to DN encoding differences)

### Changed

- **CLI renamed** — tool command changed from `simplesign-cli` to `simplesign`

## [0.2.0] - 2026-05-17

### Added

- **Benchmark suite** — 6 benchmark classes (46+ benchmarks): feature overhead, incremental signing, stream I/O, deferred signing latency, PDF parsing cost, batch concurrency. Results in `BenchmarkDotNet.Artifacts/`
- **Fuzz testing** — 7 SharpFuzz targets: `dss`, `timestamp`, `ocsp`, `pdf`, `cms`, `validator`, `xref`. Added 5-second timeout cancellation and unified `IsExpectedException()` filter. Corpus seeds: PAdES-B-B, PAdES-LTA, bad-encoded-cms
- **Stress tests** — 3 tests tagged `[Trait("Category","Stress")]`: 1,000 sequential signs (memory growth < 50 MB), 500 concurrent (SemaphoreSlim, < 60 s), 100 incremental signatures on one document
- **Docs split** — `docs/interoperability.md`, `docs/conformance.md`, `docs/performance.md`, `docs/architecture.md` (extracted from README)
- **ISO 32000-1:2008 compliance test suite** — 46 unit tests mapping to specific standard sections (§7.3.4.2, §7.5.4–8, §7.9.4, §8.6.5, §8.7, §12.7, §12.8.1–3)
- **ISO 32000-2:2020 (PDF 2.0) compliance** — PDF 2.0 header detection, VRI validation, SHA-1 deprecation flags
- **ETSI EN 319 142 compliance tests** — 16 tests covering B-B/B-T/B-LT/B-LTA profiles, signed attributes, conformance detection
- **RFC 5652 (CMS) compliance tests** — 15 tests for SignedData structure, SignerInfo, signed attributes, DER encoding
- **DOC-ICP-15 compliance tests** — 16 tests for AD-RB/AD-RT profiles, ICP-Brasil chain, CPF/CNPJ extraction, Lei 14.063
- **OWASP security hardening** — SSRF protection (UrlValidator), path traversal guards, CORS restriction, nonce hardening, error sanitization, HMAC session integrity, SHA-1/MD5 rejection
- **CLI install script** from GitHub Releases (`scripts/install-cli.ps1`)
- **Real-world compatibility matrix** — Adobe, iText, pyHanko, LibreOffice, Word, EU DSS, ICP-Brasil
- **Resilience features** — BER/DER handling, malformed xref recovery, encrypted PDF detection

### Fixed

- **Cross-reference streams** — incremental updates now use xref streams when the original PDF uses them (ISO 32000 §7.5.8), with self-entry included
- **ObjStm-compressed AcroForm** — preserve all `/Fields` entries from compressed Object Streams when signing multi-signature PDFs
- **Indirect `/Fields` references** — resolve indirect references in AcroForm during signing
- **`/Type /AcroForm` removed** — adding this key broke Adobe Reader diff analysis on multi-signed PDFs
- **Duplicate field names** — ObjStm-compressed PDFs no longer produce duplicate `/Fields` entries
- **`/P` page reference** — added to field annotations for both regular and ObjStm-compressed page objects
- **`/Annots` array** — page annotation updates now work for ObjStm-compressed pages
- **`/M` date format** — changed from `Z` suffix to `+00'00'` per ISO 32000 §7.9.4
- **DocTimeStampWriter** — skip unnecessary Catalog rewrite when `reuseAcroForm=true`
- **AcroForm key preservation** — `/DR`, `/DA`, `/Q`, `/NeedAppearances`, `/XFA` no longer lost during signing
- **`EscapePdfString`** — added `\n`, `\r`, `\t`, `\b`, `\f` escapes per ISO 32000 §7.3.4.2
- **`endobj` termination** — catalog and page objects now always end with newline separator
- **Code review fixes** — 29 issues (2 Critical, 13 High, 14 Medium): `IsValid` includes revocation check, revocation exception handling, `IsNotRevoked` default, nonce entropy, error sanitization, and more

### Changed

- **Test assertions** — migrated from FluentAssertions (Xceed commercial license) to Shouldly (MIT) across all 7 test projects
- **HostSigner** — React/shadcn UI overhaul
- **README** — comprehensive rewrite: lib-focused structure, real benchmark numbers, dependency clarity, merged enterprise features

[0.7.0]: https://github.com/eupassarin/SimpleSign/releases/tag/v0.7.0
[0.6.0]: https://github.com/eupassarin/SimpleSign/releases/tag/v0.6.0
[0.5.0]: https://github.com/eupassarin/SimpleSign/releases/tag/v0.5.0
[0.4.0]: https://github.com/eupassarin/SimpleSign/releases/tag/v0.4.0
[0.3.2]: https://github.com/eupassarin/SimpleSign/releases/tag/v0.3.2
[0.3.1]: https://github.com/eupassarin/SimpleSign/releases/tag/v0.3.1
[0.3.0]: https://github.com/eupassarin/SimpleSign/releases/tag/v0.3.0
[0.2.3]: https://github.com/eupassarin/SimpleSign/releases/tag/v0.2.3
[0.2.2]: https://github.com/eupassarin/SimpleSign/releases/tag/v0.2.2
[0.2.1]: https://github.com/eupassarin/SimpleSign/releases/tag/v0.2.1
[0.2.0]: https://github.com/eupassarin/SimpleSign/releases/tag/v0.2.0
