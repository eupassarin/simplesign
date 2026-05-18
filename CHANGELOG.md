# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

[0.2.0]: https://github.com/eupassarin/SimpleSign/releases/tag/v0.2.0
