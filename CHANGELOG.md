# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-05-15

### Added

- **ISO 32000-1:2008 compliance test suite** — 46 unit tests mapping to specific standard sections (§7.3.4.2, §7.5.4–8, §7.9.4, §8.6.5, §8.7, §12.7, §12.8.1–3)
- **CLI install script** from GitHub Releases (`scripts/install-cli.ps1`)
- **Real-world compatibility matrix** in README — Adobe, iText, pyHanko, LibreOffice, Word, EU DSS, ICP-Brasil
- **Resilience section** in README — BER/DER handling, malformed xref recovery, encrypted PDF detection

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

### Changed

- **HostSigner** — React/shadcn UI overhaul
- **README** — comprehensive rewrite with compatibility matrix, ISO compliance tables, resilience docs

[0.2.0]: https://github.com/eupassarin/SimpleSign/releases/tag/v0.2.0
