# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0-alpha] - 2025-05-13

### Added

- **SimpleSign.Core** — Crypto primitives, CMS parsing/building, TSA client with pooling and retry (Polly), CRL/OCSP revocation checking, structured logging (126 LoggerMessage definitions)
- **SimpleSign.Pdf** — Pure-.NET PDF structure parser (xref, objects, signature fields, incremental updates)
- **SimpleSign.PAdES** — PAdES signing (B-B, B-T, B-LT, B-LTA), validation, inspection, batch signing, deferred signing, visible signatures with QR codes, DocMDP certification, PDF/A preservation
- **SimpleSign.Brasil** — ICP-Brasil chain validation (AD-RB through AD-RA), Gov.br assurance levels, Lei 14.063 AEA support, embedded trust anchors (v4–v13)
- **SimpleSign.HtmlToPdf** — Pure-.NET HTML-to-PDF converter (no external dependencies)
- **SimpleSign.Cli** — Command-line tool for sign, validate, inspect, batch-sign, extract operations
- **SimpleSign.Agent** — Desktop signing agent (Tauri 2) with `simplesign://` protocol handler, HTTP API for CLI/web integration, multi-document signing support
- Native AOT compatibility across all library packages
- Multi-target: net8.0 + net10.0
- Interoperability testing against EU DSS, iText 7, Apache PDFBox
- ETSI corpus tests (33 real-world signed PDFs)
- Fuzzing harnesses (SharpFuzz)

[0.1.0-alpha]: https://github.com/eupassarin/SimpleSign/releases/tag/v0.1.0-alpha
