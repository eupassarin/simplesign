← [Back to README](../README.md)

# Architecture & Design

## Architecture

```
SimpleSign.Core               Crypto primitives, CMS, TSA, revocation, HTTP
├── Crypto/                    CmsSignatureBuilder, TimestampClient, TsaPool, CmsParser
├── Validation/                CryptoVerifier, CertificateChainUtility, RevocationChecker
├── Revocation/                CrlClient, OcspClient, RevocationChecker
└── Http/                      IHttpClientProvider

SimpleSign.Pdf                 PDF structure parsing (no crypto)
├── PdfStructureReader         Xref, objects, signature fields
└── PdfStructureParser         Low-level token/stream parser

SimpleSign.PAdES               PDF Advanced Electronic Signatures
├── SimpleSigner               Fluent API entry point
├── SignerBuilder               Immutable builder (16 options)
├── PdfSignatureWriter         Incremental PDF update (append-only)
├── BatchSigner                Parallel signing with metrics
├── DeferredSigner             Two-phase signing for web apps
├── LtvEmbedder                DSS dictionary (CRL/OCSP/VRI)
├── DocTimeStampWriter         PAdES B-LTA archival timestamp
├── Validation/                PdfSignatureValidator, IntegrityVerifier, DssExtractor
├── Inspection/                PdfSignatureInspector (static)
└── PadesExtractor             CMS extraction from signed PDFs

SimpleSign.Brasil              Brazilian PKI (ICP-Brasil + Gov.br + Lei 14.063)
├── IcpBrasilChainValidator    ICP-Brasil chain validation (AD-RB..AD-RA)
├── GovBrChainValidator        Gov.br assurance levels
├── AdvancedSignatureInfo      AEA Lei 14.063 metadata
└── BrasilExtension            Registration entry point

SimpleSign.Cli                 Commands via Spectre.Console
SimpleSign.HostSigner          Windows tray app — local signing HTTP API
```

## Design Principles

| Principle | Implementation |
|---|---|
| **Immutable builders** | Every `.WithX()` returns a new instance — safe to share across threads |
| **Async-first** | All signing/validation methods return `Task<T>` — no blocking calls anywhere |
| **Zero-allocation hot paths** | `Span<byte>` and `ReadOnlySpan<byte>` for PDF parsing and hash computation |
| **Pooled memory** | `RecyclableMemoryStream` for buffer reuse |
| **Structured logging** | 105 `[LoggerMessage]` definitions — zero-cost when disabled |
| **Native AOT** | No reflection in hot paths, trimmer-friendly |
| **Nullable enabled** | All public APIs are fully annotated |

## Quality

| Metric | Value |
|---|---|
| **Tests** | 1,602 (unit, integration, interop, fuzz, corpus, ISO compliance) |
| **Test categories** | Unit (algorithm + ISO 32000 compliance), Integration (sign→validate round-trip), Interop (EU DSS, iText, PDFBox), ETSI Corpus (9 test methods), Fuzz (7 SharpFuzz harnesses), Stress (1,000-op memory + concurrency) |
| **Real-world fixtures** | 57 PDFs from Adobe, iText, EU DSS, ICP-Brasil, Belgian eID, Spanish/German/French/Hungarian gov |
| **Source lines** | ~32,800 |
| **Warnings** | 0 (all warnings treated as errors) |
| **Code analysis** | Full Roslyn analyzer suite enabled |
| **CI** | Build + test, CodeQL SAST, benchmarks |
| **AOT** | Native AOT smoke-tested in CI |
| **Target frameworks** | net8.0 + net10.0 |

## Resilience

| Scenario | Behavior |
|---|---|
| Malformed xref table | Falls back to brute-force `/ByteRange` scanning |
| BER-encoded CMS (Gov.br) | Parses both BER and DER transparently |
| Missing `/Length` in streams | Scans up to 10 MB for `endstream` marker |
| Encrypted PDF | Throws `EncryptedPdfException` with actionable message |
| Malformed CMS structure | Returns partial field info, no crash |
| SHA-1 legacy signatures | Validates (deprecated since 2016, supported for legacy) |
