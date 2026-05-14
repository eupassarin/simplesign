<p align="center">
  <img src="assets/icon.svg" alt="SimpleSign" width="96" height="96" />
</p>

<h1 align="center">SimpleSign</h1>

<p align="center">
  <strong>Digital signatures for .NET — PAdES.</strong><br/>
  Sign, validate, and inspect PDF documents with a clean, modern API.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/.NET-8%20%7C%2010-512BD4?style=flat-square&logo=dotnet" alt=".NET 8 | 10" />
  <img src="https://img.shields.io/badge/License-MIT-green?style=flat-square" alt="MIT License" />
  <img src="https://img.shields.io/badge/AOT-Compatible-blueviolet?style=flat-square" alt="Native AOT" />
  <img src="https://img.shields.io/badge/Tests-1%2C544-brightgreen?style=flat-square" alt="1,544 tests" />
  <img src="https://img.shields.io/badge/Zero%20Dependencies-✓-blue?style=flat-square" alt="Zero crypto dependencies" />
</p>

---

## What is SimpleSign?

SimpleSign is a .NET library for creating and validating **digitally signed PDF documents** according to European (ETSI) and Brazilian (ICP-Brasil) standards, implementing PAdES (ETSI EN 319 142).

All cryptography is handled by `System.Security.Cryptography` — **no third-party crypto libraries** are used.

---

## Quick Start

### Sign a PDF (PAdES)

```csharp
using SimpleSign.Signing;

var signedPdf = await SimpleSigner
    .Document("contract.pdf")
    .WithCertificate(certificate)
    .WithTimestamp("http://timestamp.digicert.com")
    .WithLtv()
    .SignAsync();

File.WriteAllBytes("contract-signed.pdf", signedPdf);
```

### Validate Signatures

```csharp
using SimpleSign.Validation;

var validator = new PdfSignatureValidator(new ValidationOptions
{
    CheckRevocation = true,
    TrustSystemRoots = true
});

var results = await validator.ValidateAsync(File.OpenRead("signed.pdf"));

foreach (var r in results)
{
    Console.WriteLine($"{r.FieldName}: Valid={r.IsValid}");
    Console.WriteLine($"  Integrity={r.IsIntegrityValid}");
    Console.WriteLine($"  Chain={r.IsCertificateChainValid}");
    Console.WriteLine($"  Signer: {r.SignerName} at {r.SigningTime}");
}
```

---

## Installation

Packages are split by concern — install only what you need:

```bash
# Full PAdES stack (most common)
dotnet add package SimpleSign

# Brazilian PKI (ICP-Brasil + Gov.br)
dotnet add package SimpleSign.Brasil

# CLI tool
dotnet tool install -g SimpleSign.Cli
```

### Package Map

```
SimpleSign (meta-package)
├── SimpleSign.PAdES        PDF signing & validation (PAdES B-B/T/LT/LTA)
│   ├── SimpleSign.Pdf      PDF structure parser (xref, objects, fields)
│   └── SimpleSign.Core     Crypto primitives, CMS, TSA, revocation, HTTP
│
SimpleSign.Brasil           ICP-Brasil + Gov.br + Lei 14.063  → depends on PAdES
SimpleSign.HtmlToPdf        Pure-.NET HTML→PDF (independent)
```

---

## Features

### PAdES — PDF Signatures

Sign PDFs with full European standard compliance, from basic signatures to long-term archival:

```csharp
var signed = await SimpleSigner
    .Document(pdfBytes)
    .WithCertificate(cert)
    .WithMetadata(signerName: "Jane Doe", reason: "Approval", location: "New York")
    .WithTimestamp("http://timestamp.digicert.com")
    .WithLtv()                    // Embed CRL/OCSP for offline validation
    .WithArchivalTimestamp()      // PAdES B-LTA — valid for decades
    .WithHashAlgorithm(HashAlgorithmName.SHA512)
    .SignAsync();
```

| Capability | API |
|---|---|
| Basic signature (B-B) | `.WithCertificate(cert).SignAsync()` |
| Timestamp (B-T) | `.WithTimestamp(tsaUrl)` |
| Long-term validation (B-LT) | `.WithLtv()` |
| Archival (B-LTA) | `.WithArchivalTimestamp()` |
| Document certification (DocMDP) | `.AsCertification(level)` |
| PDF/A preservation | `.WithPdfAPreservation()` |
| Visible signature with QR code | `.WithAppearance(appearance)` |
| External signer (HSM, KMS) | `.WithExternalSigner(cert, signerFunc)` |
| Existing field | `.WithExistingField("SignHere")` |
| Deferred (2-phase) | `DeferredSigner.PrepareAsync()` → `CompleteAsync()` |
| Batch (parallel) | `BatchSigner.Create(cert).Build()` |

#### Signature Appearance

```csharp
var appearance = new SignatureAppearance
{
    Page = 1,
    X = 50, Y = 50,
    ShowDate = true,
    ShowReason = true,
    BackgroundImagePng = logoBytes,
    VerificationUrl = "https://verify.example.com/abc123",  // Renders a QR code
    ExtraLines = ["Department: Legal", "Ref: DOC-2025-001"]
};

await SimpleSigner
    .Document(pdfBytes)
    .WithCertificate(cert)
    .WithAppearance(appearance)
    .SignAsync(output);
```

---

### Validation

Validate signatures with detailed results:

```csharp
var pdfResults = await new PdfSignatureValidator(options).ValidateAsync(stream);
```

Each result includes:
- `IsIntegrityValid` — byte-range hash matches (no tampering)
- `IsSignatureValid` — cryptographic signature verifies against public key
- `IsCertificateChainValid` — chain builds to a trusted root
- `IsTimestampValid` — RFC 3161 token is valid
- `IsValid` — all checks pass
- `SignerName`, `SigningTime`, `DigestAlgorithmOid`, `SubFilter`, `Warnings`

---

### Inspection

Extract metadata without full validation (fast, non-cryptographic):

```csharp
var inspector = new PdfSignatureInspector();
var sigs = await inspector.InspectAsync(stream);
foreach (var s in sigs)
    Console.WriteLine($"{s.FieldName}: {s.SignerName}, {s.SigningTime}, {s.DigestAlgorithm}");
```

---

## Enterprise Features

### Batch Signing

Sign multiple documents in parallel with shared resources:

```csharp
var batch = BatchSigner.Create(cert)
    .WithTimestamp("http://timestamp.digicert.com")
    .WithLtv()
    .Build();

var results = await batch.SignAsync(documents);
// results.Succeeded, results.Failed, results.ElapsedMs
```

### Deferred Signing (Two-Phase)

For web applications where the signing key is on a client device:

```csharp
// Server: prepare the hash
var prepared = await DeferredSigner.PrepareAsync(pdfBytes, cert);
byte[] hashToSign = prepared.HashToSign;

// Client: sign the hash with the private key (RSA PKCS#1 v1.5, ECDSA, etc.)
byte[] signature = SignWithClientKey(hashToSign);

// Server: embed the signature
byte[] signedPdf = await DeferredSigner.CompleteAsync(prepared.SessionData, signature);
```

#### Builder API (Fluent)

```csharp
// Two-phase with builder
var builder = new DeferredSignerBuilder(pdfBytes, cert)
    .WithSignerName("Jane Doe")
    .WithReason("Contract approval")
    .WithTimestamp("http://timestamp.digicert.com");

var prepared = await builder.PrepareAsync();
byte[] signature = await SignExternallyAsync(prepared.HashToSign);
byte[] signedPdf = await builder.CompleteAsync(prepared.SessionData, signature);
```

### TSA Connection Pool

Resilient timestamp authority connections with pooling and retry:

```csharp
var pool = new TsaPool([
    "http://timestamp.digicert.com",
    "http://tsa.starfieldtech.com",
    "http://timestamp.sectigo.com"
]);

await SimpleSigner.Document(pdf)
    .WithCertificate(cert)
    .WithTimestampPool(pool)
    .SignAsync();
```

### Structured Logging

126 source-generated `[LoggerMessage]` definitions with semantic fields:

```csharp
services.AddLogging(b => b.AddConsole());
var validator = new PdfSignatureValidator(options, logger: loggerFactory.CreateLogger<PdfSignatureValidator>());
```

---

## 🇧🇷 Brazilian PKI (ICP-Brasil)

Full support for Brazilian digital signature standards:

### ICP-Brasil Chain Validation

```csharp
services.AddSimpleSignBrasil(); // registers ICP-Brasil trust anchors (v4–v13)

var validator = new IcpBrasilChainValidator();
var result = await validator.ValidateAsync(signedPdf);
// result.Level: AD_RB, AD_RT, AD_RV, AD_RC, AD_RA
```

### Gov.br Validation

```csharp
var govValidator = new GovBrChainValidator();
var level = await govValidator.GetAssuranceLevelAsync(certificate);
// Bronze, Silver, Gold
```

### AEA — Advanced Electronic Signature (Lei 14.063/2020)

```csharp
var info = AdvancedSignatureInfo.FromCertificate(cert);
Console.WriteLine($"Type: {info.SignatureType}, Level: {info.AssuranceLevel}");
```

### Trust Anchors for Validation

```csharp
var options = new ValidationOptions
{
    TrustSystemRoots = false, // don't use OS store
    CustomTrustAnchors = IcpBrasilRoots.All // use ICP-Brasil roots only
};
```

---

## CLI Tool

```bash
# Sign a PDF
simplesign sign contract.pdf --cert mycert.pfx --password secret --timestamp

# Validate
simplesign validate signed.pdf

# Inspect
simplesign inspect signed.pdf

# Batch sign
simplesign batch-sign ./documents/ --cert mycert.pfx --parallel 8

# Extract CMS from signed PDF
simplesign extract signed.pdf --output signature.p7s
```

### Validation Output

```
contract-signed.pdf  1/1 valid
├── Document
│   ├── Signatures: 1 user + 0 timestamps
│   ├── Encrypted:  No
│   ├── DocMDP:     Not locked
│   ├── PDF/A:      None
│   └── ✓ DSS (embedded)
└── Signature1  ✓ VALID
    ├── Signer:       CN=Jane Doe, O=Acme Corp
    ├── SubFilter:    ETSI.CAdES.detached
    ├── PAdES:        B-T (Timestamp)
    ├── Certificate
    │   ├── Subject:        CN=Jane Doe, O=Acme Corp
    │   ├── Issuer:         DigiCert SHA2 Assured ID CA
    │   ├── Serial:         0A:1B:2C:3D
    │   ├── Key:            RSA 2048-bit
    │   ├── Valid:          2024-01-01 – 2026-01-01
    │   └── NonRepudiation: ✓
    ├── ESS CertV2:   ✓
    ├── Validation
    │   ├── Integrity:  ✓ Valid
    │   ├── Signature:  ✓ Valid
    │   ├── Chain:      ✓ Valid
    │   ├── Revoked:    ✓ Not revoked (OCSP)
    │   └── Timestamp:  ✓ 2025-04-28 14:30:00 UTC
    ├── Timestamp
    │   ├── Time:       2025-04-28 14:30:00 UTC
    │   ├── TSA:        CN=DigiCert Timestamp 2023
    │   └── Token Size: 4.2 KB
    ├── Algorithm:    SHA-256
    ├── Byte Range:   [0, 1234, 5678, 9012]  ✓
    └── Signed at:    2025-04-28 14:30:00 UTC
```

---

---

## Interoperability & Conformance

SimpleSign is built to survive the real world — legacy PDFs from Adobe, iText, pyHanko, LibreOffice, Word, and government signers across Europe and Brazil.

### PDF Structure Compatibility

| Feature | Support | Notes |
|---|---|---|
| **Classic xref tables** | ✅ | PDF 1.0+ — all versions |
| **Cross-reference streams** | ✅ | PDF 1.5+ — iText, Adobe, Word default |
| **Compressed Object Streams (ObjStm)** | ✅ | Extracts objects from FlateDecode containers |
| **Linearized PDFs** | ✅ | Follows `startxref` from EOF correctly |
| **Incremental updates** | ✅ | Up to 100 revision layers (multi-signature) |
| **Encrypted PDFs** | ❌ | By design — throws `EncryptedPdfException` |
| **Max file size** | 200 MB | Configurable |

### Real-World PDF Generators Tested

| Generator | Sign | Inspect | Validate | Notes |
|---|---|---|---|---|
| **Adobe Acrobat/Reader** | ✅ | ✅ | ✅ | `adbe.pkcs7.detached`, embedded CRL/OCSP |
| **iText 5/7/9** | ✅ | ✅ | ✅ | Interop CI tests; xref streams + ObjStm |
| **Apache PDFBox** | ✅ | ✅ | ✅ | Docker-based CI verification |
| **EU DSS (Digital Signature Service)** | ✅ | ✅ | ✅ | ETSI corpus + cross-validation |
| **pyHanko** | ✅ | ✅ | ✅ | Standard ETSI.CAdES.detached format |
| **LibreOffice** | ✅ | ✅ | ✅ | Linearized + xref stream PDFs |
| **Microsoft Word** | ✅ | ✅ | ✅ | ObjStm-compressed objects |
| **ICP-Brasil signers** | ✅ | ✅ | ✅ | Gov.br, AD-RB profiles, BER-encoded CMS |
| **Belgian eID** | — | ✅ | ✅ | ETSI corpus fixture |
| **Spanish gov (doc-firmado)** | — | ✅ | ✅ | ETSI corpus fixture |

### Multi-Signature Stress Tests

| Scenario | Status |
|---|---|
| PDF with **51 sequential signatures** | ✅ Signs + preserves all |
| PDF with **21 ObjStm-based signatures** (real gov document) | ✅ Signs without corrupting |
| PDF with **5 signatures + 1 document timestamp** | ✅ Full round-trip |
| Adding signature to **already-certified** PDF | ✅ Respects DocMDP |

### Integration Test Fixtures (38 PDFs)

Real-world PDFs covering edge cases:

- **Adobe**: `adbe-crl-signed.pdf`, `adbe-ocsp-signed.pdf`
- **ECDSA**: `pades-ecdsa.pdf` (elliptic curve signatures)
- **PAdES levels**: B-B, B-T, B-LT, B-LTA, LTV variants
- **DSS edge cases**: `dss-1443`, `dss-1683`, `dss-2025`, `dss-2821`, `dss-3226`, `dss-3567`
- **Negative tests**: `malformed-pades.pdf`, `bad-encoded-cms.pdf`, `modified-after-sig.pdf`, `encrypted.pdf`

### ETSI Corpus Tests

33 tests against the [EU DSS interoperability corpus](https://ec.europa.eu/digital-building-blocks/wikis/display/DIGITAL/eSignature+Conformance+Testing):

- **PAdES-LT/LTA** multi-revision documents (DSS updates + archive timestamps)
- **Belgian eID** (`BG_BOR`) signed documents
- **German** (`DE_SCI`) signed documents
- **French** (`FR_CS`) signed documents
- **Spanish** (`doc-firmado`) signed documents
- **Hungarian** (`HU_MIC`) plugtest documents
- **Known-bad** fixtures (DSS-1683 SHA-1 regression)

### Cross-Validation Matrix

| Tool | Direction | Status |
|---|---|---|
| **EU DSS** | SimpleSign → EU DSS validator | ✅ |
| **EU DSS** | EU DSS signer → SimpleSign validator | ✅ |
| **iText 9** | SimpleSign → iText validation | ✅ |
| **Apache PDFBox** | SimpleSign → PDFBox verification | ✅ |

### Docker-Based CI Tests

All interop tests run in Docker containers in CI (EU DSS, iText validator, PDFBox) — see [`interop/`](interop/) for details.

### ISO 32000-1:2008 Compliance

SimpleSign implements PDF digital signatures in strict conformance with ISO 32000-1. Compliance is verified by **46 automated unit tests**, each mapping to a specific section of the standard:

| ISO Section | Requirement | Tests |
|---|---|---|
| §7.3.4.2 | String escaping (`\n`, `\r`, `\t`, `\b`, `\f`, `\\`, `\(`, `\)`) | 2 |
| §7.5.4–6 | Incremental updates (original bytes, `/Prev` chain, `/Size`, `startxref`, `%%EOF`) | 5 |
| §7.5.4 | Xref table entries exactly 20 bytes (`oooooooooo ggggg n\r\n`) | 1 |
| §7.5.8 | Cross-reference streams (`/Type /XRef`, `/W`, `/Index`, self-entry, `/FlateDecode`) | 7 |
| §7.9.4 | Date format `D:YYYYMMDDHHmmss+HH'mm'` (not `Z` suffix) | 1 |
| §8.6.5 | Widget annotation flags (`/F 132` visible, `/F 0` invisible) | 2 |
| §8.7 | Page `/Annots` array updated with field reference | 1 |
| §12.7 | AcroForm (`/Fields`, `/SigFlags 3`, no `/Type`, preserves `/DR`, `/DA`, `/Q`) | 4 |
| §12.7.4.5 | Signature fields (`/FT /Sig`, `/V`, `/T`, `/P`, unique names) | 5 |
| §12.8.1 | Signature dictionary (`/Type /Sig`, `/Filter`, `/SubFilter`, `/ByteRange`, `/Contents`) | 7 |
| §12.8.2 | DocMDP certification (`/Reference`, `/TransformMethod`, `/P`, `/Perms`) | 4 |
| §12.8.3 | Appearance stream (`/AP /N`, `/Subtype /Form`, `/BBox`) | 2 |
| Cross-cutting | Every object has matching `endobj`, `BuildXrefStream` correctness | 5 |

---

## Performance

Benchmarks run on Apple M2 Pro, .NET 10, using [BenchmarkDotNet](https://benchmarkdotnet.org/).

### Signing Performance

| Operation | Time | Memory |
|---|---|---|
| PAdES sign 1 KB PDF | 71 ms | 1.8 MB |
| PAdES sign 100 KB PDF | 44 ms | 2.5 MB |
| PAdES sign 1 MB PDF | 47 ms | 7.4 MB |
| PAdES sign 10 MB PDF | 82 ms | 61 MB |
| ECDSA-P384 / SHA-384 | 51 ms | 1.8 MB |

### Validation Performance

| Operation | Time | Memory |
|---|---|---|
| PAdES validate (1 signature) | 15 ms | 338 KB |
| PAdES validate (5 signatures) | 22 ms | 1.6 MB |
| PAdES validate (chain: Root→Intermediate→End) | 17 ms | 338 KB |

### Concurrency Scaling

| Workload | Time | vs Sequential |
|---|---|---|
| Sequential (32 signs) | 476 ms | 1.00× |
| 8 concurrent tasks (32 signs) | 450 ms | 0.94× |
| 16 concurrent tasks (32 signs) | 466 ms | 0.98× |
| 32 concurrent tasks (32 signs) | 440 ms | 0.92× |

### vs Competitors (PAdES signing)

| Library | Time | Relative | Memory |
|---|---|---|---|
| **SimpleSign** | 23 ms | 1.0× | 13 KB |
| BouncyCastle | 58 ms | 2.5× | 46 KB |
| iText7 v9 | 92 ms | 2.5× | 742 KB |

> **Note:** Benchmarks are single-iteration cold starts (Dry run). Use for relative comparison, not absolute throughput measurement.

---

## Extension Points

| Extension | Interface / Pattern |
|---|---|
| Custom trust anchors | `ITrustAnchorProvider` |
| Custom hash algorithm | `HashAlgorithmName` parameter |
| External signer (HSM/KMS) | `Func<byte[], Task<byte[]>>` callback |
| Custom revocation | `IRevocationChecker` |
| Custom timestamp | `ITimestampClient` |
| Custom HTTP | `IHttpClientFactory` / `HttpClient` injection |
| Custom logging | `ILogger<T>` injection |
| Custom PDF rendering | `ISignatureAppearanceRenderer` |

---

## Conformance Matrix

| Standard | Levels | Status | Notes |
|---|---|---|---|
| **ISO 32000-1:2008** | Signature subsystem | ✅ | 46 unit tests per section (see above) |
| **PAdES** (ETSI EN 319 142) | B-B (Basic) | ✅ | CMS + `signingCertificateV2` |
| | B-T (Timestamp) | ✅ | RFC 3161 timestamp token |
| | B-LT (Long-Term) | ✅ | DSS dictionary with CRL/OCSP |
| | B-LTA (Archive) | ✅ | Document timestamp for decade-long validity |
| | DocMDP (Certification) | ✅ | Three permission levels (P=1, 2, 3) |
| | PDF/A preservation | ✅ | Detects and preserves 1a/1b/2a/2b/3a/3b |

### SubFilter Support

| SubFilter | Sign | Inspect | Validate | Notes |
|---|---|---|---|---|
| `ETSI.CAdES.detached` | ✅ (default) | ✅ | ✅ | Modern ETSI standard |
| `adbe.pkcs7.detached` | ✅ | ✅ | ✅ | Adobe legacy format |
| `ETSI.RFC3161` | ✅ | ✅ | ✅ | Document timestamps (B-LTA) |


---

## Supported Algorithms

| Category | Algorithms |
|---|---|
| **Hash** | SHA-256, SHA-384, SHA-512, SHA3-256, SHA3-384, SHA3-512 |
| **Signature** | RSA PKCS#1 v1.5, RSA-PSS, ECDSA (P-256/P-384/P-521), EdDSA (Ed25519/Ed448)¹ |
| **Revocation** | CRL, OCSP, embedded DSS |
| **Timestamps** | RFC 3161 |
| **PDF/A** | 1a, 1b, 2a, 2b, 3a, 3b (detection + preservation) |

¹ EdDSA via external signer pipeline; verification depends on runtime support.

---

## Architecture

```
SimpleSign.Core               Crypto primitives, CMS, TSA, revocation, HTTP
├── Signing/                   CmsSignatureBuilder, TimestampClient, TsaPool
├── Validation/                IntegrityVerifier, CryptoVerifier, ChainBuilder
├── Revocation/                CrlClient, OcspClient, RevocationChecker
└── Inspection/                CmsParser, DssExtractor

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
├── PdfSignatureValidator      Full validation pipeline
├── PdfSignatureInspector      Metadata extraction
└── PadesExtractor             CMS extraction from signed PDFs

SimpleSign.Brasil              Brazilian PKI (ICP-Brasil + Gov.br + Lei 14.063)
├── IcpBrasilChainValidator    ICP-Brasil chain validation (AD-RB..AD-RA)
├── GovBrChainValidator        Gov.br assurance levels
├── AdvancedSignatureInfo      AEA Lei 14.063 metadata
└── BrasilExtension            Registration entry point

SimpleSign.Cli                 Commands via Spectre.Console
SimpleSign.HostSigner          Windows tray app — local signing HTTP API
```

---

## Design Principles

| Principle | Implementation |
|---|---|
| **Immutable builders** | Every `.WithX()` returns a new instance — safe to share across threads |
| **Async-first** | All signing/validation methods return `Task<T>` — no blocking calls anywhere |
| **Zero-allocation hot paths** | `Span<byte>` and `ReadOnlySpan<byte>` for PDF parsing and hash computation |
| **Pooled memory** | `RecyclableMemoryStream` for buffer reuse |
| **Structured logging** | 126 `[LoggerMessage]` definitions — zero-cost when disabled |
| **Native AOT** | No reflection in hot paths, trimmer-friendly |
| **Nullable enabled** | All public APIs are fully annotated |

---

## Quality

| Metric | Value |
|---|---|
| **Tests** | 1,544+ (unit, integration, interop, fuzz, corpus, ISO compliance) |
| **Test categories** | Unit (algorithm + ISO 32000 compliance), Integration (sign→validate round-trip), Interop (EU DSS, iText, PDFBox), ETSI Corpus (33 real-world PDFs), Fuzz (SharpFuzz harnesses) |
| **Real-world fixtures** | 55 PDFs from Adobe, iText, EU DSS, ICP-Brasil, Belgian eID, Spanish/German/French/Hungarian gov |
| **Source lines** | ~33,500 |
| **Warnings** | 0 (all warnings treated as errors) |
| **Code analysis** | Full Roslyn analyzer suite enabled |
| **CI** | Build + test, CodeQL SAST, weekly benchmarks, weekly fuzz |
| **AOT** | Native AOT smoke-tested in CI |
| **Target frameworks** | net8.0 + net10.0 |

### Resilience

| Scenario | Behavior |
|---|---|
| Malformed xref table | Falls back to brute-force `/ByteRange` scanning |
| BER-encoded CMS (Gov.br) | Parses both BER and DER transparently |
| Missing `/Length` in streams | Scans up to 10 MB for `endstream` marker |
| Encrypted PDF | Throws `EncryptedPdfException` with actionable message |
| Malformed CMS structure | Returns partial field info, no crash |
| SHA-1 legacy signatures | Validates (deprecated since 2016, supported for legacy) |

---

## Documentation

| Document | Description |
|---|---|
| [API Reference](https://eupassarin.github.io/simplesign/) | Full API documentation (Docfx) |
| [Deferred Signing Guide](docs/articles/deferred-signing.md) | Two-phase signing for web apps |
| [HostSigner](src/SimpleSign.HostSigner/README.md) | Local signing tray app — API docs & install |
| [Web Signing Sample](samples/WebSigningSample/README.md) | Browser-based PDF signing demo |
| [Web Inspect Sample](samples/WebInspectSample/README.md) | Browser-based PDF inspector & validator |
| [Contributing](CONTRIBUTING.md) | How to contribute, coding standards, PR process |
| [Security](SECURITY.md) | Vulnerability reporting |
| [Changelog](CHANGELOG.md) | Release history |

---

## Requirements

- **.NET 8** or **.NET 10** (multi-target: net8.0 + net10.0)
- No native or COM dependencies
- No third-party cryptography libraries
- Runs on Windows, macOS, and Linux

---

## License

[MIT](LICENSE) — use it anywhere, for anything, forever.

## Contributing

Contributions are welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) before submitting a pull request.

---

<p align="center">
  <em>Built for developers who believe document signing should be simple.</em>
</p>
