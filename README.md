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
  <img src="https://img.shields.io/badge/Tests-1%2C602-brightgreen?style=flat-square" alt="1,602 tests" />
  <img src="https://img.shields.io/badge/No%20Crypto%20Deps-✓-blue?style=flat-square" alt="No third-party crypto dependencies" />
</p>

---

## What is SimpleSign?

SimpleSign is a .NET library for creating and validating **digitally signed PDF documents** according to European (ETSI) and Brazilian (ICP-Brasil) standards, implementing PAdES (ETSI EN 319 142).

All cryptography is handled by `System.Security.Cryptography` — **no third-party crypto libraries** are used. Runtime dependencies are limited to Polly (resilience), RecyclableMemoryStream (pooling), QRCoder (appearance QR codes), and Microsoft.Extensions abstractions — **nothing** touches your keys but the BCL.

---

## Quick Start

### Sign a PDF (PAdES)

```csharp
using SimpleSign.PAdES;

var pdfBytes = File.ReadAllBytes("contract.pdf");
var signedPdf = await SimpleSigner
    .Document(pdfBytes)
    .WithCertificate(certificate)
    .WithTimestamp("http://timestamp.digicert.com")
    .WithLtv()
    .SignAsync();

File.WriteAllBytes("contract-signed.pdf", signedPdf);
```

### Validate Signatures

```csharp
using SimpleSign.PAdES.Validation;

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
    Console.WriteLine($"  Timestamp={r.HasValidTimestamp}");
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
- `HasValidTimestamp` — RFC 3161 token is valid (bool?)
- `IsValid` — all checks pass
- `SignerName`, `SigningTime`, `DigestAlgorithmOid`, `SubFilter`, `Warnings`

---

### Inspection

Extract metadata without full validation (fast, non-cryptographic):

```csharp
using SimpleSign.PAdES.Inspection;

var result = await PdfSignatureInspector.InspectAsync(stream);
foreach (var s in result.Signatures)
    Console.WriteLine($"{s.FieldName}: {s.SignerName}, {s.SigningTime}, {s.DigestAlgorithm}");
```

---

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
using SimpleSign.Core.Crypto;

var pool = new TsaPool([
    "http://timestamp.digicert.com",
    "http://tsa.starfieldtech.com",
    "http://timestamp.sectigo.com"
]);

// Use TsaPool directly for resilient timestamp requests
byte[] tsaResponse = await pool.GetTimestampAsync(hash);
```

### Structured Logging

105 source-generated `[LoggerMessage]` definitions with semantic fields:

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
// Use AddSimpleSignBrasil() to register ICP-Brasil trust anchors automatically.
// For manual configuration, supply trusted roots via the TrustedRoots property:
var options = new ValidationOptions
{
    TrustSystemRoots = false, // don't use OS store
    TrustedRoots = icpBrasilCertificates // IReadOnlyList<X509Certificate2>
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

## Extension Points

| Extension | Interface / Pattern |
|---|---|
| Custom trust anchors | `ITrustAnchorProvider` |
| Custom hash algorithm | `HashAlgorithmName` parameter |
| External signer (HSM/KMS) | `Func<byte[], Task<byte[]>>` callback |
| Custom HTTP | `IHttpClientProvider` / `HttpClient` injection |
| Custom logging | `ILogger<T>` injection |
| Country extensions | `ICountryExtension` |
| Chain validation | `IChainValidationProvider` |
| Signature manifest | `ISignatureManifestProvider` |
| Certificate caching | `ICertificateCache` |
| Certificate store | `ICertificateStore` |

---

## Documentation

| Document | Description |
|---|---|
| [API Reference](https://eupassarin.github.io/simplesign/) | Full API documentation (Docfx) |
| [Getting Started](docs/articles/getting-started.md) | Installation, first signature, validation |
| [Deferred Signing](docs/articles/deferred-signing.md) | Two-phase signing for web apps |
| [Inspection & Validation](docs/articles/inspection-validation.md) | Metadata extraction and cryptographic verification |
| [ICP-Brasil](docs/articles/icp-brasil.md) | Brazilian PKI integration |
| [Interoperability](docs/interoperability.md) | PDF generators tested, cross-validation matrix, ETSI corpus |
| [Conformance](docs/conformance.md) | ISO 32000, PAdES ETSI EN 319 142, RFC 5652 compliance |
| [Performance](docs/performance.md) | Benchmarks: signing, validation, concurrency, vs competitors |
| [Architecture](docs/architecture.md) | Package structure, design principles, quality metrics |
| [HostSigner](src/SimpleSign.HostSigner/README.md) | Local signing tray app — API docs & install |
| [Web Signing Sample](samples/WebSigningSample/README.md) | Browser-based PDF signing demo |
| [Web Inspect Sample](samples/WebInspectSample/README.md) | Browser-based PDF inspector & validator |
| [Contributing](CONTRIBUTING.md) | How to contribute, coding standards, PR process |
| [Security](SECURITY.md) | Vulnerability reporting |
| [Changelog](CHANGELOG.md) | Release history |

---

## Requirements

- **.NET 8** or **.NET 10** (multi-target: `net8.0` + `net10.0`)
- No native or COM dependencies
- **No third-party cryptography** — all crypto via `System.Security.Cryptography` (BCL)
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
