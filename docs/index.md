# SimpleSign

**SimpleSign** is a .NET library for creating, inspecting, and validating **PAdES**, **CAdES**, and **XAdES** digital signatures.

## Features

- **PAdES B-B, B-T, B-LT, B-LTA** conformance levels
- **CAdES B-B, B-T, B-LT, B-LTA** detached CMS signatures
- **XAdES B-B, B-T, B-LT, B-LTA** XML signatures (enveloped, detached, enveloping)
- **Deferred signing** — hash on server, sign on client (private key never leaves the device)
- **PDF inspection** — extract signature metadata, certificates, timestamps
- **Signature validation** — integrity, chain, revocation, timestamp verification
- **ICP-Brasil** trust anchors and CPF/CNPJ extraction
- **HTML to PDF** conversion
- **Native AOT** compatible

## Quick Start

```bash
dotnet add package SimpleSign.PAdES
```

```csharp
using SimpleSign.PAdES;

// Sign a PDF
byte[] signedPdf = await PadesSigner
    .Document(pdfBytes)
    .WithCertificate(certificate)
    .WithMetadata(signerName: "John Doe", reason: "Approval")
    .SignAsync();
```

## Packages

| Package | Description |
|---------|-------------|
| [`SimpleSign.Core`](xref:SimpleSign.Core) | Core cryptographic primitives (CMS, X.509, TSA) |
| [`SimpleSign.Pdf`](xref:SimpleSign.Pdf) | Low-level PDF manipulation and signature structures |
| [`SimpleSign.PAdES`](xref:SimpleSign.PAdES) | PAdES signing, validation, inspection |
| [`SimpleSign.CAdES`](xref:SimpleSign.CAdES) | CAdES detached CMS signing and validation |
| [`SimpleSign.XAdES`](xref:SimpleSign.XAdES) | XAdES XML signing and validation (enveloped, detached, enveloping) |
| [`SimpleSign.Brasil`](xref:SimpleSign.Brasil) | ICP-Brasil trust anchors and certificate utilities |
| [`SimpleSign.HtmlToPdf`](xref:SimpleSign.HtmlToPdf) | HTML-to-PDF conversion |
| [`SimpleSign.Cli`](https://www.nuget.org/packages/SimpleSign.Cli) | CLI tool for signing, validation, inspection |

## Learn More

- [Getting Started](articles/getting-started.md)
- [Deferred Signing](articles/deferred-signing.md)
- [Inspection & Validation](articles/inspection-validation.md)
- [ICP-Brasil](articles/icp-brasil.md)
- [Standards Conformance](conformance.md)
- [Interoperability](interoperability.md)
- [Benchmarks](benchmarks.md)
- [ADRs](adr/) — Architecture Decision Records
- [Migration Guides](migration/)
- [HostSigner](https://github.com/eupassarin/SimpleSign/tree/main/src/SimpleSign.HostSigner) — Windows tray app for local signing
- [CLI Tool](https://www.nuget.org/packages/SimpleSign.Cli) — command-line signing and validation
- [GitHub Repository](https://github.com/eupassarin/SimpleSign)
