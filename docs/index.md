# SimpleSign

**SimpleSign** is a .NET library for creating, inspecting, and validating **PAdES** (PDF Advanced Electronic Signatures) compliant digital signatures.

## Features

- **PAdES B-B, B-T, B-LT, B-LTA** conformance levels
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
var signer = new SignerBuilder(pdfBytes, certificate)
    .WithSignerName("John Doe")
    .WithReason("Approval")
    .Build();

byte[] signedPdf = await signer.SignAsync();
```

## Packages

| Package | Description |
|---------|-------------|
| [`SimpleSign.Core`](xref:SimpleSign.Core) | Core cryptographic primitives (CMS, X.509, TSA) |
| [`SimpleSign.Pdf`](xref:SimpleSign.Pdf) | Low-level PDF manipulation and signature structures |
| [`SimpleSign.PAdES`](xref:SimpleSign.PAdES) | PAdES signing, validation, inspection |
| [`SimpleSign.Brasil`](xref:SimpleSign.Brasil) | ICP-Brasil trust anchors and certificate utilities |
| [`SimpleSign.HtmlToPdf`](xref:SimpleSign.HtmlToPdf) | HTML-to-PDF conversion |

## Learn More

- [Getting Started](articles/getting-started.md)
- [Deferred Signing](articles/deferred-signing.md)
- [Inspection & Validation](articles/inspection-validation.md)
- [ICP-Brasil](articles/icp-brasil.md)
- [GitHub Repository](https://github.com/eupassarin/SimpleSign)
