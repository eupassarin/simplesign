# Getting Started

## Installation

SimpleSign packages are split by concern — install only what you need:

```bash
# Full PAdES stack (most common)
dotnet add package SimpleSign

# Or individual packages
dotnet add package SimpleSign.PAdES    # PAdES signing, validation, inspection
dotnet add package SimpleSign.Brasil   # ICP-Brasil trust anchors
dotnet add package SimpleSign.HtmlToPdf # HTML-to-PDF conversion
```

### Package Dependency Graph

```
SimpleSign (meta-package)
├── SimpleSign.PAdES        PDF signing & validation (PAdES B-B/T/LT/LTA)
│   ├── SimpleSign.Pdf      PDF structure parser (xref, objects, fields)
│   └── SimpleSign.Core     Crypto primitives, CMS, TSA, revocation
│
SimpleSign.Brasil           ICP-Brasil + Gov.br + Lei 14.063  → depends on PAdES
SimpleSign.HtmlToPdf        Pure-.NET HTML→PDF (independent)
```

## Sign a PDF

The simplest way to sign a PDF:

```csharp
using SimpleSign.PAdES;

// From a byte array
var signedPdf = await SimpleSigner
    .Document(pdfBytes)
    .WithCertificate(certificate)
    .SignAsync();

File.WriteAllBytes("contract-signed.pdf", signedPdf);

// Or from a file path (async I/O)
var builder = await SimpleSigner.DocumentAsync("contract.pdf");
var signedPdf2 = await builder
    .WithCertificate(certificate)
    .SignAsync();
```

This creates a **PAdES B-B** (basic) signature.

## Add a Timestamp (PAdES B-T)

Include an RFC 3161 timestamp from a trusted TSA:

```csharp
var signedPdf = await SimpleSigner
    .Document(pdfBytes)
    .WithCertificate(cert)
    .WithTimestamp("http://timestamp.digicert.com")
    .SignAsync();
```

## Long-Term Validation (PAdES B-LT / B-LTA)

Embed CRL/OCSP responses so the signature can be validated even after the certificate expires:

```csharp
var signedPdf = await SimpleSigner
    .Document(pdfBytes)
    .WithCertificate(cert)
    .WithTimestamp("http://timestamp.digicert.com")
    .WithLtv()                    // Embed revocation data (B-LT)
    .WithArchivalTimestamp()      // Add archive timestamp (B-LTA)
    .SignAsync();
```

## Signature Appearance

Add a visible signature with optional QR code:

```csharp
var appearance = new SignatureAppearance
{
    Page = 1,
    X = 50, Y = 50,
    ShowDate = true,
    ShowReason = true,
    BackgroundImagePng = logoBytes,
    VerificationUrl = "https://verify.example.com/abc123"
};

await SimpleSigner
    .Document(pdfBytes)
    .WithCertificate(cert)
    .WithAppearance(appearance)
    .SignAsync(output);
```

## Validate Signatures

```csharp
using SimpleSign.Core.Validation;
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
}
```

## Dependency Injection

Register SimpleSign in your DI container:

```csharp
using SimpleSign.PAdES;

services.AddSimpleSign(options =>
{
    options.DefaultTsaUrl = "http://timestamp.digicert.com";
});

// For ICP-Brasil support
services.AddSimpleSignBrasil();
```

## Next Steps

- [Deferred Signing](deferred-signing.md) — for web apps where the key is on a client device
- [Inspection & Validation](inspection-validation.md) — detailed metadata extraction
- [ICP-Brasil](icp-brasil.md) — Brazilian PKI integration
