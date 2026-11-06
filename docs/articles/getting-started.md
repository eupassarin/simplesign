# Getting Started

## Installation

SimpleSign packages are split by concern — install only what you need:

```bash
# Full PAdES + CAdES stack (most common)
dotnet add package SimpleSign

# Or individual packages
dotnet add package SimpleSign.PAdES    # PAdES signing, validation, inspection
dotnet add package SimpleSign.CAdES    # standalone CMS/PKCS#7 signing & validation
dotnet add package SimpleSign.XAdES    # XML-DSig signing & validation (XAdES)
dotnet add package SimpleSign.Brasil   # ICP-Brasil trust anchors
dotnet add package SimpleSign.HtmlToPdf # HTML-to-PDF conversion
```

### Package Dependency Graph

```
SimpleSign (meta-package)
├── SimpleSign.PAdES        PDF signing & validation (PAdES B-B/T/LT/LTA), PDF parser
│   └── SimpleSign.Core     Crypto primitives, CMS, TSA, revocation
├── SimpleSign.CAdES        standalone CMS/PKCS#7 signing & validation
│   └── SimpleSign.Core     (shared)
├── SimpleSign.XAdES        XML-DSig signing & validation (XAdES)
│   └── SimpleSign.Core     (shared)

SimpleSign.Brasil           ICP-Brasil + Gov.br + Lei 14.063  → depends on PAdES
SimpleSign.HtmlToPdf        Pure-.NET HTML→PDF (independent)
```

## Sign a PDF

The simplest way to sign a PDF:

```csharp
using SimpleSign.PAdES;

// From a byte array
var signedPdf = await PadesSigner
    .Document(pdfBytes)
    .WithCertificate(certificate)
    .SignAsync();

File.WriteAllBytes("contract-signed.pdf", signedPdf);

// Or from a file path (async I/O)
var builder = await PadesSigner.DocumentAsync("contract.pdf");
var signedPdf2 = await builder
    .WithCertificate(certificate)
    .SignAsync();
```

This creates a **PAdES B-B** (basic) signature.

### In one line, from a .pfx file

```csharp
await PadesSigner.SignFileAsync("contract.pdf", "contract-signed.pdf", "me.pfx", password);
```

The first certificate with a private key in the file signs; the other certificates are embedded
as its chain. To combine a .pfx file with other options, use `WithCertificateFile`:

```csharp
var builder = await PadesSigner.DocumentAsync("contract.pdf");
var signedPdf3 = await builder
    .WithCertificateFile("me.pfx", password)
    .WithLevel(AdesBaselineProfile.Timestamped(TimestampOptions.DigiCert))
    .SignAsync();
```

`TimestampOptions.DigiCert`, `TimestampOptions.Sectigo` and `TimestampOptions.FreeTsa` are ready-made
public timestamp services. They are rate-limited and have no SLA; FreeTSA is not trusted by Adobe,
so use it only for testing.

## Add a Timestamp (PAdES B-T)

Include an RFC 3161 timestamp from a trusted TSA:

```csharp
using SimpleSign.Core.Signing;
using SimpleSign.PAdES;

var signedPdf = await PadesSigner
    .Document(pdfBytes)
    .WithCertificate(cert)
    .WithLevel(AdesBaselineProfile.Timestamped(
        new TimestampOptions(new Uri("http://timestamp.digicert.com"))))
    .SignAsync();
```

## Long-Term Validation (PAdES B-LT / B-LTA)

Embed CRL/OCSP responses so the signature can be validated even after the certificate expires:

```csharp
using SimpleSign.Core.Signing;
using SimpleSign.PAdES;

var tsa = new TimestampOptions(new Uri("http://timestamp.digicert.com"));

// B-LT — embed revocation data
var signedBlt = await PadesSigner
    .Document(pdfBytes)
    .WithCertificate(cert)
    .WithLevel(AdesBaselineProfile.LongTerm(tsa, new LongTermValidationOptions()))
    .SignAsync();

// B-LTA — add an archive timestamp (reuses the signature TSA by default)
var signedBlta = await PadesSigner
    .Document(pdfBytes)
    .WithCertificate(cert)
    .WithLevel(AdesBaselineProfile.Archive(tsa, new LongTermValidationOptions()))
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

await PadesSigner
    .Document(pdfBytes)
    .WithCertificate(cert)
    .WithAppearance(appearance)
    .SignAsync(output);
```

The stamp texts are customizable. For a stamp in Portuguese with the date in Brasília time:

```csharp
var appearance = new SignatureAppearance { ShowReason = true, ShowLocation = true }
    .WithLabels(signedBy: "Assinado digitalmente por", reason: "Motivo: ", location: "Local: ")
    .WithDateFormat(null, TimeZoneInfo.FindSystemTimeZoneById("America/Sao_Paulo"));
// "Assinado digitalmente por / Maria Silva / 15/06/2025 11:30 UTC-03:00 / Motivo: ..."
```

| Property | Default | Purpose |
|---|---|---|
| `SignedByLabel` | `"Signed by"` | First line; `""` hides it |
| `SignerDisplayName` | signer name | Name shown in the stamp (the `/Name` entry is unchanged) |
| `ReasonLabel` / `LocationLabel` / `DateLabel` | `"Reason: "` / `"Location: "` / `""` | Line prefixes |
| `DateFormat` / `TimeZone` / `DateCulture` | `dd/MM/yyyy HH:mm` + offset, UTC, invariant | Date display |
| `Width` / `Height` | computed | Fixed stamp size |
| `ShrinkToFit` | `true` | With a fixed size, scale text down so every line fits |
| `TextAlignment` / `VerticalAlignment` | `Left` / `Top` | Text position inside the stamp |
| `MaxTextLength` | `40` | Characters per line before `...`; `0` disables |
| `BackgroundColor` | none | Stamp fill color |
| `BackgroundImageFit` | `Stretch` | `Stretch`, `Contain` (keep ratio) or `Cover` (fill and crop) |

PNG backgrounds may have transparency (RGBA, gray+alpha, or palette with `tRNS`), which is kept
through a soft mask. PDF/A-1 forbids transparency, so use an opaque PNG or a JPEG there.

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
    Console.WriteLine($"{r.FieldName}: {r.Indication}");
    Console.WriteLine($"  Integrity={r.IsIntegrityValid}");
    Console.WriteLine($"  Chain={r.IsCertificateChainValid}");
}
```

## Dependency Injection

Register SimpleSign in your DI container:

```csharp
using SimpleSign.PAdES.DependencyInjection;

services.AddSimpleSign(options =>
{
    options.TsaUrl = "http://timestamp.digicert.com";
});

// For ICP-Brasil support
services.AddSimpleSignBrasil();
```

## Next Steps

- [Deferred Signing](deferred-signing.md) — for web apps where the key is on a client device
- [Inspection & Validation](inspection-validation.md) — detailed metadata extraction
- [ICP-Brasil](icp-brasil.md) — Brazilian PKI integration
