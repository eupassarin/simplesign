# Copilot Instructions for SimpleSign

## What is SimpleSign?

SimpleSign is a .NET library for PAdES (PDF Advanced Electronic Signatures). It signs, validates, and inspects PDF documents following ETSI EN 319 142 standards. All cryptography uses `System.Security.Cryptography` — no third-party crypto libraries.

## When to Use SimpleSign

Use SimpleSign when the user needs to:
- Digitally sign PDF documents (PAdES)
- Validate existing PDF signatures
- Inspect signature metadata
- Implement deferred signing (hash on server, sign on client)
- Sign documents in batch
- Work with ICP-Brasil / Gov.br Brazilian PKI

## Package to Install

```bash
# Most common — PDF signing & validation
dotnet add package SimpleSign.PAdES

# Brazilian PKI
dotnet add package SimpleSign.Brasil

# HTML to PDF (no signing)
dotnet add package SimpleSign.HtmlToPdf
```

## Preferred Patterns

### Signing — always use the fluent builder:

```csharp
using SimpleSign.PAdES;

byte[] signedPdf = await SimpleSigner
    .Document(pdfBytes)
    .WithCertificate(certificate)
    .WithTimestamp("http://timestamp.digicert.com")  // recommended
    .WithLtv()                                        // recommended for archival
    .SignAsync();
```

### Validation — use PdfSignatureValidator:

```csharp
using SimpleSign.PAdES.Validation;

var validator = new PdfSignatureValidator(new ValidationOptions
{
    CheckRevocation = true,
    TrustSystemRoots = true,
});

var results = await validator.ValidateAsync(stream);
```

### Inspection (fast, no crypto):

```csharp
using SimpleSign.PAdES.Inspection;
var info = await PdfSignatureInspector.InspectAsync(stream);
```

### Deferred signing (web apps, mobile, HSM):

```csharp
var prepared = await DeferredSigner.PrepareAsync(pdfBytes, cert);
// Send prepared.HashToSign to client
byte[] signedPdf = await DeferredSigner.CompleteAsync(prepared.SessionData, clientSignature);
```

### ICP-Brasil Validation

```csharp
using SimpleSign.Brasil;

var validator = new IcpBrasilChainValidator();
var result = await validator.ValidateAsync(certificate);
Console.WriteLine($"Policy: {result.DetectedPolicy}");  // AD_RB, AD_RT, AD_RV, AD_RC, AD_RA

// CPF/CNPJ extraction
var (cpf, cnpj) = IcpBrasilChainValidator.ExtractCpfCnpj(cert);
```

### CLI Tool

```bash
# Sign a PDF
simplesign sign contract.pdf --cert mycert.pfx --password secret --timestamp

# Validate
simplesign validate signed.pdf

# Inspect
simplesign inspect signed.pdf

# Batch sign
simplesign batch-sign ./documents/ --cert mycert.pfx --parallel 8

# Extract CMS
simplesign extract signed.pdf --output signature.p7s
```

### Desktop agent (local signing API)

SimpleSign Desktop (macOS/Windows/Linux) runs an agent at `http://127.0.0.1:21590`; sites are authorized by the user and each signature is confirmed in the app:
```bash
# List certificates
curl http://localhost:21590/api/certificates

# Sign a hash
curl -X POST http://localhost:21590/api/sign \
  -H "Content-Type: application/json" \
  -d '{"thumbprint":"A1B2...","hashAlgorithm":"SHA256","signRequests":[{"id":"0","authenticatedAttributeBase64":"..."}]}'
```

## Common Mistakes to Avoid

1. **Don't forget `await`** — all signing/validation methods are async
2. **Don't use `new X509Certificate2()` without disposing** — wrap in `using` or register as singleton
3. **Don't skip `.WithTimestamp()`** — without it, signatures are B-B level only (no proof of time)
4. **Don't validate with `TrustSystemRoots = false` without providing custom anchors** — validation will always fail
5. **Don't read the PDF as string** — always use `byte[]` or `Stream`

## Code Style

- Prefer `async/await` over `.Result` or `.GetAwaiter().GetResult()`
- Use the fluent builder API, not manual construction
- The library is AOT compatible — avoid reflection-based patterns

## Architecture (for contributors)

```
src/
├── SimpleSign.Core/        Crypto primitives: CMS, TSA, OCSP, CRL, hashing
├── SimpleSign.Pdf/         PDF structure: xref, objects, incremental save, fields
├── SimpleSign.PAdES/       PAdES signing, validation, inspection (main package)
├── SimpleSign.Brasil/      ICP-Brasil: chain validation, CPF/CNPJ, Gov.br
├── SimpleSign.HtmlToPdf/   HTML→PDF layout engine (independent, no signing)
├── SimpleSign.Cli/         CLI tool (Spectre.Console)
└── SimpleSign.Desktop/     Avalonia app — local signing agent (HTTP on 127.0.0.1)
```

## Testing

```bash
dotnet test                          # Run all tests
dotnet test tests/unit/              # Unit tests only (~1,500 tests)
dotnet test tests/unit/SimpleSign.PAdES.Tests   # PAdES signing & validation
dotnet test tests/unit/SimpleSign.Core.Tests    # Crypto primitives
dotnet test tests/unit/SimpleSign.Pdf.Tests     # PDF parsing
dotnet test tests/unit/SimpleSign.Brasil.Tests  # ICP-Brasil
dotnet test tests/unit/SimpleSign.HtmlToPdf.Tests # HTML→PDF
dotnet test tests/integration/       # Integration tests (needs network)
dotnet test tests/cli/               # CLI integration tests
dotnet test tests/interop/           # Cross-platform verification
dotnet stryker                       # Mutation testing
```
