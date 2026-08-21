# SimpleSign Samples

Working examples demonstrating common digital signature scenarios.

## Scenario Index

| I want to... | Sample | Package |
|---|---|---|
| Sign a PDF with a certificate | [WebSigningSample](WebSigningSample/) | `SimpleSign.PAdES` |
| Inspect signature metadata | [WebInspectSample](WebInspectSample/) | `SimpleSign.PAdES` |
| Convert HTML to PDF | [WebHtmlToPDF](WebHtmlToPDF/) | `SimpleSign.HtmlToPdf` |

## Quick Start Code

### Sign a PDF

```csharp
using SimpleSign.Core.Signing;
using SimpleSign.PAdES;

var pdf = File.ReadAllBytes("contract.pdf");
var cert = new X509Certificate2("cert.pfx", "password");

byte[] signed = await PadesSigner
    .Document(pdf)
    .WithCertificate(cert)
    .WithLevel(AdesBaselineProfile.LongTerm(
        new TimestampOptions(new Uri("http://timestamp.digicert.com")),
        new LongTermValidationOptions()))
    .SignAsync();

File.WriteAllBytes("signed.pdf", signed);
```

### Validate Signatures

```csharp
using SimpleSign.PAdES.Validation;

var validator = new PdfSignatureValidator(new ValidationOptions
{
    CheckRevocation = true,
    TrustSystemRoots = true,
});

var results = await validator.ValidateAsync(File.OpenRead("signed.pdf"));
foreach (var r in results)
{
    Console.WriteLine($"{r.FieldName}: Valid={r.IsValid}, Signer={r.SignerName}");
}
```

### Inspect (fast, no crypto)

```csharp
using SimpleSign.PAdES.Inspection;

var info = await PdfSignatureInspector.InspectAsync(File.OpenRead("doc.pdf"));
foreach (var sig in info.Signatures)
{
    Console.WriteLine($"{sig.FieldName}: {sig.SignerName} at {sig.SigningTime}");
}
```

### Deferred Signing (web/mobile/HSM)

```csharp
using SimpleSign.PAdES;

// Server: prepare hash
var prepared = await DeferredSigner.PrepareAsync(pdfBytes, cert);
byte[] hash = prepared.HashToSign;  // → send to client

// Client: sign hash with private key
byte[] signature = clientDevice.Sign(hash);

// Server: complete
byte[] signedPdf = await DeferredSigner.CompleteAsync(prepared.SessionData, signature);
```

### HTML to PDF

```csharp
using SimpleSign.HtmlToPdf;

byte[] pdf = HtmlToPdfConverter.Html("<h1>Hello</h1><p>World</p>")
    .WithPageSize(PageSize.A4)
    .Convert();
```

## Running Samples

```bash
# Web signing sample
cd samples/WebSigningSample
dotnet run

# Web inspection sample
cd samples/WebInspectSample
dotnet run

# HTML to PDF sample
cd samples/WebHtmlToPDF
dotnet run
# Open http://localhost:5210
```
