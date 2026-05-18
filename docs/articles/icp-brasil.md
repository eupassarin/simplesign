# ICP-Brasil

SimpleSign provides built-in support for the **Brazilian Public Key Infrastructure** (ICP-Brasil), including trust anchors, certificate detection, and CPF/CNPJ extraction.

## Installation

```bash
dotnet add package SimpleSign.Brasil
```

## Trust Anchors

The `SimpleSign.Brasil` package bundles all AC Raiz (root CA) certificates from ICP-Brasil (v4 through v13), enabling offline chain validation:

```csharp
using SimpleSign.Brasil;
using SimpleSign.Brasil.Signing;

// Register ICP-Brasil trust anchors for validation
var brasil = new BrasilExtension();
var validator = new PdfSignatureValidator(
    new ValidationOptions { CheckRevocation = true },
    trustAnchorProviders: brasil.TrustAnchorProviders
);

var results = await validator.ValidateAsync(File.OpenRead("signed.pdf"));
```

## Certificate Detection

Detect whether a certificate belongs to the ICP-Brasil chain:

```csharp
using SimpleSign.Brasil.IcpBrasil;

bool isIcpBrasil = IcpBrasilChainValidator.IsIcpBrasilCertificate(cert);
```

### Extract CPF / CNPJ

ICP-Brasil certificates embed the holder's CPF or CNPJ in custom OIDs:

```csharp
var (cpf, cnpj) = IcpBrasilChainValidator.ExtractCpfCnpj(cert);

if (cpf is not null)
    Console.WriteLine($"CPF: {cpf}");
if (cnpj is not null)
    Console.WriteLine($"CNPJ: {cnpj}");
```

### Detect Certificate Level

ICP-Brasil certificates have levels (A1–A4 for authentication, S1–S4 for confidentiality):

```csharp
var level = IcpBrasilChainValidator.DetectCertificateLevel(cert);
// IcpBrasilCertificateLevel.A1, A3, S1, etc.
```

### Detect Signature Policy

```csharp
var policy = IcpBrasilChainValidator.DetectPolicy(cert);
// IcpBrasilPolicy.AdRb, AdRt, AdRv, AdRc, AdRa
```

## Full Chain Validation

Validate the entire certificate chain against ICP-Brasil root CAs:

```csharp
var validator = new IcpBrasilChainValidator();
var result = await validator.ValidateAsync(cert);

Console.WriteLine($"Chain Valid: {result.IsChainValid}");
Console.WriteLine($"ICP-Brasil: {result.IsIcpBrasilCertificate}");
Console.WriteLine($"Policy: {result.DetectedPolicy}");
Console.WriteLine($"Level: {result.CertificateLevel}");

foreach (var error in result.Errors)
    Console.WriteLine($"Error: {error}");
```

## AEA — Advanced Electronic Signature (Lei 14.063/2020)

SimpleSign supports signature manifests for Lei 14.063 compliance, which defines three levels of electronic signatures in Brazilian government interactions:

- **Simple (EES)** — basic electronic signature
- **Advanced (AES)** — uses ICP-Brasil or Gov.br credentials
- **Qualified (QES)** — uses ICP-Brasil digital certificate

## Gov.br Integration

Validate certificate assurance levels for Gov.br authentication:

```csharp
var govValidator = new GovBrChainValidator();
var result = await govValidator.ValidateAsync(certificate);
// result.AssuranceLevel: Bronze, Silver, Gold

// Or use the static method for quick detection (no chain validation):
var level = GovBrChainValidator.DetectAssuranceLevel(certificate);
```

## CLI Support

The CLI tool automatically detects ICP-Brasil certificates during validation:

```bash
simplesign validate signed.pdf
```

The output will show ICP-Brasil specific information when a signer certificate is from the Brazilian PKI.
