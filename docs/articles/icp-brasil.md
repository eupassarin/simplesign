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

// Trusts the bundled ICP-Brasil and Gov.br roots and applies their chain rules
var validator = BrasilExtension.CreateValidator(
    new ValidationOptions { CheckRevocation = true });

var results = await validator.ValidateAsync(File.OpenRead("signed.pdf"));
```

## Certificate Detection

Detect whether a certificate belongs to the ICP-Brasil chain:

```csharp
using SimpleSign.Brasil.IcpBrasil;

bool isIcpBrasil = IcpBrasilChainValidator.IsIcpBrasilCertificate(cert);
```

### Extract CPF / CNPJ

ICP-Brasil certificates embed the holder's CPF (SAN otherName `2.16.76.1.3.1`) or the company's
CNPJ (`2.16.76.1.3.3`). Both are checked with their check digits, and CNPJs may be alphanumeric
(IN RFB 2.229/2024, in force since July 2026):

```csharp
var (cpf, cnpj) = IcpBrasilChainValidator.ExtractCpfCnpj(cert);

if (cpf is not null)
    Console.WriteLine($"CPF: {cpf}");
if (cnpj is not null)
    Console.WriteLine($"CNPJ: {cnpj}");   // e.g. 11444777000161 or 12ABC34501DE35
```

### Professional registrations (CRM, CRF, OAB…)

Certificates issued to professionals carry their council registration under
`2.16.76.1.4.2.{council}` (ADE-ICP-04.01): `.1` registration number, `.2` UF, `.3` specialty.
All 16 councils of the arc are recognized (OAB, CFM, CFF, CFO, COFEN…):

```csharp
foreach (var r in IcpBrasilChainValidator.ExtractProfessionalRegistrations(cert))
{
    Console.WriteLine($"{r.Council} {r.RegistrationNumber}/{r.StateCode} {r.Specialty}");
    // Cfm 123456/SP Cardiologia
}
```

### Detect Certificate Type

The certificate policy `2.16.76.1.2.{type}.{n}` gives the type: A1–A4 (signature), S1–S4
(confidentiality), T3/T4 (timestamp authorities), A CF-e-SAT and OM-BR:

```csharp
var level = IcpBrasilChainValidator.DetectCertificateLevel(cert);
// IcpBrasilCertificateLevel.A1, A3, S1, T3, etc.
```

### Identify the Signature Policy

Signature policies (AD-RB, AD-RT, AD-RV, AD-RC, AD-RA) belong to the **signature**: they travel
in its `signature-policy-identifier` attribute, not in the certificate. Pass the policy OID found
in the signature to `IcpBrasilPolicyInfo.TryParse`:

```csharp
if (IcpBrasilPolicyInfo.TryParse(signaturePolicyOid, out var policy))
{
    Console.WriteLine($"{policy.Policy} for {policy.Format}, version {policy.Version}");
    // AdRt for Pades, version 1.1
}
```

### QR codes for VALIDAR

The [ITI VALIDAR](https://validar.iti.gov.br) portal reads QR codes that point to **your** URL.
When a user scans one, VALIDAR calls that URL with `_format=application/validador-iti+json` and
the secret code the user typed, and expects the signed files in JSON. `ValidarItiQrEndpoint`
implements both sides:

```csharp
Uri qr = ValidarItiQrEndpoint.BuildQrCodeUrl(new Uri($"https://clinic.example/rx/{id}"));   // print this

app.MapGet("/rx/{id}", (string id, string? _format, string? _secretCode) =>
{
    if (!ValidarItiQrEndpoint.IsValidarRequest(_format))
        return Results.Redirect($"/rx/{id}/view");   // a person opened the link
    var doc = repository.Find(id);
    var response = doc is null
        ? ValidarItiQrEndpoint.NotFound()
        : ValidarItiQrEndpoint.Respond(_secretCode, doc.SecretCode, [doc.SignedPdfUrl]);
    return Results.Content(response.Json ?? "", ValidarItiResponse.ContentType, statusCode: response.StatusCode);
});
```

## Full Chain Validation

Validate the entire certificate chain against ICP-Brasil root CAs:

```csharp
var validator = new IcpBrasilChainValidator();
var result = await validator.ValidateAsync(cert);

Console.WriteLine($"Chain Valid: {result.IsChainValid}");
Console.WriteLine($"ICP-Brasil: {result.IsIcpBrasilCertificate}");
Console.WriteLine($"Type: {result.CertificateLevel}");
Console.WriteLine($"CPF: {result.CpfFormatted} CNPJ: {result.CnpjFormatted}");

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
