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

### New AC Raiz versions

A root is self-signed, so nothing but its published fingerprint can vouch for it. When the ITI
publishes a new AC Raiz, download it pinned to the SHA-256 fingerprint from the official
publication and pass it to the extension (or to `IcpBrasilChainValidator.AdditionalTrustAnchors`):

```csharp
var v14 = await IcpBrasilRoots.DownloadAsync(httpClient, 14, "<SHA-256 fingerprint from the ITI>");
var validator = new PdfSignatureValidator(options, httpClient,
    countryExtensions: [new BrasilExtension(httpClient, logger, [v14])]);
```

`IcpBrasilRoots.ExpiringWithin(TimeSpan)` lists bundled roots close to expiry (v5 ends on
2029-03-02); a unit test fails a year before any bundled root expires.

### Timestamps for AD-RT (ACT)

AD-RT and above need a signature timestamp. For ICP-Brasil conformance use an **ACT** (Autoridade
de Carimbo do Tempo) accredited by the ITI; the list of accredited ACTs is published at
[gov.br/iti — Estrutura da ICP-Brasil](https://www.gov.br/iti/pt-br/assuntos/icp-brasil/estrutura).
ACT services usually require a contract and credentials. Public TSAs such as
`TimestampOptions.DigiCert` produce valid RFC 3161 tokens, but they are not ICP-Brasil ACTs.

## CPF and CNPJ

`Cpf` and `Cnpj` validate and format numbers, formatted or not; CNPJs may be alphanumeric:

```csharp
Cpf.IsValid("123.456.789-09");     // true
Cpf.Format("12345678909");         // 123.456.789-09
Cpf.Mask("12345678909");           // ***.456.789-**
Cnpj.IsValid("12.ABC.345/01DE-35"); // true
Cnpj.Format("12abc34501de35");     // 12.ABC.345/01DE-35
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

### Sign under an ICP-Brasil policy (AD-RB / AD-RT)

ICP-Brasil signatures name a signature policy (PA) **and carry its hash** (`sigPolicyHash`).
SimpleSign embeds the ITI's policy lists (LPA_PAdES and LPA_CAdES: 55 policies with their hashes
and signing periods) and picks the version in force:

```csharp
// PAdES AD-RB (current version, e.g. v1.3) — ETSI.CAdES.detached, policy with its hash
await PadesSigner.Document(pdf).WithCertificate(cert)
    .WithIcpBrasilPolicy(IcpBrasilPolicy.AdRb)
    .SignAsync(output);

// PAdES AD-RT — needs a signature timestamp; use an ICP-Brasil accredited ACT
await PadesSigner.Document(pdf).WithCertificate(cert)
    .WithIcpBrasilPolicy(IcpBrasilPolicy.AdRt, new TimestampOptions(new Uri(actUrl)))
    .SignAsync(output);

// CAdES (.p7s): pass the policy reference
var policy = IcpBrasilSignaturePolicies.Current(IcpBrasilPolicy.AdRb, IcpBrasilPolicyFormat.Cades);
await CadesSigner.Document(data).WithCertificate(cert)
    .WithSignaturePolicy(policy.ToReference())
    .SignAsync();
```

The VALIDAR portal expects PAdES AD-RB or AD-RT. XAdES policies are not embedded. For a policy
published after this release, read its PA with `IcpBrasilSignaturePolicies.FromPolicyDocument`
(after checking the file against the digest in the current LPA).

### Check a signature against its policy

`IcpBrasilPolicyValidator.Validate` checks what DOC-ICP-15.03 requires of a signature that
declares a policy: the `sigPolicyHash` matches the PA, the policy could be used at the signing
time (signing period, not revoked), and AD-RT and above have a signature timestamp. The
ICP-Brasil provider runs it during PDF validation and reports `BR.SignaturePolicy` and
`BR.SignaturePolicyStatus` (`Valid`, `Invalid`, `Unknown`, `NotIcpBrasil`) in
`ChainValidationMetadata`; failures are listed in the warnings.

```csharp
var check = IcpBrasilPolicyValidator.Validate(cms, signingTime, IcpBrasilPolicyFormat.Pades);
Console.WriteLine($"{check.Status}: {string.Join("; ", check.Errors)}");
```

### DocMDP (certification)

`AsCertification(...)` writes DocMDP the way the VALIDAR guide asks: a `/Reference` with
`/TransformMethod /DocMDP` and `/TransformParams << /P n /V /1.2 >>`, and **no** `/Perms` entry in
the catalog (the guide advises against it for Adobe compatibility).

### Prescriptions and other health documents

VALIDAR identifies health documents by OIDs in the PDF metadata: the document type
(`2.16.76.1.12.1.1` prescrição, `.2` atestado, `.3` solicitação de exame, `.11` relatório) and the
professional's council registration (`2.16.76.1.4.2.{council}.1` number, `.2` UF):

```csharp
await PadesSigner.Document(pdf).WithCertificate(cert)
    .WithIcpBrasilPolicy(IcpBrasilPolicy.AdRb)
    .WithHealthDocument(HealthDocumentType.Prescricao,
        new ProfessionalRegistration(ProfessionalCouncil.Cfm, "123456", "SP", null))
    .SignAsync(output);
```

The entries go into the PDF document information dictionary (keyed by OID) in the signing
revision, so the signature covers them. The guide says "metadados" without naming the location;
check your documents on validar.iti.gov.br. `PadesSignerBuilder.WithDocumentInfo(key, value)` sets
any other Info entry.

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

Validate the entire certificate chain against ICP-Brasil root CAs. Revocation is checked for the
certificate and every AC with their LCRs (CRLs), then OCSP:

```csharp
var validator = new IcpBrasilChainValidator();
var result = await validator.ValidateAsync(cert);

Console.WriteLine($"Chain Valid: {result.IsChainValid}");
Console.WriteLine($"ICP-Brasil: {result.IsIcpBrasilCertificate}");
Console.WriteLine($"Type: {result.CertificateLevel}");
Console.WriteLine($"CPF: {result.CpfFormatted} CNPJ: {result.CnpjFormatted}");
Console.WriteLine($"Revocation: {result.RevocationStatus}"); // Good, Revoked, Unknown, NotChecked

foreach (var error in result.Errors)
    Console.WriteLine($"Error: {error}");
```

### Long-term signatures (B-LT / B-LTA)

When `PdfSignatureValidator` (or `BrasilExtension.CreateValidator()`) validates a PDF, the ICP-Brasil
and Gov.br providers receive a `ChainValidationContext`: the chain is validated at the time of a
trusted **signature timestamp**, and revocation is checked against the LCRs and OCSP responses
**embedded in the document** (DSS) before going online. A B-LTA signature therefore stays valid after
the signer's certificate expires, and a certificate revoked after the timestamp does not invalidate
it. You can do the same by hand:

```csharp
var result = await validator.ValidateAsync(new ChainValidationContext
{
    Certificate = signer,
    Certificates = embeddedCerts,
    ValidationTime = timestampGenTime,      // null = now
    EmbeddedCrls = dssCrls,
    EmbeddedOcsps = dssOcsps,
    CheckRevocation = true,                 // false = embedded evidence only
});
```

When no LCR or OCSP response covers a certificate, `RevocationStatus` is `Unknown` and a warning
names the certificate; the PAdES result then carries it as a warning.

### Holder data

`IcpBrasilCertificateData.FromCertificate(cert)` (also `result.CertificateData`) reads every
SubjectAltName field of DOC-ICP-04: birth date, CPF, NIS, RG and issuer (`2.16.76.1.3.1`), voter
registration (`3.5`), CEI (`3.6`/`3.7`), and for e-CNPJ the responsible person's name and data
(`3.2`, `3.4`, including the CPF), the CNPJ (`3.3`) and the company name (`3.8`).

```csharp
var data = IcpBrasilCertificateData.FromCertificate(cert);
Console.WriteLine($"{data.HolderType}: signer CPF {data.SignerCpf}, company {data.CompanyName}");
```

## AEA — Advanced Electronic Signature (Lei 14.063/2020)

Lei 14.063/2020, art. 4, defines three levels of electronic signature. `Lei14063.Classify` returns
the level of a validated signature:

- **Simples** — any other valid signature
- **Avançada** — Gov.br, or a signature with a SimpleSign advanced-signature manifest
- **Qualificada** — a trusted ICP-Brasil signature certificate (A1–A4)

```csharp
var validator = BrasilExtension.CreateValidator();
foreach (var r in await validator.ValidateAsync(File.OpenRead("signed.pdf")))
{
    Console.WriteLine($"{r.FieldName}: {Lei14063.Classify(r)}");   // null when not valid
}
```

The providers also put the level in `ChainValidationMetadata["BR.Lei14063"]`, with
`BR.Hierarchy`, `BR.RevocationStatus`, `BR.ValidationTime` and, for e-CNPJ, `BR.ResponsibleCpf`.

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

`validate` runs the ICP-Brasil and Gov.br providers and shows, per signature, the Lei 14.063 level,
the hierarchy and certificate type, CPF/CNPJ, professional registrations, the signature policy
and its status, and the revocation status at the validation time (`--json` adds `lei14063` and a
`brasil` object):

```bash
simplesign validate signed.pdf
simplesign validate signed.pdf --json
```

`sign` can sign under an ICP-Brasil policy and mark health documents for VALIDAR:

```bash
# AD-RB
simplesign sign doc.pdf --cert cert.pfx --icp-policy ad-rb

# AD-RT with an ICP-Brasil ACT
simplesign sign doc.pdf --cert cert.pfx --icp-policy ad-rt --tsa https://act.example/tsa

# Prescription: document type and CRM in the PDF metadata
simplesign sign receita.pdf --cert cert.pfx --icp-policy ad-rb \
  --health-document prescricao --registration crm:123456/SP
```

`--registration` takes `COUNCIL:NUMBER/UF` (crm, crf, cro, oab, coren… or the federal council
acronym) and may be repeated.
