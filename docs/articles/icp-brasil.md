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

### Intermediate ACs (offline chains)

The package also bundles the ~176 intermediate ICP-Brasil ACs published by the ITI
(`ACcompactado.zip`), so a chain builds without network access even when a signature carries only
the signer certificate. They only help build chains; trust still comes from the AC Raiz.
`IcpBrasilChainValidator.LoadBundledIntermediateCerts()` returns them, and the ICP-Brasil trust
anchor provider passes them to `PdfSignatureValidator`. Maintainers refresh them with
`scripts/update-icp-intermediates.sh`; a unit test checks that each one chains to a bundled root.

### LCR cache

ICP-Brasil LCRs reach several megabytes. On servers and CLIs, keep them on disk; each one is reused
until its `nextUpdate`:

```csharp
var brasil = new BrasilExtension(new BrasilExtensionOptions
{
    HttpClient = httpClient,
    CrlCacheDirectory = Path.Combine(Path.GetTempPath(), "simplesign-lcr"),
});
// or: new IcpBrasilChainValidator(httpClient) { CrlCacheDirectory = "..." }
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

ACTs usually authenticate the client. `TimestampOptions` supports the common ways:

```csharp
// HTTP Basic or a bearer token, sent with each request (never on the shared HttpClient)
var act = new TimestampOptions(new Uri("https://act.example.com.br/tsa"))
{
    Authorization = new AuthenticationHeaderValue("Basic", Convert.ToBase64String(Encoding.UTF8.GetBytes($"{user}:{password}"))),
};

// Mutual TLS with a client certificate (with private key)
var actMtls = new TimestampOptions(new Uri("https://act.example.com.br/tsa")) { ClientCertificate = clientCert };

// RFC 3161 over TCP (socket transport, port 318 by default)
var actTcp = new TimestampOptions(new Uri("tcp://act.example.com.br:318"));

await PadesSigner.Document(pdf).WithCertificate(cert)
    .WithIcpBrasilPolicy(IcpBrasilPolicy.AdRt, act)
    .SignAsync(output);
```

ACTs that require the time-stamp request itself to be CMS-signed with the client's certificate are
not supported yet.

### Standalone timestamps (.tst)

To prove that a file existed at a given time without signing it, request an RFC 3161 token for its
hash (the file never leaves the machine) and keep it next to the file:

```csharp
byte[] tst = await TimestampToken.CreateAsync(File.ReadAllBytes("contrato.pdf"), act);
File.WriteAllBytes("contrato.pdf.tst", tst);

var check = IcpBrasilTimestamp.Verify(tst, File.ReadAllBytes("contrato.pdf"));   // ACT must chain to an AC Raiz
Console.WriteLine($"{check.IsValid} at {check.Info?.GenerationTime}");
```

`TimestampToken.CreateForHashAsync` / `VerifyHash` work from a hash; `TimestampToken.Verify(token, data, trustAnchors)`
checks any TSA. CLI: `simplesign timestamp create contrato.pdf --tsa <url>` and
`simplesign timestamp verify contrato.pdf --token contrato.pdf.tst --icp`.

### Homologation (test) certificates

SERPRO and the ACs issue test certificates under an ICP-Brasil homologation hierarchy ("AC Raiz
Brasileira v12 - HOM", "AC Raiz Hom do SERPRO" …). SimpleSign bundles it (50 certificates, from the
keystore Demoiselle Signer ships; `scripts/update-icp-homologation.sh`) but trusts it only on request:

```csharp
var brasil = new BrasilExtension(new BrasilExtensionOptions { IcpEnvironment = IcpBrasilEnvironment.Homologation });
```

Chains that end in a test root are reported with `IcpBrasilValidationResult.IsHomologation`,
`BR.Environment = Homologation` and a warning, and never as qualified (Lei 14.063). One test root
uses the exact name of the production AC Raiz v12 with another key, so roots are compared by
their bytes. CLI: `simplesign validate signed.pdf --icp-homologation`.

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

### Sign under an ICP-Brasil policy

ICP-Brasil signatures name a signature policy (PA) **and carry its hash** (`sigPolicyHash`).
SimpleSign embeds the ITI's policy lists (LPA_PAdES and LPA_CAdES: 55 policies with their hashes
and signing periods) and picks the version in force:

```csharp
// PAdES AD-RB (current version, e.g. v1.3) — /Filter /PBAD_PAdES /SubFilter /PBAD.PAdES, policy with its hash
await PadesSigner.Document(pdf).WithCertificate(cert)
    .WithIcpBrasilPolicy(IcpBrasilPolicy.AdRb)
    .SignAsync(output);

// PAdES AD-RT — needs a signature timestamp; use an ICP-Brasil accredited ACT
await PadesSigner.Document(pdf).WithCertificate(cert)
    .WithIcpBrasilPolicy(IcpBrasilPolicy.AdRt, new TimestampOptions(new Uri(actUrl)))
    .SignAsync(output);

// PAdES AD-RC — signature timestamp, DSS with VRI, document timestamp
var act = new TimestampOptions(new Uri(actUrl));
await PadesSigner.Document(pdf).WithCertificate(cert)
    .WithIcpBrasilPolicy(IcpBrasilPolicy.AdRc, new IcpBrasilPadesOptions { Timestamp = act })
    .SignAsync(output);

// PAdES AD-RA — AD-RC plus the PA, LPA and LPA signature in the DSS
var builder = PadesSigner.Document(pdf).WithCertificate(cert);
var artifacts = await IcpBrasilPolicyArtifacts.DownloadAsync(httpClient, builder.ResolveIcpBrasilPolicy(IcpBrasilPolicy.AdRa));
await builder
    .WithIcpBrasilPolicy(IcpBrasilPolicy.AdRa, new IcpBrasilPadesOptions { Timestamp = act, Artifacts = artifacts })
    .SignAsync(output);

// CAdES (.p7s): AD-RB, AD-RT, AD-RV, AD-RC or AD-RA (a TSA is required above AD-RB)
await CadesSigner.Document(data).WithCertificate(cert)
    .WithIcpBrasilPolicy(IcpBrasilPolicy.AdRc, new TimestampOptions(new Uri(actUrl)))
    .SignAsync();

// XAdES (package SimpleSign.Brasil.Xades): AD-RB … AD-RA
await XadesSigner.Document(xml).WithCertificate(cert)
    .WithIcpBrasilPolicy(IcpBrasilPolicy.AdRc, new TimestampOptions(new Uri(actUrl)))
    .SignAsync();
```

`IcpBrasilPadesOptions` also takes a separate document-timestamp TSA (`ArchiveTimestamp`), the
revocation settings for the DSS (`LongTermValidation`) and a specific `Version` of the policy
(refused when it is not in force or does not accept the signer's root). The catalog also holds the 45 XAdES policies of
`LPA_XAdES.xml` (version 2), with their rules.

#### XAdES (SimpleSign.Brasil.Xades)

```bash
dotnet add package SimpleSign.Brasil.Xades
```

The XML PAs mandate the XAdES 1.3.2 `SigningCertificate` (not `SigningCertificateV2`) and, per
policy, these unsigned properties (ETSI TS 101 903 v1.3.2):

| Policy | Unsigned properties |
|--------|---------------------|
| AD-RB | none |
| AD-RT | SignatureTimeStamp |
| AD-RV | SignatureTimeStamp, CompleteCertificateRefs, CompleteRevocationRefs, SigAndRefsTimeStamp |
| AD-RC | AD-RV plus CertificateValues and RevocationValues |
| AD-RA | SignatureTimeStamp, references, values and ArchiveTimeStamp |

`XadesSignerBuilder.WithIcpBrasilPolicy` writes them all: it picks the newest XML PA that accepts
the signer's AC Raiz, sets `WithSigningCertificateForm(XadesSigningCertificateForm.V1)`, the policy
reference and `WithExtendedValidationData(XadesExtendedForm…)`. The forms are also available
without a policy, in SimpleSign.XAdES. Validate with:

```csharp
var result = new XadesSignatureValidator().Validate(signedXml);   // HasValidSigAndRefsTimeStamp, HasValidCompleteReferences
var policy = IcpBrasilXadesPolicyValidator.Validate(signedXml, result);
```

`IcpBrasilXadesPolicyValidator` checks the hash, signing period, accepted roots, the mandated
properties and the signature algorithm and key size. `IcpBrasilXadesPolicies.RefreshAsync` downloads
`LPA_XAdES.xml`, verifies its ITI XML signature and applies new policies and revocations. The ITI
signs the list in a way .NET's `SignedXml` rejects (an enveloped-signature transform on KeyInfo),
so the verification is done by a strict verifier that accepts only that shape and refuses any
element smuggled into the signature.

#### Accepted roots

Each PA lists the AC Raiz versions a signer's chain may end in. CAdES up to v2.3 and PAdES up to
v1.1 accept only roots v2 and v5; CAdES v2.4/v2.5 and PAdES v1.2/v1.3 accept v5 and v12. No PA in
force accepts v13. `WithIcpBrasilPolicy` builds the signer's chain with the bundled roots and
intermediates and picks the newest version of the policy that accepts its root; it throws
`IcpBrasilPolicyException` when none does. `IcpBrasilSignaturePolicies.TryGetRules(oid, out rules)`
gives the rules of each CAdES/PAdES PA: accepted roots (matched by public key, since the PAs embed
re-encoded roots), mandatory signed and unsigned attributes, and allowed signature algorithms with
their minimum key size. `IcpBrasilPolicyRules.Parse` reads them from a PA file;
`scripts/IcpBrasilPolicyRulesGenerator` regenerates the embedded table.

#### CAdES AD-RV, AD-RC and AD-RA

`CadesSignerBuilder.WithIcpBrasilPolicy` adds the unsigned attributes the CAdES PAs mandate after
the signature timestamp (RFC 5126 extended forms, also available as
`WithExtendedValidationData(CadesExtendedForm)`):

| Policy | Adds |
|--------|------|
| AD-RV | complete-certificate-references, complete-revocation-references, CAdES-C-time-stamp (escTimeStamp) |
| AD-RC | the above plus certificate-values and revocation-values (LCRs and OCSP responses) |
| AD-RA | the above plus archive-time-stamp v2 (`1.2.840.113549.1.9.16.2.48`) |

#### PAdES: what each policy writes

The PAdES PAs describe PDF structures in the ICP-Brasil attributes `2.16.76.1.8.1` to `.3`
(DOC-ICP-15.03, Tables A.18–A.22), the same in every version of a policy:

| Policy | Written by `WithIcpBrasilPolicy` |
|--------|-----------------------------------|
| every policy | signature dictionary `/Type /Sig /Filter /PBAD_PAdES /SubFilter /PBAD.PAdES` (`.8.1`) |
| AD-RT | signature timestamp (B-T) |
| AD-RC | signature timestamp; DSS with `Certs`, `CRLs`/`OCSPs` and the signature's VRI (`.8.2`); a document timestamp `/Type /DocTimeStamp /SubFilter /ETSI.RFC3161` (`.8.3`) |
| AD-RA | AD-RC plus `PBAD_PolicyArtifacts`, `PBAD_LpaArtifacts` and `PBAD_LpaSignatures` in the DSS and `PBAD_PolicyArtifact`, `PBAD_LpaArtifact`, `PBAD_LpaSignature` in the VRI (Annex 4 §2.4) |

`IcpBrasilPolicyArtifacts.DownloadAsync` gets the current `LPA_PAdES.der` and `.p7s`, checks that
the ITI signed the LPA, and downloads the PA, checking it against the digest the LPA lists. Any
PAdES signature can embed its own artifacts with `PadesSignerBuilder.WithDssArtifacts` (B-LT and
above).

Before this release, ICP-Brasil PAdES signatures used `ETSI.CAdES.detached`; the PAs mandate
`PBAD.PAdES`, which the policy validator now checks.

The embedded catalog is a snapshot of the LPAs. To pick up policies and revocations the ITI
published later, refresh it at start-up:

```csharp
await IcpBrasilSignaturePolicies.RefreshAsync(httpClient, IcpBrasilPolicyFormat.Pades);
await IcpBrasilSignaturePolicies.RefreshAsync(httpClient, IcpBrasilPolicyFormat.Cades);
```

`RefreshAsync` downloads `LPA_*.der` and its detached signature `LPA_*.p7s` over HTTPS, and accepts
the list only if the signature verifies, is made by the ITI (CNPJ 04.039.532/0001-93) and chains to
an ICP-Brasil AC Raiz without being revoked. Known policies take the LPA's period and revocation
date; new policies are downloaded and accepted only if the PA file matches the LPA digest. On any
failure it throws and the current catalog stays as it was. `IcpBrasilLpa.Parse` reads an LPA you
obtained yourself.

Signatures carry the PA's own `signPolicyHash` in `sigPolicyHash` (not the digest of the PA file
that the LPA lists): a production PAdES AD-RB signature in the integration tests confirms it.
XAdES signatures likewise carry the XML PA's own `SignPolicyDigest` in `SigPolicyHash`, with the
identifier written as `urn:oid:…` (`Qualifier="OIDAsURN"`), as Demoiselle Signer does; this has not
been checked against VALIDAR yet.

### Check a signature against its policy

`IcpBrasilPolicyValidator.Validate` checks what DOC-ICP-15.03 requires of a signature that
declares a policy: the `sigPolicyHash` matches the PA, the policy could be used at the signing
time (signing period, not revoked), and AD-RT and above have a signature timestamp. For PDF
signatures it also checks the PDF structures of the table above (filter and sub-filter; DSS, VRI
and document timestamp for AD-RC/AD-RA; the policy artifacts for AD-RA). The
ICP-Brasil provider runs it during PDF validation and reports `BR.SignaturePolicy` and
`BR.SignaturePolicyStatus` (`Valid`, `Invalid`, `Unknown`, `NotIcpBrasil`) in
`ChainValidationMetadata`; failures are listed in the warnings.

```csharp
var check = IcpBrasilPolicyValidator.Validate(cms, signingTime, IcpBrasilPolicyFormat.Pades);
Console.WriteLine($"{check.Status}: {string.Join("; ", check.Errors)}");
```

Given the root of the signer's chain (`IcpBrasilChainValidator.FindBundledRoot`), the overload
with `signerRoot` also checks the PA's rules: the root is one the PA accepts, the mandatory signed
and unsigned attributes are present, and the signature algorithm and key size are allowed. The
ICP-Brasil provider passes the root it found. CAdES escTimeStamp and archive-time-stamp v2 imprints
are verified by `CadesSignatureValidator`.

For XAdES, use `IcpBrasilXadesPolicyValidator` (SimpleSign.Brasil.Xades, above). Without that
package, `IcpBrasilPolicyValidator.Validate(xades.SignaturePolicy, time, hasSignatureTimestamp, IcpBrasilPolicyFormat.Xades)`
checks the hash, signing period, timestamp and format.

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

# AD-RC and AD-RA (AD-RA downloads the PA and LPA from the ITI)
simplesign sign doc.pdf --cert cert.pfx --icp-policy ad-ra --tsa https://act.example/tsa

# Prescription: document type and CRM in the PDF metadata
simplesign sign receita.pdf --cert cert.pfx --icp-policy ad-rb \
  --health-document prescricao --registration crm:123456/SP
```

Test certificates and standalone timestamps:

```bash
simplesign validate signed.pdf --icp-homologation
simplesign timestamp create contrato.pdf --tsa https://act.example/tsa
simplesign timestamp verify contrato.pdf --token contrato.pdf.tst --icp
```

`--registration` takes `COUNCIL:NUMBER/UF` (crm, crf, cro, oab, coren… or the federal council
acronym) and may be repeated.
