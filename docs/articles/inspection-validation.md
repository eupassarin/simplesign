# Inspection & Validation

SimpleSign combines PDF metadata inspection with format-specific cryptographic
validation for PAdES, CAdES, and XAdES:

- **Inspection** — fast PDF metadata extraction without cryptographic verification
- **Validation** — checked signature integrity, evidence, and configured trust policy

The APIs below describe the current source tree. The [changelog](https://github.com/eupassarin/SimpleSign/blob/main/CHANGELOG.md)
records which changes are released; use release-tagged documentation when working
with a particular package version.

## Inspection

Extract signature metadata without performing cryptographic operations:

```csharp
using SimpleSign.PAdES.Inspection;

var result = await PdfSignatureInspector.InspectAsync(File.OpenRead("signed.pdf"));

// Document-level info
Console.WriteLine($"Encrypted: {result.Document.IsEncrypted}");
Console.WriteLine($"PDF/A: {result.Document.PdfALevel}");
Console.WriteLine($"DSS: {result.Document.SecurityStore?.IsPresent}");

// Per-signature details
foreach (var sig in result.Signatures)
{
    Console.WriteLine($"{sig.FieldName}: {sig.Signer?.Subject}");
    Console.WriteLine($"  SubFilter: {sig.SubFilter}");
    Console.WriteLine($"  Signed: {sig.SigningTime}");
    Console.WriteLine($"  Certs: {sig.EmbeddedCertificates.Count}");
}
```

### Inspection Result Structure

| Property | Description |
|----------|-------------|
| `Document` | PDF-level metadata (encryption, PDF/A, DSS, DocMDP) |
| `Signatures` | List of all signature fields — user signatures and document timestamps (`IsDocumentTimestamp`) |

Each `SignatureFieldInfo` includes:

- Signer certificate details (subject, issuer, key algorithm, validity)
- SubFilter (`ETSI.CAdES.detached`, `adbe.pkcs7.detached`, `ETSI.RFC3161`)
- Signing time (CMS signed attribute and PDF /M entry)
- Byte range and coverage validation
- Embedded certificates chain
- RFC 3161 timestamp details (TSA, generation time, token size)
- ESS signing-certificate-v2 presence
- Commitment type and signature policy OIDs

## Conformance Level Detection

Detect the PAdES conformance level of each signature:

```csharp
using SimpleSign.PAdES.Validation;

var inspection = await PdfSignatureInspector.InspectAsync(stream);
var levels = ConformanceDetector.DetectAll(inspection);

foreach (var item in levels)
{
    Console.WriteLine($"{item.Signature.FieldName}: {item.Level}");
    // B-B, B-T, B-LT, B-LTA
}
```

Conformance detection identifies observed PDF structures. Timestamp integrity,
revocation evidence, and certificate trust require the validation API.

## Signing Guarantees and Evidence

PAdES, CAdES, and XAdES signing revalidate the completed base signature and content
integrity before returning a result. `SignWithDetailsAsync` reports the requested
and achieved baseline levels, checked timestamp/LTV/archive facts, and structured
warnings. Strict success requires `RequestedLevel == AchievedLevel`. An explicit
`ReturnLowerLevel` profile permits enrichment failures to return a lower level;
base-signature failures and cancellation still fail. Byte-only `SignAsync` accepts
strict profiles only.

Signature and archive timestamps require a cryptographically valid RFC 3161 token
bound to the format-required input. The response must match the request's hash
OID, imprint, and nonce. Token checks include the TSA signer certificate,
authenticated TSTInfo signed attributes (`contentType`, `messageDigest`, and
signing-certificate binding), CMS signature, and exclusive critical timestamping
EKU. Token integrity and TSA trust are separate outcomes.

B-LT evidence must identify the required certificate, verify under an authorized
issuer or responder, and be usable at the checked time. Required non-root signer,
prior-TSA, and responder paths need embedded issuers and applicable OCSP or CRL
evidence. Cryptographically self-signed root candidates and authorized OCSP
responders with `id-pkix-ocsp-nocheck` do not need their own revocation objects.

| Format | Embedded validation material |
|---|---|
| PAdES | PDF DSS certificates, OCSP responses, and CRLs |
| CAdES | Root CMS `SignedData` certificate/revocation sets, including RFC 5940 OCSP choices; legacy CAdES-XL unsigned attributes remain readable |
| XAdES | `CertificateValues` and `RevocationValues` unsigned properties |

Embedding a root candidate does not make it trusted. `AchievedLevel` and the
artifact flags establish checked evidence; signer-chain trust and TSA trust
require validation against the application's trust anchors and policy.

## Validation

Perform cryptographic verification of each PDF signature under the configured
validation policy:

```csharp
using SimpleSign.Core.Validation;
using SimpleSign.PAdES.Validation;

var options = new ValidationOptions
{
    CheckRevocation = true,
    TrustSystemRoots = true
};

var validator = new PdfSignatureValidator(options);
var results = await validator.ValidateAsync(File.OpenRead("signed.pdf"));

foreach (var r in results)
{
    Console.WriteLine($"{r.FieldName}: {(r.IsValid ? "VALID" : "INVALID")}");
    Console.WriteLine($"  Integrity:  {r.IsIntegrityValid}");
    Console.WriteLine($"  Signature:  {r.IsSignatureValid}");
    Console.WriteLine($"  Chain:      {r.IsCertificateChainValid}");
    Console.WriteLine($"  Revocation: {r.RevocationSource} (no revocation established: {r.IsNotRevoked})");

    if (r.HasValidTimestamp == true)
        Console.WriteLine($"  Timestamp:  {r.SigningTime}");

    foreach (var err in r.Errors)
        Console.WriteLine($"  ERROR: {err}");
}
```

### Validation Result Fields

| Property | Type | Description |
|----------|------|-------------|
| `IsValid` | `bool` | Integrity, signature, configured chain trust, and revocation policy pass |
| `IsIntegrityValid` | `bool` | Byte-range hash matches (no tampering) |
| `IsSignatureValid` | `bool` | Cryptographic signature verifies |
| `IsCertificateChainValid` | `bool` | Chain builds to a trusted root |
| `IsNotRevoked` | `bool` | No revocation established; consult `RevocationSource` for unknown or unchecked status |
| `HasValidTimestamp` | `bool?` | RFC 3161 token signature, signed content, and imprint verify (null if no TS) |
| `IsTsaTrusted` | `bool?` | TSA chain and timestamping-purpose policy pass (null if token absent, invalid, or unchecked) |
| `IsDocumentTimestamp` | `bool` | True for archive/document timestamps |
| `SignerName` | `string?` | Signer common name |
| `SigningTime` | `DateTimeOffset?` | Signing time from timestamp or CMS |
| `RevocationSource` | `enum` | Embedded/online CRL or OCSP, `None` (unchecked), or `Indeterminate` (unknown) |
| `Errors` | `IReadOnlyList<string>` | Validation errors |
| `Warnings` | `IReadOnlyList<string>` | Diagnostic warnings; unknown revocation prevents overall validity |

Inspect `HasValidTimestamp` and `IsTsaTrusted` separately when the application
requires a valid or trusted timestamp; these optional outcomes are not included
in `SignatureValidationResult.IsValid`.

### Revocation and Network Policy

When revocation is enabled, `Indeterminate` prevents `IsValid` from becoming true,
even if integrity, signature, and chain checks pass. Disabling revocation keeps
`RevocationSource.None` and permits validity under that configured policy. The CLI
shows unknown and unchecked states explicitly; its JSON uses `revoked: null` for
both, and a boolean only for a determined status.

`ValidationOptions.NetworkTimeout` bounds each AIA download phase and each
revocation check (OCSP and CRL together), and sets the chain URL retrieval timeout.
Timeouts produce structured validation failures; caller cancellation propagates
as `OperationCanceledException`, including during batch validation.

### Custom Trust Anchors

```csharp
var options = new ValidationOptions
{
    TrustSystemRoots = false,
    TrustedRoots = myRootCertificates
};
```

## XAdES Validation

For XML signatures, use `XadesSignatureValidator.Validate` when the document has
one signature, or `ValidateAll` for independently identified results when it has
multiple signatures. Supply the application's trust anchors for chain evaluation.

`DetectedLevel` reports observed unsigned-property elements. A malformed
`SignatureTimeStamp` can report `Timestamped` while its checked outcome is false;
invalid LTV or archive properties likewise retain their structural level.

| XAdES property | Checked outcome |
|---|---|
| `IsSignatureValid` / `IsIntegrityValid` | Base signature and referenced-content integrity |
| `HasValidSignatureTimeStamp` | Token integrity and binding to canonicalized `SignatureValue` |
| `IsLtvDataValid` | Applicable, authenticated embedded certificate/revocation evidence |
| `HasValidArchiveTimeStamp` | Archive token integrity and ETSI archive coverage |
| `IsCertificateChainValid` | Signer-chain trust |
| `IsTsaTrusted` | Signature TSA chain and timestamping-purpose trust |

`XadesValidationResult.IsValid` combines fundamental signature, integrity, and
signer-chain checks. Inspect the optional timestamp/LTV/archive outcomes as well
when the application requires B-T, B-LT, or B-LTA. Structural `DetectedLevel` is
not the signing result's checked `AchievedLevel`.

## Web Sample

A web-based inspection and validation UI is available at [`samples/WebInspectSample/`](https://github.com/eupassarin/SimpleSign/tree/main/samples/WebInspectSample), featuring collapsible signature cards, search, and ICP-Brasil certificate detection.
