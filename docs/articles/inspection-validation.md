# Inspection & Validation

SimpleSign provides two complementary APIs for analyzing signed PDFs:

- **Inspection** — fast metadata extraction (no cryptographic verification)
- **Validation** — full cryptographic verification (integrity, chain, revocation)

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
| `Signatures` | List of signature fields with full metadata |
| `DocumentTimestamps` | Archive/document-level timestamps |

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

## Validation

Perform full cryptographic verification:

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
    Console.WriteLine($"  Revoked:    {!r.IsNotRevoked}");

    if (r.HasValidTimestamp == true)
        Console.WriteLine($"  Timestamp:  {r.SigningTime}");

    foreach (var err in r.Errors)
        Console.WriteLine($"  ERROR: {err}");
}
```

### Validation Result Fields

| Property | Type | Description |
|----------|------|-------------|
| `IsValid` | `bool` | All checks passed |
| `IsIntegrityValid` | `bool` | Byte-range hash matches (no tampering) |
| `IsSignatureValid` | `bool` | Cryptographic signature verifies |
| `IsCertificateChainValid` | `bool` | Chain builds to a trusted root |
| `IsNotRevoked` | `bool` | Certificate is not revoked |
| `HasValidTimestamp` | `bool?` | RFC 3161 timestamp is valid (null if no TS) |
| `IsDocumentTimestamp` | `bool` | True for archive/document timestamps |
| `SignerName` | `string?` | Signer common name |
| `SigningTime` | `DateTimeOffset?` | Signing time from timestamp or CMS |
| `RevocationSource` | `enum` | CRL, OCSP, or None |
| `Errors` | `IReadOnlyList<string>` | Validation errors |
| `Warnings` | `IReadOnlyList<string>` | Non-blocking warnings |

### Custom Trust Anchors

```csharp
var options = new ValidationOptions
{
    TrustSystemRoots = false,
    CustomTrustAnchors = myRootCertificates
};
```

## Web Sample

A web-based inspection and validation UI is available at [`samples/WebInspectSample/`](https://github.com/eupassarin/SimpleSign/tree/main/samples/WebInspectSample), featuring collapsible signature cards, search, and ICP-Brasil certificate detection.
