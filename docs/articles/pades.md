# PAdES signing

Sign PDFs with full European standard compliance, from basic signatures to long-term archival:

```csharp
using SimpleSign.Core.Extensions;
using SimpleSign.Core.Signing;
using SimpleSign.PAdES;

var signed = await PadesSigner
    .Document(pdfBytes)
    .WithCertificate(cert)
    .WithMetadata(new SignatureMetadata
    {
        SignerName = "Jane Doe",
        Reason = "Approval",
        Location = "New York"
    })
    .WithLevel(AdesBaselineProfile.Archive(      // PAdES B-LTA — valid for decades
        new TimestampOptions(new Uri("http://timestamp.digicert.com")),
        new LongTermValidationOptions()))         // Embeds CRL/OCSP for offline validation
    .WithHashAlgorithm(HashAlgorithmName.SHA512)
    .SignAsync();
```

| Capability | API |
|---|---|
| Basic signature (B-B) | `.WithCertificate(cert).SignAsync()` |
| Timestamp (B-T) | `.WithLevel(AdesBaselineProfile.Timestamped(new TimestampOptions(new Uri(tsaUrl))))` |
| Long-term validation (B-LT) | `.WithLevel(AdesBaselineProfile.LongTerm(new TimestampOptions(new Uri(tsaUrl)), new LongTermValidationOptions()))` |
| Archival (B-LTA) | `.WithLevel(AdesBaselineProfile.Archive(new TimestampOptions(new Uri(tsaUrl)), new LongTermValidationOptions()))` |
| Document certification (DocMDP) | `.AsCertification(level)` |
| PDF/A preservation | `.WithPdfAPreservation()` |
| Visible signature with QR code | `.WithAppearance(appearance)` |
| External signer (HSM, KMS) | `.WithExternalSigner(cert, signer)` (`IExternalSigner`) |
| Custom signing time | `.WithSigningTime(dateTimeOffset)` — drives the signature dictionary `/M` entry |
| Custom HTTP client | `.WithHttpClientProvider(provider)` / scoped providers in `TimestampOptions` |
| Existing field | `.WithExistingField("SignHere")` |
| Deferred (2-phase) | `Document(pdf).WithCertificate(cert).WithSessionIntegrityKey(key).PrepareAsync()` → `Resume(session, key).CompleteAsync()` |
| Batch (parallel) | `BatchSigner.Create(cert).Build()` |

### Signature Appearance

```csharp
var appearance = new SignatureAppearance
{
    Page = 1,
    X = 50, Y = 50,
    ShowDate = true,
    ShowReason = true,
    BackgroundImagePng = logoBytes,
    VerificationUrl = "https://verify.example.com/abc123",  // Renders a QR code
    ExtraLines = ["Department: Legal", "Ref: DOC-2025-001"]
};

await PadesSigner
    .Document(pdfBytes)
    .WithCertificate(cert)
    .WithAppearance(appearance)
    .SignAsync(output);
```

Every text in the stamp can be changed, and the date can be shown in a local time zone:

```csharp
var appearance = new SignatureAppearance
{
    ShowReason = true,
    BackgroundImagePng = handwrittenSignaturePng,   // transparency is kept
    BackgroundImageFit = SignatureImageFit.Contain,  // keep the aspect ratio
    BackgroundColor = (1f, 1f, 1f),
    BorderColor = (0.2f, 0.2f, 0.2f),
}
.WithLabels(signedBy: "Assinado digitalmente por", reason: "Motivo: ", location: "Local: ", date: "Data: ")
.WithDateFormat("dd/MM/yyyy HH:mm:ss", TimeZoneInfo.FindSystemTimeZoneById("America/Sao_Paulo"));
```

Set `SignedByLabel = ""` to hide the first line, `SignerDisplayName` to show a name other than the
`/Name` entry, and `Width`/`Height` to give the stamp a fixed size (text shrinks to fit; use
`TextAlignment` and `VerticalAlignment` to place it).

## Signing Policy

Before anything is signed, the builder checks the certificate, its chain and the algorithms with a `SigningPolicy`.
A refusal is a `SigningException` with its `Reason`:

| Policy | Checks | Reasons |
|---|---|---|
| `SigningPolicy.Default` | Validity of every certificate of the chain; key usage digitalSignature or nonRepudiation; RSA ≥ 2048 bits; P-256/384/521 or brainpool r1 curves; SHA-2/SHA-3 | `ChainCertificateNotValid`, `KeyUsageNotPermitted`, `KeyTooWeak`, `AlgorithmNotPermitted` |
| `SigningPolicy.Strict` | Default plus the revocation of the whole chain (CRL and OCSP) | also `CertificateRevoked`, `RevocationStatusUnknown` |
| `SigningPolicy.Minimal` | Only the dates of the signing certificate | `CertificateExpired`, `CertificateNotCurrentlyValid` |

```csharp
byte[] signed = await PadesSigner.Document(pdf)
    .WithCertificate(certificate, chain)            // Strict needs the chain up to the root
    .WithSigningPolicy(SigningPolicy.Strict)
    .SignAsync();
```

`WithSigningPolicy` is on the CAdES, XAdES, deferred and batch builders too. `WithChainRevocationChecker` replaces the
checker used for the revocation check (by default it downloads through the builder's `IHttpClientProvider`).

## Validation

Signing revalidates the completed base signature and content integrity before
returning a result. `SignWithDetailsAsync` reports `RequestedLevel`, `AchievedLevel`,
and checked timestamp/LTV/archive facts. Strict success fulfills the requested
level; an explicit `ReturnLowerLevel` profile permits enrichment failures to return
a lower level with structured warnings. Base-signature failures and cancellation
still fail, and byte-only `SignAsync` accepts strict profiles only.

Embedded-evidence checks authenticate OCSP/CRL signatures, certificate association,
responder authorization, and usable validity bounds. Signer-chain trust and TSA
trust depend on validation anchors and policy. Evaluate them with detailed results:

```csharp
var pdfResults = await new PdfSignatureValidator(options).ValidateAsync(stream);
```

Each result includes:

- `IsIntegrityValid` — byte-range hash matches (no tampering)
- `IsSignatureValid` — cryptographic signature verifies against public key
- `IsCertificateChainValid` — chain builds to a trusted root
- `HasValidTimestamp` — RFC 3161 token signature, signed content, and imprint verify (bool?)
- `IsTsaTrusted` — TSA certificate passes the evaluated chain and timestamping-purpose policy (bool?; null when the token is absent, invalid, or unchecked)
- `Indication` / `SubIndication` — the ETSI EN 319 102-1 outcome and, when not valid, why (`HASH_FAILURE`, `TRY_LATER`, `CRYPTO_CONSTRAINTS_FAILURE_NO_POE`…)
- `Constraints` — every check, the validation policy's (`ValidationOptions.Policy`) included
- `SignerName`, `SigningTime`, `DigestAlgorithmOid`, `SubFilter`, `Warnings`

## Inspection

Extract metadata without full validation (fast, non-cryptographic):

```csharp
using SimpleSign.PAdES.Inspection;

var result = await PdfSignatureInspector.InspectAsync(stream);
foreach (var s in result.Signatures)
    Console.WriteLine($"{s.FieldName}: {s.DeclaredSignerName}, {s.SigningTime}, {s.DigestAlgorithm}");
```

## Batch Signing

Sign multiple documents in parallel with shared resources:

```csharp
var batch = BatchSigner.Create(cert)
    .WithFieldOptions(new SignatureFieldOptions
    {
        SignerName = "Jane Doe",
        Reason = "Batch approval"
    })
    .WithLevel(AdesBaselineProfile.Basic())
    .WithMaxConcurrency(4)
    .Build();

// Sign a single document
byte[] signed = await batch.SignAsync(pdfBytes);

// Or stream results as they complete
await foreach (var result in batch.SignAllAsync(inputs))
{
    if (result.SignedPdf is not null)
        Console.WriteLine($"{result.Id}: signed");
}

// Results are ordered by completion, not source order. Breaking the enumeration
// cancels pending batch work and the cancellation-aware input source.

// Access aggregate stats after signing
Console.WriteLine($"Success: {batch.SuccessCount}, Fail: {batch.FailureCount}, Avg: {batch.AverageElapsedMs:F0}ms");
```

## Deferred Signing (Two-Phase)

For web applications where the signing key is on a client device:

```csharp
var builder = DeferredSigner.Document(pdfBytes)
    .WithCertificate(cert, chain)
    .WithSessionIntegrityKey(sessionIntegrityKey)
    .WithLevel(AdesBaselineProfile.Timestamped(
        new TimestampOptions(new Uri("https://tsa.example"))))
    .WithHttpClientProvider(httpClientProvider);

// Server: prepare the signed attributes
var prepared = await builder.PrepareAsync();
byte[] hashToSign = prepared.HashToSign;

// Client: sign the hash with the private key (RSA PKCS#1 v1.5, ECDSA, etc.)
byte[] signature = SignWithClientKey(hashToSign);

// Server: load the persisted session, then validate and embed the raw signature.
byte[] signedPdf = await DeferredSigner.Resume(prepared.SessionData, sessionIntegrityKey)
    .WithHttpClientProvider(httpClientProvider)
    .CompleteAsync(signature);
```

## TSA Connection Pool

Resilient timestamp authority connections with pooling and retry:

```csharp
using SimpleSign.Core.Crypto;

var pool = new TsaPool([
    "http://timestamp.digicert.com",
    "http://tsa.starfieldtech.com",
    "http://timestamp.sectigo.com"
]);

// Send timestamp request with auto-failover across servers
byte[] tsaResponse = await pool.GetTimestampAsync(
    hash, HashAlgorithmName.SHA256, httpClient, cancellationToken);
```

## Structured Logging

105 source-generated `[LoggerMessage]` definitions with semantic fields:

```csharp
services.AddLogging(b => b.AddConsole());
var validator = new PdfSignatureValidator(options, logger: loggerFactory.CreateLogger<PdfSignatureValidator>());
```
