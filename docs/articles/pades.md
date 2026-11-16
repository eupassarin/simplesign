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

Before anything is signed, the builder checks the certificate, its chain and the algorithms with a `SigningPolicy`,
a JSON document with the certificate and cryptographic constraints of the validation policy (root
`SigningConstraints`, levels FAIL, WARN, INFORM, IGNORE — see [ADR 0024](../adr/0024-own-policy-format.md)). A FAIL constraint refuses the signature with a
`SigningException` and its `Reason`; a WARN one adds a `SigningWarning` (`PolicyConstraint`); an INFORM one is logged.

| Constraint | Checks | Reason |
|---|---|---|
| `SigningCertificate/NotExpired`, `CACertificate/NotExpired` | Validity of the signing certificate and of every certificate of the chain | `CertificateExpired`, `CertificateNotCurrentlyValid`, `ChainCertificateNotValid` |
| `SigningCertificate/KeyUsage`, `ExtendedKeyUsage` | One of the listed usages | `KeyUsageNotPermitted` |
| `Cryptographic` | Key algorithm and size, digest algorithm (DSS `AcceptableEncryptionAlgo`, `MiniPublicKeySize`, `AcceptableDigestAlgo`, `AlgoExpirationDate`) | `KeyTooWeak`, `AlgorithmNotPermitted` |
| `NotRevoked`, `RevocationDataAvailable` | The revocation of the whole chain as it is now: each OCSP responder first, then the CRL downloaded again (never a cached copy). Needs the chain up to the root | `CertificateRevoked`, `RevocationStatusUnknown` |

`SigningPolicy.Default` checks the validity of the chain, key usage digitalSignature or nonRepudiation, RSA and
RSASSA-PSS ≥ 2048 bits, ECDSA ≥ 256 bits and SHA-2/SHA-3; revocation is at IGNORE. To also check revocation:

```json
{
  "SigningConstraints": {
    "SigningCertificate": {
      "NotExpired": { "Level": "FAIL" },
      "KeyUsage": { "Level": "FAIL", "Id": [ "digitalSignature", "nonRepudiation" ] },
      "NotRevoked": { "Level": "FAIL" },
      "RevocationDataAvailable": { "Level": "FAIL" }
    },
    "CACertificate": { "NotExpired": { "Level": "FAIL" }, "NotRevoked": { "Level": "FAIL" }, "RevocationDataAvailable": { "Level": "FAIL" } },
    "Cryptographic": {
      "Level": "FAIL",
      "AcceptableEncryptionAlgo": { "Algo": [ "RSA", "RSASSA-PSS", "ECDSA" ] },
      "MiniPublicKeySize": { "Algo": [ { "Value": "RSA", "Size": 2048 }, { "Value": "ECDSA", "Size": 256 } ] },
      "AcceptableDigestAlgo": { "Algo": [ "SHA256", "SHA384", "SHA512" ] }
    }
  }
}
```

```csharp
byte[] signed = await PadesSigner.Document(pdf)
    .WithCertificate(certificate, chain)            // the revocation check needs the chain up to the root
    .WithSigningPolicy(SigningPolicy.Load("signing-policy.json"))
    .SignAsync();
```

The same in code: `SigningPolicy.Default.With("SigningCertificate/NotRevoked", new PolicyConstraint(ConstraintLevel.Fail))`.
`SigningPolicy.LoadSigned` refuses a file whose detached signature is not by the trusted certificate, and
`WithCryptographicSuite` replaces the `Cryptographic` constraints with an ETSI TS 119 322 suite (JSON).

`WithSigningPolicy` is on the CAdES, XAdES, deferred and batch builders too. `WithChainRevocationChecker` replaces the
checker used for the revocation check (by default it downloads through the builder's `IHttpClientProvider`).

### Checking a certificate before signing

`SigningCertificateCheck.EvaluateAsync` runs the signers' own checks without signing: a server can tell the user
whether their certificate will be accepted before asking for the PIN. It covers everything above (validity of the
certificate and its chain, key usage, key and algorithms, chain to the trust anchors, revocation of the chain) and
never throws for a refused certificate:

```csharp
var check = await SigningCertificateCheck.EvaluateAsync(certificate, new SigningCertificateCheckOptions
{
    Chain = chain,
    Policy = policy,                                   // the one the signer will use
    TrustAnchors = [extension.TrustAnchorProviders[0]],
    HashAlgorithm = HashAlgorithmName.SHA256,          // optional: the digest of the signature to be made
});
if (!check.IsAcceptable)
{
    return Refuse(check.Reason, check.Message);       // the SigningErrorReason the signer would throw with
}
```

`Findings` lists every constraint not passed (FAIL, WARN, INFORM), where a signer stops at the first FAIL. `Time`
moves the validity, trust and cryptographic checks; revocation is always checked as it is now. `SigningPolicy.Evaluate`
remains the offline subset (the signing certificate alone, no chain, anchors or network).

### Audit trail

`WithAuditSink(ISignatureAuditSink)` records every signature made or refused. `JsonLinesAuditSink` appends one JSON
line per record, chained by SHA-256 (`prev`, `hash`); `JsonLinesAuditSink.Verify` and `simplesign audit verify` find a
line changed, removed or inserted later. A sink that writes to a database produces the same chain with `AuditChain`:

```csharp
sealed class DatabaseAuditSink(AuditDb db) : ISignatureAuditSink
{
    public async ValueTask RecordAsync(SignatureAuditEvent e, CancellationToken ct)
    {
        string previous = await db.LastHashAsync(ct) ?? AuditChain.Genesis;  // under the same lock or transaction
        AuditChainRecord record = AuditChain.Append(previous, e);          // Content, PreviousHash, Hash
        await db.InsertAsync(record.Content, record.PreviousHash, record.Hash, ct);
    }
}

int broken = AuditChain.Verify(await db.ReadAllInOrderAsync());           // 0 = intact, else the 1-based record
```

`AuditChain.Canonicalize` is the content the file sink writes (without `prev` and `hash`) and `AuditChain.Link` its hash,
so the records of both stores can be compared.

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

## Augmenting an existing signature

`PadesAugmenter` raises a PDF that is already signed to a higher baseline level, without touching
what is signed: the signature, its byte range and the original revisions stay exactly as they are,
and the evidence is appended in a new incremental update (ADR 0025).

```csharp
using SimpleSign.PAdES;

var result = await PadesAugmenter
    .Document(await File.ReadAllBytesAsync("signed-b-b.pdf"))
    .ToLevel(AdesBaselineLevel.Archive)
    .WithTimestamp(TimestampOptions.DigiCert)
    .AugmentAsync();

Console.WriteLine($"{result.InitialLevel} -> {result.Level}");
await File.WriteAllBytesAsync("signed-b-lta.pdf", result.Document);
```

`RenewArchive()` adds a new document timestamp to a B-LTA before the current archive timestamp's TSA
certificate expires, which is how a long-term signature stays verifiable:

```csharp
var renewed = await PadesAugmenter.Document(bytes)
    .RenewArchive()
    .WithTimestamp(TimestampOptions.DigiCert)
    .AugmentAsync();
```

A level that cannot be reached — no TSA for B-T, no revocation data available for B-LT — throws
`SigningException` with `SigningErrorReason.LevelNotAchievable` rather than quietly returning a
lower level. Augmenting never downgrades: asking for a level the document already has is a no-op.

From the CLI:

```bash
simplesign augment signed.pdf --level BLTA --tsa http://timestamp.digicert.com
```

CAdES and XAdES have the same shape — see
[Augmenting an existing signature](cades-xades.md#augmenting-an-existing-signature).

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
byte[] dataToSign = prepared.DataToSign;

// Client: sign them with the private key (RSA PKCS#1 v1.5, ECDSA, etc.)
byte[] signature = SignWithClientKey(dataToSign);

// Server: load the persisted session, then validate and embed the raw signature.
byte[] signedPdf = await DeferredSigner.Resume(prepared.SessionData, sessionIntegrityKey)
    .WithHttpClientProvider(httpClientProvider)
    .CompleteAsync(signature);
```

The deferred builder takes the options of `PadesSigner` (operation id, PDF/A preservation, signature
policy, country extensions, metadata, document information, DSS artifacts…).
`DeferredSigner.From(builder)` prepares the signature a `PadesSigner` builder is already configured for, and
`CompleteWithDetailsAsync` returns the `PadesSigningResult` of one-call signing (the level achieved, the
warnings). See [Deferred signing](deferred-signing.md), which also covers CAdES and XAdES.

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

Source-generated `[LoggerMessage]` definitions with semantic fields:

```csharp
services.AddLogging(b => b.AddConsole());
var validator = new PdfSignatureValidator(options, logger: loggerFactory.CreateLogger<PdfSignatureValidator>());
```

Traces and metrics (signing, TSA, OCSP, CRL, trusted lists, validation) are described in
[Observability](observability.md).
