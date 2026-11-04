# ADR 0011: Validation Pipeline Architecture

**Status:** Accepted

**Context:**
PAdES signature validation comprises multiple independent checks: cryptographic integrity, certificate chain building, revocation status, and timestamp validity. Each check can pass, fail with specific errors, or be inconclusive. The results must be aggregated so that consumers can inspect all issues simultaneously — not just the first failure.

Design requirements:
- A single PDF may have multiple signatures (each validated independently)
- Country/regulation-specific validators must be extensible
- Batch validation across hundreds of PDFs must be supported
- Network-dependent validation (revocation, AIA chasing) must be cancellable
- The whole pipeline must be AOT-compatible

**Decision:**
A sequential multi-phase validation pipeline that accumulates results rather than failing fast, returning structured result objects (not exceptions) for all expected outcomes.

### 1. Core orchestrator: `PdfSignatureValidator`

Entry points include single-PDF (`ValidateAsync`), single-field (`ValidateFieldAsync`), and batch (`ValidateBatchAsync`) overloads — all returning structured result objects (never throwing for expected failures).

### 2. Validation phases (executed sequentially per signature)

```
┌─ 1. CmsParser.Parse ───────────────────────────────┐
│   Extracts CMS SignedData from /Contents hex string  │
│   Returns CmsSignedData (or null → invalid result)   │
└──────────────────────────────────────────────────────┘
                          │
             ┌─── IsDocumentTimestamp? ─────┐
             ▼                              ▼
      [DocTimestamp path]            [Normal signature path]
      Integrity against              2. contentType signed attribute
      TSTInfo.messageImprint          (RFC 5652 §5.3)
      (not CMS messageDigest)
                                      ┌──────────────────────────┐
                                      │ 3. IntegrityVerifier      │
                                      │    streaming SHA hash of  │
                                      │    ByteRange vs message   │
                                      │    Digest                 │
                                      └──────────────────────────┘
                                      ┌──────────────────────────┐
                                      │ 4. CryptoVerifier         │
                                      │    RSA/ECDSA verification │
                                      │    over signed attributes │
                                      └──────────────────────────┘
                                      ┌──────────────────────────┐
                                      │ 5. signingCertificateV2   │
                                      │    cert hash anti-        │
                                      │    substitution check     │
                                      └──────────────────────────┘
                                      ┌──────────────────────────┐
                                      │ 6. Certificate chain      │
                                      │    X509Chain.Build() with │
                                      │    trust anchors from:    │
                                      │    • ITrustAnchorProvider │
                                      │    • ValidationOptions    │
                                      │    • System roots (opt)   │
                                      │    + AIA BFS chasing      │
                                      └──────────────────────────┘
                                      ┌──────────────────────────┐
                                      │ 7. Revocation:            │
                                      │    embedded OCSP → CRL →  │
                                      │    online OCSP → online   │
                                      │    CRL → Indeterminate    │
                                      └──────────────────────────┘
                                      ┌──────────────────────────┐
                                      │ 8. TimestampValidator     │
                                      │    RFC 3161 token:        │
                                      │    • TSA signature        │
                                      │    • hash match           │
                                      │    • temporal validity    │
                                      │    • chain (delegate)     │
                                      └──────────────────────────┘

                           8. SignatureValidationResult
                              (all booleans + errors + warnings)
```

Each phase is **independent**: a failure in phase 3 does not skip phases 4-8. Errors are accumulated.

### 3. Document timestamp special path

When `SubFilter = ETSI.RFC3161` (document timestamp, not a signer signature):

- Integrity is verified against `TSTInfo.messageImprint.hashedMessage` instead of CMS `messageDigest`
- Chain trust failures are downgraded to `IsChainTrustWarning = true` — archive timestamps derive value from cryptographic proof, not just PKI trust at validation time
- `HasValidTimestamp` is set to `null` (document timestamps are the timestamp — there is no inner RFC 3161 token)

### 4. Trust anchor loading

`PdfSignatureValidator` accepts `IEnumerable<ITrustAnchorProvider>?` in its constructor.
During `ValidateCertificateChain`:

```csharp
foreach (var provider in _trustAnchorProviders)
{
    foreach (var cert in provider.GetTrustAnchors())
    {
        if (cert.Subject == cert.Issuer)
            chain.ChainPolicy.CustomTrustStore.Add(cert);  // self-signed → root
        else
            chain.ChainPolicy.ExtraStore.Add(cert);        // intermediate
    }
}
```

Also merges `ValidationOptions.TrustedRoots` and (if `TrustSystemRoots = true`) system root certificates.

### 5. Revocation fallback chain

Checked in priority order (embedded DSS OCSPs → embedded DSS CRLs → online OCSP → online CRL → indeterminate). First definitive result wins; ambiguous results fall through to the next step.

At each step: if the result is definitive (revoked or not revoked), return immediately. If ambiguous (stale CRL, mismatched serial), fall through to the next step.

### 6. Result structure

**`SignatureValidationResult`:**

```csharp
public sealed class SignatureValidationResult
{
    public bool IsIntegrityValid { get; init; }
    public bool IsSignatureValid { get; init; }
    public bool IsCertificateChainValid { get; init; }
    public bool IsNotRevoked { get; init; }
    public RevocationSource RevocationSource { get; init; }
    public bool? HasValidTimestamp { get; init; }    // null = absent
    public bool IsChainTrustWarning { get; init; }   // doc timestamp chain
    public SignatureIndication Indication { get; }
    public IReadOnlyList<string> Errors { get; init; }
    public IReadOnlyList<string> Warnings { get; init; }
}
```

Validation has a single overall outcome: `Valid`, `Invalid`, or `Indeterminate`. The individual
checks remain available so consumers can inspect why the result was reached; there is no
parallel overall `IsValid` boolean that would collapse `Indeterminate` into `false`.

### 7. Batch validation

`ValidateBatchAsync` processes documents concurrently with configurable degree of parallelism. Results are returned as `BatchValidationResult` (per-document wrapper with index, identifier, error string for parse failures).

`BulkValidator` provides a streaming API: `IAsyncEnumerable<BulkValidationResult>` for processing hundreds/thousands of documents without loading all results into memory.

### 8. Configuration

**`ValidationOptions`** — immutable (`init`-only), with a `Default` static instance. Properties include revocation gating, trust anchor configuration, and network timeout.

**Consequences:**
- All validation outcomes are inspectable — consumers see every error, warning, and informational message across all phases
- Validation is safe to call without try/catch (expected failures return results, not exceptions)
- Exceptions are only thrown for programming errors (null arguments, invalid config) and I/O failures
- `IChainValidationProvider` is NOT consumed in the built-in pipeline — region-specific chain validation (ICP-Brasil policy detection, Gov.br assurance levels) is a separate API invoked independently by consumers
- Document timestamp signatures have relaxed chain requirements (proof by cryptography, not just PKI trust)
- Batch validation can process documents independently, with per-document error isolation
- Revocation fallback order favours OCSP (smaller, faster, more current) but falls through reliably

**Alternatives considered:**

| Approach | Pros | Cons | Verdict |
|---|---|---|---|
| **Fail-fast (throw on first error)** | Simple | Only first issue reported | Rejected |
| **Accumulating result objects (chosen)** | Full diagnostic visibility | More complex API | **Chosen** |
| **Single boolean result** | Simplest consumer | No actionable feedback | Rejected |
| **Event/callback per phase** | Decoupled pipeline evolution | Hard to trace, no single result | Rejected |
| **Plugin-based validator discovery** | Zero-config extensibility | Reflection, AOT incompatible | Rejected |

**Status:** Accepted. The multi-phase accumulating pipeline is the canonical validation architecture. Region-specific chain validation (`IChainValidationProvider`) integration into the built-in pipeline is deferred — currently invoked independently by consumers. `IChainValidationProvider` may be wired into the pipeline in a future version.
