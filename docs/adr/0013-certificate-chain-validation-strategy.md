# ADR 0013: Certificate Chain Validation Strategy

**Status:** Accepted — amended by [ADR 0021](0021-signing-policy-ldap-crl-and-revocation-cache.md) and [ADR 0022](0022-validation-policy-and-etsi-report.md): a generic minimum key size and accepted algorithms now live in `SigningPolicy`/`ValidationPolicy`, and the revocation of a whole chain is the public `ChainRevocationChecker` in Core (used before signing, by the CAdES/XAdES `ValidateAsync` and by the country validators).

**Context:**
Certificate chain validation for PAdES signatures goes beyond standard X.509 path building. Each jurisdiction defines:

- **Trust anchors:** which root CAs are trusted (ICP-Brasil AC Raiz family, Gov.br AC hierarchy)
- **Policy constraints:** minimum key sizes, Extended Key Usage requirements, certificate policy OID mapping
- **Revocation rules:** OCSP vs CRL, indirect CRL handling, revocation unknown = warning vs error
- **Identity extraction:** national IDs (CPF, CNPJ) from Subject Alternative Name extensions

The .NET BCL provides `X509Chain` for standard path building, but it does not support:
- Bundling trust anchors from in-memory certificates without installing them in the OS store
- Country-specific policy OID detection
- CPF/CNPJ extraction from SAN with check-digit validation
- Differentiated error classification (revocation unknown → warning, not error)

**Decision:**
A layered approach using .NET `X509Chain` with `CustomRootTrust` mode for standard path building, wrapped by jurisdiction-specific validators that add policy detection, identity extraction, and differentiated error handling.

### 1. Trust anchor model

Two strategies, both using `X509Chain.ChainPolicy.CustomTrustStore`:

**Strategy A — Bundled (offline, preferred):**
Root CA certificates are embedded as assembly resources (`Certs/*.crt` in `SimpleSign.Brazil.IcpBrasil.dll` and `SimpleSign.Brazil.GovBr.dll`). Loaded at runtime via `Assembly.GetManifestResourceStream()` — no network required.

| Validator | Certificates |
|---|---|
| ICP-Brasil | Multiple AC Raiz versions, covering all active and legacy roots |
| Gov.br | Three-tier hierarchy: AC Raiz, AC Intermediaria, AC Final v1 |

**Strategy B — AIA chasing (online, fallback):**
When the bundled roots are insufficient or the chain includes intermediate CAs not present in the CMS certificate bag, `CertificateChainUtility.DownloadAiaCertsAsync()` performs BFS-based AIA chasing:
- Starts with the signer certificate's AIA extension
- Hard limit on certificate count (`maxCerts` guard)
- URL deduplication via `visited` hash set
- Supports DER, PEM, PKCS#12, and PKCS#7 (.p7b/.p7c) response formats

### 2. Chain construction with `X509Chain`

```csharp
var chain = new X509Chain();
chain.ChainPolicy.RevocationMode = X509RevocationMode.Online;
chain.ChainPolicy.RevocationFlag = X509RevocationFlag.ExcludeRoot;
chain.ChainPolicy.VerificationFlags =
    X509VerificationFlags.IgnoreEndRevocationUnknown |
    X509VerificationFlags.IgnoreCertificateAuthorityRevocationUnknown;
chain.ChainPolicy.TrustMode = X509TrustMode.CustomRootTrust;

// Root CAs → CustomTrustStore (self-signed)
foreach (var root in trustAnchors.Where(c => c.Subject == c.Issuer))
    chain.ChainPolicy.CustomTrustStore.Add(root);

// Intermediates → ExtraStore
foreach (var cert in extraCerts)
    chain.ChainPolicy.ExtraStore.Add(cert);

bool built = chain.Build(certificate);
```

### 3. Error classification

`ProcessChainErrors` iterates `chain.ChainElements` and classifies each `ChainElementStatus`:

| `ChainStatusStatus` | Classification |
|---|---|
| `RevocationStatusUnknown` | **Warning** |
| `OfflineRevocation` | **Warning** |
| All others (UntrustedRoot, NotSignatureValid, etc.) | **Error** |

Revocation unknown is a warning because:
- Some platforms (macOS with CustomRootTrust) cannot complete CRL/OCSP for custom trust anchors
- The revocation check is handled separately by the LTV pipeline (embedded DSS, online OCSP/CRL)
- A cert may be known-good from an embedded OCSP response even if the online check fails

### 4. Country-specific validators

**ICP-Brasil (`IcpBrasilChainValidator`):**

| Check | Implementation |
|---|---|
| Policy detection | Searches Certificate Policies extension for ICP-Brasil OID patterns; multiple variants per policy across cert versions/types |
| Key size | Enforces minimum key size per DOC-ICP-04.01 → runtime warning if below threshold |
| EKU validation | Must include Document Signing, Email Protection, or Client Auth |
| CPF/CNPJ extraction | Parses Subject Alternative Name with check-digit validation |
| Chain building | AIA chasing + `X509Chain` with bundled AC Raiz roots |

**Gov.br (`GovBrChainValidator`):**

| Check | Implementation |
|---|---|
| Detection | Issuer DN contains `O=Gov-Br` or certificate policy OID arc `2.16.76.3` |
| Assurance levels | Extracted from policy extension DER |
| CPF extraction | Parses SAN for DirName matching Gov.br format |
| Chain building | Bundled hierarchy + AIA chasing |

### 5. How validators are consumed

```
CLI / HostSigner / app
  │
  ├─► IcpBrasilChainValidator.ValidateAsync(cert)
  │     ├─ Detects policy (AD-RB, AD-RT, ...)
  │     ├─ Builds chain with bundled roots + AIA
  │     ├─ Extracts CPF/CNPJ
  │     └─ Returns IcpBrasilValidationResult
  │
  └─► PdfSignatureValidator.ValidateAsync(pdf)
        ├─ Uses ITrustAnchorProvider for chain building
        │   (roots → CustomTrustStore)
        └─ Does NOT call IChainValidationProvider
            (separate API, invoked independently)
```

`IcpBrasilChainValidationProvider` and `GovBrChainValidationProvider` wrap the validators to implement `IChainValidationProvider`, bridging the `.ValidateAsync()` call to the generic `ChainValidationResult` type.

### 6. CompositeCertificateStore

`CompositeCertificateStore` implements `ICertificateStore` by wrapping multiple stores:
- `FindByThumbprint` searches stores in order, returns first match
- `FindBySubject` and `ListAll` aggregate results from all stores

Used for searching certificates across multiple locations (file system, OS store, HSMs).

**Consequences:**
- Bundled trust anchors work offline — no network required for root trust validation
- BFS AIA chasing discovers intermediate CAs not present in the CMS certificate bag
- `RevocationStatusUnknown` as a warning (not error) prevents platform-specific false positives
- OCSP/CRL revocation handling is delegated to the separate LTV pipeline, not `X509Chain.Build()`
- Country-specific validators can be invoked independently of the standard validation pipeline
- Policy OID detection uses raw DER byte searching (not `X509Certificate2.Extensions` parsing) — more robust but fragile to schema changes
- CPF/CNPJ check-digit validation follows ICP-Brasil rules
- The Gov.br bundled hierarchy covers the full chain in most cases without AIA chasing

**Alternatives considered:**

| Approach | Pros | Cons | Verdict |
|---|---|---|---|
| **X509Chain only (no country validators)** | Simple, .NET-native | No policy detection, no ID extraction | Rejected |
| **Full custom chain builder** | Full control | Reimplementation of X509Chain logic, CVE risk | Rejected |
| **X509Chain + per-jurisdiction wrappers (chosen)** | Best of both | Two validation paths to maintain | **Chosen** |
| **Online trust anchor list (download root CAs)** | Always current | Network dependency, startup latency | Rejected (offline preferred) |

**Status:** Accepted. `X509Chain.CustomRootTrust` + bundled anchors + country-specific validators is the canonical chain validation strategy. Integrating `IChainValidationProvider` into the built-in `PdfSignatureValidator` pipeline is deferred.
