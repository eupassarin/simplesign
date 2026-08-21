# ADR 0006: External Signer / Deferred Signing

**Status:** Accepted

**Context:**
Many real-world signing scenarios require the private key to remain on a separate device or service:

- **HSM** (Hardware Security Module) — key never leaves the device
- **Smart cards** (ICP-Brasil, eID) — key on physical token
- **Web applications** — key in browser (WebCrypto), hash signed server-side
- **Mobile apps** — key in secure enclave (iOS Secure Enclave, Android Keystore)
- **Cloud KMS** — AWS KMS, Azure Key Vault, Google Cloud KMS

Traditional signing libraries assume the private key is loaded into process memory. SimpleSign needed an architecture that works when the key is *external*.

**Decision:**
Two complementary patterns, both supporting AOT compatibility:

### 1. External Signer (`WithExternalSigner` + `IExternalSigner`)

For scenarios where the caller controls the full signing operation:

```csharp
.WithExternalSigner(cert, signer)
// signer : IExternalSigner
// ValueTask<ReadOnlyMemory<byte>> SignAsync(ExternalSigningRequest request, CancellationToken ct)
```

The signer receives an explicit `ExternalSigningRequest` carrying the payload bytes (CMS signed attributes for PAdES/CAdES; canonicalized XML `SignedInfo` for XAdES — distinguished by `PayloadKind`), the fully resolved hash algorithm, the signature algorithm OID, and the operation ID. It returns raw signature bytes (RSA PKCS#1 v1.5, ECDSA DER SEQUENCE { r, s }, or raw EdDSA bytes). Legacy delegates are adapted via `FuncExternalSigner`. Algorithm inference and compatibility validation happen at terminal execution, after all fluent calls, so configuration order cannot freeze mismatched digest/signature pairs. See ADR 0015.

### 2. Deferred Signing (`DeferredSigner.PrepareAsync` + `CompleteAsync`)

For web/mobile scenarios where server and client are separate:

```
Server                          Client
──────                          ──────
PrepareAsync(pdf, cert)
→ hashToSign + sessionData
                                  Sign(hashToSign)
                                  → raw signature
CompleteAsync(sessionData, sig)
→ signed.pdf
```

The `sessionData` is an opaque blob that encodes the PDF state between phases. The private key never travels over the network — only the hash digest.

**Consequences:**

- Private key isolation: key never enters SimpleSign process memory
- AOT-safe: `IExternalSigner` is a plain interface, no dynamic invocation
- `DeferredSigner` requires stateful session management (opaque blob approach chosen over session IDs to avoid server-side storage dependency)
- Algorithm inference: resolved at terminal execution from the certificate and configuration
- Timestamp hash: derived from the fully resolved signing hash
- External signer returns a raw signature — SimpleSign constructs the CMS/XML container
- Deferred session data is not encrypted (caller is responsible for secure storage)
- EdDSA (Ed25519/Ed448) only supported via external signer path (no BCL API for direct EdDSA signing)

**Alternatives considered:**

| Approach | Pros | Cons | Verdict |
|----------|------|------|---------|
| **Session IDs + server storage** | Simpler API | Requires persistent storage, cleanup complexity, scaling issues | Rejected |
| **Opaque blob (chosen)** | Stateless, no server storage | Blob can be large (includes full PDF state) | **Chosen** |
| **SignedInfo for pre-signed CMS** | Standards-compliant (RFC 5652) | More complex implementation, not supported by all HSMs | Rejected |

**Status:** This decision is accepted. Both patterns will remain the primary way to sign with external/remote keys.
