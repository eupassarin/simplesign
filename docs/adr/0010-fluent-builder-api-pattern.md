# ADR 0010: Fluent Builder API Pattern

**Status:** Accepted (superseded in part by ADR 0015)

**Context:**
PAdES signing requires configuring multiple independent concerns: the input document, signer certificate, timestamp authority, appearance, signature field options, LTV archival, metadata attributes, and output format. Traditional approaches include:

- **Constructor injection** — many optional parameters → telescoping constructors, confusing positional arguments
- **Options object** — passes a single mutable configuration object through the pipeline → callers can't tell which options are required vs. optional, and mutability allows stale reads
- **XML/JSON config files** — external configuration, compile-time type safety lost

The library's consumers include ASP.NET web APIs (DI, dependency injection), console CLIs, Windows tray apps (HostSigner), and cloud functions (AOT-compiled). The API must be intuitive, immutable, thread-safe, and AOT-compatible.

**Decision:**
An **immutable fluent builder** (`PadesSignerBuilder`) accessed through a **static factory** (`PadesSigner`).

### 1. Static factory entry point

`PadesSigner` is a sealed class with a private constructor — it is never instantiated. It exposes three static overloads:

```csharp
var b1 = PadesSigner.Document(pdfBytes);               // byte[]
var b2 = PadesSigner.Document(stream);                  // seekable Stream
var b3 = await PadesSigner.DocumentAsync(path);         // file path
```

All three return a new `PadesSignerBuilder` wrapping the PDF in a `MemoryStream` (byte-array inputs are snapshotted; a caller-supplied stream is retained and makes the builder single-execution). This is the sole public entry point — no constructor access. The same pattern is used by `CadesSigner.Document` and `XadesSigner.Document`.

### 2. Immutable builder pattern

`PadesSignerBuilder` holds **one immutable options record** (`PadesSigningOptions`) plus an injected **dependency bundle** (`PadesDependencies`: TSA factory, LTV embedder, logger, HTTP provider). Every `With*` method returns a **new instance** using a record `with` expression, so injected collaborators survive every fluent call:

```csharp
internal sealed record PadesSigningOptions(
    SigningCredential? Credential,
    HashAlgorithmName HashAlgorithm,
    bool HashAlgorithmExplicitlySet,
    string? SignatureAlgorithmOid,
    DateTimeOffset? SigningTime,
    SignatureFieldOptions Field,
    SignatureMetadata? Metadata,
    bool PadesAttributes,
    bool EnforcePdfA,
    string? OperationId,
    AdesBaselineProfile Profile,
    IReadOnlyList<ICountryExtension> CountryExtensions,
    PadesDependencies Dependencies);

public PadesSignerBuilder WithOperationId(string operationId) =>
    With(_options with { OperationId = operationId });
```

Credentials are a discriminated union (`LocalCredential` / `ExternalCredential`); `WithCertificate` and `WithExternalSigner` replace the complete credential, so no nullable "clear" semantics are needed. Collections are defensively copied at configuration time.

**Example chain (each step creates a new object):**
```csharp
var signed = await PadesSigner.Document(pdf)
    .WithCertificate(cert)
    .WithLevel(AdesBaselineProfile.LongTerm(
        new TimestampOptions(new Uri("http://tsa.example")),
        new LongTermValidationOptions()))
    .WithAppearance(new SignatureAppearance { AutoPosition = true })
    .SignAsync();
```

### 3. Configuration methods (all on `PadesSignerBuilder`, not extensions)

Methods are grouped by concern: credential, baseline profile (`WithLevel`), HTTP provider, signing algorithm, metadata, appearance, PDF/A conformance, SubFilter selection, and advanced options (existing field targeting, operation IDs). Level configuration is exactly one call — see ADR 0015.

The only extension method in a separate assembly is `SignerBuilderBrasilExtensions.WithAdvancedSignature()` in `SimpleSign.Brasil`.

### 4. Terminal methods

Three overloads: stream-target (`SignAsync(stream, ct)` returns `Task`), byte-array (`SignAsync(ct)` returns `Task<byte[]>`), and detailed (`SignWithDetailsAsync(ct)` returns `Task<PadesSigningResult>` implementing `ISigningResult` with requested/achieved levels, actual feature flags, and structured warnings).

### 5. Local vs. external signing

**Local:** certificate has private key → `CmsSignatureBuilder.Build()` signs the CMS SignedData directly using the BCL key.

**External:** the caller implements `IExternalSigner` and receives an explicit `ExternalSigningRequest` (payload bytes, resolved hash algorithm, signature algorithm OID, payload kind, operation ID):

```csharp
.WithExternalSigner(cert, signer)
// signer implements IExternalSigner; legacy delegates can use FuncExternalSigner
```

Algorithm resolution happens at terminal execution, so builder call order does not affect the resolved digest/signature pair. See ADR 0006 and ADR 0015.

### 6. Two-phase deferred signing (`DeferredSigner`)

For web/mobile scenarios where the private key is on a different machine:

```csharp
// Phase 1 — server
var prepared = await DeferredSigner.PrepareAsync(pdf, cert);
sessionDb.Save(prepared.SessionData);
return prepared.HashToSign;  // send to client

// Phase 2 — client signs (browser, mobile)
byte[] rawSig = await webSigner.SignAsync(prepared.HashToSign);

// Phase 2b — server completes
var signedPdf = await DeferredSigner.CompleteAsync(sessionData, rawSig);
```

`DeferredSigningSession` serialises to JSON with optional HMAC integrity check. AOT-safe via `JsonSerializerContext`.

### 7. Validation upfront

Before any PDF modification, `SignCoreAsync` validates: credential presence, private-key availability (local signing), certificate expiry, DocMDP lock, PDF/A compatibility (when enabled), algorithm compatibility, and level dependencies (the baseline profile factories make invalid level combinations unrepresentable). Level-enrichment failures are strict by default (see ADR 0015).

**Consequences:**
- Immutable configuration state: all builder options live in one record; each `With*` starts from the previous state
- Injected collaborators survive every fluent call (dependency bundle is carried, not recreated)
- AOT compatible: no dynamic invocation, no `Expression` trees, no reflection
- Single obvious way to create a signer: `PadesSigner.Document()` → `PadesSignerBuilder` → terminal method
- Allocation overhead per `With*` call (record copy) — negligible for typical usage
- Stream-backed builders are single-execution and not safe for concurrent terminal calls; byte-array builders snapshot their input
- `BatchSignerBuilder` also uses immutable `With(...)` helpers returning new instances (the historical note describing it as mutable was inaccurate)
- Validation upfront prevents late failures after PDF modification
- `DeferredSigner` requires session state management; opaque blob approach avoids server-side storage but blobs can be large

**Alternatives considered:**

| Approach | Pros | Cons | Verdict |
|---|---|---|---|
| **Immutable fluent builder (chosen)** | Thread-safe, AOT-safe, self-documenting | Allocation overhead per step | **Chosen** |
| **Mutable builder** | Zero allocation, simpler implementation | Thread-unsafe, stale read bugs | Rejected |
| **Options object** | Familiar to .NET devs | No method-chaining discoverability | Rejected (removed for CAdES/XAdES in 0.8.0) |
| **Decorator pattern** | Flexible runtime composition | Complex type hierarchy, hard to trace | Rejected |

**Status:** Accepted. The immutable fluent builder is the canonical API pattern. `PadesSignerBuilder` will not become mutable. `DeferredSigner` and `DeferredSignerBuilder` extend the same pattern to two-phase signing. ADR 0015 refines the cross-format contract built on this pattern.
