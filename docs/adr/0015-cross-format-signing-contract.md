# ADR 0015: Cross-Format Signing Contract (PAdES, CAdES, XAdES)

**Status:** Accepted (v0.8.0)

**Context:**
SimpleSign exposes three signing APIs — PAdES, CAdES, and XAdES — that had converged on the same broad shape (`static entry point → immutable fluent builder → async terminal method`) but with inconsistent contracts:

- PAdES expressed conformance levels through ordered capability calls (`WithTimestamp` → `WithLtv` → `WithArchivalTimestamp`), while CAdES/XAdES combined a level enum with a side-effecting `WithTimestamp`. Call order changed behavior, and B-LT/B-LTA could be requested without their mandatory dependencies.
- Result flags partly described requested configuration rather than the produced artifact (`DssEmbedded = true` on basic PAdES signatures; CAdES/XAdES `LtvDataEmbedded` derived from the requested enum).
- The nullable copy-helper in the builders could not distinguish "leave unchanged" from "clear", and injected collaborators (TSA factory, LTV embedder, CMS parser) were discarded by the first fluent clone.
- External signing used an opaque `Func<byte[], Task<byte[]>>` whose payload meaning differed per format, with algorithm inference frozen at configuration time.
- HTTP client methods had three different meanings across formats.

**Decision:**
Keep the immutable fluent-builder architecture, but define it as a real cross-format contract:

1. **One strongly typed baseline profile is the source of truth.** `AdesBaselineProfile` (in `SimpleSign.Core`) carries the requested `AdesBaselineLevel` and all level-specific dependencies. Its factories — `Basic()`, `Timestamped(TimestampOptions)`, `LongTerm(TimestampOptions, LongTermValidationOptions)`, `Archive(TimestampOptions, LongTermValidationOptions, ArchiveTimestampOptions?)` — encode the cumulative B-B → B-T → B-LT → B-LTA structure, making invalid level combinations unrepresentable. `WithLevel(profile)` replaces the complete profile atomically; no other method changes the level.

2. **The requested level is a postcondition.** Successful strict signing reports the requested level as achieved. Failures adding level-enrichment material (signature timestamp, long-term validation material, archive timestamp) throw `SigningException` unless the profile explicitly opts into `SigningLevelFailureBehavior.ReturnLowerLevel`, in which case `SignWithDetailsAsync` reports requested level, achieved level, and structured warnings. The byte-only `SignAsync` rejects best-effort profiles.

3. **Results report observed facts.** All three result types implement `ISigningResult` (`RequestedLevel`, `AchievedLevel`, `HasSignatureTimestamp`, `HasLongTermValidationMaterial`, `HasArchiveTimestamp`, `Warnings`). Feature flags are derived from the produced artifact (e.g., PAdES B-LT requires DSS certificate **and** revocation values), never from the requested enum. `SigningWarning` carries a stable machine-readable code.

4. **Credentials are mutually exclusive states.** `WithCertificate` and `WithExternalSigner` each replace the complete internal credential. External signers implement `IExternalSigner` and receive an explicit `ExternalSigningRequest` (payload bytes, resolved hash algorithm, signature algorithm OID, payload kind, operation ID). Algorithm resolution happens at terminal execution, so builder call order cannot freeze mismatched digest/OID pairs. `FuncExternalSigner` adapts legacy delegates.

5. **HTTP access goes through `IHttpClientProvider`** with deterministic scoped-over-builder-wide precedence: `TimestampOptions`/`LongTermValidationOptions`/`ArchiveTimestampOptions` providers fall back to the builder-wide `WithHttpClientProvider`, which defaults to `DefaultHttpClientProvider`. Providers are resolved lazily at operation time; caller-supplied providers/clients are never disposed. `SingleClientProvider` adapts a non-owned `HttpClient`.

6. **Mechanically safe immutable state.** Builders hold one state record plus an injected dependency bundle; fluent calls use record `with` expressions, so injected collaborators survive every call and collections are defensively copied. Input ownership is documented (byte arrays are snapshotted; stream-backed builders are single-execution).

7. **Format-qualified names.** PAdES entry/builder are `PadesSigner`/`PadesSignerBuilder`. CAdES and XAdES keep their qualified names. Format-only capabilities (PDF fields/appearances, XAdES packaging forms, CAdES content type) remain on their native builders; there is no public common builder base class.

**Consequences:**
- Strict level guarantees can change observable behavior: B-LT/B-LTA requests that previously "succeeded" without complete material now throw (or explicitly downgrade).
- A shared contract vocabulary (`AdesBaselineProfile`, `ISigningResult`, `SigningWarning`, `IExternalSigner`, `SigningErrorReason`) lives in `SimpleSign.Core` and is used by all three format packages.
- The legacy capability API (`WithTimestamp`/`WithLtv`/`WithArchivalTimestamp`, enum-based `WithLevel`, static options shortcuts, `SimpleSigner`/`SignerBuilder`) was removed in v0.8.0; see `docs/migration/v0.7-to-v0.8.md`.
- Cross-format invariants are guarded by `tests/unit/SimpleSign.Contracts.Tests`.
- The AOT constraint is preserved: no reflection, no generic base builder, minimal interfaces.

**Alternatives considered:**

| Approach | Pros | Cons | Verdict |
|---|---|---|---|
| **One universal signer builder** | Single entry point | PDF/XML/CMS differ too much; lowest-common-denominator API | Rejected |
| **Three composable level methods (status quo)** | Familiar | Order-sensitive, contradictory state, silent B-LT without B-T | Rejected |
| **Shared baseline profile (chosen)** | Cumulative dependencies encoded in types; level is a postcondition; one vocabulary | Migration cost; new concepts to learn | **Chosen** |
| **Per-format result types only** | Format-native detail | No machine-readable cross-format reporting | Rejected (interface added instead) |
