# ADR 0008: HTTP Client Provider Pattern

**Status:** Accepted

**Context:**
SimpleSign performs HTTP operations for two distinct concerns:

- **TSA** (Time-Stamp Authority) — signature timestamps and archival DocTimeStamps
- **Revocation** — OCSP and CRL fetches for certificate validation

These operations may require different `HttpClient` configurations:

- TSA often needs **authentication** (API key, bearer token, client certificate)
- Revocation typically uses **anonymous** HTTP (public OCSP responders, CRL distribution points)
- ASP.NET Core users want `IHttpClientFactory` integration for connection pooling, DNS refresh, and resilience handlers
- AOT deployments need a simple zero-configuration default

The initial implementation used a single `HttpClient` for all operations, which leaked TSA authentication to revocation calls.

**Decision:**
Three-layer architecture:

### 1. `IHttpClientProvider` interface

```csharp
public interface IHttpClientProvider
{
    HttpClient GetClient();
}
```

Single-method interface — intentionally minimal to be AOT-safe and trimmable.

### 2. Two built-in implementations

Two built-in implementations are provided: `DefaultHttpClientProvider` (static singleton for simple scenarios) and `HttpClientFactoryProvider` (ASP.NET Core DI, wraps `IHttpClientFactory`).

### 3. Scoped provider slots with deterministic precedence

Since v0.8.0, all formats use `IHttpClientProvider` with a builder-wide fallback and optional operation-scoped overrides carried inside the shared option values (see ADR 0015):

```text
Archive timestamp endpoint:
  ArchiveTimestampOptions.Endpoint -> TimestampOptions.Endpoint

Signature timestamp client:
  TimestampOptions.HttpClientProvider -> builder-wide provider

Certificate / AIA / OCSP / CRL retrieval:
  LongTermValidationOptions.HttpClientProvider -> builder-wide provider

Archive timestamp client:
  ArchiveTimestampOptions.HttpClientProvider -> TimestampOptions.HttpClientProvider -> builder-wide provider
```

The builder-wide provider is set via `WithHttpClientProvider(provider)` and defaults to `DefaultHttpClientProvider`. `SingleClientProvider` adapts a non-owned `HttpClient` (e.g. for proxies, testing, mTLS). This separation prevents TSA authentication from leaking to revocation calls.

### Lazy resolution

`IHttpClientProvider.GetClient()` is called at **signing time**, not at configuration time. This enables factory-style providers that create fresh clients per call (e.g., rotating bearer tokens, certificate authentication per operation). Caller-supplied providers and clients are never disposed by the signer.

### DI auto-detection

`AddSimpleSign()` checks for `IHttpClientFactory` in the DI container. When present, it wires `HttpClientFactoryProvider` automatically — no manual adapter needed.

**Consequences:**

- TSA and revocation HTTP clients are fully independent (auth isolation)
- DI users get `IHttpClientFactory` benefits automatically
- Simple console apps work with zero configuration (static default)
- AOT-safe: no reflection-based DI inspection, minimal interface surface
- Lazy resolution enables dynamic credential rotation
- Provider is preserved through all builder methods (carried in the dependency bundle)
- Breaking change in 0.5.0: `WithTimestamp(url, httpClient)` scope narrowed to TSA only
- Breaking change in 0.8.0: direct `HttpClient` methods (`WithHttpClient`, `WithRevocationHttpClient`, `WithTimestamp(url, client)`) replaced by the provider model above

**Alternatives considered:**

| Approach | Pros | Cons | Verdict |
|----------|------|------|---------|
| **Single HttpClient** | Simple | Auth leakage, no DI integration | Rejected (0.5.0 change) |
| **Per-operation HttpClient parameters** | Explicit | Verbose API, 4+ client parameters | Rejected |
| **Provider pattern (chosen)** | Flexible, DI-native, AOT-safe | Indirection cost, docs needed | **Chosen** |
| **`HttpClientFactory` only** | DI standard | Requires ASP.NET Core, not AOT-friendly | Rejected |

**Status:** This decision is accepted. The provider pattern is the primary mechanism for HTTP client configuration.
