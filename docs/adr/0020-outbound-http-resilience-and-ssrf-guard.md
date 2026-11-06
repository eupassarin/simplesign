# ADR 0020: Outbound HTTP — Retries and SSRF Guard

**Status:** Accepted

**Context:**
Signing and validation reach the network on behalf of whoever supplied the input:
- **TSA requests** go to a URL from the caller's options.
- **OCSP, CRL and AIA `caIssuers` downloads** go to URLs read from the certificates inside the document being signed or validated.
- **Country packages** download trust roots, intermediates and signature policies (`SimpleSign.Brasil`).

Two problems follow:
1. **Untrusted URLs.** A validation service that accepts uploaded PDFs would fetch whatever URL an attacker puts in a certificate's CRL distribution point or AIA extension. This is a classic SSRF path to `localhost`, internal services or cloud metadata at `169.254.169.254`.
2. **Flaky endpoints.** Public TSAs, OCSP responders and CRL servers fail transiently. A single failed fetch can turn a B-LT signature into an error or a valid signature into `Indeterminate`.

ADR 0008 decided **which** `HttpClient` is used (`IHttpClientProvider`). This ADR decides **what every outbound request must go through**.

**Decision:**
All library-initiated HTTP goes through `ResilientHttp` (`src/SimpleSign.Core/Http`), which applies two rules before and around the request.

1. **SSRF guard (`UrlValidator`).**
   - The URL must be absolute `http` or `https`.
   - The host is resolved and **every** resolved address is checked, which defeats DNS rebinding.
   - Loopback, RFC 1918 private ranges, link-local (`169.254.0.0/16`, IPv6 link-local) and IPv4-mapped IPv6 forms of those are refused.
   - A blocked GET returns `null` with a log entry, so validation degrades to "revocation unknown". A blocked POST throws.
   - `TimestampClient` checks the TSA URL at construction, including `tcp://` endpoints (RFC 3161 §3.3), so a bad TSA fails fast.
2. **Retries (Polly).**
   - Up to 3 retries with exponential backoff from 200 ms with jitter.
   - Only `HttpRequestException`, timeouts and HTTP 5xx are retried. 4xx responses are returned immediately.
   - The shared clients use a 30 s request timeout. `X509Chain` URL retrieval gets `ResilientHttp.DefaultChainRetrievalTimeout` (15 s).
3. **Public for extensions.** `ResilientHttp.GetBytesAsync(HttpClient, Uri, …)` is public, so country packages download through the same guard and retry policy instead of calling `HttpClient` directly (ADR 0018).
4. **Cloud signers are separate.** `SimpleSign.Signers.Cloud` talks to a service the application configured, not to URLs from documents. It requires HTTPS base URIs (HTTP only for loopback, for local test servers) and does not use the SSRF guard (ADR 0019).

**Consequences:**
- Validating hostile documents cannot make SimpleSign call internal endpoints, whichever `HttpClient` the caller injects.
- TSAs, OCSP responders and CRL servers on private networks are **not reachable**, and there is no opt-out today. Deployments that need an internal TSA or responder must expose it on a public address, or the guard must gain an explicit allow-list (a future, deliberate API change).
- `X509Chain`'s own online retrieval is done by the operating system and is outside this guard. SimpleSign limits it with the chain retrieval timeout and prefers its own AIA and revocation downloads.
- Polly is a runtime dependency of `SimpleSign.Core`. It is AOT compatible and used only through `ResilientHttp`.
- Transient failures cost up to roughly 1.4 s of backoff before a fetch is declared failed.

**Alternatives considered:**

| Approach | Pros | Cons | Verdict |
|---|---|---|---|
| **No guard; trust the injected `HttpClient`** | Simplest; caller decides | Every server-side validator would need its own SSRF defense; most would not have one | Rejected |
| **Guard on the URL string only** | No DNS lookup | Bypassed by DNS names that resolve to private addresses | Rejected (sync `IsSafeUrl` kept only for constructor checks) |
| **Resolve-and-check guard + retries (chosen)** | Safe by default; consistent behavior for TSA, OCSP, CRL, AIA and extensions | Private-network services unreachable without a future allow-list | **Chosen** |
| **`Microsoft.Extensions.Http.Resilience` handlers** | Standard in ASP.NET Core | Only applies to factory-created clients; not to clients users pass directly | Rejected |
