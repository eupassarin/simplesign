# Observability: traces and metrics

SimpleSign publishes OpenTelemetry-compatible traces and metrics through the .NET BCL
(`System.Diagnostics.ActivitySource` and `System.Diagnostics.Metrics.Meter`), both named `SimpleSign`
(`SimpleSignTelemetry.Name`). No package is needed in SimpleSign, and nothing is measured until something listens:
with no listener, activities are not created and instruments are not recorded.

```csharp
builder.Services.AddOpenTelemetry()
    .WithTracing(t => t.AddSource(SimpleSignTelemetry.Name))
    .WithMetrics(m => m.AddMeter(SimpleSignTelemetry.Name));
```

The names are constants of `SimpleSignTelemetry` (`Activities`, `Instruments`, `Tags`, `Outcomes`).

## What is measured

| Activity | Counter / histogram (seconds) | Tags | Where |
|---|---|---|---|
| `SimpleSign.Sign` | `simplesign.signing.operations` / `simplesign.signing.duration` | `simplesign.format`, `simplesign.level.requested`, `simplesign.level.achieved`, `simplesign.outcome` (`success`, `refused`, `error`), `simplesign.reason` (`SigningErrorReason`) | Every PAdES, CAdES and XAdES signer, one-call, deferred and batch |
| `SimpleSign.Timestamp` | `simplesign.timestamp.requests` / `simplesign.timestamp.duration` | `server.address`, `simplesign.outcome` | Each request to a TSA (HTTP or RFC 3161 socket) |
| `SimpleSign.Ocsp` | `simplesign.ocsp.requests` / `simplesign.ocsp.duration` | `server.address`, `simplesign.outcome` (`success`, `revoked`, `error`) | Each OCSP request |
| `SimpleSign.Crl` | `simplesign.crl.fetches` / `simplesign.crl.duration` | `server.address`, `simplesign.outcome`, `simplesign.cache.hit` | Each CRL fetched, from a cache, HTTP or LDAP |
| `SimpleSign.TrustedList.Load` | `simplesign.trusted_list.loads` / `simplesign.trusted_list.duration` | `simplesign.outcome` (`refused` for a list that does not verify), `simplesign.trust_anchors` | `TrustedList.Load` and `DownloadAsync` |
| `SimpleSign.Validate` | `simplesign.validations` (one per signature) / `simplesign.validation.duration` (one per document) | `simplesign.format`, `simplesign.indication` (`Valid`, `Invalid`, `Indeterminate`; the duration's is the document's: one value or `Mixed`) | `PdfSignatureValidator.ValidateAsync`/`ValidateFieldAsync`, `CadesSignatureValidator.ValidateAsync`/`ValidateAllAsync`, `XadesSignatureValidator.ValidateAsync`/`ValidateAllAsync` |

The synchronous `Validate` methods of CAdES and XAdES (offline, no revocation) are not measured on their own.

## What is never recorded

Tags carry formats, levels, outcomes, reasons, indications and server host names only. Payloads, document hashes,
certificate subjects, issuers and serial numbers, full URLs (paths and queries may hold tokens) and personal data are
never recorded. Signing measurements read the format and levels from the audit event the signer builds; when no
audit sink is registered and something listens, that event is built for the measure only (it computes the SHA-256 of
the input), and nothing of it but the format and levels leaves.

Logs are separate: see [Structured logging](pades.md#structured-logging).
