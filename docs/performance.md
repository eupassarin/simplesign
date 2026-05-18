← [Back to README](../README.md)

# Performance

Benchmarks use [BenchmarkDotNet](https://benchmarkdotnet.org/) on **12th Gen Intel Core i7-1265U, .NET 8.0.27, Windows 11**.  
Full results live in [`BenchmarkDotNet.Artifacts/`](../BenchmarkDotNet.Artifacts/).

---

## Steady-State Signing (Short run — 3 iterations, 1 warmup)

Plain PAdES-B-B signature of a minimal PDF, no network calls:

| Configuration | Mean | vs Baseline | Allocated |
|---|---|---|---|
| Plain sign (PAdES-B-B) | **725 μs** | 1.00× | 499 KB |
| + visual appearance | 741 μs | 1.02× | 506 KB |
| + metadata (name/reason/location) | 705 μs | 0.97× | 500 KB |
| + appearance + metadata | 844 μs | 1.16× | 507 KB |
| + certification (DocMDP NoChanges) | 792 μs | 1.09× | 500 KB |
| + PDF/A preservation | 749 μs | 1.03× | 499 KB |

> Appearance is the only feature with measurable overhead (+2% standalone, +16% combined with metadata). All other options are cost-free.

---

## Incremental Signing (Cold start — JIT included)

Cost per signature added to the same PDF (the accumulating allocated memory reflects the growing document, not a leak):

| Signature | Mean | Allocated |
|---|---|---|
| 1st (unsigned → 1 sig) | 4.2 ms | 502 KB |
| 2nd (1 → 2 sigs) | 3.2 ms | 664 KB |
| 3rd (2 → 3 sigs) | 2.5 ms | 925 KB |
| 4th (3 → 4 sigs) | 2.7 ms | 1,122 KB |
| 5th (4 → 5 sigs) | 3.6 ms | 1,447 KB |

> Cold-start times include JIT compilation. Steady-state per-signature cost is ~725 μs (see table above). Memory scales with document size (each incremental update appends to the PDF).

---

## I/O Path Overhead (Cold start)

Comparing three input/output strategies for the same document:

| I/O Mode | Mean | vs byte[] | Allocated |
|---|---|---|---|
| `byte[]` → `byte[]` (baseline) | 47.5 ms | 1.00× | 500 KB |
| `MemoryStream` → `MemoryStream` | 55.8 ms | +18% | 466 KB |
| `FileStream` → `FileStream` | 56.4 ms | +19% | 382 KB |

> `FileStream` allocates ~24% less memory than `byte[]` by avoiding in-memory buffering — useful for large documents. The ~19% time overhead is stream seek/read cost.

---

## Concurrency Scaling

| Workload | Time | vs Sequential |
|---|---|---|
| Sequential (32 signs) | 476 ms | 1.00× |
| 8 concurrent tasks (32 signs) | 450 ms | 0.94× |
| 16 concurrent tasks (32 signs) | 466 ms | 0.98× |
| 32 concurrent tasks (32 signs) | 440 ms | 0.92× |

> Signing is stateless — each call creates an isolated context. No locks on the hot path; concurrency scales linearly with available cores.

---

## Running Benchmarks

```bash
cd bench
dotnet run -c Release -- --job short --runtimes net8.0
```

Filter to a specific suite:

```bash
dotnet run -c Release -- --filter "*Feature*" --job short
dotnet run -c Release -- --filter "*Stream*" --job short
dotnet run -c Release -- --filter "*Incremental*" --job short
```
