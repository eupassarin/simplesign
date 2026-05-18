# SimpleSign.Fuzz

Fuzz testing harness for SimpleSign parsers using SharpFuzz (libFuzzer/AFL integration). Targets the most security-critical parsing code paths to discover crashes, hangs, and unexpected behavior from malformed inputs.

## Features

- 7 fuzz targets covering the main parser entry points
- SharpFuzz integration with libFuzzer
- Corpus seed files for guided fuzzing
- 5-second timeout protection per input
- Unified exception filter for all expected malformed-input errors
- Crash reproduction and triage support
- CI integration (weekly, non-blocking)

## Targets

| Target | Description |
|--------|-------------|
| `pdf` | PDF structure parser (xref, objects, signature fields) |
| `dss` | Document Security Store (DSS) extractor |
| `timestamp` | RFC 3161 timestamp token parser |
| `ocsp` | OCSP response parser |
| `cms` | CMS/PKCS#7 SignedData parser (certificates, signed attributes) |
| `validator` | Full PAdES validation pipeline (end-to-end) |
| `xref` | PDF xref and object locator (low-level structure) |

## Usage

```bash
# Run a specific fuzz target
dotnet run -c Release -f net8.0 -- pdf

# Run another target
dotnet run -c Release -f net8.0 -- cms

# Run the validator target
dotnet run -c Release -f net8.0 -- validator

# Run with a time limit (seconds, depends on fuzzer front-end)
dotnet run -c Release -f net8.0 -- ocsp --timeout 300

# Reproduce a crash
dotnet run -c Release -f net8.0 -- cms --input crash-file.bin
```

## Building Instrumented Assemblies

SharpFuzz requires instrumenting the target assembly DLLs before fuzzing:

```bash
# 1. Publish the fuzz harness
dotnet publish tests/fuzz/SimpleSign.Fuzz -c Release -f net8.0 -o ./fuzz-publish

# 2. Instrument the target assemblies
sharpfuzz ./fuzz-publish/SimpleSign.Core.dll
sharpfuzz ./fuzz-publish/SimpleSign.Pdf.dll
sharpfuzz ./fuzz-publish/SimpleSign.PAdES.dll

# 3. Run with AFL or libFuzzer (example with AFL)
afl-fuzz -i tests/fuzz/SimpleSign.Fuzz/CorpusSeed/pdf -o findings -- \
    dotnet ./fuzz-publish/SimpleSign.Fuzz.dll pdf
```

## Corpus Seeds

Seed files are located in the `CorpusSeed/` directory, organized by target:

| Directory | Contents |
|-----------|----------|
| `cms/` | CMS/PKCS#7 DER blobs, CRL files, malformed CMS |
| `dss/` | PDFs containing DSS dictionaries |
| `ocsp/` | OCSP response DER blobs |
| `pdf/` | Minimal PDFs, signed PDFs (PAdES-BES, PAdES-LTA) |
| `timestamp/` | RFC 3161 timestamp tokens and responses |

## Exception Handling

All targets use a unified exception filter that catches exceptions expected from malformed input (e.g., `FormatException`, `CryptographicException`, `AsnContentException`, `OverflowException`, `OutOfMemoryException`, `OperationCanceledException`). Only truly unexpected exceptions (segfaults, unhandled crashes) will surface as findings.

## Reporting Crashes

Security-sensitive crashes should be reported via [GitHub Security Advisories](https://github.com/eupassarin/SimpleSign/security/advisories) rather than public issues.

## CI Integration

The fuzz workflow runs weekly (Wednesday 05:00 UTC) with a 15-minute timeout per target. Failures are non-blocking — they generate artifacts for manual triage but do not fail the CI pipeline.

## See Also

- [Main README](../../README.md)
- [Fuzz Workflow](../../.github/workflows/fuzz.yml)
