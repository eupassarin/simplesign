# SimpleSign.Fuzz

Fuzz testing harness for SimpleSign parsers using SharpFuzz (libFuzzer/AFL integration). Targets the most security-critical parsing code paths to discover crashes, hangs, and unexpected behavior from malformed inputs.

## Features

- 6 fuzz targets covering all parser entry points
- SharpFuzz integration with libFuzzer
- Corpus seed files for guided fuzzing
- Crash reproduction and triage support
- CI integration (weekly, non-blocking)

## Targets

| Target | Description |
|--------|-------------|
| `cms` | CMS/PKCS#7 SignedData parser |
| `pdf` | PDF structure parser (xref, objects) |
| `xml` | XAdES XML signature parser |
| `dss` | Document Security Store (DSS) extractor |
| `timestamp` | RFC 3161 timestamp token parser |
| `ocsp` | OCSP response parser |

## Usage

```bash
# Run a specific fuzz target
dotnet run -c Release -- cms

# Run with a time limit (seconds)
dotnet run -c Release -- pdf --timeout 300

# Reproduce a crash
dotnet run -c Release -- cms --input crash-file.bin
```

## Corpus Seeds

Seed files are located in the `CorpusSeed/` directory, organized by target. These provide initial valid inputs to guide the fuzzer toward interesting code paths.

## Reporting Crashes

Security-sensitive crashes should be reported via [GitHub Security Advisories](https://github.com/eupassarin/SimpleSign/security/advisories) rather than public issues.

## CI Integration

The fuzz workflow runs weekly (Wednesday 05:00 UTC) with a 15-minute timeout per target. Failures are non-blocking — they generate artifacts for manual triage but do not fail the CI pipeline.

## See Also

- [Main README](../../README.md)
- [Fuzz Workflow](../../.github/workflows/fuzz.yml)
