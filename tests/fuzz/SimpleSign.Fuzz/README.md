# SimpleSign.Fuzz

Fuzz testing harness for SimpleSign parsers using SharpFuzz (libFuzzer/AFL integration). Targets the most security-critical parsing code paths to discover crashes, hangs, and unexpected behavior from malformed inputs.

## Features

- 12 fuzz targets covering the parser entry points (PDF, CMS, OCSP, timestamps, XAdES, CAdES, HTML, CSS)
- Built-in mutation fuzzer that needs no external tools (`--mutate`), used in CI
- SharpFuzz integration with AFL for coverage-guided runs
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
| `html` | Full HTML → PDF conversion (tokenizer, CSS, layout, rendering); any exception is a finding |
| `css` | CSS parser, selector engine, and cascade |
| `xades-sign` | XAdES signing of arbitrary XML |
| `xades-validate` | XAdES validation of arbitrary XML |
| `cades-sign` | CAdES signing of arbitrary data |

## Usage

The harness has three modes:

```bash
# 1. Built-in mutation fuzzer (no external tools; what CI runs).
#    Mutates CorpusSeed/<target>, runs each input in-process, and stops a target on its first hang.
dotnet run -c Release -f net10.0 -- pdf --mutate 300                 # 5 minutes
dotnet run -c Release -f net10.0 -- html --mutate 300 --seed 42 --out ./Crashes --hang-seconds 20

# 2. Reproduce a finding (prints the unexpected exception, exit code 2)
dotnet run -c Release -f net10.0 -- pdf --input ./Crashes/crash-pdf-0123abcd.bin

# 3. Coverage-guided fuzzing with AFL (see "Building Instrumented Assemblies")
afl-fuzz -i CorpusSeed/pdf -o findings -- dotnet ./fuzz-publish/SimpleSign.Fuzz.dll pdf
```

`--mutate` writes each distinct finding to the output directory as `crash-<target>-<hash>.bin` or
`hang-<target>-<hash>.bin`, with a `.txt` report (exception and stack trace) next to it, and exits
with code 3 when it found anything. The `validator` and `xref` targets use the `pdf` seeds.

## Building Instrumented Assemblies

SharpFuzz requires instrumenting the target assembly DLLs before fuzzing:

```bash
# 1. Publish the fuzz harness
dotnet publish tests/fuzz/SimpleSign.Fuzz -c Release -f net8.0 -o ./fuzz-publish

# 2. Instrument the target assemblies (tool: dotnet tool install --global SharpFuzz.CommandLine)
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

All targets share one filter of exceptions that are expected from malformed input: the library's
own `SimpleSignException` family (for example `PdfStructureException`), `ArgumentException`,
`FormatException`, `CryptographicException`, `AsnContentException`, `InvalidDataException`,
`InvalidOperationException`, `OverflowException`, `NotSupportedException`, `IOException`,
`OperationCanceledException` and `ObjectDisposedException`.

`NullReferenceException`, `IndexOutOfRangeException`, `DivideByZeroException` and
`OutOfMemoryException` are deliberately **not** expected: each means a missing check (or an
allocation sized by untrusted input) and is reported as a finding. So is any input that runs
longer than the hang limit — quadratic parsing is a denial-of-service bug.

## Reporting Crashes

Security-sensitive crashes should be reported via [GitHub Security Advisories](https://github.com/eupassarin/SimpleSign/security/advisories) rather than public issues.

## CI Integration

The fuzz workflow runs weekly (Wednesday 05:00 UTC) and on demand. Each target runs the built-in
mutation fuzzer for 10 minutes; a finding fails that target's job and its inputs are uploaded as the
`fuzz-crashes-<target>` artifact. The workflow does not run on pull requests.

## See Also

- [Main README](../../../README.md)
- [Fuzz Workflow](../../../.github/workflows/fuzz.yml)
