# CLAUDE.md — Claude Code Project Instructions

## Project Overview

SimpleSign is a .NET library for PAdES (PDF Advanced Electronic Signatures). It signs, validates, and inspects digitally signed PDF documents following ETSI EN 319 142 standards.

**Key principle:** All cryptography uses `System.Security.Cryptography` from the .NET BCL — no BouncyCastle, no third-party crypto.

## Build & Test Commands

```bash
# Build everything
dotnet build

# Run all unit tests (~1,600 tests)
dotnet test tests/unit/

# Run specific test project
dotnet test tests/unit/SimpleSign.PAdES.Tests
dotnet test tests/unit/SimpleSign.Core.Tests
dotnet test tests/unit/SimpleSign.Pdf.Tests
dotnet test tests/unit/SimpleSign.Brasil.Tests
dotnet test tests/unit/SimpleSign.HtmlToPdf.Tests

# Integration tests (requires network for TSA/OCSP)
dotnet test tests/integration/

# Interop tests (cross-platform signature verification)
dotnet test tests/interop/

# AOT smoke test
dotnet publish tests/smoke/SimpleSign.AotSmokeTest -r linux-x64

# Mutation testing
dotnet stryker
```

## Architecture

```
src/
├── SimpleSign/             Meta-package
├── SimpleSign.Core/        Crypto primitives: CMS, TSA, OCSP, CRL, hashing
├── SimpleSign.Pdf/         PDF structure: xref, objects, incremental save, fields
├── SimpleSign.PAdES/       PAdES signing, validation, inspection (main package)
├── SimpleSign.CAdES/       standalone CMS/PKCS#7 signing & validation
├── SimpleSign.Brasil/      ICP-Brasil: chain validation, CPF/CNPJ, Gov.br
├── SimpleSign.HtmlToPdf/   HTML→PDF layout engine (independent, no signing)
├── SimpleSign.Cli/         CLI tool
└── SimpleSign.HostSigner/  Signing service host
```

## Coding Conventions

- **Target frameworks:** net8.0 and net10.0 (multi-target)
- **Language version:** C# 13
- **Nullable:** enabled globally
- **Analysis:** `AnalysisMode=All`, `TreatWarningsAsErrors=true`, `EnforceCodeStyleInBuild=true`
- **Style rules enforced as errors:** IDE0022 (expression bodies), IDE0011 (braces required on if/foreach), IDE0055 (formatting)
- **AOT compatible:** no reflection-based serialization, no `dynamic`
- **No unsafe code:** `AllowUnsafeBlocks=false`
- **Documentation:** all public APIs must have XML docs (`GenerateDocumentationFile=true`)

## Key Patterns

### Fluent Builder (public API)
```csharp
// Signing
await SimpleSigner.Document(pdf).WithCertificate(cert).WithTimestamp(url).SignAsync();

// With signature algorithm override (e.g., RSASSA-PSS)
await SimpleSigner.Document(pdf).WithCertificate(cert).WithSignatureAlgorithm(Oids.RsaPss).SignAsync();

// Deferred
var prepared = await DeferredSigner.PrepareAsync(pdf, cert);
await DeferredSigner.CompleteAsync(session, signature);

// Deferred builder
var builder = new DeferredSignerBuilder(pdfBytes, cert)
    .WithSignerName("Jane Doe")
    .WithTimestamp("http://timestamp.digicert.com");
var prepared = await builder.PrepareAsync();
var signedPdf = await builder.CompleteAsync(prepared.SessionData, signature);

// Batch
var batch = BatchSigner.Create(cert).WithTimestamp(url).Build();
byte[] signed = await batch.SignAsync(pdfBytes);
await foreach (var r in batch.SignAllAsync(inputs)) { }

// CAdES
await CadesSigner.Document(data).WithCertificate(cert).WithTimestamp(url).WithLevel(CadesLevel.Timestamped).SignAsync();
```

### Extension Points (interfaces)
- `ITrustAnchorProvider` — custom trust roots
- `IHttpClientProvider` — custom HTTP for TSA/OCSP/CRL
- `ICertificateCache` — cert caching
- `IChainValidationProvider` — custom chain logic

### Error Handling
- `SigningException` — signing failures
- `InvalidPdfException` — malformed PDF input
- Validation returns result objects (never throws for invalid signatures)

## Test Conventions

- Unit tests use xUnit
- Test fixtures in `tests/shared/SimpleSign.TestFixtures`
- Test helpers in `tests/shared/SimpleSign.TestHelpers`
- Test cert generation: use helpers, don't commit real certificates
- Name format: `MethodName_Condition_ExpectedResult`
- Each test class maps to one production class

## When Making Changes

1. Run `dotnet build` first — check it compiles clean (0 warnings, 0 errors)
2. Run relevant test project after changes
3. If modifying public API, update XML docs
4. If adding new public types, they must have XML documentation
5. Don't break AOT compatibility (check with smoke test if unsure)
6. Keep `Directory.Build.props` settings consistent

## NuGet Package Structure

```
SimpleSign.PAdES (most users install this)
  └── depends on SimpleSign.Pdf + SimpleSign.Core

SimpleSign.Brasil (adds ICP-Brasil on top of PAdES)
  └── depends on SimpleSign.PAdES

SimpleSign.HtmlToPdf (independent, no signing)
```
