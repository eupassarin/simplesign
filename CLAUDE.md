# CLAUDE.md — Claude Code Project Instructions

## Project Overview

SimpleSign is a .NET library for PAdES, CAdES and XAdES signatures (ETSI EN 319 142 / 319 122 / 319 132): it signs, validates and inspects them.

**Key principle:** All cryptography uses `System.Security.Cryptography` from the .NET BCL — no BouncyCastle, no third-party crypto.

## Build & Test Commands

```bash
# Build everything
dotnet build

# Run every test project (what CI runs)
dotnet test SimpleSign.sln --filter "Category!=Stress"

# Run specific test project
dotnet test tests/unit/Formats/SimpleSign.PAdES.Tests
dotnet test tests/unit/Core/SimpleSign.Core.Tests
dotnet test tests/unit/TrustFrameworks/Brazil/IcpBrasil/SimpleSign.Brazil.IcpBrasil.Tests
dotnet test tests/unit/Extras/SimpleSign.HtmlToPdf.Tests
dotnet test tests/unit/TrustFrameworks/Peru/Iofe/SimpleSign.Peru.Iofe.Tests

# Integration tests (requires network for TSA/OCSP)
dotnet test tests/integration/SimpleSign.Integration.Tests

# CLI tests
dotnet test tests/unit/Apps/SimpleSign.Cli.Tests

# TestBench tests need a running Sandbox (skipped without one; CI starts it)
dotnet run --project src/Apps/SimpleSign.Sandbox -- --ephemeral
dotnet test tests/unit/Apps/SimpleSign.TestBench.Tests

# AOT smoke test
dotnet publish tests/smoke/SimpleSign.AotSmokeTest -r linux-x64
```

## Architecture

```
src/
├── Core/
│   └── SimpleSign.Core/        Crypto primitives: CMS, TSA, OCSP, CRL (HTTP; LDAP opt-in), hashing, signing/validation policies, trust store
├── Formats/
│   ├── SimpleSign.PAdES/       PAdES signing, validation, inspection (main package); Pdf/ = PDF parser
│   ├── SimpleSign.CAdES/       standalone CMS/PKCS#7 signing & validation
│   ├── SimpleSign.XAdES/       XML signatures; ETSI trusted lists (TrustedList)
│   └── SimpleSign/             Meta-package
├── TrustFrameworks/
│   ├── Brazil/
│   │   ├── SimpleSign.Brazil/                  shared: CPF/CNPJ, Lei 14.063, AEA manifest, VALIDAR
│   │   ├── IcpBrasil/
│   │   │   ├── SimpleSign.Brazil.IcpBrasil/        ICP-Brasil: chain validation, roots, policies, ACT timestamps
│   │   │   ├── SimpleSign.Brazil.IcpBrasil.Xades/  ICP-Brasil XAdES policies
│   │   │   └── SimpleSign.Brazil.Fiscal/           XML-DSig for NF-e, CT-e, eSocial…
│   │   └── GovBr/
│   │       └── SimpleSign.Brazil.GovBr/            Gov.br: chain validation, assurance level
│   ├── Europe/Eidas/                   planned (README only)
│   └── Peru/Iofe/
│       └── SimpleSign.Peru.Iofe/        IOFE (Peru): anchors from INDECOPI's trusted list, INDECOPI policies
├── Signers/
│   ├── SimpleSign.Signers.Pkcs11/  sign through a PKCS#11 driver (tokens, HSMs)
│   └── SimpleSign.Signers.Cloud/   cloud certificates: ICP-Brasil PSC and CSC v2
├── Extras/
│   └── SimpleSign.HtmlToPdf/   HTML→PDF layout engine (independent, no signing)
└── Apps/
    ├── SimpleSign.Cli/         CLI tool
    ├── SimpleSign.Agent/       Avalonia tray app + window (pt-BR/en-US, TestBench look, Native AOT): local signing agent (HTTP on 127.0.0.1)
    ├── SimpleSign.TestBench/   Local web app (ASP.NET Core + React/shadcn in web/) to try every signing option (real network + a connected Sandbox);
    │                           its Certification page runs certification scripts (docs/certification-scripts) and exports the evidence
    └── SimpleSign.Sandbox/     Test PKI on real endpoints (CRL over HTTP/HTTPS/LDAP, OCSP, TSA, CSC) and failures to switch on; API only (its UI is the TestBench's Sandbox control)
```

Internal infrastructure (logs, DER helpers, revocation plumbing) lives in each project's `Internal/` folder (ADR 0018).

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
// PAdES signing
await PadesSigner.Document(pdf).WithCertificate(cert).WithLevel(AdesBaselineProfile.Basic()).SignAsync();

// With signature algorithm override (e.g., RSASSA-PSS)
await PadesSigner.Document(pdf).WithCertificate(cert).WithSignatureAlgorithm(Oids.RsaPss).SignAsync();

// Deferred
var builder = DeferredSigner.Document(pdfBytes)
    .WithCertificate(cert)
    .WithSessionIntegrityKey(sessionIntegrityKey)
    .WithLevel(AdesBaselineProfile.Basic());
var prepared = await builder.PrepareAsync();
var signedPdf = await DeferredSigner.Resume(prepared.SessionData, sessionIntegrityKey)
    .CompleteAsync(signature);

// Batch
var batch = BatchSigner.Create(cert)
    .WithLevel(AdesBaselineProfile.Basic())
    .Build();
byte[] signed = await batch.SignAsync(pdfBytes);
await foreach (var r in batch.SignAllAsync(inputs)) { }

// CAdES
await CadesSigner.Document(data).WithCertificate(cert)
    .WithLevel(AdesBaselineProfile.Timestamped(new TimestampOptions(new Uri(url))))
    .SignAsync();
```

### Extension Points (interfaces)
- `ITrustAnchorProvider` — custom trust roots
- `IHttpClientProvider` — custom HTTP for TSA/OCSP/CRL
- `ICertificateCache` — cert caching
- `IChainValidationProvider` — custom chain logic
- `IChainRevocationChecker` / `IRevocationCache` — revocation of a whole chain, CRL cache
- `ICountryExtension` — country packages (ICP-Brasil, Gov.br, IOFE)
- `DirectoryTrustAnchorProvider`, `TrustedList` — ready-made `ITrustAnchorProvider`s

### Error Handling
- `SigningException` — signing failures; `Reason` (`SigningErrorReason`) says which check of the `SigningPolicy` refused the certificate, key or algorithm (`KeyUsageNotPermitted`, `KeyTooWeak`, `ChainCertificateNotValid`, `CertificateRevoked`…)
- `InvalidPdfException` — malformed PDF input
- Validation returns result objects (never throws for invalid signatures)

## Test Conventions

- Unit tests use xUnit
- `tests/unit/` mirrors `src/`: `src/Formats/SimpleSign.CAdES` is tested by
  `tests/unit/Formats/SimpleSign.CAdES.Tests` (the CLI too: `tests/unit/Apps/SimpleSign.Cli.Tests`).
  Every test project is in `SimpleSign.sln`.
- Every test class has `[Trait("Category", …)]`: `Unit` by default, `Contract` in Contracts.Tests,
  `Integration` (network), `Stress` (excluded from the regular CI run)
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
  └── depends on SimpleSign.Core (the PDF parser is part of it, namespace SimpleSign.PAdES.Pdf)

SimpleSign.Brazil (shared Brazilian building blocks)
  └── depends on SimpleSign.PAdES + SimpleSign.CAdES — public API only, no InternalsVisibleTo from them

SimpleSign.Brazil.IcpBrasil / SimpleSign.Brazil.GovBr (one ICountryExtension each)
  └── depend on SimpleSign.Brazil only, never on each other (Fiscal and IcpBrasil.Xades build on IcpBrasil)

SimpleSign.Peru.Iofe (one ICountryExtension)
  └── depends on SimpleSign.Core + SimpleSign.XAdES — public API only

SimpleSign.CAdES / SimpleSign.XAdES
  └── each depends on SimpleSign.Core only

SimpleSign.HtmlToPdf (independent, no signing)
```
