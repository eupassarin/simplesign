# CLAUDE.md — Claude Code Project Instructions

## Project Overview

SimpleSign is a .NET library for PAdES, CAdES and XAdES signatures (ETSI EN 319 142 / 319 122 / 319 132): it signs, validates and inspects them.

**Key principle:** All cryptography uses `System.Security.Cryptography` from the .NET BCL — no BouncyCastle, no third-party crypto.

## Build & Test Commands

```bash
# Build everything
dotnet build

# Run every test project (what CI runs)
dotnet test SimpleSign.sln --filter "Category!=Stress&Category!=VeraPdf&Category!=Interop&Category!=EtsiChecker"

# PDF/A preservation checked by veraPDF (Docker: docker pull the image in VeraPdf.cs; or SIMPLESIGN_VERAPDF=<local CLI>)
dotnet test tests/integration/SimpleSign.VeraPdf.Tests --framework net10.0

# Interop with qpdf, pyHanko, OpenSSL 3, xmlsec1 (on the PATH, or SIMPLESIGN_QPDF/_OPENSSL/_XMLSEC1/_PYTHON;
# pyHanko: pip install -r tests/integration/SimpleSign.Interop.Tests/tools/requirements.txt)
dotnet test tests/integration/SimpleSign.Interop.Tests --framework net10.0

# Structure checked by the ETSI Signatures Conformance Checker (needs an account there: SIMPLESIGN_ETSI_USER/_PASSWORD;
# writes the reports to docs/conformance/etsi-checker; SIMPLESIGN_ETSI_CORPUS=<dir> only writes the samples)
dotnet test tests/integration/SimpleSign.EtsiChecker.Tests --framework net10.0

# Run specific test project
dotnet test tests/unit/Formats/SimpleSign.PAdES.Tests
dotnet test tests/unit/Core/SimpleSign.Core.Tests
dotnet test tests/unit/Extensions/Brazil/IcpBrasil/SimpleSign.Brazil.IcpBrasil.Tests
dotnet test tests/unit/Extras/SimpleSign.HtmlToPdf.Tests
dotnet test tests/unit/Extensions/Peru/Iofe/SimpleSign.Peru.Iofe.Tests

# PKCS#11 on a SoftHSM2 token, in Docker (Signers.Pkcs11.Tests; skipped without SOFTHSM2_MODULE)
scripts/tests/pkcs11.sh

# Integration tests (requires network for TSA/OCSP)
dotnet test tests/integration/SimpleSign.Integration.Tests

# Adobe's real AATL against the bundled Adobe root (network)
dotnet test tests/unit/Extensions/Adobe/Aatl/SimpleSign.Adobe.Aatl.Tests --filter "Category=Integration"

# CLI tests (the CLI and its extension mechanism; each extension's are next to its framework's:
# tests/unit/Extensions/{Brazil/SimpleSign.Brazil.Cli.Tests, Europe/Eidas/SimpleSign.Europe.Eidas.Cli.Tests, Peru/Iofe/SimpleSign.Peru.Iofe.Cli.Tests,
# Adobe/Aatl/SimpleSign.Adobe.Aatl.Cli.Tests})
dotnet test tests/unit/Apps/SimpleSign.Cli.Tests

# TestBench tests need a running Sandbox (skipped without one; CI starts it)
dotnet run --project src/Apps/Development/SimpleSign.Sandbox -- --ephemeral
dotnet test tests/unit/Apps/Development/SimpleSign.TestBench.Tests

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
├── Extensions/                 trust frameworks and what goes with each (code, CLI extension, docs, playbooks, tools; ADR 0030)
│   ├── CliExtension.targets                  what makes a project a CLI extension (manifest, packaging), imported by the three *.Cli projects
│   ├── Brazil/                               everything of ICP-Brasil, Gov.br and Lei 14.063 lives here
│   │   ├── SimpleSign.Brazil/                  shared: CPF/CNPJ, Lei 14.063, AEA manifest, VALIDAR
│   │   ├── IcpBrasil/
│   │   │   └── SimpleSign.Brazil.IcpBrasil/        ICP-Brasil: chain validation, roots, policies, ACT timestamps
│   │   ├── GovBr/
│   │   │   └── SimpleSign.Brazil.GovBr/            Gov.br: chain validation, assurance level
│   │   ├── SimpleSign.Brazil.Cli/              the CLI extension (one for both): --profile icp-brasil|gov-br, their policies, `simplesign brasil sign`
│   │   │                                       (sign + --icp-policy, --aea, --health-document), `brasil timestamp verify`, Lei 14.063 in validate/inspect
│   │   ├── docs/                               icp-brasil.md, icp-brasil-validar-check.md
│   │   ├── playbooks/                          icp-brasil-pades.json, govbr-pades.json
│   │   └── tools/update-icp-intermediates.sh   refreshes the bundled intermediates
│   ├── Europe/Eidas/                         everything of eIDAS lives here
│   │   ├── SimpleSign.Europe.Eidas/            eIDAS (EU): anchors from the EU LOTL (pivots followed), qualification (QESig, AdESig-QC…), policies
│   │   ├── SimpleSign.Europe.Eidas.Cli/        the CLI extension: --profile eidas, eidas policies
│   │   ├── docs/eidas.md
│   │   ├── playbooks/                          eidas-checklist.md, eidas-baseline.json
│   │   └── tools/eidas.py                      writes that playbook
│   ├── Adobe/Aatl/                           everything of the Adobe Approved Trust List lives here (ADR 0031)
│   │   ├── SimpleSign.Adobe.Aatl/              the AATL: Adobe's signed list read at run time (not bundled), its anchors with their
│   │   │                                       certificate policy restrictions (IConstrainedTrustAnchorProvider), the aatl profile and policies
│   │   ├── SimpleSign.Adobe.Aatl.Cli/          the CLI extension: --profile aatl, aatl policies
│   │   └── docs/aatl.md
│   └── Peru/Iofe/                            everything of Peru/IOFE/INDECOPI lives here
│       ├── SimpleSign.Peru.Iofe/             IOFE (Peru): anchors from INDECOPI's trusted list, INDECOPI policies
│       ├── SimpleSign.Peru.Iofe.Cli/         the CLI extension: --profile iofe, iofe policies, --tsl-profile iofe
│       ├── docs/                             iofe.md
│       ├── playbooks/                        indecopi-checklist.md (annex B), indecopi-guia-v4.json
│       └── tools/                            indecopi.py writes that playbook
├── Signers/
│   ├── SimpleSign.Signers.Pkcs11/  sign through a PKCS#11 driver (tokens, HSMs)
│   └── SimpleSign.Signers.Cloud/   cloud certificates: ICP-Brasil PSC and CSC v2
├── Extras/
│   └── SimpleSign.HtmlToPdf/   HTML→PDF layout engine (independent, no signing)
└── Apps/
    ├── SimpleSign.Cli/                CLI tool; references no trust framework (its own profile is `sandbox`): each comes as an extension
    ├── SimpleSign.Cli.Extensibility/  the contract of a CLI extension (ICliExtension), installed with `simplesign extension install`
    ├── SimpleSign.Agent/              Avalonia tray app + window (pt-BR/en-US, TestBench look, Native AOT): local signing agent (HTTP on 127.0.0.1)
    └── Development/                   tools for developing and testing, not for end users
        ├── SimpleSign.TestBench/      Local web app (ASP.NET Core + React/shadcn in web/) to try every signing option (real network + a connected Sandbox);
        │                              its Playbook tab runs playbooks (docs/playbooks, Extensions/*/playbooks): preview, run and keep each step's result, export the evidence
        └── SimpleSign.Sandbox/        Test PKI on real endpoints (CRL over HTTP/HTTPS/LDAP, OCSP, TSA, CSC) and failures to switch on; API only (its UI is the TestBench's Sandbox control)
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
// Same shape for CAdES and XAdES: CadesDeferredSigner / XadesDeferredSigner (.Document → PrepareAsync, .Resume → CompleteAsync)

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

// Augmentation: raise an existing signature without touching what is signed (ADR 0025)
var augmented = await PadesAugmenter.Document(signedPdf)
    .ToLevel(AdesBaselineLevel.Archive)          // or .RenewArchive() on a B-LTA
    .WithTimestamp(TimestampOptions.DigiCert)
    .AugmentAsync();                              // .Document, .InitialLevel, .Level
// Same shape: CadesAugmenter.Signature(cms, detachedContent?) / XadesAugmenter.Document(xml, detachedData?)
```

### Trust profiles
```csharp
// A trust framework as one value: its trust and its policies (IofeProfile, EidasProfile, IcpBrasilProfile, GovBrProfile)
var iofe = await IofeProfile.LoadAsync();
await PadesSigner.Document(pdf).WithCertificate(cert).WithProfile(iofe).SignAsync();
var results = await new PdfSignatureValidator(new ValidationOptions { Profile = iofe }).ValidateAsync(signed);
// One profile sets the policies; others add trust only: IcpBrasilProfile.Create().WithTrustFrom(GovBrProfile.Create())
// CLI: --profile iofe [--trust-profile gov-br] [--sandbox URL]; `simplesign profiles` lists them
// eidas also qualifies each signature: results[0].Qualification?.Level is QESig, AdESig-QC… (ISignatureQualifier)
// What Acrobat trusts, without a national framework (ADR 0031): anchors only, no legal level
var aatl = await AatlProfile.LoadAsync();   // SimpleSign.Adobe.Aatl; CLI: --profile aatl
```

### Extension Points (interfaces)
- `ITrustAnchorProvider` — custom trust roots
- `ITimedTrustAnchorProvider` — the anchors at a given time (trusted-list service history, ADR 0026)
- `IConstrainedTrustAnchorProvider` — anchors that can refuse a chain that reached them (`WhyRefused`), asked by the validators and before
  signing: the AATL's certificate policy restrictions. A profile's reach the validators as `ValidationOptions.ConstrainedTrustAnchors` (ADR 0031)
- `IHttpClientProvider` — custom HTTP for TSA/OCSP/CRL
- `ICertificateCache` — cert caching
- `IChainValidationProvider` — custom chain logic
- `IChainRevocationChecker` / `IRevocationCache` — revocation of a whole chain, CRL cache
- `ICountryExtension` — country packages (ICP-Brasil, Gov.br, IOFE, eIDAS)
- `ICliExtension` (`SimpleSign.Cli.Extensibility`) — what a package adds to the CLI once installed: commands, `--profile`, policy presets, `--tsl-profile`;
  and, with defaults, a command that runs the standard `sign` with options of its own (`PassThroughCommands`, `CliExtensionContext.SignAsync(CliSignRequest)`),
  services, chain validation and notes about a signature in `validate`/`inspect` (`ConfigureServices`, `CreateChainValidationProviders`, `Annotate`) (ADR 0030)
- `ISignatureQualifier` — the qualification of a validated signature under a framework (eIDAS's `EidasQualifier`)
- `ISignatureAuditSink` — a record of every signature made or refused (`AuditChain`, `JsonLinesAuditSink`)
- `IPolicyProvider` / `ISignaturePolicyDocumentProvider` — the validation policy, and policy documents
- `DirectoryTrustAnchorProvider`, `TrustedList` — ready-made `ITrustAnchorProvider`s

### Error Handling
- `SigningException` — signing failures; `Reason` (`SigningErrorReason`) says which check of the `SigningPolicy` refused the certificate, key or algorithm (`KeyUsageNotPermitted`, `KeyTooWeak`, `ChainCertificateNotValid`, `CertificateRevoked`…)
- `InvalidPdfException` — malformed PDF input
- Validation returns result objects (never throws for invalid signatures)

## Test Conventions

- Unit tests use xUnit
- `tests/unit/` mirrors `src/`: `src/Formats/SimpleSign.CAdES` is tested by
  `tests/unit/Formats/SimpleSign.CAdES.Tests` (the CLI too: `tests/unit/Apps/SimpleSign.Cli.Tests`; the TestBench and
  the Sandbox under `tests/unit/Apps/Development`).
  Every test project is in `SimpleSign.sln`.
- Every test class has `[Trait("Category", …)]`: `Unit` by default, `Contract` in Contracts.Tests,
  `Integration` (network), `Stress` (excluded from the regular CI run), `VeraPdf` (needs veraPDF; its own CI job), `Interop` (needs qpdf/pyHanko/OpenSSL/xmlsec1; its own CI job), `EtsiChecker` (needs an account at the ETSI checker; run by hand, not in CI)
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
  └── depend on SimpleSign.Brazil only, never on each other

SimpleSign.Peru.Iofe / SimpleSign.Europe.Eidas (one ICountryExtension each)
  └── depend on SimpleSign.Core + SimpleSign.XAdES — public API only

SimpleSign.Adobe.Aatl (the Adobe Approved Trust List; one ICountryExtension)
  └── depends on SimpleSign.Core + SimpleSign.PAdES — public API only; downloads Adobe's list at run time, bundles only the Adobe root

SimpleSign.Cli.Extensibility (the contract of CLI extensions)
  └── depends on SimpleSign.Core + SimpleSign.XAdES + SimpleSign.PAdES + Spectre.Console.Cli

SimpleSign.Peru.Iofe.Cli / SimpleSign.Brazil.Cli / SimpleSign.Europe.Eidas.Cli / SimpleSign.Adobe.Aatl.Cli
(CLI extensions, not libraries: each package carries cli-extension/)
  └── depend on their framework's packages + SimpleSign.Cli.Extensibility; SimpleSign.Cli references none of them, nor any framework

SimpleSign.CAdES / SimpleSign.XAdES
  └── each depends on SimpleSign.Core only

SimpleSign.HtmlToPdf (independent, no signing)
```
