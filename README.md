<p align="center">
  <img src="assets/icon.svg" alt="SimpleSign" width="96" height="96" />
</p>

<h1 align="center">SimpleSign</h1>

<p align="center">
  <strong>Digital signatures for .NET</strong><br/>
  PAdES · CAdES · XAdES — sign, validate, inspect.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/.NET-8%20%7C%2010-512BD4?style=flat-square&logo=dotnet" alt=".NET 8 | 10" />
  <img src="https://img.shields.io/nuget/v/SimpleSign?style=flat-square&logo=nuget" alt="NuGet" />
  <img src="https://img.shields.io/github/actions/workflow/status/eupassarin/simplesign/ci.yml?style=flat-square&logo=github" alt="CI" />
  <a href="https://codecov.io/gh/eupassarin/SimpleSign"><img src="https://codecov.io/gh/eupassarin/SimpleSign/branch/main/graph/badge.svg" alt="codecov" /></a>
  <img src="https://img.shields.io/badge/License-MIT-green?style=flat-square" alt="MIT License" />
</p>

SimpleSign creates and validates **PAdES** (ETSI EN 319 142), **CAdES** (ETSI EN 319 122) and
**XAdES** (ETSI EN 319 132) signatures.

- All cryptography uses `System.Security.Cryptography`: no BouncyCastle, no third-party crypto.
- Native AOT compatible; .NET 8 and .NET 10 on Windows, macOS and Linux.
- MIT licensed.

## Installation

```bash
dotnet add package SimpleSign                  # PAdES + CAdES + XAdES
dotnet add package SimpleSign.Brazil.IcpBrasil # ICP-Brasil, Lei 14.063
dotnet add package SimpleSign.Brazil.GovBr     # Gov.br
dotnet add package SimpleSign.Peru.Iofe        # IOFE (Peru), INDECOPI policies
dotnet add package SimpleSign.Signers.Pkcs11   # A3 tokens, smartcards, HSMs
dotnet add package SimpleSign.Signers.Cloud    # cloud certificates (PSC, CSC v2)
dotnet tool install -g SimpleSign.Cli          # command line
```

| Package | What it does |
|---|---|
| `SimpleSign` | Meta-package: PAdES, CAdES and XAdES |
| `SimpleSign.PAdES` | PDF signing, validation and inspection (B-B/T/LT/LTA) |
| `SimpleSign.CAdES` | Standalone CMS/PKCS#7 signatures |
| `SimpleSign.XAdES` | XML signatures; ETSI trusted lists (`TrustedList`) |
| `SimpleSign.Core` | CMS, TSA, OCSP, CRL (HTTP; LDAP opt-in), signing and validation policies, trust store (used by the above) |
| `SimpleSign.Brazil.IcpBrasil` | ICP-Brasil chain, roots and policies, Lei 14.063 |
| `SimpleSign.Brazil.GovBr` | Gov.br chain and assurance level, Lei 14.063 |
| `SimpleSign.Brazil` | Shared: CPF/CNPJ, Lei 14.063 levels, AEA manifest (pulled in by both) |
| `SimpleSign.Peru.Iofe` | IOFE (Ley 27269): anchors from INDECOPI's signed trusted list, INDECOPI signing and validation policies |
| `SimpleSign.Brazil.Fiscal` | XML-DSig for NF-e, CT-e, MDF-e, NFS-e, eSocial, EFD-Reinf |
| `SimpleSign.Signers.Pkcs11` | Sign through a token's PKCS#11 driver |
| `SimpleSign.Signers.Cloud` | Sign with cloud certificates (ICP-Brasil PSCs, CSC API v2) |
| `SimpleSign.HtmlToPdf` | Pure .NET HTML→PDF (independent of signing) |

## Quick start

Sign a PDF with a .pfx file:

```csharp
using SimpleSign.PAdES;

await PadesSigner.SignFileAsync("contract.pdf", "contract-signed.pdf", "me.pfx", password);
```

With the fluent builder (PAdES B-LT, with a timestamp and revocation data):

```csharp
using SimpleSign.Core.Signing;
using SimpleSign.PAdES;

var signedPdf = await PadesSigner
    .Document(pdfBytes)
    .WithCertificate(certificate)
    .WithLevel(AdesBaselineProfile.LongTerm(TimestampOptions.DigiCert, new LongTermValidationOptions()))
    .SignAsync();
```

Before anything is signed, the default `SigningPolicy` refuses a certificate without the digitalSignature or
nonRepudiation key usage, an RSA key under 2048 bits, an expired certificate in the chain and SHA-1/MD5.
`.WithSigningPolicy(SigningPolicy.Strict)` also checks the revocation of the whole chain; `SigningPolicy.Minimal`
keeps only the date check of the signing certificate.

Validate:

```csharp
using SimpleSign.Core.Validation;
using SimpleSign.PAdES.Validation;

var validator = new PdfSignatureValidator(new ValidationOptions { CheckRevocation = true, TrustSystemRoots = true });

foreach (var r in await validator.ValidateAsync(File.OpenRead("signed.pdf")))
{
    Console.WriteLine($"{r.FieldName}: {r.Indication} {r.SubIndication} — {r.SignerName} at {r.SigningTime}");
}
```

Each result carries the ETSI EN 319 102-1 indication and sub-indication and the list of checks (`Constraints`);
`ValidationOptions.Policy` (`ValidationPolicy.Load("policy.json")`) sets the accepted algorithms, key sizes and key usage.

CAdES and XAdES use the same builder and profiles:

```csharp
byte[] p7s = await CadesSigner.Document(data).WithCertificate(certificate).SignAsync();
byte[] xml = await XadesSigner.Document(xmlBytes).WithCertificate(certificate).SignAsync();
```

Sign with a key that is not in memory (token, HSM, cloud, browser) through `IExternalSigner`:

```csharp
using var token = Pkcs11Signer.Open(new Pkcs11SignerOptions { LibraryPath = "/usr/lib/libeToken.so", Pin = pin });

var signedPdf = await PadesSigner.Document(pdfBytes)
    .WithExternalSigner(token.Certificate, token, token.Chain)
    .SignAsync();
```

## Documentation

| Guide | |
|---|---|
| [Getting started](docs/articles/getting-started.md) | First signature, validation, appearance |
| [PAdES signing](docs/articles/pades.md) | Levels, appearance, batch, TSA pool, logging |
| [CAdES and XAdES](docs/articles/cades-xades.md) | Detached/enveloped CMS, XML forms, validation |
| [Inspection and validation](docs/articles/inspection-validation.md) | Validation results and fast inspection |
| [Deferred signing](docs/articles/deferred-signing.md) | Two-phase signing for web apps |
| [Remote signing](docs/articles/remote-signing.md) | The generic interface for keys outside the engine |
| [PKCS#11](docs/articles/pkcs11.md) / [Cloud signing](docs/articles/cloud-signing.md) | Tokens, HSMs and cloud certificates |
| [HTML to PDF](docs/articles/html-to-pdf.md) | The layout engine |
| [ICP-Brasil](docs/articles/icp-brasil.md) / [Fiscal XML](docs/articles/fiscal-xml.md) | Brazilian PKI and NF-e/eSocial signing |
| [CLI](docs/articles/cli.md) | `simplesign sign`, `validate`, `cades`, `xades`… |
| [Signing agent](docs/articles/agent.md) / [TestBench](docs/articles/testbench.md) | Tray app with a local signing API; local web app to try every option |
| [Standard coverage](docs/articles/coverage.md) | Every option with the clause that defines it, and what is not implemented |
| [Conformance](docs/conformance.md) / [ADRs](docs/adr/) | Standards coverage and design decisions |
| [INDECOPI evidence](docs/articles/indecopi-evidence.md) | Running the tests that back each requirement of the INDECOPI accreditation guide |

## Extension points

`ITrustAnchorProvider` (trust roots; `DirectoryTrustAnchorProvider` and `TrustedList` are ready-made),
`IChainValidationProvider` (chain rules), `IExternalSigner` (remote keys), `IHttpClientProvider` (TSA/OCSP/CRL HTTP),
`IChainRevocationChecker` and `IRevocationCache` (revocation of a chain), `ICertificateCache`, `ICertificateStore`
and `ICountryExtension` (country packages such as `SimpleSign.Brazil.IcpBrasil` and `SimpleSign.Peru.Iofe`).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md) and the [changelog](CHANGELOG.md).
If SimpleSign is useful to you, consider [sponsoring the project](https://github.com/sponsors/eupassarin).

[MIT](LICENSE)
