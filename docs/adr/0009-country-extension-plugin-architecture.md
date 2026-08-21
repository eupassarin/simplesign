# ADR 0009: Country Extension / Plug-in Architecture

**Status:** Accepted

**Context:**
Digital signature regulations vary by country. Brazil has ICP-Brasil with 13 AC Raiz policies (AD-RB through AD-RA) and Gov.br with 4 assurance levels, plus the Lei 14.063 signature manifest. The European Union has the eIDAS Trusted List with national root stores. The United States has the FPKI trust framework. Each jurisdiction defines:
- Which root CAs are trusted (trust anchor lists)
- How certificate chains are validated beyond standard X.509 (policy OIDs, assurance levels)
- What metadata must be embedded in the signature (manifest attributes, national IDs)
- Which signer identity attributes are extracted from certificates (CPF/CNPJ, VAT number, etc.)

The simplest approach — a single hard-coded validation path for each supported regulation — would not scale. Adding a new country would require changes across the signing, validation, and inspection layers.

**Decision:**
A two-interface plug-in architecture where each country bundles trust anchors and chain validation logic into a single registration unit.

### 1. Core interfaces (all in `SimpleSign.Core.Extensions`)

**`ICountryExtension`** — the composite registration unit:
```csharp
public interface ICountryExtension
{
    string RegionCode { get; }
    string DisplayName { get; }
    IReadOnlyList<ITrustAnchorProvider> TrustAnchorProviders { get; }
    IReadOnlyList<IChainValidationProvider> ChainValidationProviders { get; }
}
```

Two sub-interfaces (in `SimpleSign.Core.Extensions`):

- **`ITrustAnchorProvider`** — returns a list of root/intermediate CA certificates (bundled as embedded resources or loaded from a store).
- **`IChainValidationProvider`** — performs region-specific chain validation beyond standard X.509 path building: policy OID detection, assurance level mapping, national ID extraction, CRL/OCSP fallback rules. The `ValidateAsync` method is async for network-dependent validators.

`ISignatureManifestProvider` was removed in v0.5.0. Manifest construction uses `SignatureMetadata` directly; Brazil-specific Lei 14.063 manifests are built via `WithAdvancedSignature()` without an interface indirection.

### 2. BrasilExtension — reference implementation

`BrasilExtension` bundles 4 internal classes: two `ITrustAnchorProvider` implementations (one per PKI hierarchy) loading bundled root certificates, and two `IChainValidationProvider` implementations for ICP-Brasil and Gov.br policy detection and identity extraction.

### 3. Registration

**DI path:**
```csharp
services.AddSingleton<ICountryExtension, BrasilExtension>();
services.AddSingleton<ITrustAnchorProvider, IcpBrasilTrustAnchorProvider>();
services.AddSingleton<ITrustAnchorProvider, GovBrTrustAnchorProvider>();
```

**Non-DI path:**
```csharp
PadesSigner.Document(pdf)
    .WithCountryExtension<BrasilExtension>()
    .WithCertificate(cert)
    .SignAsync();
```

### 4. Consumption in PAdES

| Layer | Extension point consumed | Mechanism |
|---|---|---|
| **Validation** | `ITrustAnchorProvider` | DI collection injected into `PdfSignatureValidator` constructor; roots loaded into `X509Chain.CustomTrustStore` |
| **Validation** | `IChainValidationProvider` | Construction injection into `PdfSignatureValidator` (or via `PadesSignerBuilder.CountryExtensions`); first matching provider enriches `SignatureValidationResult` with `PolicyLevel`, `SignerId`, `SignerIdType`, `ChainValidationRegion`, and `ChainValidationMetadata` |
| **Signing** | Brazil-specific metadata | `WithAdvancedSignature()` extension maps `AdvancedSignatureInfo` → `SignatureMetadata` → CMS signed attributes (no provider indirection) |
| **Inspection** | None (OID hard-coded) | `CmsParser` recognises manifest OID directly; no provider needed |

**Consequences:**
- Adding a new country requires implementing 2 interfaces and registering the composite
- Trust anchors can be offline (embedded resources) or online (AIA chasing or downloaded lists)
- `IChainValidationProvider` is wired into `PdfSignatureValidator`'s built-in validation pipeline. After standard `X509Chain.Build()`, the first matching provider (via `CanValidate`) enriches the result. If the standard chain fails but a country provider trusts it, chain errors are demoted to warnings (`IsChainTrustWarning = true`).
- `SignatureMetadata` is the canonical signer metadata type; `AdvancedSignatureInfo` is the Brazil-specific DTO that maps to it.
- The manifest OID is hard-coded in the CMS parser; manifest format is not extensible at runtime.

**Alternatives considered:**

| Approach | Pros | Cons | Verdict |
|---|---|---|---|
| **Single flat interface** (one big API per country) | Simple | No separation of concerns, hard to test | Rejected |
| **Two-interface composite (chosen)** | Clear separation, easy to test each concern, flexible | More files, consumer must know where to inject | **Chosen** |
| **No plug-in (hard-coded per country)** | Fast to implement first country | Impossible to extend, violates OCP | Rejected |
| **Attribute-based discovery** | Zero-config for new assemblies | Reflection, AOT incompatible | Rejected |

**Status:** Accepted. The two-interface composite is the canonical extension mechanism. `WithCountryExtension<T>()` on `PadesSignerBuilder` provides both DI and builder-based registration paths. `PdfSignatureValidator` consumes both `ITrustAnchorProvider` and `IChainValidationProvider` via constructor injection or `ICountryExtension` aggregator.
