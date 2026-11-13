# IOFE (Peru)

SimpleSign supports Peru's **Infraestructura Oficial de Firma Electrónica** (IOFE, Ley 27269 and its regulation):
trust anchors from INDECOPI's signed trusted list, kept current, and the signing and validation policies of INDECOPI's
accreditation guide for signature software.

## Installation

```bash
dotnet add package SimpleSign.Peru.Iofe
```

It depends on `SimpleSign.Core` and `SimpleSign.XAdES` (the trusted-list reader), and is one `ICountryExtension`
(`IofeExtension`, region `PE`).

## What IOFE is

INDECOPI is the IOFE's accreditation authority. It accredits the certification entities (*entidades de certificación*,
ECs: RENIEC, Camerfirma Perú, Acepta, Certisign/Core Andina…), the time-stamping authorities, and signature software,
and publishes them all in one **trusted list**: <https://iofe.indecopi.gob.pe/TSL/tsl-pe.xml>.

That list is not laid out like an EU member state's:

| | INDECOPI's list | EU lists |
|---|---|---|
| Format | ETSI TS 102 231 v3 (`TSLVersionIdentifier` 3, the `eSigDir-1999-93-EC-TrustedList` URIs) | TS 119 612 v5/v6 |
| TSLType | `…/TSLType/generic` | `…/EUgeneric` |
| Status of an accredited service | `…/Svcstatus/undersupervision` (two services carry the literal `No acredited`) | `granted` |
| ECs | `Svctype/CA/QC` | `CA/QC` |
| TSAs | one as CA/QC (Camerfirma's TSU, Acepta's TSA CA), the others as **`Svctype/unspecified`** (Llama.pe, BPO Advisors, Girasol/FirmEasy) | `TSA/QTST` |
| Signature software | `Svctype/unspecified`, with the software's **code-signing** certificate (RENIEC, Indenova) or a TSA certificate (Viettel BISIGN) | — |
| TSA URLs | none (`ServiceSupplyPoints` are not given) | usually given |
| LOTL | none points to it | the EU LOTL |

`IofeExtension.DefaultListOptions` reads it accordingly: the CA services and the `unspecified` ones become anchors,
except end-entity certificates with the code-signing EKU (the signature software). The Llama.pe entry is the CA of its
TSUs ("Llama.pe Timestamping CA"), so a Llama.pe time-stamp chains to that `unspecified` service.

As of sequence 25 (issued 2026-11-06, NextUpdate 2027-05-06) the list has 75 services; the time-stamping anchors are
Camerfirma TSA II - 2014, Acepta Peru Autoridad de Sellado de Tiempo - V1, Llama.pe Timestamping CA, BPO TSA and
FirmEasy TSA. Whether the Viettel BISIGN entry (a time-stamping certificate listed as signature software) should be an
anchor is an open question to ask INDECOPI; today it is one.

## Loading the list

```csharp
using SimpleSign.Peru.Iofe;

var iofe = await IofeExtension.LoadAsync(new IofeExtensionOptions
{
    TrustedListSigners = [indecopiTslSigner],          // obtained from INDECOPI, fingerprint checked out of band
    CacheFile = "/var/lib/simplesign/tsl-pe.xml",      // last good copy, used when the download fails
});
```

- **The signer certificate is required and never taken from the list.** The list is signed (XAdES enveloped) by
  `CN=TSL Suscriptor, OU=DGI, O=INDECOPI`, issued by `CN=INDECOPI AAC RAIZ`, valid to 2027-08-23. The copy the tests
  use has SHA-256 `bc32323c7ba0af62bdef9ca7e7f499bb71eeb4fa092b9017e15acc4d0bf612ed`
  (`tests/unit/TrustFrameworks/Peru/Iofe/SimpleSign.Peru.Iofe.Tests/Fixtures/`) — **to be confirmed with INDECOPI**
  before a deployment trusts it. A list signed by any other key is refused.
- `CacheFile`: a list that was read successfully is kept there, and used when the download fails while its NextUpdate
  has not passed.
- `HttpClientProvider`: the HTTP client (proxy, outbound policy); `ListOptions`: other service rules than the defaults.
- `IofeExtension.Load(bytes, signers)` reads a copy the deployment keeps itself.

### Keeping it current

A server runs for months; INDECOPI publishes a list about every six months, and adds or withdraws ECs in between.
`IofeTrustedListSource` reads the list again and swaps it while signers keep running:

```csharp
var iofe = await IofeExtension.LoadRefreshableAsync(options);    // an IofeExtension over an IofeTrustedListSource
var source = iofe.Source!;
source.Changed += (_, e) => logger.LogInformation("INDECOPI list #{Old} -> #{New}: +{Added} -{Removed}",
    e.Previous?.SequenceNumber, e.Current.SequenceNumber,
    string.Join(", ", e.AddedServices.Select(s => s.ServiceName)), string.Join(", ", e.RemovedServices.Select(s => s.ServiceName)));
source.RefreshFailed += (_, e) => logger.LogWarning("INDECOPI list not refreshed: {Reason}", e.Reason);
source.StartAutoRefresh(TimeSpan.FromHours(6));                  // or: await source.RefreshAsync();
```

- Each copy is verified like the first (signature, not expired) and replaces the one served in one step: a signature
  or validation in progress sees the old list or the new one, never part of each.
- A copy that cannot be downloaded or verified, or whose sequence number is lower than the one served (a rollback), is
  refused and the last good copy keeps being served — from `CacheFile` after a restart — until its NextUpdate passes;
  then the list gives no anchors until a good copy is read.
- `source.Current` gives the sequence number, issue time, NextUpdate, SHA-256 and whether it came from the cache.
- The source is an `ITimedTrustAnchorProvider` (anchors at a past time, from the services' history) and an
  `ITrustedListInfoProvider` (for the `TrustedLists` constraints of a validation policy).

With dependency injection, a hosted service reads the list when the host starts and every 6 hours:

```csharp
builder.Services.AddSimpleSignIofe(new IofeExtensionOptions
{
    TrustedListSigners = [indecopiTslSigner],
    CacheFile = "/var/lib/simplesign/tsl-pe.xml",
}, refreshInterval: TimeSpan.FromHours(6));
// resolves IofeTrustedListSource, IofeExtension, ICountryExtension and ITrustAnchorProvider once the host has started
```

## Policies

`IofePolicies` holds the policies of the guide (also as files in `docs/policies/iofe-*.json`, and as the CLI/TestBench
presets `iofe` and `iofe-nonrepudiation`):

| Policy | For | What it adds to SimpleSign's defaults |
|---|---|---|
| `IofePolicies.Signing` | End-user signing software (guide §4.1) | The signer chains to a trust anchor (the extension); revocation of the whole chain, CRL or OCSP, refused when revoked or unknown, CRLs without nextUpdate refused (Req. 1, 11); no SHA-1/MD5 in the chain (Req. 6, 16); each TSA trusted, valid and not revoked (§4.4); key usage digitalSignature or nonRepudiation (Req. 3) |
| `IofePolicies.SigningNonRepudiation` | Signing by an automated agent (§4.2) | As `Signing`, with nonRepudiation required (Req. 13) |
| `IofePolicies.Validation` | Verification (§4.3) | Signing certificate with digitalSignature or nonRepudiation; an expired or badly signed trusted list gives no anchors; trusted lists of version 3 accepted (INDECOPI's) besides 5 and 6 |
| `IofePolicies.ValidationNonRepudiation` | Verification by automated agents (§4.3, Req. 23) | As `Validation`, with nonRepudiation required |

```csharp
byte[] signed = await PadesSigner.Document(pdf)
    .WithCertificate(certificate, chain)
    .WithCountryExtension(iofe)                        // the signer and each TSA must chain to INDECOPI's list
    .WithSigningPolicy(IofePolicies.SigningNonRepudiation)
    .WithLevel(AdesBaselineProfile.Timestamped(new TimestampOptions(new Uri(tsaUrl))))
    .SignAsync();

var validator = new PdfSignatureValidator(
    new ValidationOptions { Policy = IofePolicies.Validation },
    httpClient: null, logger: null, countryExtensions: [iofe]);
```

Use `IofePolicies.Validation` (not `ValidationPolicy.Default`) with INDECOPI's list: the default `TLVersion`
constraint accepts versions 5 and 6 only, which makes every signature under a version 3 list INDETERMINATE.

## Time-stamping authorities

The list says which TSAs are accredited, not where they are: configure each TSA's URL (and credentials) as its provider
gives them. With `IofePolicies.Signing*`, a time-stamp from a TSA that does not chain to the list is refused before the
signature is returned (`TimestampUntrusted`); give `TimestampOptions.ExpectedTsaCertificate` to also pin the TSA.

## The INDECOPI playbook

The TestBench's Playbook tab runs `docs/playbooks/indecopi-guia-v4.json` (written by `tools/playbooks/indecopi.py`):
the automated part of annex B, about 70 steps through the library and the CLI against a Sandbox.

1. Start a Sandbox and the TestBench and connect them ([testbench.md](testbench.md)); start DSS for cross-validation.
2. Open the **Playbook** tab and pick the `indecopi-guia-v4` sample; run everything.
3. The `tsl` section reads the Sandbox's trusted list **as `IofeExtension` reads INDECOPI's** (`/tl/tl.xml` with
   `IofeExtension.DefaultListOptions`: a self-signed Timestamping CA and a code-signing certificate are listed as
   `unspecified` — see [sandbox.md](sandbox.md#reading-it-as-indecopis-list)), with the trust choice `SandboxIofeList`
   and the TSA `SandboxIofe`, and switches on its failures (signed by another key, tampered, expired).
4. **Evidence**: export the page and the zip (per step the signed file, the SimpleSign and ETSI reports, the CLI
   commands and the logs, a summary by item id): see [playbook.md](playbook.md).

The CLI reads the same list with `--tsl … --tsl-signer … --tsl-profile iofe`.

## Checklist of the guide

[`docs/playbooks/indecopi-checklist.md`](../playbooks/indecopi-checklist.md) lists every item of annex B of the
*Guía de Acreditación de Aplicaciones de Software* v4.0 — §4.2 F-1…F-32, §4.3 V-1…V-32, §4.4 S-1…S-4 and §4.1
E-1…E-19 — and what shows it: a playbook step (P), tests (U), or the accredited product (X: access control, the
cryptographic module and key custody, code signing of the application, manuals). Every item a library can show has a
step or a test.

## Not covered yet

- Data of Peruvian certificates (DNI, RUC in the subject) and the DNIe middleware: they need real certificates and
  hardware.
- Whether the Viettel BISIGN time-stamping certificate, listed as signature software, should stay an anchor.
