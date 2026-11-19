# IOFE (Peru)

Everything SimpleSign has for Peru's Infraestructura Oficial de Firma Electrónica (Ley 27269) and INDECOPI's
accreditation of signature software, in one folder.

| | |
|---|---|
| [`SimpleSign.Peru.Iofe/`](SimpleSign.Peru.Iofe) | The library: trust anchors from INDECOPI's signed trusted list, kept current, and the policies of the accreditation guide. One `ICountryExtension`, built on the public API of Core and XAdES |
| [`SimpleSign.Peru.Iofe.Cli/`](SimpleSign.Peru.Iofe.Cli) | The extension of the `simplesign` command line: `--profile iofe`, the `iofe` policies, `--tsl-profile iofe` |
| [`docs/iofe.md`](docs/iofe.md) | The article: the list, the policies, the profile |
| [`playbooks/`](playbooks) | `indecopi-checklist.md`, every item of the guide's annex B and what shows it, and `indecopi-guia-v4.json`, the playbook the TestBench runs |
| [`tools/indecopi.py`](tools/indecopi.py) | Writes that playbook |

The accredited configuration of the guide's sections 4.2 to 4.4 — `SimpleSign.Peru.Iofe.Accredited`, its CLI extension
(`simplesign iofe sign|verify|view`), the manuals the guide asks for, the audit walk-through and the script that runs
annex B — is in [its own repository](https://github.com/eupassarin/simplesign-iofe-accredited), built on these packages. It was in this folder up to SimpleSign 0.14.0.

The tests are in `tests/unit/Extensions/Peru/Iofe` (and `IofeTrustedListIntegrationTests` in `tests/integration`, which
reads INDECOPI's real list).

- `IofeExtension`: trust anchors from INDECOPI's trusted list (`TrustedList`, ETSI TS 119 612 / TS 102 231 v3),
  whose signature is checked against the certificate INDECOPI signs it with (`IofeExtension.IndecopiSigners`, bundled;
  confirm its fingerprint with INDECOPI before a deployment trusts it). The list types several accredited TSAs as
  `Svctype/unspecified` (Llama.pe, BPO Advisors, Girasol): `IofeExtension.DefaultListOptions` keeps that type too,
  without the code-signing certificates of the signature software listed under it.
- `IofeTrustedListSource` (`IofeExtension.LoadRefreshableAsync`, `services.AddSimpleSignIofe(options)`): the list read
  again on demand or on a schedule, swapped atomically, the last good copy kept until its NextUpdate, a `Changed`
  event with the services added and removed.
- `IofePolicies.Signing` / `Validation`, and `AgentSigning` / `AgentValidation` for an automated agent: the policies
  of INDECOPI's accreditation guide (v4.0). Signing with them needs trust anchors (the extension or `WithTrustAnchors`)
  and checks the whole chain's revocation and every TSA before signing.

```csharp
var iofe = await IofeProfile.LoadAsync();                  // INDECOPI's list + the IOFE policies
byte[] signed = await PadesSigner.Document(pdf).WithCertificate(certificate, chain).WithProfile(iofe).SignAsync();
var results = await new PdfSignatureValidator(new ValidationOptions { Profile = iofe }).ValidateAsync(signed);
```

```bash
simplesign extension install SimpleSign.Peru.Iofe.Cli
simplesign validate contrato.pdf --profile iofe
```

What is still elsewhere: the TestBench, the Agent and the Sandbox know IOFE directly (the profile menu, the catalog of
frameworks, test services shaped as INDECOPI's list); see [ADR 0030](../../../../docs/adr/0030-cli-extensions.md).
