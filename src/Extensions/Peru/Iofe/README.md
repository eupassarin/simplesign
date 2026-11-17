# IOFE (Peru)

Everything SimpleSign has for Peru's Infraestructura Oficial de Firma Electrónica (Ley 27269) and INDECOPI's
accreditation of signature software, in one folder.

| | |
|---|---|
| [`SimpleSign.Peru.Iofe/`](SimpleSign.Peru.Iofe) | The library: trust anchors from INDECOPI's signed trusted list, kept current, and the policies of the accreditation guide. One `ICountryExtension`, built on the public API of Core and XAdES |
| [`SimpleSign.Peru.Iofe.Accredited/`](SimpleSign.Peru.Iofe.Accredited) | The configuration the guide asks for in sections 4.2 to 4.4, with nothing to relax: signing and verification agents, key in a PKCS#11 module, audit trails |
| [`SimpleSign.Peru.Iofe.Cli/`](SimpleSign.Peru.Iofe.Cli) | The extension of the `simplesign` command line: `--profile iofe`, the `iofe` policies, `--tsl-profile iofe`, `simplesign iofe sign\|verify\|view` |
| [`docs/iofe.md`](docs/iofe.md) | The article: the list, the policies, the profile, the accredited configuration |
| [`docs/acreditacion/`](docs/acreditacion/README.md) | The manuals the guide asks for, in Spanish (the text handed to INDECOPI) and in English ([`en/`](docs/acreditacion/en/README.md)): administration, user, programmer, security configuration, scope |
| [`docs/roteiro-de-auditoria.md`](docs/roteiro-de-auditoria.md) | The audit walk-through: what to prepare, run and show the auditor, rehearsed. Also in [English](docs/audit-walkthrough.md) and [Spanish](docs/guion-de-auditoria.md) |
| [`playbooks/`](playbooks) | `indecopi-checklist.md`, every item of the guide's annex B and what shows it, and `indecopi-guia-v4.json`, the playbook the TestBench runs |
| [`tools/indecopi.py`](tools/indecopi.py) | Writes that playbook |
| [`tools/auditoria/auditoria.py`](tools/auditoria/auditoria.py) | The audit, run: for each item of annex B it prepares a Sandbox, runs `simplesign iofe` (the accredited package, not the general signers), checks the signature or the refusal and its reason, and keeps the evidence with a report in Spanish, English and Portuguese. `escenarios.json` is its catalog |

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
