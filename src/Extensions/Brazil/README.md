# Brazil (ICP-Brasil, Gov.br, Lei 14.063)

Everything SimpleSign has for Brazil's trust frameworks — the Infraestrutura de Chaves Públicas Brasileira (MP
2.200-2/2001, DOC-ICP-15) and the Gov.br signature — and for the signature levels of Lei 14.063/2020, in one folder.

| | |
|---|---|
| [`SimpleSign.Brazil/`](SimpleSign.Brazil) | What the two frameworks share: CPF/CNPJ, the Lei 14.063 level (`Lei14063`), the advanced electronic signature and its manifest (AEA), VALIDAR health documents. Built on the public API of PAdES and CAdES |
| [`IcpBrasil/SimpleSign.Brazil.IcpBrasil/`](IcpBrasil/SimpleSign.Brazil.IcpBrasil) | ICP-Brasil: the AC Raiz roots, the chain validation, the signature policies (AD-RB to AD-RA, PA and LPA), ACT time-stamps. One `ICountryExtension` |
| [`GovBr/SimpleSign.Brazil.GovBr/`](GovBr/SimpleSign.Brazil.GovBr) | Gov.br: its roots, the chain validation and the assurance level. One `ICountryExtension` |
| [`SimpleSign.Brazil.Cli/`](SimpleSign.Brazil.Cli) | The extension of the `simplesign` command line: `--profile icp-brasil` and `gov-br`, the `icp-brasil` and `govbr` policies, `simplesign brasil sign` and `brasil timestamp verify`, and the Brazilian data in `validate` and `inspect` |
| [`docs/icp-brasil.md`](docs/icp-brasil.md) | The article: certificates, policies, time-stamps, validation, the command line |
| [`docs/icp-brasil-validar-check.md`](docs/icp-brasil-validar-check.md) | How a signature is checked against the ITI's VALIDAR service |
| [`playbooks/`](playbooks) | `icp-brasil-pades.json` and `govbr-pades.json`, the playbooks the TestBench runs |
| [`tools/update-icp-intermediates.sh`](tools/update-icp-intermediates.sh) | Refreshes the bundled ICP-Brasil intermediate certificates from the ITI |

The tests are in `tests/unit/Extensions/Brazil`.

```csharp
var icpBrasil = IcpBrasilProfile.Create().WithTrustFrom(GovBrProfile.Create());   // ICP-Brasil's policies, both trusts
byte[] signed = await PadesSigner.Document(pdf).WithCertificate(certificate).WithIcpBrasilPolicy(IcpBrasilPolicy.AdRb).SignAsync();
var results = await new PdfSignatureValidator(new ValidationOptions { Profile = icpBrasil }).ValidateAsync(signed);
```

```bash
simplesign extension install SimpleSign.Brazil.Cli
simplesign brasil sign contrato.pdf --cert assinante.pfx --icp-policy ad-rt --tsa https://act.example/tsa
simplesign validate contrato_signed.pdf --profile icp-brasil --trust-profile gov-br
```

`SimpleSign.Brazil.IcpBrasil` and `SimpleSign.Brazil.GovBr` depend on `SimpleSign.Brazil` only, never on each other;
the standard CLI references none of them ([ADR 0030](../../../docs/adr/0030-cli-extensions.md)).

What is still elsewhere: the TestBench, the Agent and the Sandbox know ICP-Brasil and Gov.br directly (the kind of
signature, the profile menu, the catalog of frameworks).
