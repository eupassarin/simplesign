# Brazil (ICP-Brasil, Gov.br, Lei 14.063)

Everything SimpleSign has for Brazil's trust frameworks — the Infraestrutura de Chaves Públicas Brasileira (MP
2.200-2/2001, DOC-ICP-15) and the Gov.br signature — and for the signature levels of Lei 14.063/2020, in one folder.

| | |
|---|---|
| [`SimpleSign.Brazil/`](SimpleSign.Brazil) | What the two frameworks share: CPF/CNPJ, the Lei 14.063 level (`Lei14063`), the advanced electronic signature and its manifest (AEA), VALIDAR health documents. Built on the public API of PAdES and CAdES |
| [`IcpBrasil/SimpleSign.Brazil.IcpBrasil/`](IcpBrasil/SimpleSign.Brazil.IcpBrasil) | ICP-Brasil: the AC Raiz roots, the chain validation, the signature policies (AD-RB to AD-RA, PA and LPA), ACT time-stamps. One `ICountryExtension` |
| [`IcpBrasil/SimpleSign.Brazil.IcpBrasil.Xades/`](IcpBrasil/SimpleSign.Brazil.IcpBrasil.Xades) | XAdES under the ICP-Brasil XML policies (AD-RB to AD-RA): `WithIcpBrasilPolicy`, the rules of the XML PAs, the verified `LPA_XAdES.xml` refresh |
| [`Fiscal/SimpleSign.Brazil.Fiscal/`](Fiscal/SimpleSign.Brazil.Fiscal) | Fiscal XML (NF-e, NFC-e, CT-e, MDF-e, events, NFS-e, eSocial, EFD-Reinf): the layouts as profiles of the XML-DSig signer of SimpleSign.XAdES, the SEFAZ policy (SHA-1), the validator |
| [`GovBr/SimpleSign.Brazil.GovBr/`](GovBr/SimpleSign.Brazil.GovBr) | Gov.br: its roots, the chain validation and the assurance level. One `ICountryExtension` |
| [`SimpleSign.Brazil.Cli/`](SimpleSign.Brazil.Cli) | The extension of the `simplesign` command line: `--profile icp-brasil` and `gov-br`, the `icp-brasil`, `fiscal-sefaz` and `govbr` policies, `simplesign brasil sign`, `brasil cades sign`, `brasil xades sign`, `brasil fiscal sign|validate` and `brasil timestamp verify`, and the Brazilian data in `validate` and `inspect` (PDF) |
| [`docs/icp-brasil.md`](docs/icp-brasil.md) | The article: certificates, policies, time-stamps, validation, the command line |
| [`docs/fiscal-xml.md`](docs/fiscal-xml.md) | Fiscal XML: the layouts, SHA-1, two phases, validation, the command line |
| [`docs/icp-brasil-validar-check.md`](docs/icp-brasil-validar-check.md) | How a signature is checked against the ITI's VALIDAR service |
| [`playbooks/`](playbooks) | `icp-brasil-pades.json`, `icp-brasil-cades.json`, `icp-brasil-xades.json` and `govbr-pades.json`, the playbooks the TestBench runs |
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

`SimpleSign.Brazil.IcpBrasil` and `SimpleSign.Brazil.GovBr` depend on `SimpleSign.Brazil` only, never on each other
(`SimpleSign.Brazil.Fiscal` and `SimpleSign.Brazil.IcpBrasil.Xades` build on IcpBrasil and SimpleSign.XAdES);
the standard CLI references none of them ([ADR 0030](../../../docs/adr/0030-cli-extensions.md)).

What is still elsewhere: the TestBench, the Agent and the Sandbox know ICP-Brasil and Gov.br directly (the kind of
signature, the profile menu, the catalog of frameworks).
