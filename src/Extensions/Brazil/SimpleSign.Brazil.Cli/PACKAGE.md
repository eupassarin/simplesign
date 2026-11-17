# SimpleSign.Brazil.Cli

Brazil — ICP-Brasil, Gov.br and Lei 14.063 — for the `simplesign` command line. It is an extension, not a library:
install it into a CLI that is already there.

```bash
dotnet tool install --global SimpleSign.Cli
simplesign extension install SimpleSign.Brazil.Cli
```

What it adds:

| | |
|---|---|
| `--profile icp-brasil`, `--profile gov-br` | The roots and the chain validation of each, and their policies, for `sign`, `validate` and the other standard commands (Gov.br validates only). With `--sandbox URL`, `icp-brasil` also trusts the Sandbox's root as an AC Raiz (test) |
| `--signing-policy icp-brasil`, `--policy icp-brasil`, `--policy govbr`, `policy export … --preset …` | The ICP-Brasil and Gov.br policies |
| `simplesign brasil sign` (or `icp-brasil sign`) | `simplesign sign`, every option of it, plus `--icp-policy ad-rb\|ad-rt\|ad-rc\|ad-ra`, `--aea --cpf …` (advanced electronic signature, Lei 14.063) and `--health-document … --registration …` (VALIDAR) |
| `simplesign brasil timestamp verify` | A `.tst` checked against the ICP-Brasil roots: its authority must be an ACT |
| `validate`, `validate-dir`, `inspect` | The ICP-Brasil and Gov.br chain validation and roots for every signature, the Lei 14.063 level, the certificate's data (hierarchy, CPF/CNPJ, registrations) and the manifest of an advanced signature — in the text and in `--json` (`lei14063`, `brasil`, `manifest`) |

```bash
simplesign brasil sign contrato.pdf --cert assinante.pfx --icp-policy ad-rt --tsa https://act.example/
simplesign brasil sign recibo.pdf --cert assinante.pfx --aea --cpf 12345678909 --signer-name "Maria Silva"
simplesign validate contrato_signed.pdf --profile icp-brasil --trust-profile gov-br
simplesign extension remove brasil
```

The Brazilian options of `brasil sign` can be typed anywhere on the line; what the command receives is
`simplesign brasil sign [Brazilian options] -- [arguments of simplesign sign]`.

More in the [ICP-Brasil article](https://github.com/eupassarin/SimpleSign/tree/main/src/Extensions/Brazil/docs/icp-brasil.md).
MIT licensed.
