# SimpleSign.Europe.Eidas.Cli

eIDAS (EU) for the `simplesign` command line. It is an extension, not a library: install it into a CLI that is
already there.

```bash
dotnet tool install --global SimpleSign.Cli
simplesign extension install SimpleSign.Europe.Eidas.Cli
```

What it adds:

| | |
|---|---|
| `--profile eidas` | The EU LOTL and its trusted lists (checked against the bundled signers, pivots followed; or the Sandbox's LOTL with `--sandbox`), the eIDAS policies, and the qualification of each validated signature (QESig, AdESig-QC…), for `sign`, `validate` and the other standard commands |
| `--signing-policy eidas`, `--policy eidas`, `policy export … --preset eidas` | The `eidas` policies |

```bash
simplesign validate contract.pdf --profile eidas
simplesign sign contract.pdf --cert signer.pfx --profile eidas --tsa https://tsa.example/
simplesign extension remove eidas
```

More in the [eIDAS article](https://github.com/eupassarin/SimpleSign/tree/main/src/Extensions/Europe/Eidas/docs/eidas.md).
MIT licensed.
