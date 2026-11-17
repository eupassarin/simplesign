# SimpleSign.Peru.Iofe.Cli

IOFE (Peru) for the `simplesign` command line. It is an extension, not a library: install it into a CLI that is
already there.

```bash
dotnet tool install --global SimpleSign.Cli
simplesign extension install SimpleSign.Peru.Iofe.Cli
```

What it adds:

| | |
|---|---|
| `--profile iofe` | INDECOPI's trusted list (checked against the bundled signer, or the Sandbox's with `--sandbox`) and the policies of INDECOPI's accreditation guide, for `sign`, `validate` and the other standard commands |
| `--signing-policy iofe`, `--policy iofe`, `policy export … --preset iofe` | The `iofe` policies, and `iofe-agent` for an automated agent (nonRepudiation required) |
| `--tsl-profile iofe` | A trusted list read as INDECOPI's: its `unspecified` services too, never a code-signing certificate |
| `simplesign iofe sign`, `iofe verify`, `iofe view` | The accredited configuration of the guide's sections 4.2 to 4.4 (`SimpleSign.Peru.Iofe.Accredited`); `iofe sign` takes the key from a PKCS#11 module (`--pkcs11-lib`) or from a remote signing service (`--csc-url`), never from a PFX file |

```bash
simplesign validate contrato.pdf --profile iofe
simplesign iofe verify recibido.pdf --sender 20123456789 --audit-log verificacion.jsonl --notice comunicado.txt
simplesign extension remove iofe
```

More in the [IOFE article](https://github.com/eupassarin/SimpleSign/tree/main/src/Extensions/Peru/Iofe/docs/iofe.md) and
the manuals in Spanish next to it. MIT licensed.
