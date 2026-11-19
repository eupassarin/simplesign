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

```bash
simplesign validate contrato.pdf --profile iofe
simplesign extension remove iofe
```

The accredited configuration of INDECOPI's guide, sections 4.2 to 4.4 (`simplesign iofe sign`, `iofe verify`,
`iofe view`, with `SimpleSign.Peru.Iofe.Accredited`), comes with its own extension,
`SimpleSign.Peru.Iofe.Accredited.Cli`, from [its repository](https://github.com/eupassarin/simplesign-iofe-accredited).

More in the [IOFE article](https://github.com/eupassarin/SimpleSign/tree/main/src/Extensions/Peru/Iofe/docs/iofe.md). MIT
licensed.
