# SimpleSign.Cli.Extensibility

The contract of the extensions of the `simplesign` command line: implement `ICliExtension` to add commands, trust
profiles (`--profile`), policy presets (`--signing-policy`, `--policy`) and trusted-list profiles (`--tsl-profile`) to
a CLI that is already installed — and, for a trust framework, a command that runs the standard `sign` with options of
its own (`CliSignRequest`), its chain validation in `validate`, and what it has to say about each signature shown.

```bash
simplesign extension install SimpleSign.Peru.Iofe.Cli     # adds --profile iofe and 'simplesign iofe …'
simplesign extension list
simplesign extension remove iofe
```

An extension is a NuGet package with a `cli-extension/` folder: an `extension.json` manifest and the assemblies.

```json
{ "name": "iofe", "assembly": "SimpleSign.Peru.Iofe.Cli.dll", "type": "SimpleSign.Peru.Iofe.Cli.IofeCliExtension",
  "contract": 1, "minCliVersion": "0.13.0", "version": "0.18.0", "package": "SimpleSign.Peru.Iofe.Cli" }
```

Installing an extension runs its code with the rights of whoever runs `simplesign`: install only packages you trust.
More in the [CLI extensions article](https://github.com/eupassarin/SimpleSign/tree/main/docs/articles/cli-extensions.md).
MIT licensed.
