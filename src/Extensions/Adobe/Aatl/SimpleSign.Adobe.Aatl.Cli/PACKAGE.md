# SimpleSign.Adobe.Aatl.Cli

The Adobe Approved Trust List (AATL) for the `simplesign` command line. It is an extension, not a library: install it
into a CLI that is already there. Not affiliated with or endorsed by Adobe.

```bash
dotnet tool install --global SimpleSign.Cli
simplesign extension install SimpleSign.Adobe.Aatl.Cli
```

What it adds:

| | |
|---|---|
| `--profile aatl`, `--trust-profile aatl` | The anchors Acrobat trusts for signatures: Adobe's list, downloaded from Adobe and checked against the bundled Adobe root, each anchor with its certificate policy restrictions; the `aatl` policies; not the system's roots. For `sign`, `validate` and the other standard commands |
| `--signing-policy aatl`, `--policy aatl`, `policy export … --preset aatl` | The `aatl` policies |

```bash
simplesign validate contract.pdf --profile aatl
simplesign validate contract.pdf --profile icp-brasil --trust-profile aatl
simplesign extension remove aatl
```

More in the [AATL article](https://github.com/eupassarin/SimpleSign/tree/main/src/Extensions/Adobe/Aatl/docs/aatl.md).
MIT licensed. "Adobe" and "Acrobat" are trademarks of Adobe.
