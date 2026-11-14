# SimpleSign.Cli

The `simplesign` command-line tool: sign, validate, inspect and augment PAdES, CAdES and XAdES from
a shell, a script or CI.

```bash
dotnet tool install -g SimpleSign.Cli          # published as the SimpleSign.Cli .NET tool
dotnet run --project src/Apps/SimpleSign.Cli -- --help   # from this repo
```

It targets **net8.0 only** — a .NET tool takes exactly one target framework — while the libraries
multi-target net8.0 and net10.0.

## Commands

`sign` · `sign-dir` · `validate` · `validate-dir` · `inspect` · `extract` · `augment` ·
`deferred prepare|complete` · `cades sign|validate` · `xades sign|validate` ·
`timestamp create|verify` · `policy export|schema` · `audit verify` · `pkcs11 list|drivers` ·
`psc certificates` · `csc list` · `fiscal sign|validate` · `profiles` · `explain` · `html-to-pdf`

```bash
simplesign sign contract.pdf --cert me.pfx --output signed.pdf --ltv --tsa http://timestamp.digicert.com
simplesign validate signed.pdf --json
simplesign augment signed.pdf --level BLTA --tsa http://timestamp.digicert.com
```

A whole trust framework comes from one flag — `--profile icp-brasil`, `iofe`, `gov-br`, `eidas` or
`sandbox` — which sets the trust anchors and the policies together.

## Files here

- `PACKAGE.md` — the readme shown on NuGet.
- `Commands/` — one class per command; `Json/` — the `--json` shapes, source-generated.

Every option, with examples: [docs/articles/cli.md](../../../docs/articles/cli.md). How it fits
with the other apps: [docs/articles/apps.md](../../../docs/articles/apps.md).
