# SimpleSign.Cli

Cross-platform command-line tool for digital signatures — sign, validate, and
inspect PAdES, CAdES, and XAdES documents.

## Install

```bash
dotnet tool install --global SimpleSign.Cli
```

## Usage

```bash
# Sign a PDF with an ICP-Brasil certificate from the Windows store
simplesign sign document.pdf --thumbprint <THUMBPRINT>

# Validate all signatures
simplesign validate signed.pdf

# Inspect signatures without validation
simplesign inspect signed.pdf

# CAdES / XAdES
simplesign cades sign document.pdf --certificate cert.pfx
simplesign xades validate signed.xml
```

Run `simplesign --help` for all commands and options.

More at [github.com/eupassarin/SimpleSign](https://github.com/eupassarin/SimpleSign)
and the [docs](https://eupassarin.github.io/SimpleSign/). MIT licensed.
