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

# Validate all signatures (--trust adds your own root CA; --json for scripts)
simplesign validate signed.pdf --trust root-ca.pem

# Inspect signatures without validation
simplesign inspect signed.pdf

# CAdES / XAdES
simplesign cades sign document.pdf --cert cert.pfx
simplesign xades validate signed.xml
```

Run `simplesign --help` for all commands and options.

More at [github.com/eupassarin/SimpleSign](https://github.com/eupassarin/SimpleSign)
and the [docs](https://github.com/eupassarin/SimpleSign/tree/main/docs/articles). MIT licensed.
