# Interop Testing

This directory contains the cross-implementation validation infrastructure for SimpleSign. It runs 81 test scenarios against 7 independent verifiers to ensure signatures produced by SimpleSign are correctly validated by third-party tools, and vice versa.

## Features

- 81 automated test scenarios
- Forward interop: SimpleSign signatures → external verifiers
- Reverse interop: external tool signatures → SimpleSign validation
- Docker-based isolated environments for reproducibility
- CI integration (weekly schedule + manual dispatch)

## Verifiers

| Verifier | Purpose | Directory |
|----------|---------|-----------|
| OpenSSL | CMS/PKCS#7 signature verification | `dss-validator/` |
| xmlsec1 | W3C XML-DSig verification | `dss-validator/` |
| pyHanko | PAdES-level PDF validation | `dss-validator/` |
| Apache PDFBox | PDF structure and signature inspection | `pdfbox/` |
| EU DSS | ETSI EN 319 102 conformance validation | `eu-dss/` |
| iText 9 | Independent PAdES validation | `itext/` |
| pyHanko-sign | Reverse interop (external → SimpleSign) | `dss-validator/` |

## Running Locally

```bash
# Build Docker images
docker compose build

# Run all interop tests
dotnet test tests/SimpleSign.Interop/
```

## See Also

- [Main README](../README.md)
- [EU DSS Validator](eu-dss/README.md)
- [iText Validator](itext/README.md)
