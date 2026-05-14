# EU DSS Validator

Docker-based ETSI EN 319 102 conformance validator using the official EU Digital Signature Service (DSS) library. This container validates PAdES, CAdES, and XAdES signatures against the ETSI standards and produces detailed validation reports.

## Features

- ETSI EN 319 102 conformance validation
- PAdES, CAdES, and XAdES signature support
- Detailed validation reports with sub-indications
- Docker container for isolated, reproducible execution
- Used in CI for automated cross-validation

## Usage

```bash
# Build the Docker image
docker build -t simplesign-eu-dss .

# Validate a signed PDF
docker run --rm -v $(pwd):/data simplesign-eu-dss validate /data/signed.pdf

# Validate a CAdES signature
docker run --rm -v $(pwd):/data simplesign-eu-dss validate /data/signature.p7s --detached /data/original.dat
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | TOTAL_PASSED — signature is valid |
| 1 | TOTAL_FAILED — signature is invalid |
| 2 | INDETERMINATE — cannot determine validity |

> **Note:** Self-signed certificates will correctly report INDETERMINATE per ETSI standards, as the trust anchor is not in the EU Trusted List. This is expected behavior in test environments.

## See Also

- [Interop README](../README.md)
- [Main README](../../README.md)
