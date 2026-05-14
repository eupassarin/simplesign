# iText Validator

Independent PAdES signature validation tool using iText Core 9 (AGPL license). Provides PDF signature validation, inspection, and structure checking as an external reference implementation for cross-validation testing.

## Features

- PAdES signature validation using iText Core 9
- Signature metadata inspection
- PDF structure integrity checking
- Three operation modes: validate, inspect, and check-structure
- Used exclusively for automated interop testing

## Usage

```bash
# Build the Docker image
docker build -t simplesign-itext .

# Validate PDF signatures
docker run --rm -v $(pwd):/data simplesign-itext validate-pdf /data/signed.pdf

# Inspect signature metadata
docker run --rm -v $(pwd):/data simplesign-itext inspect-pdf /data/signed.pdf

# Check PDF structure
docker run --rm -v $(pwd):/data simplesign-itext check-structure /data/signed.pdf
```

## Commands

| Command | Description |
|---------|-------------|
| `validate-pdf` | Validate all signatures in a PDF |
| `inspect-pdf` | Display signature metadata without validation |
| `check-structure` | Verify PDF structure integrity |

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Valid / OK |
| 1 | Invalid / Failed |
| 2 | Error (e.g., file not found, parse error) |

## See Also

- [Interop README](../README.md)
- [Main README](../../README.md)
