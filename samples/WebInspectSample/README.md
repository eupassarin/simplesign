# WebInspectSample — PDF Inspector & Validator

A web-based PDF signature inspector and validator using **SimpleSign**, matching the output of the CLI `inspect` and `validate` commands.

## Features

- **Inspect Tab** — Displays full signature metadata as a tree view:
  - Document properties (encryption, DocMDP, PDF/A, DSS)
  - Per-signature details (SubFilter, level, algorithms, signing time, byte range)
  - Signer certificate (subject, issuer, key, validity, revocation URLs)
  - RFC 3161 timestamps
  - Archive timestamps (LTA)
  - Embedded certificates chain
  - Signature manifests (Lei 14.063)

- **Validate Tab** — Runs full cryptographic validation:
  - Integrity check (hash match)
  - Signature verification
  - Certificate chain validation (with ICP-Brasil trust anchors)
  - Revocation checking (CRL/OCSP, optional)
  - PAdES conformance level detection

## Architecture

```
Browser ←→ Server (ASP.NET Minimal API)
              │
              ├── POST /api/inspect  → PdfSignatureInspector.InspectAsync()
              └── POST /api/validate → PdfSignatureValidator.ValidateAsync()
```

Everything runs server-side. The browser just uploads a PDF and renders the JSON response.

## Running

```bash
cd samples/WebInspectSample
dotnet run
```

Open http://localhost:5180 in your browser and drop a PDF file.
