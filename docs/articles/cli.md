# CLI

Install with `dotnet tool install -g SimpleSign.Cli`.

## PDF Signatures

```bash
# Sign a PDF
simplesign sign contract.pdf --cert mycert.pfx --password secret --tsa http://timestamp.digicert.com

# Validate (add --trust to accept your own root CA, --json for machine-readable output)
simplesign validate signed.pdf
simplesign validate signed.pdf --trust my-root-ca.pem --json

# Validate a directory of signed PDFs
simplesign validate-dir ./documents/

# Inspect
simplesign inspect signed.pdf

# Extract CMS from signed PDF
simplesign extract signed.pdf --output-dir ./extracted

# Convert HTML to PDF (relative images/CSS resolve against the HTML file's folder)
simplesign html-to-pdf page.html --output page.pdf

# ... with an embedded Unicode font, footer, and PDF/A-2b for archiving
simplesign html-to-pdf page.html --font "Noto Sans=NotoSans-Regular.ttf" --footer "{page}/{pages}" --pdfa

# Explain a signature term (omit the term for the full glossary)
simplesign explain ByteRange

# Show version
simplesign version
```

## CAdES Signatures

```bash
# CAdES-B-B (basic)
simplesign cades sign document.pdf --cert mycert.pfx

# CAdES-B-T (with timestamp)
simplesign cades sign document.pdf --cert mycert.pfx \
    --tsa http://timestamp.digicert.com --level timestamped

# CAdES-B-LT (long-term with LTV)
simplesign cades sign document.pdf --cert mycert.pfx \
    --tsa http://timestamp.digicert.com --level longterm --chain chain.pem

# CAdES-B-LTA (with archival timestamp)
simplesign cades sign document.pdf --cert mycert.pfx \
    --tsa http://timestamp.digicert.com --level archive

# Enveloped mode — data embedded inside the CMS (.p7m)
simplesign cades sign document.pdf --cert mycert.pfx --content-type enveloped

# Signer location, role and a description of the content
simplesign cades sign document.pdf --cert mycert.pfx \
    --signer-country BR --signer-locality "São Paulo" --signer-postal-address "Av. Paulista, 1000" \
    --signer-role Director --mime-type application/pdf --content-description "Contract"

# Roles vouched for by a third party (embedded as given, not verified)
simplesign cades sign document.pdf --cert mycert.pfx \
    --attribute-certificate role.ac --signed-assertion assertion.xml

# Timestamp the content before signing
simplesign cades sign document.pdf --cert mycert.pfx \
    --tsa http://timestamp.digicert.com --content-timestamp

# Carry the policy document in the signature (its SHA-256 goes in the policy identifier)
simplesign cades sign document.pdf --cert mycert.pfx \
    --policy-oid 1.2.3.4.5 --policy-document policy.der --policy-specification 1.2.3.4.5.1

# B-LT asking the CRL before OCSP (also on `sign` and `xades sign`)
simplesign cades sign document.pdf --cert mycert.pfx \
    --tsa http://timestamp.digicert.com --level longterm --revocation-preference crl

# Validate a CAdES signature
simplesign cades validate document.pdf.p7s --data document.pdf

# Validate with custom trust anchors
simplesign cades validate document.pdf.p7s --data document.pdf --trust root-ca.pem
```

## XAdES Signatures

```bash
# XAdES-B-B enveloped (default form)
simplesign xades sign invoice.xml --cert mycert.pfx

# XAdES-B-T detached
simplesign xades sign data.xml --cert mycert.pfx \
    --tsa http://timestamp.digicert.com --level timestamped \
    --form detached --data-uri data.xml

# XAdES-B-LT enveloping
simplesign xades sign data.xml --cert mycert.pfx \
    --tsa http://timestamp.digicert.com --level longterm \
    --form enveloping --chain chain.pem

# Production place and Canonical XML 1.0 instead of Exclusive C14N
simplesign xades sign invoice.xml --cert mycert.pfx \
    --place-city "São Paulo" --place-state SP --place-country BR --canonicalization inclusive

# More files signed with the document: one inside the signature, one referenced by URI
simplesign xades sign invoice.xml --cert mycert.pfx \
    --embed-object attachment.pdf,application/pdf --external-object terms.txt=terms.txt,text/plain

# Timestamp the signed data before signing; carry the policy document in the signature
simplesign xades sign invoice.xml --cert mycert.pfx \
    --tsa http://timestamp.digicert.com --data-objects-timestamp \
    --policy-oid 1.2.3.4.5 --policy-document policy.xml --policy-specification https://example.com/policy-syntax

# Roles vouched for by a third party (embedded as given, not verified)
simplesign xades sign invoice.xml --cert mycert.pfx \
    --attribute-certificate role.ac --signed-assertion assertion.xml

# Countersign a signature of an already signed document (--countersign-id picks one of several)
simplesign xades sign signed.xml --cert witness.pfx --countersign --output countersigned.xml

# Validate a XAdES signature
simplesign xades validate signed.xml

# Validate a signature with external data objects: give each by its URI
simplesign xades validate signed.xml --external-object terms.txt=terms.txt

# Validate detached with original data
simplesign xades validate signed.xml --data data.xml

# Validate with custom trust anchors
simplesign xades validate signed.xml --trust root-ca.pem
```

## Validation Output

```
contract-signed.pdf  1/1 valid
├── Document
│   ├── Signatures: 1 user + 0 timestamps
│   ├── Encrypted:  No
│   ├── DocMDP:     Not locked
│   ├── PDF/A:      None
│   └── ✓ DSS (embedded)
└── Signature1  ✓ VALID
    ├── Signer:       CN=Jane Doe, O=Acme Corp
    ├── SubFilter:    ETSI.CAdES.detached
    ├── PAdES:        B-T (Timestamp)
    ├── Certificate
    │   ├── Subject:        CN=Jane Doe, O=Acme Corp
    │   ├── Issuer:         DigiCert SHA2 Assured ID CA
    │   ├── Serial:         0A:1B:2C:3D
    │   ├── Key:            RSA 2048-bit
    │   ├── Valid:          2024-01-01 – 2026-01-01
    │   └── NonRepudiation: ✓
    ├── ESS CertV2:   ✓
    ├── Validation
    │   ├── Integrity:  ✓ Valid
    │   ├── Signature:  ✓ Valid
    │   ├── Chain:      ✓ Valid
    │   ├── Revoked:    ✓ Not revoked (OCSP)
    │   └── Timestamp:  ✓ 2025-04-28 14:30:00 UTC
    ├── Timestamp
    │   ├── Time:       2025-04-28 14:30:00 UTC
    │   ├── TSA:        CN=DigiCert Timestamp 2023
    │   └── Token Size: 4.2 KB
    ├── Algorithm:    SHA-256
    ├── Byte Range:   [0, 1234, 5678, 9012]  ✓
    └── Signed at:    2025-04-28 14:30:00 UTC
```
