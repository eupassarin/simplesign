# CLI

Install with `dotnet tool install -g SimpleSign.Cli`.

## PDF Signatures

```bash
# Sign a PDF
simplesign sign contract.pdf --cert mycert.pfx --password secret --tsa http://timestamp.digicert.com

# Claimed signing time, document information, a larger /Contents and structured signer metadata
simplesign sign contract.pdf --cert mycert.pfx --password secret \
    --signing-time 2026-11-09T10:00:00-03:00 --doc-info Title=Contract --contents-size 32768 \
    --signer-id 12345678909 --signer-id-type CPF --legal-basis "Lei 14.063/2020" --commitment origin

# Explicit signature policy (signature-policy-identifier with the document's hash)
simplesign sign contract.pdf --cert mycert.pfx --password secret \
    --policy-oid 1.2.3.4.5 --policy-hash 9F86D081884C7D65... --policy-uri https://example.com/policy.der

# B-LTA with a separate archive TSA; accept a lower level when the TSA or revocation data are unreachable
simplesign sign contract.pdf --cert mycert.pfx --password secret --tsa http://timestamp.digicert.com \
    --archival --archive-tsa https://tsa.example.com/tsr --return-lower-level

# A TSA that asks for credentials (also on `cades sign` and `xades sign`; secrets accept env:NAME)
simplesign sign contract.pdf --cert mycert.pfx --password secret --tsa https://tsa.example.com/tsr \
    --tsa-user alice --tsa-password env:TSA_PASSWORD        # or --tsa-token env:TSA_TOKEN, or --tsa-cert client.pfx

# Validate (add --trust to accept your own root CA, --no-system-roots to trust only it, --json for machine-readable output)
simplesign validate signed.pdf
simplesign validate signed.pdf --trust my-root-ca.pem --json

# Sign every PDF of a folder (BatchSigner), four at a time, into folder/signed
simplesign sign-dir contracts/ --cert mycert.pfx --password secret --tsa http://timestamp.digicert.com --max-concurrency 4

# Deferred signing: the key is elsewhere (browser, token, remote service)
simplesign deferred prepare contract.pdf --cert signer.cer --session-key env:SESSION_KEY   # writes .session and .tbs
#   ...the signer hashes contract.pdf.tbs with SHA-256 and signs it (RSA PKCS#1 v1.5, or ECDSA in DER)...
simplesign deferred complete contract.pdf.session --session-key env:SESSION_KEY --signature contract.sig -o signed.pdf

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

# Add a second signer of the same content, or countersign the first signer
simplesign cades sign document.pdf.p7s --cosign --data document.pdf --cert second.pfx --password secret
simplesign cades sign document.pdf.p7s --countersign --signer-index 0 --cert notary.pfx --password secret

# Claimed signing time, RSASSA-PSS and an extended form (-C, -X-L or -A; also on xades sign)
simplesign cades sign document.pdf --cert mycert.pfx --password secret --signing-time 2026-11-09T10:00:00Z \
    --signature-algorithm rsassa-pss --tsa http://timestamp.digicert.com --level longterm --extended-form extended-long

# Validate a CAdES signature
simplesign cades validate document.pdf.p7s --data document.pdf

# Validate with custom trust anchors (the operating system's roots stay trusted; add --no-system-roots to trust only these)
simplesign cades validate document.pdf.p7s --data document.pdf --trust root-ca.pem
```

`cades validate` checks every signer and countersignature. With `--json`, `signatures` lists them (`signer-1`,
`signer-2`…, each with its `counterSignatures`: `signer-1.1`…); the top-level fields are those of the first signer.
The exit code is 0 only when all are valid.

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

# SigningCertificate V1 for older validators, the data's MIME type, and a PKCS#11 token as the key
simplesign xades sign invoice.xml --pkcs11-lib auto --signing-certificate-v1 --data-mime-type application/xml

# Validate a XAdES signature
simplesign xades validate signed.xml

# Validate a signature with external data objects: give each by its URI
simplesign xades validate signed.xml --external-object terms.txt=terms.txt

# Validate detached with original data
simplesign xades validate signed.xml --data data.xml

# Validate with custom trust anchors (the operating system's roots stay trusted; add --no-system-roots to trust only these)
simplesign xades validate signed.xml --trust root-ca.pem
```

`xades validate` checks every `ds:Signature` of the document and their countersignatures. With `--json`,
`signatures` lists them, each with its `counterSignatures`; the top-level fields are those of the first. The exit
code is 0 only when all are valid.

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

## Signing Policy

`sign`, `cades sign` and `xades sign` check the certificate before signing. `--signing-policy` chooses the checks:

| Value | Checks |
|---|---|
| `default` | Validity of every certificate of the chain, key usage digitalSignature or nonRepudiation, RSA ≥ 2048 bits, SHA-2/SHA-3 |
| `strict` | `default` plus the revocation of the whole chain (CRL/OCSP); give the chain up to the root |
| `minimal` | Only the dates of the signing certificate (tests and migrations) |

A refusal prints the reason (`KeyTooWeak`, `KeyUsageNotPermitted`, `ChainCertificateNotValid`, `CertificateRevoked`,
`RevocationStatusUnknown`, `AlgorithmNotPermitted`) and what to do about it. `simplesign explain <TERM>` explains the
ETSI sub-indications of a validation report, such as `CRYPTO_CONSTRAINTS_FAILURE_NO_POE`.

### JSON result

With `--json`, `sign`, `cades sign` and `xades sign` print one JSON object instead of text, for scripts and
test runners:

```json
{ "success": true, "format": "pades", "output": "contract_signed.pdf", "signer": "CN=…",
  "requestedLevel": "B-LT", "achievedLevel": "B-LT", "warnings": [], "error": null }
```

A refusal is `"success": false` with `"error": { "type": "SigningException", "reason": "CertificateRevoked",
"message": "…" }`; the exit code is not 0.

## Network

The library refuses requests to `localhost` and private addresses (the SSRF guard). To use a local test
environment, such as the [SimpleSign Sandbox](sandbox.md), every command accepts:

| Option | Environment variable | Effect |
|---|---|---|
| `--allow-origin <URL>` (repeatable) | `SIMPLESIGN_ALLOW_ORIGINS` (comma-separated) | A loopback origin (scheme, host, port) the TSA, CRL, OCSP and AIA requests may reach |
| `--allow-ldap` | `SIMPLESIGN_ALLOW_LDAP=true` | CRLs over `ldap://` |
| `--tls-trust <PEM>` | `SIMPLESIGN_TLS_TRUST` | A root, and its intermediates, accepted for HTTPS next to the system's |

```bash
curl -s http://localhost:5300/chain.pem > sandbox-chain.pem
simplesign sign contract.pdf --cert revoked-ocsp.pfx --password sandbox --signing-policy strict-signing-policy.json --json \
  --allow-origin http://localhost:5300 --allow-origin https://localhost:5301 --allow-origin ldap://localhost:5302 \
  --allow-ldap --tls-trust sandbox-chain.pem
```

## Validation Policy, Trust Store and Verification Report

`validate`, `validate-dir`, `cades validate` and `xades validate` share these options:

| Option | What it does |
|---|---|
| `--policy <file>` | Validation policy: JSON, root `ValidationConstraints`; see [ADR 0024](../adr/0024-own-policy-format.md) |
| `--policy-signer <cert>` | The policy must be signed with this certificate (detached CMS in `<policy>.p7s`) |
| `--trust-dir <dir>` | Folder of trust anchor certificates (`.cer`, `.crt`, `.der`, `.pem`) |
| `--trust-dir-signer <cert>` | The folder must carry `manifest.json` (SHA-256 of every file) signed with this certificate |
| `--tsl <url\|file>` + `--tsl-signer <cert>` | Trusted list (ETSI TS 119 612 / TS 102 231): its active CA and TSA services become trust anchors |
| `--lotl <url>` + `--lotl-signer <cert>` | List of trusted lists (e.g. the EU LOTL): the national lists it points to are checked with the certificates it gives and their CA and TSA services become trust anchors; `--lotl-territory PT` (repeatable) loads only some |
| `--lang es` | Write the verification report in Spanish |
| `--check-revocation` (CAdES, XAdES) | Check the revocation of the signer and TSA chains |
| `--level basic\|timestamps\|lt\|lta` | How much is validated: the signature and chain only, plus signature timestamps, plus revocation and long-term data, plus archive timestamps (default) |
| `--revocation-strategy ocsp-first\|crl-first` | Which revocation source is asked first (default `ocsp-first`); the other one answers when the first gives nothing |
| `--etsi-report <file>` | Write the ETSI TS 119 102-2 signature validation report (XML, namespace `http://uri.etsi.org/19102/v1.2.1#`) |
| `--simple-report <file>` | Write the simple report (JSON): per signature the indication, sub-indication, signer, times, policy, errors and warnings |
| `--revocation-for-untrusted` | Also check the revocation of chains that do not reach a trust anchor (off by default) |

Every signature gets a verification report: the indication (TOTAL-PASSED, TOTAL-FAILED, INDETERMINATE), the
ETSI EN 319 102-1 sub-indication, the signer's public key (algorithm, size, SHA-256 of the SubjectPublicKeyInfo and
the PEM) and each check of the validation. With `--json` the same data is in `subIndication`, `publicKey` and
`constraints`.

```bash
simplesign validate contrato.pdf --policy indecopi.json --tsl tsl-pe.xml --tsl-signer indecopi-tsl.cer --lang es
```

A policy file lists constraints grouped by what they apply to, each with a level; a constraint left out is not
evaluated, and one SimpleSign does not evaluate yet is reported as `NOT_CHECKED`. Start from the default
(`simplesign policy export validation -o policy.json`) and change what you need:

```json
{
  "ValidationConstraints": {
    "Name": "INDECOPI",
    "Description": "Key usage required; obsolete algorithms fail.",
    "SignatureConstraints": {
      "BasicSignatureConstraints": {
        "SigningCertificate": {
          "NotExpired": { "Level": "FAIL" },
          "KeyUsage": { "Level": "FAIL", "Id": [ "digitalSignature", "nonRepudiation" ] }
        }
      }
    },
    "Cryptographic": {
      "Level": "FAIL",
      "AcceptableDigestAlgo": { "Algo": [ "SHA1", "SHA256", "SHA384", "SHA512" ] },
      "MiniPublicKeySize": { "Algo": [ { "Value": "RSA", "Size": 2048 } ] },
      "AlgoExpirationDate": {
        "Format": "yyyy-MM-dd",
        "Algo": [ { "Value": "SHA1", "Date": "2012-08-01" }, "SHA256", "SHA384", "SHA512", { "Value": "RSA", "Size": 2048 } ]
      }
    }
  }
}
```

`--signing-policy <file>` on the sign commands takes the signing policy (root `SigningConstraints`, see
[PAdES signing](pades.md#signing-policy)); `simplesign policy export signing` writes the default one.

`timestamp verify` also tells whether the `tsa` name of the token matches the TSA certificate (RFC 3161 §2.4.2).
