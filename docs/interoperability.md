← [Back to README](../README.md)

# Interoperability

SimpleSign is built to survive the real world — legacy PDFs from Adobe, iText, pyHanko, LibreOffice, Word, and government signers across Europe and Brazil.

## PDF Structure Compatibility

| Feature | Support | Notes |
|---|---|---|
| **Classic xref tables** | ✅ | PDF 1.0+ — all versions |
| **Cross-reference streams** | ✅ | PDF 1.5+ — iText, Adobe, Word default |
| **Compressed Object Streams (ObjStm)** | ✅ | Extracts objects from FlateDecode containers |
| **Linearized PDFs** | ✅ | Follows `startxref` from EOF correctly |
| **Incremental updates** | ✅ | Up to 100 revision layers (multi-signature) |
| **Encrypted PDFs** | ❌ | By design — throws `EncryptedPdfException` |
| **Max file size** | 200 MB | Configurable |

## Real-World PDF Generators Tested

| Generator | Sign | Inspect | Validate | Notes |
|---|---|---|---|---|
| **Adobe Acrobat/Reader** | ✅ | ✅ | ✅ | `adbe.pkcs7.detached`, embedded CRL/OCSP |
| **iText 5/7/9** | ✅ | ✅ | ✅ | Interop CI tests; xref streams + ObjStm |
| **Apache PDFBox** | ✅ | ✅ | ✅ | Docker-based CI verification |
| **EU DSS (Digital Signature Service)** | ✅ | ✅ | ✅ | ETSI corpus + cross-validation |
| **pyHanko** | ✅ | ✅ | ✅ | Standard ETSI.CAdES.detached format |
| **LibreOffice** | ✅ | ✅ | ✅ | Linearized + xref stream PDFs |
| **Microsoft Word** | ✅ | ✅ | ✅ | ObjStm-compressed objects |
| **ICP-Brasil signers** | ✅ | ✅ | ✅ | Gov.br, AD-RB profiles, BER-encoded CMS |
| **Belgian eID** | — | ✅ | ✅ | ETSI corpus fixture |
| **Spanish gov (doc-firmado)** | — | ✅ | ✅ | ETSI corpus fixture |

## Multi-Signature Stress Tests

| Scenario | Status |
|---|---|
| PDF with **51 sequential signatures** | ✅ Signs + preserves all |
| PDF with **21 ObjStm-based signatures** (real gov document) | ✅ Signs without corrupting |
| PDF with **5 signatures + 1 document timestamp** | ✅ Full round-trip |
| Adding signature to **already-certified** PDF | ✅ Respects DocMDP |

## Integration Test Fixtures (57 PDFs)

Real-world PDFs covering edge cases:

- **Adobe**: `adbe-crl-signed.pdf`, `adbe-ocsp-signed.pdf`
- **ECDSA**: `pades-ecdsa.pdf` (elliptic curve signatures)
- **PAdES levels**: B-B, B-T, B-LT, B-LTA, LTV variants
- **DSS edge cases**: `dss-1443`, `dss-1683`, `dss-2025`, `dss-2821`, `dss-3226`, `dss-3567`
- **Negative tests**: `malformed-pades.pdf`, `bad-encoded-cms.pdf`, `modified-after-sig.pdf`, `encrypted.pdf`

## ETSI Corpus Tests

9 test methods against the [EU DSS interoperability corpus](https://ec.europa.eu/digital-building-blocks/wikis/display/DIGITAL/eSignature+Conformance+Testing):

- **PAdES-LT/LTA** multi-revision documents (DSS updates + archive timestamps)
- **Belgian eID** (`BG_BOR`) signed documents
- **German** (`DE_SCI`) signed documents
- **French** (`FR_CS`) signed documents
- **Spanish** (`doc-firmado`) signed documents
- **Hungarian** (`HU_MIC`) plugtest documents
- **Known-bad** fixtures (DSS-1683 SHA-1 regression)

## Cross-Validation Matrix

| Tool | Direction | Status |
|---|---|---|
| **EU DSS** | SimpleSign → EU DSS validator | ✅ |
| **EU DSS** | EU DSS signer → SimpleSign validator | ✅ |
| **iText 9** | SimpleSign → iText validation | ✅ |
| **Apache PDFBox** | SimpleSign → PDFBox verification | ✅ |

## Docker-Based CI Tests

All interop tests run in Docker containers in CI (EU DSS, iText validator, PDFBox) — see [`interop/`](../interop/) for details.
