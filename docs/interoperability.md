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
| **iText 5/7/9** | ✅ | ✅ | ✅ | Interop CI tests (LTA, cross-validator, cert edge cases); xref streams + ObjStm |
| **Apache PDFBox** | ✅ | ✅ | ✅ | Docker-based CI verification (PAdES-B-B, double-signed) |
| **EU DSS (Digital Signature Service)** | ✅ | ✅ | ✅ | ETSI corpus + cross-validation (CRL, LTA, cross-validator) |
| **pyHanko** | ✅ | ✅ | ✅ | CRL, document timestamps, form fields, unicode metadata |
| **LibreOffice** | ✅ | ✅ | ✅ | Linearized + xref stream PDFs |
| **Microsoft Word** | ✅ | ✅ | ✅ | ObjStm-compressed objects |
| **ICP-Brasil signers** | ✅ | ✅ | ✅ | Gov.br, AD-RB profiles, BER-encoded CMS, AEA Lei 14.063 |
| **Belgian eID** | — | ✅ | ✅ | ETSI corpus fixture |
| **Spanish gov (doc-firmado)** | — | ✅ | ✅ | ETSI corpus fixture |
| **OpenSSL** | — | ✅ | ✅ | CMS/PKCS#7 signature verification |
| **xmlsec1** | — | ✅ | ✅ | XML-DSig verification |
| **veraPDF** | — | — | ✅ | PDF/A conformance after incremental signing |

## Multi-Signature Stress Tests

| Scenario | Status |
|---|--|
| PDF with **51 sequential signatures** | ✅ Signs + preserves all |
| PDF with **21 ObjStm-based signatures** (real gov document) | ✅ Signs without corrupting |
| PDF with **5 signatures + 1 document timestamp** | ✅ Full round-trip |
| PDF with **double signature + LTV + archival timestamp** | ✅ Full PAdES-LTA round-trip |
| Adding signature to **already-certified** PDF | ✅ Respects DocMDP |

## Interop Test Coverage (18 test files, ~150 scenarios)

### Forward Interop (SimpleSign → External Validators)

| Test File | Scenarios | Validators |
|-----------|-----------|------------|
| `ExpandedInteropTests.cs` | Incremental updates, stream I/O, PDF structure variants, certification/DocMDP | pyHanko, OpenSSL, iText, EU DSS, pdfbox |
| `PadesDssInteropTests.cs` | DSS/VRI embedding, LTV at various PAdES levels | pyHanko, iText, EU DSS |
| `PadesCrossValidatorTests.cs` | Cross-algorithm (SHA-384/512, ECDSA P-256/P-384) | iText, EU DSS, pyHanko |
| `ITextInteropTests.cs` | PAdES-B signatures (B-B, B-T, B-LT, B-LTA), incremental | iText 9 |
| `EuDssInteropTests.cs` | B-B, B-T, B-LT, B-LTA round-trip | EU DSS |
| `ComplexPdfInteropTests.cs` | Multi-signature, ObjStm, compressed xref, linearized | pyHanko, iText, EU DSS, pdfbox |
| `CertEdgeCaseInteropTests.cs` | Large keys (4096-bit RSA), certificate chains | iText, EU DSS, OpenSSL, xmlsec1 |
| `LtaInteropTests.cs` | PAdES-LTA archival timestamps with full LTV | iText, EU DSS |
| `CrlInteropTests.cs` | CRL-based revocation in PAdES-LT DSS | pyHanko, EU DSS |
| `DocumentTimestampInteropTests.cs` | Standalone RFC 3161 document timestamps | pyHanko |
| `FormFieldInteropTests.cs` | Named AcroForm field signing | pyHanko |
| `UnicodeInteropTests.cs` | CJK, Arabic, emoji, accented metadata | pyHanko |
| `BrasilInteropTests.cs` | AEA Lei 14.063, ICP-Brasil policy OIDs | OpenSSL |
| `PdfboxInteropTests.cs` | PAdES-B-B, double-signed parseability | Apache PDFBox |
| `VeraPdfInteropTests.cs` | PDF/A-2b/3b conformance after 1x and 2x signing | veraPDF |
| `TamperedInteropTests.cs` | Tampered signatures must be rejected | pyHanko, iText, EU DSS |

### Reverse Interop (External Tools → SimpleSign)

| Test File | Scenarios | Sources |
|-----------|-----------|---------|
| `ReverseInteropTests.cs` | CMS/PKCS#7 signatures produced by OpenSSL, xmlsec1 | OpenSSL, xmlsec1 |

### ETSI Corpus Tests

| Test File | Scenarios |
|-----------|-----------|
| `EtsiCorpusTests.cs` | PAdES-LT/LTA multi-revision (DSS + archive timestamps), Belgian eID (`BG_BOR`), German (`DE_SCI`), French (`FR_CS`), Spanish (`doc-firmado`), Hungarian (`HU_MIC`), known-bad fixtures (DSS-1683 SHA-1 regression) |

## Cross-Validation Matrix

| Tool | Direction | Status |
|---|---|---|
| **EU DSS** | SimpleSign → EU DSS validator | ✅ |
| **EU DSS** | EU DSS signer → SimpleSign validator | ✅ |
| **iText 9** | SimpleSign → iText validation | ✅ |
| **Apache PDFBox** | SimpleSign → PDFBox verification | ✅ |
| **OpenSSL** | SimpleSign → OpenSSL CMS verification | ✅ |
| **OpenSSL** | OpenSSL → SimpleSign validation | ✅ |
| **pyHanko** | SimpleSign → pyHanko validation | ✅ |
| **xmlsec1** | xmlsec1 → SimpleSign validation | ✅ |
| **veraPDF** | SimpleSign → veraPDF PDF/A conformance | ✅ |

> **SHA-3 and EdDSA interop:** Interop tests with SHA-3 digests and EdDSA signatures against external validators (EU DSS, iText, PDFBox, pyHanko) are tracked in the interop test backlog.

## Docker-Based CI Tests

All interop tests run in Docker containers in CI (EU DSS, iText validator, PDFBox, veraPDF, OpenSSL, pyHanko, xmlsec1) — see [`interop/`](../interop/) for details.
