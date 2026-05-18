← [Back to README](../README.md)

# Standards Conformance

SimpleSign implements PDF digital signatures in strict conformance with international standards. This document details compliance with ISO, ETSI, and Brazilian (ICP-Brasil) specifications.

## ISO 32000-1:2008 Compliance

SimpleSign implements PDF digital signatures in strict conformance with ISO 32000-1. Compliance is verified by **46 automated unit tests**, each mapping to a specific section of the standard:

| ISO Section | Requirement | Tests |
|---|---|---|
| §7.3.4.2 | String escaping (`\n`, `\r`, `\t`, `\b`, `\f`, `\\`, `\(`, `\)`) | 2 |
| §7.5.4–6 | Incremental updates (original bytes, `/Prev` chain, `/Size`, `startxref`, `%%EOF`) | 5 |
| §7.5.4 | Xref table entries exactly 20 bytes (`oooooooooo ggggg n\r\n`) | 1 |
| §7.5.8 | Cross-reference streams (`/Type /XRef`, `/W`, `/Index`, self-entry, `/FlateDecode`) | 7 |
| §7.9.4 | Date format `D:YYYYMMDDHHmmss+HH'mm'` (not `Z` suffix) | 1 |
| §8.6.5 | Widget annotation flags (`/F 132` visible, `/F 0` invisible) | 2 |
| §8.7 | Page `/Annots` array updated with field reference | 1 |
| §12.7 | AcroForm (`/Fields`, `/SigFlags 3`, no `/Type`, preserves `/DR`, `/DA`, `/Q`) | 4 |
| §12.7.4.5 | Signature fields (`/FT /Sig`, `/V`, `/T`, `/P`, unique names) | 5 |
| §12.8.1 | Signature dictionary (`/Type /Sig`, `/Filter`, `/SubFilter`, `/ByteRange`, `/Contents`) | 7 |
| §12.8.2 | DocMDP certification (`/Reference`, `/TransformMethod`, `/P`, `/Perms`) | 4 |
| §12.8.3 | Appearance stream (`/AP /N`, `/Subtype /Form`, `/BBox`) | 2 |
| Cross-cutting | Every object has matching `endobj`, `BuildXrefStream` correctness | 5 |

## ISO 32000-2:2020 (PDF 2.0) Compliance

SimpleSign is designed with PDF 2.0 alignment in mind. The digital signature subsystem covers the key requirements introduced or formalized in ISO 32000-2:

| Feature | 32000-2 Requirement | Status | Notes |
|---|---|---|---|
| **SubFilter** | `ETSI.CAdES.detached` as default | ✅ | `adbe.pkcs7.detached` supported for legacy only |
| **Cross-reference streams** | Xref streams required (classic deprecated) | ✅ | Full support: `/Type /XRef`, `/W`, `/Index`, ObjStm, FlateDecode, PNG predictors |
| **Hash algorithms** | SHA-256/384/512 required; MD5 deprecated | ✅ | SHA-256 default; MD5 rejected at signing time |
| **DSS dictionary** | Formalized in §12.8.4.3 | ✅ | CRLs, OCSPs, Certs extraction and embedding |
| **VRI structure** | Formalized in §12.8.4.4 | ✅ | Keys validated, `/TU` timestamps, per-signature entries |
| **DocMDP certification** | Enhanced in §12.8.2 | ✅ | Permission levels 1/2/3, `/Perms`, `/TransformMethod` |
| **PAdES alignment** | Aligns with ETSI EN 319 142 | ✅ | B-B, B-T, B-LT, B-LTA fully implemented |
| **RC4 encryption** | Removed | ✅ | Encrypted PDFs refused entirely |
| **AES-256 encryption** | Required for encrypted PDFs | N/A | Encrypted PDFs out of scope (decrypt first) |
| **PDF 2.0 header** | `%PDF-2.0` | ✅ | Detected, parsed, reported in inspection |
| **SHA-1** | Deprecated for new signatures | ✅ | Rejected for signing; flagged as deprecated in inspection/validation |

**Design philosophy:** SimpleSign refuses unsafe operations (RC4, MD5, encrypted PDFs) rather than implementing them insecurely. Encryption is intentionally out of scope — use [qpdf](https://qpdf.sourceforge.io/) or Adobe Acrobat to decrypt before signing.

## Conformance Matrix

| Standard | Levels | Status | Notes |
|---|---|---|---|
| **ISO 32000-1:2008** | Signature subsystem | ✅ | 46 unit tests per section (see above) |
| **ISO 32000-2:2020** | Signature subsystem | ✅ | XRef streams, CAdES, DSS, VRI, DocMDP, SHA-1 deprecation, PDF 2.0 detection |
| **PAdES** (ETSI EN 319 142) | B-B (Basic) | ✅ | CMS + `signingCertificateV2` |
| | B-T (Timestamp) | ✅ | RFC 3161 timestamp token |
| | B-LT (Long-Term) | ✅ | DSS dictionary with CRL/OCSP |
| | B-LTA (Archive) | ✅ | Document timestamp for decade-long validity |
| | DocMDP (Certification) | ✅ | Three permission levels (P=1, 2, 3) |
| | PDF/A preservation | ✅ | Detects and preserves 1a/1b/2a/2b/3a/3b |
| **DOC-ICP-15** | AD-RB (Referência Básica) | ✅ | CMS + signingCertificateV2, ICP-Brasil chain |
| | AD-RT (Referência Temporal) | ✅ | AD-RB + RFC 3161 timestamp |
| | AD-RV/AD-RC/AD-RA | ❌ | Future: requires CAdES-XL/A validation references |
| **RFC 5652** | CMS SignedData | ✅ | Full compliance (§5.1–5.6), detached signatures |
| **ETSI EN 319 142-1** | PAdES core (B-B, B-T, B-LT, B-LTA) | ✅ | Signature creation & augmentation |
| **ETSI EN 319 142-2** | PAdES extended (LTV, archival) | ✅ | DSS/VRI + document timestamps |

## SubFilter Support

| SubFilter | Sign | Inspect | Validate | Notes |
|---|---|---|---|---|
| `ETSI.CAdES.detached` | ✅ (default) | ✅ | ✅ | Modern ETSI standard |
| `adbe.pkcs7.detached` | ✅ | ✅ | ✅ | Adobe legacy format |
| `ETSI.RFC3161` | ✅ | ✅ | ✅ | Document timestamps (B-LTA) |

## Supported Algorithms

| Category | Algorithms |
|---|---|
| **Hash** | SHA-256, SHA-384, SHA-512, SHA3-256, SHA3-384, SHA3-512 |
| **Signature** | RSA PKCS#1 v1.5, RSA-PSS, ECDSA (P-256/P-384/P-521), EdDSA (Ed25519/Ed448)¹ |
| **Revocation** | CRL, OCSP, embedded DSS |
| **Timestamps** | RFC 3161 |
| **PDF/A** | 1a, 1b, 2a, 2b, 3a, 3b (detection + preservation) |

¹ EdDSA via external signer pipeline; verification depends on runtime support.
