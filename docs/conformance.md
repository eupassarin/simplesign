← [Back to README](https://github.com/eupassarin/SimpleSign#readme)

# Standards Conformance

SimpleSign implements PAdES, CAdES, and XAdES digital signatures with conformance
boundaries documented below. This document details compliance with ISO, ETSI, RFC, and
Brazilian (ICP-Brasil) specifications for the current source tree. Consult the
[release history](https://github.com/eupassarin/SimpleSign/blob/main/CHANGELOG.md) and release-tagged documentation for the
implementation delivered in a particular package version.

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
| **SubFilter** | `ETSI.CAdES.detached` as default | ✅ | `adbe.pkcs7.detached` remains available while retaining PAdES attributes |
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

Baseline signing claims require checked artifact integrity and applicable embedded
evidence. They do not establish signer-chain or TSA trust; those depend on the
validation trust anchors and policy. XAdES `DetectedLevel` reports observed
elements, while its optional timestamp/LTV/archive fields report checked outcomes.
See [inspection and validation](articles/inspection-validation.md) for these distinctions.

| Standard | Levels | Status | Notes |
|---|---|---|---|
| **ISO 32000-1:2008** | Signature subsystem | ✅ | 46 unit tests per section (see above) |
| **ISO 32000-2:2020** | Signature subsystem | ✅ | XRef streams, CAdES, DSS, VRI, DocMDP, SHA-1 deprecation, PDF 2.0 detection |
| **PAdES** (ETSI EN 319 142) | B-B (Basic) | ✅ | CMS + `signingCertificateV2` |
| | B-T (Timestamp) | ✅ | RFC 3161 timestamp token |
| | B-LT (Long-Term) | ✅ | DSS dictionary with CRL/OCSP |
| | B-LTA (Archive) | ✅ | Document timestamp with checked PDF byte-range coverage |
| | DocMDP (Certification) | ✅ | Three permission levels (P=1, 2, 3) |
| | PDF/A preservation | ✅ | Detects and preserves 1a/1b/2a/2b/2u/3a/3b/3u/4a/4b/4u/4e |
| **DOC-ICP-15** | AD-RB (Referência Básica) | ✅ | CMS + signingCertificateV2, ICP-Brasil chain |
| | AD-RT (Referência Temporal) | ✅ | AD-RB + RFC 3161 timestamp |
| | AD-RV/AD-RC/AD-RA | ✅ | CAdES-XL/A: certificate-refs, revocation-refs, cert-values, revocation-values via CmsAttribute |
| **RFC 5652** | CMS SignedData | ✅ | Full compliance (§5.1–5.6), detached signatures |
| **ETSI EN 319 142-1** | PAdES core (B-B, B-T, B-LT, B-LTA) | ✅ | Signature creation & augmentation |
| **ETSI EN 319 142-2** | PAdES extended (LTV, archival) | ✅ | DSS/VRI + document timestamps |
| **ETSI EN 319 122-1** | CAdES B-B, B-T, B-LT, B-LTA | ✅ | RFC 3161 binding, authenticated root CMS validation sets (RFC 5940 OCSP), `archiveTimestampV3` + `ATSHashIndexV3` |
| **ETSI EN 319 132-1** | XAdES B-B, B-T, B-LT, B-LTA | ✅ | ETSI archive preimage; XMLDSig reference processing; same-document distributed unsigned properties and counter-signatures |
| **RFC 9688** | SHA-3 OIDs and parameters in CMS | ✅ | id-sha3-256/384/512, id-rsassa-pkcs1-v1_5-with-sha3-256/384/512, id-ecdsa-with-sha3-256/384/512 |
| **RFC 8933** | EdDSA in CMS | ⏳ | OIDs are recognized, but signing is deferred until raw external output is verifiable on every target |
| **RFC 8032** | EdDSA algorithm | ⏳ | Ed25519/Ed448 signing is not advertised in v0.9.0 |
| **RFC 8410** | EdDSA X.509 identifiers | ✅ | OIDs 1.3.101.112 (Ed25519) / 1.3.101.113 (Ed448) |

## SubFilter Support

| SubFilter | Sign | Inspect | Validate | Notes |
|---|---|---|---|---|
| `ETSI.CAdES.detached` | ✅ (default) | ✅ | ✅ | Modern ETSI standard |
| `adbe.pkcs7.detached` | ✅ | ✅ | ✅ | Compatibility subfilter with PAdES attributes |
| `ETSI.RFC3161` | ✅ | ✅ | ✅ | Document timestamps (B-LTA) |

## Supported Algorithms

| Category | Algorithms |
|---|---|
| **Hash** | SHA-256, SHA-384, SHA-512, SHA3-256, SHA3-384, SHA3-512 |
| **Signature** | RSA PKCS#1 v1.5, RSA-PSS, RSA-SHA3-256/384/512¹, ECDSA (P-256/P-384/P-521), ECDSA-SHA3-256/384/512¹ |
| **Revocation** | CRL, OCSP, embedded DSS |
| **Timestamps** | RFC 3161 |
| **PDF/A** | 1a, 1b, 2a, 2b, 2u, 3a, 3b, 3u, 4a, 4b, 4u, 4e (detection + preservation) |

¹ SHA-3 signature and digest OIDs defined in RFC 8702; CMS encoding defined in RFC 8933.
² EdDSA algorithm identifiers remain recognized, but v0.9.0 rejects EdDSA signing rather than producing external output that net8.0 cannot verify.

## CAdES and XAdES archival boundaries

For B-T, B-LT, and B-LTA, SimpleSign binds every RFC 3161 response to the request
before embedding it and derives the reported level from final-artifact inspection.
CAdES archive timestamps use `ATSHashIndexV3`; XAdES builds the ETSI archive
preimage from XMLDSig references, `SignedInfo`, `SignatureValue`, optional `KeyInfo`,
unsigned qualifying properties, and applicable `ds:Object` values.

XAdES accepts base64, enveloped-signature, the standard signature-exclusion XPath,
and C14N/exclusive-C14N transforms for archive-reference processing. Distributed
`ArchiveTimeStamp` properties are supported when every `Include` is a same-document
bare-name ID reference; their declared order is preserved and comments are excluded
before canonicalization. XSLT, network/external `Include` resources, unsupported
transforms, and an archive operation without an explicit target in a multi-signature
document fail closed rather than producing an archival-level claim.

Use `XadesSignatureValidator.ValidateAll(...)` for a document that contains multiple
XMLDSig signatures. `Validate(...)` intentionally returns an invalid structured result
for that ambiguous case instead of inspecting only the first signature.
