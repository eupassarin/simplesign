# ETSI Signatures Conformance Checker: results

Written by `SimpleSign.EtsiChecker.Tests` from `results.json`; see [README.md](README.md). Each sample was checked against the baseline profile of its format (EN 319 142-1, EN 319 122-1, EN 319 132-1). *Failures* are the checker's failures nobody expects; *Expected* are those `known-issues.json` lists, such as the SubFilter of a sample made not to be baseline.

| Sample | Format | Level | How it was made | Signatures | Checks passed | Failures | Expected | Warnings | Result | Checked |
|---|---|---|---|---|---|---|---|---|---|---|
| [pades-b-b](pades-b-b/) | PADES | Basic | RSA, ETSI.CAdES.detached | 1 | 60 | 0 | 0 | 0 | ✅ | 2026-11-18 (1666d22e) |
| [pades-b-t](pades-b-t/) | PADES | Timestamped | RSA | 1 | 107 | 0 | 0 | 0 | ✅ | 2026-11-18 (1666d22e) |
| [pades-b-lt](pades-b-lt/) | PADES | LongTerm | RSA, DSS with CRLs | 3 | 132 | 0 | 0 | 0 | ✅ | 2026-11-18 (1666d22e) |
| [pades-b-lta](pades-b-lta/) | PADES | Archive | RSA, DSS and a document time-stamp | 4 | 139 | 0 | 0 | 0 | ✅ | 2026-11-18 (1666d22e) |
| [pades-b-t-adbe](pades-b-t-adbe/) | PADES | Timestamped | SubFilter adbe.pkcs7.detached: B-T content, not baseline | 1 | 106 | 0 | 1 | 0 | ✅ expected | 2026-11-18 (1666d22e) |
| [pades-b-t-ecdsa](pades-b-t-ecdsa/) | PADES | Timestamped | ECDSA P-256 | 1 | 107 | 0 | 0 | 0 | ✅ | 2026-11-18 (1666d22e) |
| [pades-b-t-rsapss](pades-b-t-rsapss/) | PADES | Timestamped | RSASSA-PSS | 1 | 107 | 0 | 0 | 0 | ✅ | 2026-11-18 (1666d22e) |
| [pades-b-b-visible](pades-b-b-visible/) | PADES | Basic | visible appearance | 1 | 60 | 0 | 0 | 0 | ✅ | 2026-11-18 (1666d22e) |
| [pades-b-t-certified](pades-b-t-certified/) | PADES | Timestamped | certification (DocMDP P=2) | 1 | 107 | 0 | 0 | 0 | ✅ | 2026-11-18 (1666d22e) |
| [pades-b-t-two-signatures](pades-b-t-two-signatures/) | PADES | Timestamped | RSA then ECDSA, each B-T | 2 | 214 | 0 | 0 | 0 | ✅ | 2026-11-18 (1666d22e) |
| [pades-b-lta-augmented](pades-b-lta-augmented/) | PADES | Archive | B-B raised to B-LTA by PadesAugmenter | 5 | 99 | 0 | 0 | 0 | ✅ | 2026-11-18 (1666d22e) |
| [pades-b-lta-renewed](pades-b-lta-renewed/) | PADES | Archive | B-LTA with its archive renewed | 5 | 172 | 0 | 0 | 0 | ✅ | 2026-11-18 (1666d22e) |
| [pades-b-t-deferred](pades-b-t-deferred/) | PADES | Timestamped | two-phase (DeferredSigner) | 1 | 107 | 0 | 0 | 0 | ✅ | 2026-11-18 (1666d22e) |
| [cades-b-b](cades-b-b/) | CADES | Basic | RSA, enveloping | 1 | 46 | 0 | 0 | 0 | ✅ | 2026-11-18 (1666d22e) |
| [cades-b-t](cades-b-t/) | CADES | Timestamped | RSA, enveloping | 1 | 94 | 0 | 0 | 0 | ✅ | 2026-11-18 (1666d22e) |
| [cades-b-lt](cades-b-lt/) | CADES | LongTerm | RSA, enveloping, CRLs in the root validation data | 1 | 98 | 0 | 0 | 0 | ✅ | 2026-11-18 (1666d22e) |
| [cades-b-lta](cades-b-lta/) | CADES | Archive | RSA, enveloping, archiveTimestampV3 + ATSHashIndexV3 | 1 | 168 | 0 | 0 | 0 | ✅ | 2026-11-18 (1666d22e) |
| [cades-b-t-ecdsa](cades-b-t-ecdsa/) | CADES | Timestamped | ECDSA P-256 | 1 | 94 | 0 | 0 | 0 | ✅ | 2026-11-18 (1666d22e) |
| [cades-b-t-rsapss](cades-b-t-rsapss/) | CADES | Timestamped | RSASSA-PSS | 1 | 94 | 0 | 0 | 0 | ✅ | 2026-11-18 (1666d22e) |
| [cades-b-t-countersigned](cades-b-t-countersigned/) | CADES | Timestamped | B-T counter-signed (ECDSA) | 1 | 124 | 0 | 0 | 0 | ✅ | 2026-11-18 (1666d22e) |
| [cades-b-lta-augmented](cades-b-lta-augmented/) | CADES | Archive | B-B raised to B-LTA by CadesAugmenter | 1 | 168 | 0 | 0 | 0 | ✅ | 2026-11-18 (1666d22e) |
| [cades-b-lta-renewed](cades-b-lta-renewed/) | CADES | Archive | B-LTA with its archive renewed | 1 | 240 | 0 | 0 | 0 | ✅ | 2026-11-18 (1666d22e) |
| [cades-b-t-deferred](cades-b-t-deferred/) | CADES | Timestamped | two-phase (CadesDeferredSigner) | 1 | 94 | 0 | 0 | 0 | ✅ | 2026-11-18 (1666d22e) |
| [xades-b-b-enveloped](xades-b-b-enveloped/) | XADES | Basic | RSA, enveloped | 1 | 54 | 0 | 0 | 0 | ✅ | 2026-11-18 (1666d22e) |
| [xades-b-b-enveloping](xades-b-b-enveloping/) | XADES | Basic | RSA, enveloping | 1 | 54 | 0 | 0 | 0 | ✅ | 2026-11-18 (1666d22e) |
| [xades-b-t](xades-b-t/) | XADES | Timestamped | RSA, enveloped | 1 | 74 | 0 | 0 | 0 | ✅ | 2026-11-18 (1666d22e) |
| [xades-b-lt](xades-b-lt/) | XADES | LongTerm | RSA, enveloped, CertificateValues + RevocationValues | 1 | 122 | 0 | 0 | 0 | ✅ | 2026-11-18 (1666d22e) |
| [xades-b-lta](xades-b-lta/) | XADES | Archive | RSA, enveloped, ArchiveTimeStamp | 1 | 133 | 0 | 0 | 0 | ✅ | 2026-11-18 (1666d22e) |
| [xades-b-t-ecdsa](xades-b-t-ecdsa/) | XADES | Timestamped | ECDSA P-256 | 1 | 74 | 0 | 0 | 0 | ✅ | 2026-11-18 (1666d22e) |
| [xades-b-t-countersigned](xades-b-t-countersigned/) | XADES | Timestamped | B-T counter-signed (ECDSA) | 1 | 125 | 0 | 0 | 0 | ✅ | 2026-11-18 (1666d22e) |
| [xades-b-lta-augmented](xades-b-lta-augmented/) | XADES | Archive | B-B raised to B-LTA by XadesAugmenter | 1 | 133 | 0 | 0 | 0 | ✅ | 2026-11-18 (1666d22e) |
| [xades-b-lta-renewed](xades-b-lta-renewed/) | XADES | Archive | B-LTA with its archive renewed | 1 | 144 | 0 | 0 | 0 | ✅ | 2026-11-18 (1666d22e) |
| [xades-b-t-deferred](xades-b-t-deferred/) | XADES | Timestamped | two-phase (XadesDeferredSigner) | 1 | 74 | 0 | 0 | 0 | ✅ | 2026-11-18 (1666d22e) |

## Failures and warnings

- **pades-b-t-adbe**, PAdES-signature-1: `CheckFailure` `CheckIfValueIsOneOfDefined` (expected) at `SubFilter`: Found value: 'adbe.pkcs7.detached''. Allowed values: ETSI.CAdES.detached
