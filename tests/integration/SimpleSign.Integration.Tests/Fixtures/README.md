# Integration test fixtures

## EU DSS / ETSI corpus

Real-world signatures made by other producers, which SimpleSign validates offline (no revocation, no system
roots, every HTTP request fails). They come from the test resources of the EU Digital Signature Service,
[github.com/esig/dss](https://github.com/esig/dss), licensed under the
[LGPL-2.1](https://github.com/esig/dss/blob/master/LICENSE) (LGPL-2.1-or-later); they are kept here unchanged, as
test data only — no DSS code is used or shipped.

### PAdES

From `dss-test/src/test/resources/validation` (ETSI plugtest and DSS bug-report documents), renamed to this
folder's style. Tested by `PdfSignatureValidatorCorpusTests` and `PdfSignatureInspectorCorpusTests`.

| File | DSS name | What |
|---|---|---|
| `AD-RB.pdf` | `AD-RB.pdf` | ETSI plugtest, AdES baseline, one signature |
| `signature-p-bg-bor-1.pdf` | `Signature-P-BG_BOR-1.pdf` | Bulgarian plugtest, one signature |
| `signature-p-bg-bor-2.pdf` | `Signature-P-BG_BOR-2.pdf` | Bulgarian plugtest, SHA-512 signature + SHA-1 document timestamp |
| `signature-p-de-sci-4.pdf` | `Signature-P-DE_SCI-4.pdf` | German plugtest, signature + archive timestamp |
| `signature-p-fr-cs-5.pdf` | `Signature-P-FR_CS-5.pdf` | French plugtest, signature + two archive timestamps |
| `signature-p-hu-mic-1.pdf` | `Signature-P-HU_MIC-1.pdf` | Hungarian plugtest (`ETSI.CAdES.detached`) |
| `doc-firmado-B.pdf` | `doc-firmado.pdf` | Spanish B-B + DSS update |
| `doc-firmado-T.pdf` | `doc-firmado-T.pdf` | Spanish B-T |
| `doc-firmado-lt.pdf` | `doc-firmado-LT.pdf` | Spanish B-LT |
| `pades-lt.pdf` | `PAdES-LT.pdf` | B-LT: signature, document timestamp, DSS, archive timestamp |
| `belgian-multi-ocsp.pdf` | `belgian_pki_multiple_ocsps.pdf` | Belgian PKI, DSS with several OCSP responses |
| `dss-1983.pdf` | `DSS-1983.pdf` | DSS bug report: signature + DSS update |
| `dss-1683.pdf` | `DSS-1683.pdf` | DSS bug report: SHA-1 signature whose byte range does not verify |
| `bad-encoded-cms.pdf` | `BadEncodedCMS.pdf` | Malformed CMS |

These files were not pinned to a DSS commit when they were first taken; their bytes are the ones the removed
`tests/interop` corpus held (commit `8d167f8e^`).

### CAdES / XAdES — `ades/`

From `dss-cades/src/test/resources/validation` and `dss-xades/src/test/resources/validation` at the DSS commit
pinned in `ades/manifest.json` (`c8aea1f90958a851f651fe39f1575fcbd6d4a11d`), which records each file's DSS path,
profile and SHA-256. `EtsiCorpusManifestTests` checks that every file under `ades/` is in the manifest and matches
its hash; `CadesSignatureValidatorCorpusTests` and `XadesSignatureValidatorCorpusTests` validate them.

- The CAdES `.content` files are not DSS files: each was extracted once from its attached `SignedData`
  (`openssl cms -verify -inform DER -noverify`), so the `messageDigest` is checked without the network.
  `xades-detached-content.xml` is the detached document DSS ships with its XAdES vector.
- `cades-blta-modified-ats.p7m` (modified `ATSHashIndexV3`) and `xades-blta-copied-ats.xml` (copied
  `ArchiveTimeStamp`) are negative vectors: their archive timestamp must be rejected.
- `xades-blt-enveloped.xml` is a B-T whose `TimeStampValidationData` covers the TSA only; it must not be taken as
  the signature's B-LT material.

`.gitattributes` marks `ades/cades/**` and `ades/xades/**` as `binary`: git must not convert their line endings
(`xades-detached-content.xml` has CRLF, and the signature covers those bytes).

To update a vector: take the file from a DSS commit, replace it, update its hash (and the commit) in
`ades/manifest.json`, and say why in the pull request.
