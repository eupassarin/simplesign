# ADR 0025: Augmenting Existing Signatures

**Status:** Accepted.

**Context:**
SimpleSign produced each baseline level only while signing: a signature made at B-B stayed at B-B. ETSI EN 319 142-1,
EN 319 122-1 and EN 319 132-1 expect a signature to be raised later (B-T, then B-LT, then B-LTA) and a B-LTA to be
renewed before its last archive time-stamp's TSA certificate expires. The pieces existed inside the signing builders
(time-stamping the signature value, collecting validation data, the archive time-stamp of each format) but no public API
applied them to a file that was already signed, and the CLI had no command for it.

**Decision:**
- One public augmenter per format, in the builder style of the signers: `PadesAugmenter.Document(pdf)`,
  `CadesAugmenter.Signature(cms, detachedContent)` and `XadesAugmenter.Document(xml, detachedData)`, with
  `WithTimestamp`, `WithHttpClientProvider`, `ToLevel`, `RenewArchive`, `WithLogger` and `AugmentAsync`. The result
  carries the document and the levels before and after (`*AugmentationResult`).
- Augmenting never touches what is signed:
  - **PAdES** works with incremental updates only. B-T is a document time-stamp (EN 319 142-1 allows it in place of a
    signature time-stamp), B-LT a DSS update with the data of every signature and time-stamp, B-LTA a document
    time-stamp over the DSS; a renewal adds the last time-stamp's data and a new document time-stamp. The CMS in
    /Contents is not rewritten: that would break any later signature whose ByteRange covers it.
  - **CAdES** adds the signature-time-stamp, the SignedData's certificate and revocation sets, and archive-time-stamp-v3
    with ats-hash-index-v3, to the first signer.
  - **XAdES** adds SignatureTimeStamp, CertificateValues/RevocationValues and xades141:ArchiveTimeStamp as unsigned
    properties of the chosen ds:Signature.
- A level lower than the one the file has changes nothing. A level that cannot be reached throws `SigningException`
  with `SigningErrorReason.LevelNotAchievable` (no TSA, revocation data that cannot all be collected); B-LTA of a
  detached CAdES or XAdES signature needs its data and throws `ArgumentException` without it.
- The PAdES conformance detector counts a document time-stamp after a signature as its B-T time-stamp, and requires a
  further one for B-LTA when the signature has no signature time-stamp of its own.
- CLI: `simplesign augment <file> --level BT|BLT|BLTA --tsa URL [--data] [--signature-id] [--renew] [--json]`, the
  format read from the file's content. TestBench: run kind `augment` (library engine) and playbook step kind `augment`.

**Consequences:** the ETSI playbook raises a B-B signature of each format to B-LTA one level at a time and renews a
PAdES B-LTA (checklist items PA-6 and EX-3). Augmenting a CAdES co-signer other than the first, or a PAdES signature by
rewriting its CMS, is not offered.
