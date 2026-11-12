# ADR 0027: Past Signature Validation with Archive Time-Stamps

**Status:** Accepted. Amends ADR 0022 (proof of existence).

**Context:**
ADR 0022 took the proof of existence (POE) of a signature from its signature time-stamp only, and only when that
token's TSA was trusted today. A B-LTA signature is meant to outlive every certificate in it: after the signature
time-stamp's TSA certificate expires, the signature time-stamp is no longer trusted, the signature loses its POE, and a
signer whose certificate has expired too becomes INDETERMINATE (OUT_OF_BOUNDS_NO_POE). EN 319 102-1 §5.6 (validation
process for signatures with archival data, "past signature validation") says a later time-stamp over an object is a
proof that the object existed at the later token's time, so the earlier token can be judged at that time.

**Decision:**
- When the signature time-stamp is intact but its TSA is not trusted today, a later time-stamp over it can restore
  its trust:
  - **CAdES:** the archive-time-stamp (v2 or v3) of the signature, once it is checked to cover the signature;
  - **XAdES:** the ArchiveTimeStamp, once it is checked;
  - **PAdES:** a document time-stamp in a later revision, whose ByteRange hash and signature are checked.
- The later token must be trusted (today's anchors, or the timed anchors of its genTime, ADR 0026) and later than the
  signature time-stamp. The signature time-stamp's TSA chain is then built at the later token's genTime with today's
  anchors and the timed anchors of that time. If it holds, the signature time-stamp is trusted and its genTime is the
  signature's POE again; a warning says a later time-stamp proved it.
- Revocation of the earlier TSA is not re-checked at that time: the validation data the B-LT/B-LTA levels embed is
  judged by the existing revocation steps.
- The rule lives in Core (`TimedTrust.TrustTsaAtLaterProof`), applied by the three validators. It runs only at
  `ValidationLevel.ArchivalData` for PAdES (CAdES and XAdES validate archive time-stamps only at that level already).
- Only one step of the chain is taken: the newest time-stamp must be trusted today. A chain of renewals where every
  archive time-stamp but the last has an expired TSA is not walked down.

**Consequences:** a B-LTA whose signer and signature-time-stamp TSA have both expired stays TOTAL_PASSED while its
archive (or document) time-stamp is trusted; the same signature at B-T is INDETERMINATE / OUT_OF_BOUNDS_NO_POE. The
Sandbox gives a TSA whose certificate is issued per request and valid N seconds (`/tsa/short-lived?seconds=N`;
TestBench provider `SandboxShortLived`, 30 s), and the ETSI playbook shows both cases for PAdES and CAdES (VA-9).
