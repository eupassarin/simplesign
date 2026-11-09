# ADR 0024: SimpleSign's Own Policy Format

**Status:** Accepted. Supersedes the validation policy structure of ADR 0023 (the signing policy, the levels, the
cryptographic suites, the verifier options, the reports and the trusted lists of ADR 0023 stay).

**Context:**
ADR 0023 made the validation policy a JSON copy of another validator's complete policy tree. That tree covers far more
than SimpleSign does: containers, evidence records, attestations, JSON signatures, the qualification rules of one
jurisdiction. In the default policy about 275 constraints were active and SimpleSign evaluated about 45; the rest
appeared as "not checked", which made the file promise checks nobody made and hid which gaps were real. A policy file
is part of SimpleSign's public contract, so it should describe what SimpleSign does.

**Decision:**
- The validation policy is SimpleSign's own format: root `ValidationConstraints` (beside the signing policy's
  `SigningConstraints`), contexts `SignatureConstraints`, `CounterSignatureConstraints`, `Timestamp`, `Revocation`,
  `Cryptographic`, `Model` and `TrustedLists`. The element names and the levels (FAIL, WARN, INFORM, IGNORE) stay as
  they were, so policies written for other validators translate element by element.
- Only constraints SimpleSign evaluates, or will evaluate with the features it has, are in the format. Groups for
  features SimpleSign does not have were removed: ASiC containers, PDF/A conformance, evidence records, attestations
  and their key binding signatures, lists of trusted entities, JSON-signature headers, the qualification and PSD2
  statements of a single jurisdiction, certHash, trust anchor sunset dates and the visual comparison of PDF pages.
  Each comes back with the feature, if it is ever built.
- Kept constraints that SimpleSign does not evaluate yet are reported as not checked until they are connected; the
  list, with the state and the reason of every element, is `docs/policies/compatibility.md`.
- The reader stays strict: a name outside the format is refused with its JSON path and a pointer to the
  compatibility document. Translating another validator's policy is a separate step (the TestBench does it).
- The comparison with other validators lives only in `docs/policies/compatibility.md`; the format, the code and the
  other documents describe SimpleSign's policies on their own.

**Delivery:** the constraints kept as "to connect" were wired in four steps: the signature context (RFC 5280
certificate checks, subject attributes, PDF ByteRange and signature dictionary, signed and unsigned attributes,
formats); timestamps and revocation data evaluated as tokens in their own contexts (a timestamp that fails is not a
proof of existence, revocation data that fails is not acceptable; online data included); countersignatures in their
context and trusted lists for CAdES and XAdES (with the type and status of the trust service). `PolicyCoverage` is the
single source of what is evaluated; a test keeps `docs/policies/compatibility.md` in step with it. Then the "to implement"
ones: `RevocationHasInformationAboutCertificate`, the content timestamp, and the PDF revision comparison (DocMDP,
FieldMDP, SigFieldLock, form fill, annotation and undefined changes, page differences, annotation overlap: the
signed revision against the final one, DSS and document timestamps not counting as changes). What remains is XML
schema validation (`StructuralValidation` for XAdES, `TLStructure`).

**Consequences:**
- A policy file written for ADR 0023 must be updated: rename the root to `ValidationConstraints` and `eIDAS` to
  `TrustedLists`, and drop the removed elements (the reader names each one).
- The default policy only has constraints with meaning for SimpleSign; the count of "not checked" now measures the
  real backlog (connect the checks the validators already make; evaluate timestamps, revocation data and
  countersignatures in their own contexts; compare PDF revisions; validate XML structure).
