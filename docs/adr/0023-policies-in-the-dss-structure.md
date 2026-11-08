# ADR 0023: Signing and Validation Policies in the Structure of the EU DSS

**Status:** Accepted (first delivery; see "Not yet done")

**Context:**
ADR 0021 introduced a `SigningPolicy` with three fixed presets (`Default`, `Strict`, `Minimal`): combinations of
switches, not a configurable policy. ADR 0022 introduced a small `ValidationPolicy` JSON of SimpleSign's own
(algorithms with dates, key usage, three levels). The EU DSS, the reference implementation of ETSI EN 319 102-1,
solves the same problem with a configurable file: its validation policy (`constraint.xml`, schema
`http://dss.esig.europa.eu/validation/policy`) lists every constraint of every context (signature, counter-signature,
timestamp, revocation, signing and CA certificates, cryptography) with a level FAIL, WARN, INFORM or IGNORE. Since DSS
6.3 the cryptographic part can also come from an ETSI TS 119 322 cryptographic suite. Using the same structure lets a
policy mean the same thing in both, and their verdicts be compared.

**Decision:**
1. **One format, JSON, in the DSS structure.** `ValidationPolicy` (namespace `SimpleSign.Core.Policies`) reads and
   writes a JSON document whose root is `ConstraintsParameters` and whose tree, names and levels are those of the DSS
   `policy.xsd`: one property per element, attributes as properties, the `Id` and `Algo` lists as arrays, the text
   of an `Algo` as `Value`. A name outside the schema is refused with its JSON path. SimpleSign does not read or
   write XML policies; interoperation with DSS (XML only) is a conversion done outside the library.
2. **The DSS default values.** `ValidationPolicy.Default` is embedded (`Policies/Default/validation-policy.json`) with
   the constraints and levels of the DSS default policy, written for SimpleSign (DSS is LGPL-2.1, SimpleSign MIT: its
   files are not copied). Notable consequences: the signing certificate's key usage asks for nonRepudiation (WARN);
   RSA keys follow dated sizes (1900 bits until 2027-01-01, 3000 until 2035-01-01, with WARN for dates after the
   policy's `UpdateDate`); elliptic curves are judged by key size, not by OID.
3. **A signing policy in the same style.** DSS has no signing policy. `SigningPolicy` reads a JSON document whose root
   is `SigningConstraints`, with DSS names: `SigningCertificate` and `CACertificate` (`NotExpired`, `KeyUsage`,
   `ExtendedKeyUsage`, `NotRevoked`, `RevocationDataAvailable`, `Cryptographic`) and a `Cryptographic` element for the
   signature to be made. FAIL refuses (`SigningException` with the reasons of ADR 0021), WARN adds a
   `SigningWarning` (`PolicyConstraint`), INFORM logs. The presets are removed: `Strict` is `NotRevoked` and
   `RevocationDataAvailable` at FAIL; `Minimal` is a policy whose constraints are IGNORE.
4. **Cryptographic suites.** `CryptographicSuite` reads ETSI TS 119 322 suites (Annex B, JSON). Given to a policy,
   globally or for one context (`WithCryptographicSuite`), a suite replaces its `Cryptographic` constraints; an
   algorithm that expires after the suite's `PolicyIssueDate` gives a warning, as in DSS.
5. **Evaluation by path.** `ValidationPolicyEvaluator` evaluates the constraints SimpleSign can establish and reports
   each with its DSS path as id (`SignatureConstraints/BasicSignatureConstraints/SigningCertificate/KeyUsage`). The
   first FAIL decides the indication and the EN 319 102-1 sub-indication; INFORM gives the new
   `ConstraintStatus.Information`. A constraint with a level that SimpleSign does not evaluate is reported as
   `NotChecked`, never dropped in silence. `Cryptographic` elements are resolved as in DSS: the context's own, then
   the enclosing ones, then the global one; `Model` (SHELL, CHAIN, HYBRID) decides the time at which CA certificates
   must be valid.
6. Immutable policies, edited with `With(path, constraint)`, `WithName` and `WithCryptographicSuite`; `Digest` (SHA-256
   of the written policy and its suites) identifies the policy applied. `LoadSigned` keeps the protection of
   ADR 0022.
7. **JSON Schema.** `ValidationPolicy.GetJsonSchema()` and `SigningPolicy.GetJsonSchema()` generate the JSON Schema
   (draft 2020-12) of the files from the same element tree the reader uses (the DSS `policy.xsd` turned into JSON);
   `docs/schemas/` keeps them, a test keeps them current, and `ToJson` names them in `$schema`.
8. **Policy per signature.** `IPolicyProvider` gives the validation policy for each signature by the signature policy
   OID it names (`StaticPolicyProvider.Add(policy, "2.16.76.1.7.1.*")`); `ValidationOptions.PolicyProvider` and the DI
   registration use it, and a provider registered before `AddSimpleSign` replaces the fixed one (policies changed at
   run time). Results carry `AppliedPolicy` (name and digest), as ETSI TS 119 102-2 asks.
9. **Revocation freshness.** `ChainRevocationResult.IssuedAt` gives when the signer's CRL (thisUpdate) or OCSP
   response (producedAt) was issued, for `RevocationFreshness`.
10. **DSS interoperation outside the library.** The TestBench converts the policy to `constraint.xml` and sends it to
    DSS with every request (`DssPolicyConverter`), so both judge under the same policy. Network tests check that the DSS
    default `constraint.xml` reads into SimpleSign's model with the same levels, and that the XML written from
    SimpleSign's default is valid against the DSS `policy.xsd`.

11. **`CertificateVerifier`-style options.** `ValidationOptions.Verifier` (`VerifierOptions`) says how validation data is
    obtained, as the DSS `CertificateVerifier`: `RevocationStrategy` (OCSP first by default, as DSS; it was CRL first in
    `ChainRevocationChecker` and OCSP first in PAdES) with `RevocationFallback`, `UseAia`, and
    `CheckRevocationForUntrustedChains` (off, as DSS: an untrusted chain is not sent to the addresses it names). The DSS
    alerts are not copied: what a validation or a signature must refuse is a constraint level of the policies.
12. **Validation level.** `ValidationOptions.Level` (`BasicSignatures`, `Timestamps`, `LongTermData`, `ArchivalData`, the
    default) stops each validator at the level asked: no signature timestamps (no proof of existence), no revocation or
    long-term data, no archive timestamps.
13. **Embedded revocation data in CAdES and XAdES.** The revocation step now receives the CRLs and OCSP responses the
    signature carries (CAdES `revocation-values`, XAdES `RevocationValues`), checked before the online sources.

14. **Reports.** `ValidationReports.ToEtsiXml` writes the ETSI TS 119 102-2 signature validation report (namespace
    `http://uri.etsi.org/19102/v1.2.1#`, with the URIs DSS uses: main and sub-indications, constraint status, validation
    process Basic/LTVM/LTA, the signing certificate as a validation object, the applied policy as the validation
    service policy); `ToSimpleJson` writes a report with the content of the DSS simple report. Every result gives its
    `SignatureReportEntry` (`ToReportEntry()`). A network test validates the XML against the schema DSS ships. The DSS
    detailed report and diagnostic data are not reproduced: they are formats of DSS's own.

15. **Trusted lists from a LOTL.** `TrustedListSet` loads a list of trusted lists as the DSS trusted list validation
    job does: the LOTL is checked with the configured certificates (for the EU LOTL, those of the Official Journal),
    each `OtherTSLPointer` to an XML list with the certificates the LOTL gives for it, a list that cannot be loaded is a
    `Problem` and not a failure, and a disk cache serves a list while its NextUpdate has not passed and when a download
    fails. `TrustedList` reads its version and pointers. Both expose `TrustedListInfo` (`ITrustedListInfoProvider`), and
    the evaluator checks the `eIDAS` constraints (`TLFreshness` from the load time, `TLNotExpired`, `TLWellSigned`,
    `TLVersion`) for the list that holds a certificate of the signature's chain (PAdES, where the trust anchor
    providers are).

**Consequences:**
- A signature that was VALID can now carry warnings it did not have (key usage without nonRepudiation, self-signed
  signing certificate, RSA 2048 after 2027) and fail constraints that were not checked (CA certificate not a CA,
  missing signing time) — the same verdicts as DSS.
- Constraint ids changed from `crypto.digestAlgorithm`, `signingCertificate.keyUsage`… to DSS paths.
- Country packages derive their policies from the defaults (`IofePolicies`).

**Not yet done:**
- PAdES reports the issue time of revocation data only for live OCSP answers (`IRevocationChecker` is public and
  returns no date); for embedded or downloaded CRLs `RevocationFreshness` is reported as not checked.
- The ETSI report does not list the chain, revocation data and timestamps as validation objects yet.
- The eIDAS constraints are evaluated for PAdES only: the CAdES and XAdES validators take their anchors as
  certificates, without the trusted lists behind them.
- The EU LOTL's own certificates (published in the Official Journal) are configuration; their rotation (pivot LOTLs)
  is not followed.
