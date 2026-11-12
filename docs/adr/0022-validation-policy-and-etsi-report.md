# ADR 0022: Validation Policy and ETSI Sub-Indications

**Status:** Accepted (first step; see "Not yet done"). Proof of existence amended by ADR 0027 (archive time-stamps).

**Context:**
Validation results were booleans plus free-text errors. PAdES alone had an indication; CAdES and XAdES had only
`IsValid`. Nothing said *why* a signature was INDETERMINATE in the terms of ETSI EN 319 102-1, and the accepted
algorithms were hard-coded: a SHA-1 signature was valid with a warning, an RSA-1024 key was accepted. A structured report per signature and a
policy that can change without a rebuild were needed.

**Decision:**
1. **`ValidationPolicy`** (`SimpleSign.Core.Validation.Policy`), set on `ValidationOptions.Policy`:
   - cryptographic constraints: accepted digest algorithms, each with an optional "accepted until" date (SHA-1 until
     2012-08-01 by default, MD5 never), the minimum RSA size (2048) and the accepted elliptic curves;
   - signing certificate constraints: key usage digitalSignature or nonRepudiation (warning by default);
   - each constraint group has a level: `fail`, `warn` or `ignore`.
   It is read from JSON (`ValidationPolicy.Load`, `FromJson`) with the DOM rather than the source generator, so a
   property left out keeps its default and the code stays AOT-safe. `ValidationPolicy.LoadSigned` refuses a file
   whose detached CMS signature does not verify, does not cover the file or is not by the trusted certificate
   (the configuration is protected).
2. **`ValidationPolicyEvaluator`** turns what a format validator found into an indication, the sub-indication of the
   first decisive failure (`SignatureSubIndication`, named after EN 319 102-1 §5.1.3) and the list of checks
   (`ValidationConstraintResult`). The order is the one PAdES already used: integrity, signing certificate,
   signature value, revocation, policy constraints, certificate chain.
3. An algorithm outside the policy is **not** a plain failure: when a trusted signature timestamp proves the
   signature existed before the algorithm's limit, it passes; otherwise the result is INDETERMINATE /
   `CryptoConstraintsFailureNoPoe`, as EN 319 102-1 prescribes.
4. `SignatureValidationResult`, `CadesValidationResult` and `XadesValidationResult` expose `Indication`,
   `SubIndication` and `Constraints`. `IsValid` of CAdES and XAdES now also requires `Indication == Valid`.

**Consequences:**
- A SHA-1 or MD5 signature without an older proof of existence, or an RSA key under 2048 bits, is INDETERMINATE by
  default where it used to be VALID. A policy with `"cryptographic": { "level": "warn" }` restores the warning.
- Errors and warnings stay as they were; the constraints are the structured view.

5. **Revocation in CAdES and XAdES**: `ValidateAsync` runs the synchronous validation, then checks the signer chain
   and the signature timestamp's TSA chain through `IChainRevocationChecker` (`RevocationStep`) and evaluates
   again. The results expose `IsNotRevoked` and `RevocationSource` (`CertificateChain`). Both result types became
   records so the revocation outcome is applied with `with`.

**Not yet done:**
- One shared chain builder for the three validators (they still differ in how anchors are used), and country
  extensions in CAdES and XAdES.
- Embedded revocation values of CAdES and XAdES are not yet passed to the revocation step (it queries online).
