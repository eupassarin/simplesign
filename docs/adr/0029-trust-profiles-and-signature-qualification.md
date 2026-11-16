# ADR 0029: Trust Profiles and Signature Qualification

**Status:** Accepted.

**Context:**
Using SimpleSign under a national framework meant assembling it by hand. For ICP-Brasil a caller
had to build the extension, pass its trust anchors, pass its chain validation provider, and then
remember to set the matching signing and validation policies — four things that must agree, with
nothing tying them together. ADR 0009 gave us `ICountryExtension` for the *trust* half (anchors and
chain rules), but policies stayed separate, so "sign the way ICP-Brasil requires" was not something
the API could express. The CLI and the TestBench each rebuilt that wiring in their own way, and the
combinations a user got wrong (a framework's anchors with SimpleSign's default policy) failed in
ways that looked like library bugs.

eIDAS then added a second, distinct question. A validator says whether a signature *verifies* — the
EN 319 102-1 indication. It does not say what the signature *is* in law: whether it is a qualified
electronic signature (QESig), a qualified seal, an advanced signature backed by a qualified
certificate, and so on. ETSI TS 119 615 defines that determination, it is specific to a legal
framework, and it depends on things no generic validator should hard-code — QC statements, the
trusted list's service Qualifications, whether the key is on a QSCD. It is also **not** a verdict on
validity: a signature can verify and not be qualified, and the indication must not change because of
it.

**Decision:**

- **`TrustProfile` (`SimpleSign.Core`) is a trust framework as one value**: a name and title, a
  signing policy (nullable), a validation policy, its trust anchor providers and its chain
  validation providers. It is a `record`, and it implements `ICountryExtension`, so everything that
  already accepted an extension keeps working.
  - `WithProfile(profile)` on every signer builder — PAdES, CAdES, XAdES, deferred and batch — and
    `ValidationOptions.Profile` for validation.
  - **An explicit setting wins over the profile's**: `WithSigningPolicy(...)` or
    `ValidationOptions.Policy` set after a profile is honoured. The profile is a default, not a
    lock.
  - **Only one profile sets the policies.** Trusting more than one framework is a different need, so
    `WithTrustFrom(params TrustProfile[])` adds other profiles' anchors and chain rules and takes
    nothing else from them — not their policies, not their qualifiers.
  - `CanSign` is `SigningPolicy is not null`. A framework that only validates (Gov.br has no signing
    rules of its own) is refused by `WithProfile` with `ArgumentException` rather than silently
    signing under the default policy.
  - `TrustProfile.Default` is SimpleSign's own: default policies, no anchors of its own.
- **The profiles live in their packages, not in Core**: `IcpBrasilProfile.Create()`,
  `GovBrProfile.Create()`, `IofeProfile.LoadAsync()`, `EidasProfile.LoadAsync()`. Core defines the
  shape; it knows nothing about any country. `TrustProfile.FromExtension(...)` builds one from an
  existing `ICountryExtension`, so a third-party framework needs no change to Core.
- **`ISignatureQualifier` (`SimpleSign.Core.Extensions`) is a separate extension point** —
  deliberately not folded into `IChainValidationProvider`, because qualification is not a check that
  can fail a signature. One member:
  `SignatureQualification? Qualify(SignatureQualificationContext context)`, returning `null` when
  the signature is not under that framework.
  - The validators call it **after** a signature is validated, and write the answer to
    `Qualification` on the PAdES, CAdES and XAdES results. **The indication never changes.**
  - Qualifiers come from `ValidationOptions.SignatureQualifiers`, from the profile, or from a
    country extension; they are added together, and the first non-null answer wins.
  - `SignatureQualificationContext` carries what a qualifier may need (the signer certificate, the
    indication, the certificates gathered, the claimed signing time) rather than the whole result,
    so the contract does not widen every time a result type gains a field.
  - It reaches the reports as `SignatureQuality` in the ETSI TS 119 102-2 XML and `qualification` in
    the simple JSON and the HTML report, and the CLI prints it beside the indication.
- `EidasQualifier` (`SimpleSign.Europe.Eidas`) is the only implementation today: the EU
  determination of TS 119 615 and TS 119 172-4, reading `QcStatements` and the trusted list's
  service Qualifications.
- The CLI exposes profiles as `--profile <name>`, `--trust-profile` (repeatable, the `WithTrustFrom`
  half) and `simplesign profiles`; the TestBench as a Profile menu with an "Also trust" list.

**Consequences:**

- "Sign the way this framework requires" is now one call, and the four things that must agree travel
  together. The CLI, the TestBench and the playbooks share the same wiring instead of three copies.
- Qualification is reported without touching the indication, so no existing validation changes its
  verdict. A caller that configures no qualifier sees `Qualification` as `null` and nothing else
  differs.
- `TrustProfile` implementing `ICountryExtension` keeps one concept where there could have been two,
  at the cost of a type that is both a value and an extension.
- A profile that cannot sign throws rather than falling back. This is deliberate — the fallback
  would be a signature made under rules the caller did not choose — but it means `WithProfile` is
  not safe to call with an arbitrary profile without checking `CanSign`.
- Policies now have two sources (the profile and the explicit setters). The precedence is fixed and
  documented, and the TestBench marks each field that a profile set, because "why is this constraint
  FAIL?" is otherwise hard to answer.

**Alternatives considered:**

- *Leave the wiring to the caller (the status quo).* Rejected: the combinations that must agree are
  not discoverable, and getting them wrong produces failures that read as library bugs.
- *Put the profiles in Core.* Rejected: Core would depend on every country package, inverting
  ADR 0009 and ADR 0018's package boundaries.
- *Make qualification part of chain validation.* Rejected: a chain validation provider can fail a
  signature, and qualification must never do that. Keeping it a separate interface makes the
  "reported beside, never instead of" rule structural rather than a convention.
- *Return qualification only in the reports.* Rejected: callers that never render a report still
  need it, and it would have to be recomputed from the result.
- *Let several profiles each contribute policies.* Rejected: merging two policies has no
  well-defined answer when both set the same constraint to different levels. `WithTrustFrom` covers
  the real need — trusting more than one framework — without inventing that merge.
