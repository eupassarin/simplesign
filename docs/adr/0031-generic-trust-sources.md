# ADR 0031: Generic Trust Sources — the AATL, a Trusted List as a Profile, and Anchors with Conditions

**Status:** Accepted.

**Context:**
A country entered SimpleSign as a whole trust framework: a package, policies, a CLI extension, a checklist and a
playbook (ICP-Brasil, eIDAS, IOFE). That is right where the law asks for interpretation, and it does not scale to the
rest of the world. To validate, most organizations ask one thing — does this certificate come from an authority I should
trust? — and two sources answer it without a framework's package:

- **Adobe's Approved Trust List (AATL)**, the list that makes Acrobat show a signature as trusted. Outside a national
  framework, "Acrobat accepts it" is the criterion people use.
- **A trusted list in the ETSI TS 119 612 format** that a country or an organization publishes on its own, outside the
  EU list of trusted lists. The reader existed (`TrustedList`), and the CLI read one with `--tsl`; a list kept current
  and a profile over it did not, outside the IOFE package.

Reading the real AATL showed something no extension point could express: half of its anchors are trusted **only for
signer certificates of certain certificate policies** (ICP-Brasil's root for A3 and A4 certificates, for one). A trust
anchor was a certificate and nothing else; `IChainValidationProvider` is chosen by the signer's certificate alone, before
the chain is known, so it could not apply a rule that belongs to the anchor the chain reaches.

**Decision:**

- **`IConstrainedTrustAnchorProvider` (`SimpleSign.Core`): a trust anchor provider that can refuse a chain.** Once the
  signer's chain is built to one of its anchors, the PAdES, CAdES and XAdES validators and the checks made before
  signing (`TrustedChain`) call `WhyRefused(anchor, chain)`; a reason makes the chain untrusted, with the reason as the
  error.
  - The anchor asked about is **the one nearest to the signer**, as a chain builder stops at it.
  - **Trust stays a union.** `TrustProfile.ConstrainedTrustAnchors` gives a profile's constrained providers, each
    accepting a chain whose anchor another provider of the profile gives without conditions:
    `IcpBrasilProfile.Create().WithTrustFrom(aatl)` trusts an A1 certificate because ICP-Brasil's profile does.
  - They reach the validators as `ValidationOptions.ConstrainedTrustAnchors` (a profile's are added), next to
    `TimedTrustAnchors` (ADR 0026); the CLI passes them the same way.
  - The chain of a time-stamp's TSA is **not** asked about.
- **`PdfEmbeddedFiles` (`SimpleSign.PAdES`)** reads the files embedded in a PDF. The AATL is distributed as a signed PDF
  with an attachment, and extensions use the public API only.
- **`TrustedListSource` and `TrustedListProfile` (`SimpleSign.XAdES`)**: any ETSI TS 119 612 list kept current (each
  copy checked against the operator's certificate, swapped in one step, cached, a copy with a lower sequence number
  refused) and made a `TrustProfile` — the default policies, the list as the only trust, the system's roots not trusted.
  The CLI has `--profile tsl` for the list of `--tsl` (or the Sandbox's with `--sandbox`). `IofeTrustedListSource` is its
  specific form and is unchanged. **There is no catalog of countries**: the caller gives the list's location and the
  certificate it is signed with.
- **`SimpleSign.Adobe.Aatl`** (`src/Extensions/Adobe/Aatl`) reads the AATL.
  - The PDF's signature must verify, **cover the whole file** and chain to the bundled Adobe root — never to the
    system's roots. The one place a signature does not cover, its own `/Contents`, must hold the signature's hexadecimal
    and nothing else: the identities are found by reading the whole file, and an object hidden there would be read as
    part of the list.
  - The anchors are the trusted roots that are not removed; the policy restrictions are checked on the signer's
    certificate.
  - `AatlProfile` (`aatl`) has policies of its own: validation with the signing-certificate reference at WARN (Acrobat
    signs `adbe.pkcs7.detached` without it, and ICP-Brasil's policy does the same for the same reason), and signing that
    requires the chain to reach an accepting anchor.
  - **The list is downloaded from Adobe at run time and is not bundled.** Adobe publishes no terms we could find for its
    use by other software; the package bundles only the Adobe root, which Adobe publishes.
- It comes to the CLI as an extension (ADR 0030): `SimpleSign.Adobe.Aatl.Cli`.

**Consequences:**

- The AATL and a country's own trusted list cover the countries without a framework's package. A package remains for
  the countries whose law needs it.
- **These profiles give trust, not a legal level.** No qualifier, no national policy: a signature trusted under `aatl`
  or `tsl` chains to a recognised authority, and nothing more is said.
- A trusted list's signer has to be found and kept by the caller: when the operator changes its key, the list stops
  verifying (it fails closed) until the caller has the new certificate. There is no pivot, as the EU LOTL has.
- **The AATL has no history.** It is not an `ITimedTrustAnchorProvider`: an authority taken out of it stops being
  trusted for the signatures it vouched for before. It has no expiry date either.
- **The AATL's format is not documented by Adobe.** It was read from the list of 2026-11-12. `ImportAction` 3 is read
  as a removal because, in that list, it marks the authorities Adobe took out; `NonExplicitProcessing` is reported and
  not interpreted. A format change shows as a list that cannot be read, which fails closed.
- A non-self-signed anchor still does not anchor a chain by itself (the validators trust a chain that ends at a
  self-signed anchor), for the AATL as for every provider.
- The policy restrictions are checked on the signer's certificate only, not through the chain as RFC 5280's policy
  processing would; a TSA under a restricted anchor is trusted whatever its policies.
- `IChainValidationProvider` is unchanged. A rule that belongs to the anchor now has a place of its own, instead of a
  provider that would have to guess the anchor from the signer's certificate and could shadow another framework's.
- The TestBench and the Sandbox do not know the AATL yet: there is no test list on the Sandbox, and no playbook.

**Alternatives considered:**

- *Serve only the AATL's unrestricted anchors.* Rejected: it leaves out ICP-Brasil, Entrust, QuoVadis, Sectigo and part
  of DigiCert and GlobalSign — half of the list, and the half most signers use.
- *Trust the restricted anchors without the check.* Rejected: it would accept certificates Acrobat refuses, the opposite
  of what the profile is for.
- *Apply the restrictions in an `IChainValidationProvider`.* Rejected: it is selected by the signer's certificate before
  the chain exists. To be safe it would claim every certificate, and the first provider that claims a certificate is the
  only one that runs, so it would shadow the chain validation of a framework combined with the AATL.
- *Bundle the AATL in the package.* Rejected: it would redistribute Adobe's file, and a bundled copy is stale the day
  Adobe removes an authority.
- *A catalog of national trusted lists (a name for each country's list and signer).* Left out: no operator we looked
  at publishes its signing certificate apart from the list, so each entry would rest on a certificate taken from the
  list itself, to be replaced whenever the country changes its key.
